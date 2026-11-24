/*
 * dhcp_client.c - DHCP client for the DORA lease-lifecycle simulation
 *
 * Course : Computer Networks (25CSE153)
 *
 * States: INIT -> SELECTING -> REQUESTING -> BOUND -> RENEWING -> BOUND ...
 * - DORA with select() timeouts and exponential-backoff retransmission
 * - Automatic T1 renewal at 50 % of the lease
 * - Interactive keys: r = renew now, x = release & exit, e = stop renewing
 *   (Linux: type the key + Enter; Windows console: just press the key)
 * - Replies are filtered by xid AND chaddr, so many clients can share the
 *   same broadcast port (SO_REUSEPORT) without interfering.
 *
 * Usage: ./dhcp_client [-m <MAC>] [-b <broadcast_ip>]     (Windows: .\\dhcp_client.exe)
 *                      [--test-lifecycle | --test-nak [-r <ip>] | --test-expire]
 */
#include "dhcp_common.h"

#ifdef _WIN32
  #include <conio.h>                    /* _kbhit / _getch for key input */
#endif

#define MAX_DORA_TRIES    4
#define MAX_RENEW_TRIES   3
#define REPLY_TIMEOUT_MS  2000
#define RENEW_RETRY_MS    2000

#define MASK(t) (1u << (t))

typedef enum { MODE_INTERACTIVE, MODE_LIFECYCLE, MODE_NAK, MODE_EXPIRE } mode_t_;

typedef struct {
    sock_t             sock;
    struct sockaddr_in server;          /* <bcast>:SERVER_PORT          */
    uint8_t            mac[6];
    char               who[32];         /* log tag "CLIENT xx:..:xx"    */
    uint32_t           ip, server_id, mask, router, dns, lease_s, t1_s;
    int64_t            bound_at_ms;
    unsigned           filtered;        /* foreign replies ignored      */
} client_t;

static uint32_t g_rng;

static uint32_t new_xid(void)
{
    /* xorshift32 */
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

/* ---------------- Packet I/O ---------------- */
static int send_msg(client_t *c, uint8_t type, uint32_t xid, uint32_t ciaddr,
                    uint32_t req_ip, uint32_t server_id)
{
    dhcp_packet_t p;
    uint8_t buf[DHCP_MAX_PKT];
    size_t len;

    memset(&p, 0, sizeof(p));
    p.op     = BOOTREQUEST;
    p.htype  = HTYPE_ETHERNET;
    p.hlen   = HLEN_ETHERNET;
    p.xid    = xid;
    p.flags  = BOOTP_FLAG_BCAST;
    p.ciaddr = ciaddr;
    memcpy(p.chaddr, c->mac, 6);
    p.opt.msg_type = type;
    if (req_ip) {
        p.opt.requested_ip = req_ip;
        p.opt.present     |= OPTF_REQUESTED_IP;
    }
    if (server_id) {
        p.opt.server_id = server_id;
        p.opt.present  |= OPTF_SERVER_ID;
    }

    len = dhcp_serialize(&p, buf, sizeof(buf));
    if (len == 0 || sock_sendto(c->sock, buf, len, &c->server) < 0) {
        log_msg(c->who, "sendto failed (error %d)", sock_errno());
        return -1;
    }
    return 0;
}

/* Receive one datagram (non-blocking use after select). Returns 1 if it is
 * a BOOTREPLY for this client with matching xid and a type in type_mask.  */
static int read_one(client_t *c, uint32_t xid, uint32_t type_mask,
                    dhcp_packet_t *out)
{
    uint8_t buf[1500];
    long r = sock_recv(c->sock, buf, sizeof(buf));
    dhcp_packet_t p;

    if (r <= 0 || dhcp_deserialize(buf, (size_t)r, &p) != 0)
        return 0;
    if (p.op != BOOTREPLY)
        return 0;
    if (memcmp(p.chaddr, c->mac, 6) != 0 || p.xid != xid) {
        c->filtered++;                  /* someone else's broadcast   */
        return 0;
    }
    if (!(type_mask & MASK(p.opt.msg_type)))
        return 0;
    *out = p;
    return 1;
}

/* Wait up to timeout_ms for a matching reply. Returns 1 found, 0 timeout. */
static int wait_reply(client_t *c, uint32_t xid, uint32_t type_mask,
                      int timeout_ms, dhcp_packet_t *out)
{
    int64_t deadline = mono_ms() + timeout_ms;

    for (;;) {
        int64_t left = deadline - mono_ms();
        int n;

        if (left <= 0)
            return 0;
        n = sock_wait_readable(c->sock, left);
        if (n < 0) {
            sock_perror("select");
            return 0;
        }
        if (n > 0 && read_one(c, xid, type_mask, out))
            return 1;
    }
}

/* Sleep for ms while draining (and filtering) the socket. */
static void idle_ms(client_t *c, int64_t ms)
{
    dhcp_packet_t dummy;
    (void)wait_reply(c, 0xFFFFFFFFu, 0, (int)ms, &dummy);
}

static void apply_ack(client_t *c, const dhcp_packet_t *ack)
{
    c->ip          = ack->yiaddr;
    c->server_id   = (ack->opt.present & OPTF_SERVER_ID) ? ack->opt.server_id
                                                         : ack->siaddr;
    c->mask        = ack->opt.subnet_mask;
    c->router      = ack->opt.router_ip;
    c->dns         = ack->opt.dns_ip;
    c->lease_s     = (ack->opt.present & OPTF_LEASE_TIME) ? ack->opt.lease_time : 16;
    c->t1_s        = (ack->opt.present & OPTF_T1_TIME) ? ack->opt.t1_time
                                                       : c->lease_s / 2;
    c->bound_at_ms = mono_ms();
}

static void print_config(const client_t *c)
{
    char ip[INET_ADDRSTRLEN], m[INET_ADDRSTRLEN], g[INET_ADDRSTRLEN],
         d[INET_ADDRSTRLEN], s[INET_ADDRSTRLEN], mac[18];
    uint32_t prefix = 0, x = c->mask;

    while (x & 0x80000000u) { prefix++; x <<= 1; }
    printf("  +------------------- Assigned Network Configuration -------------------+\n");
    printf("  | Client MAC      : %-51s|\n", format_mac(c->mac, mac));
    printf("  | IP Address      : %-15s /%-34u|\n", ip_to_str(c->ip, ip), prefix);
    printf("  | Subnet Mask     : %-51s|\n", ip_to_str(c->mask, m));
    printf("  | Network Address : %-51s|\n", ip_to_str(c->ip & c->mask, s));
    printf("  | Default Gateway : %-51s|\n", ip_to_str(c->router, g));
    printf("  | DNS Server      : %-51s|\n", ip_to_str(c->dns, d));
    printf("  | DHCP Server ID  : %-51s|\n", ip_to_str(c->server_id, s));
    {
        char lt[64];
        snprintf(lt, sizeof(lt), "%u s (T1 renewal at %u s)", c->lease_s, c->t1_s);
        printf("  | Lease Time      : %-51s|\n", lt);
    }
    printf("  +----------------------------------------------------------------------+\n");
    fflush(stdout);
}

/* ---------------- Protocol phases ---------------- */
/* INIT -> SELECTING -> REQUESTING -> BOUND. Returns 0 on success. */
static int do_dora(client_t *c)
{
    int attempt;
    char ip[INET_ADDRSTRLEN], sid[INET_ADDRSTRLEN];

    for (attempt = 1; attempt <= MAX_DORA_TRIES; attempt++) {
        int timeout = 1000 << (attempt - 1);      /* 1,2,4,8 s backoff */
        uint32_t xid = new_xid();
        dhcp_packet_t offer, reply;

        log_msg(c->who, "[INIT->SELECTING] DHCPDISCOVER broadcast (xid=0x%08X, "
                        "attempt %d/%d, timeout %d ms)",
                xid, attempt, MAX_DORA_TRIES, timeout);
        if (send_msg(c, DHCP_DISCOVER, xid, 0, 0, 0) < 0)
            return -1;
        if (!wait_reply(c, xid, MASK(DHCP_OFFER), timeout, &offer)) {
            log_msg(c->who, "no DHCPOFFER received - retransmitting");
            continue;
        }
        log_msg(c->who, "DHCPOFFER received: %s from server %s",
                ip_to_str(offer.yiaddr, ip),
                ip_to_str(offer.opt.server_id, sid));

        log_msg(c->who, "[SELECTING->REQUESTING] DHCPREQUEST broadcast for %s "
                        "(xid=0x%08X)", ip, xid);
        if (send_msg(c, DHCP_REQUEST, xid, 0, offer.yiaddr,
                     offer.opt.server_id) < 0)
            return -1;
        if (!wait_reply(c, xid, MASK(DHCP_ACK) | MASK(DHCP_NAK),
                        REPLY_TIMEOUT_MS, &reply)) {
            log_msg(c->who, "no DHCPACK received - restarting DORA");
            continue;
        }
        if (reply.opt.msg_type == DHCP_NAK) {
            log_msg(c->who, "DHCPNAK received - restarting DORA");
            continue;
        }
        apply_ack(c, &reply);
        log_msg(c->who, "DHCPACK received -> [BOUND] to %s for %u s (T1 at %u s)",
                ip_to_str(c->ip, ip), c->lease_s, c->t1_s);
        print_config(c);
        return 0;
    }
    log_msg(c->who, "DORA FAILED after %d attempts (is the server running?)",
            MAX_DORA_TRIES);
    return -1;
}

/* BOUND -> RENEWING -> BOUND. Returns 1 ACK, 0 NAK, -1 no answer. */
static int do_renew(client_t *c)
{
    int attempt;
    char ip[INET_ADDRSTRLEN];

    ip_to_str(c->ip, ip);
    for (attempt = 1; attempt <= MAX_RENEW_TRIES; attempt++) {
        uint32_t xid = new_xid();
        dhcp_packet_t reply;

        log_msg(c->who, "[BOUND->RENEWING] DHCPREQUEST (ciaddr=%s, xid=0x%08X, "
                        "attempt %d/%d)", ip, xid, attempt, MAX_RENEW_TRIES);
        if (send_msg(c, DHCP_REQUEST, xid, c->ip, 0, 0) < 0)
            return -1;
        if (!wait_reply(c, xid, MASK(DHCP_ACK) | MASK(DHCP_NAK),
                        REPLY_TIMEOUT_MS, &reply))
            continue;
        if (reply.opt.msg_type == DHCP_NAK) {
            log_msg(c->who, "T1 RENEWAL: DHCPNAK - lease for %s lost", ip);
            c->ip = 0;
            return 0;
        }
        apply_ack(c, &reply);
        log_msg(c->who, "T1 RENEWAL: DHCPACK -> RENEWAL successful, [BOUND] "
                        "to %s for another %u s", ip, c->lease_s);
        return 1;
    }
    log_msg(c->who, "T1 RENEWAL: no answer from server");
    return -1;
}

static void do_release(client_t *c)
{
    char ip[INET_ADDRSTRLEN];
    log_msg(c->who, "DHCPRELEASE sent for %s -> [INIT]", ip_to_str(c->ip, ip));
    send_msg(c, DHCP_RELEASE, new_xid(), c->ip, 0, c->server_id);
    c->ip = 0;
}

/* ---------------- Modes ---------------- */
static int run_lifecycle(client_t *c)
{
    char ip[INET_ADDRSTRLEN];
    int64_t wait;

    if (do_dora(c) != 0) {
        printf("TEST-LIFECYCLE: FAIL (DORA)\n");
        return 1;
    }
    printf("ASSIGNED_IP=%s\n", ip_to_str(c->ip, ip));
    wait = c->bound_at_ms + (int64_t)c->t1_s * 1000 - mono_ms();
    log_msg(c->who, "waiting %lld ms for T1 (50%% of lease)...", (long long)wait);
    if (wait > 0)
        idle_ms(c, wait);
    if (do_renew(c) != 1) {
        printf("TEST-LIFECYCLE: FAIL (T1 renewal)\n");
        return 1;
    }
    idle_ms(c, 500);
    do_release(c);
    log_msg(c->who, "filtered %u foreign broadcast replies (xid/chaddr mismatch)",
            c->filtered);
    printf("TEST-LIFECYCLE: PASS\n");
    return 0;
}

static int run_nak(client_t *c, uint32_t target)
{
    uint32_t xid = new_xid();
    dhcp_packet_t reply;
    char ip[INET_ADDRSTRLEN];

    log_msg(c->who, "sending deliberately invalid DHCPREQUEST for %s "
                    "(xid=0x%08X)", ip_to_str(target, ip), xid);
    if (send_msg(c, DHCP_REQUEST, xid, 0, target, 0) < 0)
        return 2;
    if (!wait_reply(c, xid, MASK(DHCP_ACK) | MASK(DHCP_NAK), 3000, &reply)) {
        printf("TEST-NAK: FAIL (no reply)\n");
        return 2;
    }
    if (reply.opt.msg_type == DHCP_NAK) {
        log_msg(c->who, "DHCPNAK received for %s - server correctly refused", ip);
        printf("TEST-NAK: PASS\n");
        return 0;
    }
    log_msg(c->who, "unexpected DHCPACK for %s", ip);
    printf("TEST-NAK: FAIL (got ACK)\n");
    return 1;
}

static int run_expire(client_t *c)
{
    char ip[INET_ADDRSTRLEN];

    if (do_dora(c) != 0) {
        printf("TEST-EXPIRE: FAIL (DORA)\n");
        return 1;
    }
    printf("ASSIGNED_IP=%s\n", ip_to_str(c->ip, ip));
    idle_ms(c, 300);                     /* observe other clients' replies */
    log_msg(c->who, "filtered %u foreign broadcast replies (xid/chaddr mismatch)",
            c->filtered);
    log_msg(c->who, "exiting WITHOUT release - server must reclaim %s after "
                    "%u s", ip, c->lease_s);
    printf("TEST-EXPIRE: CLIENT DONE\n");
    return 0;
}

static void print_help(void)
{
#ifdef _WIN32
    printf("  Press a key:  r = renew now   x = release & exit   "
           "e = stop renewing (demo expiry)\n");
#else
    printf("  Keys (then Enter):  r = renew now   x = release & exit   "
           "e = stop renewing (demo expiry)\n");
#endif
    fflush(stdout);
}

/* Wait up to wait_ms for either a datagram (drained + filtered) or a key
 * press. Returns the key character, 0 if none, -1 on a socket error.     */
static int wait_event(client_t *c, int64_t wait_ms)
{
    dhcp_packet_t dummy;
#ifdef _WIN32
    /* Winsock select() cannot watch the console, so poll in 50 ms slices */
    int64_t deadline = mono_ms() + wait_ms;
    do {
        int64_t left = deadline - mono_ms();
        int n;
        if (_kbhit())
            return _getch();
        n = sock_wait_readable(c->sock, left < 50 ? left : 50);
        if (n < 0)
            return -1;
        if (n > 0)
            (void)read_one(c, 0xFFFFFFFFu, 0, &dummy);
    } while (mono_ms() < deadline);
    return _kbhit() ? _getch() : 0;
#else
    static int stdin_open = 1;
    fd_set rfds;
    struct timeval tv;
    int maxfd = c->sock, n;

    FD_ZERO(&rfds);
    FD_SET(c->sock, &rfds);
    if (stdin_open) {
        FD_SET(STDIN_FILENO, &rfds);
        if (STDIN_FILENO > maxfd)
            maxfd = STDIN_FILENO;
    }
    tv.tv_sec  = (long)(wait_ms / 1000);
    tv.tv_usec = (long)((wait_ms % 1000) * 1000);
    n = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (n < 0)
        return sock_interrupted() ? 0 : -1;
    if (n == 0)
        return 0;
    if (FD_ISSET(c->sock, &rfds))
        (void)read_one(c, 0xFFFFFFFFu, 0, &dummy);
    if (stdin_open && FD_ISSET(STDIN_FILENO, &rfds)) {
        char line[64];
        if (!fgets(line, sizeof(line), stdin)) {
            stdin_open = 0;
            return 0;
        }
        return (unsigned char)line[0];
    }
    return 0;
#endif
}

static int run_interactive(client_t *c)
{
    int auto_renew = 1;
    int64_t next_renew;
    char ip[INET_ADDRSTRLEN];

restart:
    if (do_dora(c) != 0)
        return 1;
    next_renew = c->bound_at_ms + (int64_t)c->t1_s * 1000;
    print_help();

    for (;;) {
        int64_t now = mono_ms();
        int64_t expiry = c->bound_at_ms + (int64_t)c->lease_s * 1000;
        int64_t next, wait;
        int key, n;

        if (now >= expiry) {
            log_msg(c->who, "LEASE EXPIRED for %s (no renewal) - address "
                            "relinquished, exiting", ip_to_str(c->ip, ip));
            return 0;
        }
        if (auto_renew && now >= next_renew) {
            int r;
            log_msg(c->who, "T1 timer fired (%u s = 50%% of lease)", c->t1_s);
            r = do_renew(c);
            if (r == 1) {
                next_renew = c->bound_at_ms + (int64_t)c->t1_s * 1000;
            } else if (r == 0) {
                goto restart;
            } else {
                next_renew = mono_ms() + RENEW_RETRY_MS;
            }
            continue;
        }

        next = auto_renew && next_renew < expiry ? next_renew : expiry;
        wait = next - now;
        if (wait > 1000)
            wait = 1000;                 /* wake each second for timers */

        key = wait_event(c, wait);
        if (key < 0) {
            sock_perror("select");
            return 1;
        }
        if (key > 0) {
            switch (key) {
            case 'r':
                log_msg(c->who, "manual renewal requested");
                n = do_renew(c);
                if (n == 1)
                    next_renew = c->bound_at_ms + (int64_t)c->t1_s * 1000;
                else if (n == 0)
                    goto restart;
                break;
            case 'x':
                do_release(c);
                log_msg(c->who, "exiting");
                return 0;
            case 'e':
                auto_renew = 0;
                log_msg(c->who, "auto-renewal DISABLED - lease will expire in "
                                "%lld s", (long long)((expiry - mono_ms()) / 1000));
                break;
            case '\n':
            case '\r':
                break;
            default:
                print_help();
                break;
            }
        }
    }
}

/* ---------------- main ---------------- */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-m <MAC>] [-b <broadcast_ip>] [mode]\n"
        "  -m <MAC>          client hardware address, e.g. 00:1A:2B:3C:4D:01\n"
        "  -b <ip>           broadcast address (default %s;\n"
        "                    use 255.255.255.255 for a real LAN segment)\n"
        "Modes (default: interactive):\n"
        "  --test-lifecycle  DORA -> wait for T1 renewal -> RELEASE\n"
        "  --test-nak        invalid REQUEST (default 192.168.10.250) -> expect NAK\n"
        "      -r <ip>       IP to request in --test-nak\n"
        "  --test-expire     DORA -> exit without RELEASE (server reclaims)\n",
        prog, DEFAULT_BCAST);
}

int main(int argc, char *argv[])
{
    client_t c;
    const char *bcast = DEFAULT_BCAST;
    mode_t_ mode = MODE_INTERACTIVE;
    uint32_t nak_target = (192u << 24) | (168u << 16) | (10u << 8) | 250u;
    int have_mac = 0, i, rc = 1;
    char mac[18];

    setup_stdout();
    memset(&c, 0, sizeof(c));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            if (parse_mac(argv[++i], c.mac) < 0) {
                fprintf(stderr, "invalid MAC address: %s\n", argv[i]);
                return 1;
            }
            have_mac = 1;
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bcast = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            if (str_to_ip(argv[++i], &nak_target) < 0) {
                fprintf(stderr, "invalid IP address: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--test-lifecycle") == 0) {
            mode = MODE_LIFECYCLE;
        } else if (strcmp(argv[i], "--test-nak") == 0) {
            mode = MODE_NAK;
        } else if (strcmp(argv[i], "--test-expire") == 0) {
            mode = MODE_EXPIRE;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    g_rng = (uint32_t)time(NULL) ^ (proc_id() << 16) ^
            (uint32_t)mono_ms();
    if (!have_mac) {                     /* locally administered address */
        uint32_t r = new_xid();
        c.mac[0] = 0x02;
        c.mac[1] = 0x00;
        c.mac[2] = (uint8_t)(r >> 24);
        c.mac[3] = (uint8_t)(r >> 16);
        c.mac[4] = (uint8_t)(r >> 8);
        c.mac[5] = (uint8_t)r;
    }
    g_rng ^= ((uint32_t)c.mac[4] << 8) | c.mac[5];
    if (g_rng == 0)
        g_rng = 0x9E3779B9u;
    snprintf(c.who, sizeof(c.who), "CLIENT %s", format_mac(c.mac, mac));

    if (make_bcast_addr(bcast, SERVER_PORT, &c.server) < 0) {
        fprintf(stderr, "invalid broadcast address: %s\n", bcast);
        return 1;
    }
    if (net_init() < 0)
        return 1;
    c.sock = dhcp_open_socket(CLIENT_PORT);
    if (c.sock == INVALID_SOCK) {
        net_cleanup();
        return 1;
    }
    log_msg(c.who, "client up: UDP %d -> %s:%d", CLIENT_PORT, bcast, SERVER_PORT);

    switch (mode) {
    case MODE_LIFECYCLE:   rc = run_lifecycle(&c);         break;
    case MODE_NAK:         rc = run_nak(&c, nak_target);   break;
    case MODE_EXPIRE:      rc = run_expire(&c);            break;
    case MODE_INTERACTIVE: rc = run_interactive(&c);       break;
    }
    close_socket(c.sock);
    net_cleanup();
    return rc;
}
