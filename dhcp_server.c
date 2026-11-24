/*
 * dhcp_server.c - DHCP server for the DORA lease-lifecycle simulation
 *
 * Course : Computer Networks (25CSE153)
 *
 * - Manages the pool 192.168.10.100 - 192.168.10.110 (/24)
 * - Lease states: FREE -> OFFERED -> BOUND -> (RELEASE | EXPIRY) -> FREE
 * - select() event loop with a 1 s timeout: packets are processed as they
 *   arrive, and every iteration scans for expired leases / stale offers
 *   and reclaims them automatically.
 * - Replies are broadcast to <bcast>:CLIENT_PORT
 *   (default 127.255.255.255 on Linux, 255.255.255.255 on Windows)
 *
 * Usage: ./dhcp_server [-b <broadcast_ip>] [-l <lease_seconds>]
 *        (Windows: .\\dhcp_server.exe ...)
 */
#include "dhcp_common.h"

#include <signal.h>

/* ---------------- Network configuration ---------------- */
#define IP4(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | \
                         ((uint32_t)(c) << 8)  |  (uint32_t)(d))

#define POOL_START        IP4(192, 168, 10, 100)
#define POOL_END          IP4(192, 168, 10, 110)
#define POOL_SIZE         ((int)(POOL_END - POOL_START + 1))
#define CFG_SUBNET_MASK   IP4(255, 255, 255, 0)
#define CFG_ROUTER        IP4(192, 168, 10, 1)
#define CFG_DNS           IP4(8, 8, 8, 8)
#define CFG_SERVER_ID     IP4(192, 168, 10, 1)
#define DEFAULT_LEASE_S   16
#define OFFER_TIMEOUT_S   10      /* an un-requested OFFER is held this long */

#define WHO "SERVER"

typedef enum { LEASE_FREE = 0, LEASE_OFFERED, LEASE_BOUND } lease_state_t;

typedef struct {
    uint32_t      ip;
    uint8_t       mac[6];
    lease_state_t state;
    int64_t       expiry_ms;      /* monotonic deadline                 */
    uint32_t      xid;            /* xid of the outstanding OFFER       */
} lease_t;

static lease_t            g_pool[POOL_SIZE];
static uint32_t           g_lease_s = DEFAULT_LEASE_S;
static struct sockaddr_in g_client_bcast;
static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static const char *state_name(lease_state_t s)
{
    switch (s) {
    case LEASE_FREE:    return "FREE";
    case LEASE_OFFERED: return "OFFERED";
    case LEASE_BOUND:   return "BOUND";
    }
    return "?";
}

/* ---------------- Lease table ---------------- */
static void pool_init(void)
{
    int i;
    memset(g_pool, 0, sizeof(g_pool));
    for (i = 0; i < POOL_SIZE; i++) {
        g_pool[i].ip    = POOL_START + (uint32_t)i;
        g_pool[i].state = LEASE_FREE;
    }
}

static lease_t *find_by_mac(const uint8_t mac[6])
{
    int i;
    for (i = 0; i < POOL_SIZE; i++)
        if (g_pool[i].state != LEASE_FREE &&
            memcmp(g_pool[i].mac, mac, 6) == 0)
            return &g_pool[i];
    return NULL;
}

static lease_t *find_by_ip(uint32_t ip)
{
    if (ip < POOL_START || ip > POOL_END)
        return NULL;
    return &g_pool[ip - POOL_START];
}

static lease_t *find_free(void)
{
    int i;
    for (i = 0; i < POOL_SIZE; i++)
        if (g_pool[i].state == LEASE_FREE)
            return &g_pool[i];
    return NULL;
}

static void lease_free(lease_t *l)
{
    memset(l->mac, 0, 6);
    l->state     = LEASE_FREE;
    l->expiry_ms = 0;
    l->xid       = 0;
}

static void print_lease_table(void)
{
    int i;
    int64_t now = mono_ms();
    char ip[INET_ADDRSTRLEN], mac[18];

    printf("+-----------------+-------------------+---------+--------------+\n");
    printf("| IP Address      | MAC Address       | State   | Remaining(s) |\n");
    printf("+-----------------+-------------------+---------+--------------+\n");
    for (i = 0; i < POOL_SIZE; i++) {
        lease_t *l = &g_pool[i];
        ip_to_str(l->ip, ip);
        if (l->state == LEASE_FREE) {
            printf("| %-15s | %-17s | %-7s | %12s |\n", ip, "--", "FREE", "--");
        } else {
            int64_t rem = (l->expiry_ms - now + 999) / 1000;
            if (rem < 0)
                rem = 0;
            printf("| %-15s | %-17s | %-7s | %12lld |\n", ip,
                   format_mac(l->mac, mac), state_name(l->state),
                   (long long)rem);
        }
    }
    printf("+-----------------+-------------------+---------+--------------+\n");
    fflush(stdout);
}

/* ---------------- Sending replies ---------------- */
static void send_reply(sock_t sock, const dhcp_packet_t *req, uint8_t type,
                       uint32_t yiaddr)
{
    dhcp_packet_t rep;
    uint8_t buf[DHCP_MAX_PKT];
    size_t len;
    char ip[INET_ADDRSTRLEN], mac[18];

    memset(&rep, 0, sizeof(rep));
    rep.op     = BOOTREPLY;
    rep.htype  = HTYPE_ETHERNET;
    rep.hlen   = HLEN_ETHERNET;
    rep.xid    = req->xid;
    rep.flags  = req->flags;
    rep.yiaddr = yiaddr;
    rep.siaddr = CFG_SERVER_ID;
    memcpy(rep.chaddr, req->chaddr, 6);

    rep.opt.msg_type  = type;
    rep.opt.server_id = CFG_SERVER_ID;
    rep.opt.present   = OPTF_SERVER_ID;
    if (type == DHCP_OFFER || type == DHCP_ACK) {
        rep.opt.subnet_mask = CFG_SUBNET_MASK;
        rep.opt.router_ip   = CFG_ROUTER;
        rep.opt.dns_ip      = CFG_DNS;
        rep.opt.lease_time  = g_lease_s;
        rep.opt.t1_time     = g_lease_s / 2;          /* T1 = 50 % */
        rep.opt.present    |= OPTF_SUBNET_MASK | OPTF_ROUTER | OPTF_DNS |
                              OPTF_LEASE_TIME | OPTF_T1_TIME;
    }

    len = dhcp_serialize(&rep, buf, sizeof(buf));
    if (len == 0) {
        log_msg(WHO, "internal error: serialization failed");
        return;
    }
    if (sock_sendto(sock, buf, len, &g_client_bcast) < 0) {
        log_msg(WHO, "sendto failed (error %d)", sock_errno());
        return;
    }
    log_msg(WHO, "-> %-12s to %s  yiaddr=%s  xid=0x%08X  (%zu bytes, broadcast)",
            msg_type_name(type), format_mac(req->chaddr, mac),
            ip_to_str(yiaddr, ip), req->xid, len);
}

static void send_nak(sock_t sock, const dhcp_packet_t *req, const char *reason)
{
    log_msg(WHO, "   NAK reason: %s", reason);
    send_reply(sock, req, DHCP_NAK, 0);
}

/* ---------------- Message handlers ---------------- */
static void handle_discover(sock_t sock, const dhcp_packet_t *pkt)
{
    lease_t *l = find_by_mac(pkt->chaddr);
    char ip[INET_ADDRSTRLEN];

    if (l == NULL)
        l = find_free();
    if (l == NULL) {
        log_msg(WHO, "   address pool EXHAUSTED - DISCOVER ignored");
        return;
    }

    if (l->state != LEASE_BOUND) {
        l->state     = LEASE_OFFERED;
        l->expiry_ms = mono_ms() + (int64_t)OFFER_TIMEOUT_S * 1000;
        memcpy(l->mac, pkt->chaddr, 6);
    }
    l->xid = pkt->xid;
    log_msg(WHO, "   offering %s (%s)", ip_to_str(l->ip, ip),
            l->state == LEASE_BOUND ? "existing binding for this MAC"
                                    : "next free address");
    send_reply(sock, pkt, DHCP_OFFER, l->ip);
    print_lease_table();
}

static void handle_request(sock_t sock, const dhcp_packet_t *pkt)
{
    uint32_t req_ip;
    lease_t *l;
    int renewal;
    char ip[INET_ADDRSTRLEN], mac[18];

    /* SELECTING state: REQUEST carries option 50 (+ option 54).
     * RENEWING  state: REQUEST carries ciaddr and no option 50.   */
    if (pkt->opt.present & OPTF_REQUESTED_IP)
        req_ip = pkt->opt.requested_ip;
    else
        req_ip = pkt->ciaddr;

    if ((pkt->opt.present & OPTF_SERVER_ID) &&
        pkt->opt.server_id != CFG_SERVER_ID) {
        /* Client chose another server: withdraw our offer. */
        l = find_by_mac(pkt->chaddr);
        if (l && l->state == LEASE_OFFERED) {
            lease_free(l);
            print_lease_table();
        }
        log_msg(WHO, "   REQUEST addressed to another server - ignored");
        return;
    }

    log_msg(WHO, "   requested IP %s (%s)", ip_to_str(req_ip, ip),
            (pkt->opt.present & OPTF_REQUESTED_IP) ? "option 50" : "ciaddr");

    if (req_ip == 0) {
        send_nak(sock, pkt, "no address requested");
        return;
    }
    l = find_by_ip(req_ip);
    if (l == NULL) {
        send_nak(sock, pkt, "requested IP is outside the managed pool "
                            "192.168.10.100-110");
        return;
    }
    if (l->state == LEASE_FREE) {
        send_nak(sock, pkt, "address not offered/bound to this client "
                            "(lease may have expired)");
        return;
    }
    if (memcmp(l->mac, pkt->chaddr, 6) != 0) {
        char owner[18];
        log_msg(WHO, "   conflict: %s is %s to %s", ip,
                state_name(l->state), format_mac(l->mac, owner));
        send_nak(sock, pkt, "address already in use by another MAC");
        return;
    }
    if (l->state == LEASE_OFFERED && l->xid != pkt->xid) {
        send_nak(sock, pkt, "transaction ID does not match the OFFER");
        return;
    }

    renewal      = (l->state == LEASE_BOUND);
    l->state     = LEASE_BOUND;
    l->expiry_ms = mono_ms() + (int64_t)g_lease_s * 1000;
    l->xid       = pkt->xid;
    log_msg(WHO, "   %s: %s -> %s for %u s",
            renewal ? "LEASE RENEWED (T1)" : "INITIAL BIND", ip,
            format_mac(pkt->chaddr, mac), g_lease_s);
    send_reply(sock, pkt, DHCP_ACK, l->ip);
    print_lease_table();
}

static void handle_release(const dhcp_packet_t *pkt)
{
    lease_t *l = find_by_ip(pkt->ciaddr);
    char ip[INET_ADDRSTRLEN], mac[18];

    ip_to_str(pkt->ciaddr, ip);
    if (l == NULL || l->state == LEASE_FREE ||
        memcmp(l->mac, pkt->chaddr, 6) != 0) {
        log_msg(WHO, "   invalid RELEASE for %s from %s - ignored", ip,
                format_mac(pkt->chaddr, mac));
        return;
    }
    log_msg(WHO, "   RELEASED %s (was BOUND to %s) -> FREE", ip,
            format_mac(l->mac, mac));
    lease_free(l);
    print_lease_table();
}

/* ---------------- Expiry scan / reclamation ---------------- */
static void reclaim_expired(void)
{
    int i, changed = 0;
    int64_t now = mono_ms();
    char ip[INET_ADDRSTRLEN], mac[18];

    for (i = 0; i < POOL_SIZE; i++) {
        lease_t *l = &g_pool[i];
        if (l->state == LEASE_FREE || l->expiry_ms > now)
            continue;
        ip_to_str(l->ip, ip);
        format_mac(l->mac, mac);
        if (l->state == LEASE_BOUND)
            log_msg(WHO, "RECLAIMED %s (lease of %s EXPIRED, no renewal) -> FREE",
                    ip, mac);
        else
            log_msg(WHO, "OFFER of %s to %s timed out (no REQUEST) -> FREE",
                    ip, mac);
        lease_free(l);
        changed = 1;
    }
    if (changed)
        print_lease_table();
}

/* ---------------- main ---------------- */
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-b <broadcast_ip>] [-l <lease_seconds>]\n"
                    "  -b  broadcast address for replies (default %s)\n"
                    "  -l  lease time in seconds, >= 4 (default %d)\n",
            prog, DEFAULT_BCAST, DEFAULT_LEASE_S);
}

int main(int argc, char *argv[])
{
    const char *bcast = DEFAULT_BCAST;
    sock_t sock;
    int i;
    char ip1[INET_ADDRSTRLEN], ip2[INET_ADDRSTRLEN];

    setup_stdout();

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bcast = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v < 4 || v > 86400) {
                fprintf(stderr, "lease time must be 4..86400 s\n");
                return 1;
            }
            g_lease_s = (uint32_t)v;
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    if (make_bcast_addr(bcast, CLIENT_PORT, &g_client_bcast) < 0) {
        fprintf(stderr, "invalid broadcast address: %s\n", bcast);
        return 1;
    }

#ifdef _WIN32
    signal(SIGINT, on_signal);          /* Ctrl+C in the console          */
    signal(SIGTERM, on_signal);
#else
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal;      /* no SA_RESTART: select() -> EINTR */
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
    }
#endif

    if (net_init() < 0)
        return 1;
    sock = dhcp_open_socket(SERVER_PORT);
    if (sock == INVALID_SOCK) {
        net_cleanup();
        return 1;
    }

    pool_init();
    log_msg(WHO, "DHCP server started on UDP port %d (replies -> %s:%d)",
            SERVER_PORT, bcast, CLIENT_PORT);
    log_msg(WHO, "Subnet 192.168.10.0/24  pool %s - %s (%d addresses)",
            ip_to_str(POOL_START, ip1), ip_to_str(POOL_END, ip2), POOL_SIZE);
    log_msg(WHO, "Options: mask 255.255.255.0, router 192.168.10.1, "
                 "DNS 8.8.8.8, lease %u s, T1 %u s", g_lease_s, g_lease_s / 2);
    print_lease_table();

    while (g_running) {
        /* select() with a 1 s timeout: handle a packet if one arrives,
         * otherwise fall through to the expiry scan.                    */
        int n = sock_wait_readable(sock, 1000);

        if (n < 0) {
            sock_perror("select");
            break;
        }
        if (n > 0) {
            uint8_t buf[1500];
            long r = sock_recv(sock, buf, sizeof(buf));
            dhcp_packet_t pkt;
            char mac[18];

            if (r > 0 && dhcp_deserialize(buf, (size_t)r, &pkt) == 0 &&
                pkt.op == BOOTREQUEST) {
                log_msg(WHO, "<- %-12s from %s  xid=0x%08X",
                        msg_type_name(pkt.opt.msg_type),
                        format_mac(pkt.chaddr, mac), pkt.xid);
                switch (pkt.opt.msg_type) {
                case DHCP_DISCOVER: handle_discover(sock, &pkt); break;
                case DHCP_REQUEST:  handle_request(sock, &pkt);  break;
                case DHCP_RELEASE:  handle_release(&pkt);        break;
                default:
                    log_msg(WHO, "   unsupported message type - ignored");
                    break;
                }
            }
        }
        reclaim_expired();               /* runs at least once a second */
    }

    log_msg(WHO, "shutting down");
    close_socket(sock);
    net_cleanup();
    return 0;
}
