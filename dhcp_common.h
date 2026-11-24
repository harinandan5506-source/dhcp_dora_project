/*
 * dhcp_common.h - Shared definitions for the DHCP DORA simulation
 *
 * Course : Computer Networks (25CSE153)
 * Project: Simulation of the DHCP Lease Lifecycle (DORA) Using a
 *          UDP Broadcast Client-Server Model in C
 *
 * Contains:
 *   - Port numbers, broadcast defaults, BOOTP/DHCP constants
 *   - dhcp_packet_t (host-order, structured representation)
 *   - Wire (network-byte-order) serialization / deserialization that
 *     follows the RFC 2131 BOOTP layout + RFC 2132 TLV options
 *   - MAC / IP helpers, [HH:MM:SS] logging, monotonic clock, socket setup
 *   - Portability layer: builds natively on Windows (MinGW-w64 + Winsock2)
 *     and on Linux/POSIX (BSD sockets) from the same source.
 */
#ifndef DHCP_COMMON_H
#define DHCP_COMMON_H

/* ------------------------------------------------------------------ */
/* Platform layer                                                      */
/* ------------------------------------------------------------------ */
#ifdef _WIN32
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600          /* Vista+: inet_pton/inet_ntop */
  #endif
  #ifndef __USE_MINGW_ANSI_STDIO
    #define __USE_MINGW_ANSI_STDIO 1     /* C99 printf (%zu, %lld)      */
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  typedef SOCKET sock_t;
  #define INVALID_SOCK   INVALID_SOCKET
  #define close_socket   closesocket
#else
  #include <unistd.h>
  #include <errno.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <sys/select.h>
  typedef int sock_t;
  #define INVALID_SOCK   (-1)
  #define close_socket   close
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

/* printf-style format checking that matches the C runtime in use */
#if defined(_WIN32) && defined(__MINGW_PRINTF_FORMAT)
  #define DHCP_PRINTF(f, a) __attribute__((format(__MINGW_PRINTF_FORMAT, f, a)))
#else
  #define DHCP_PRINTF(f, a) __attribute__((format(printf, f, a)))
#endif

/* ------------------------------------------------------------------ */
/* Transport configuration (non-privileged ports instead of 67/68)     */
/* ------------------------------------------------------------------ */
#define SERVER_PORT        6767
#define CLIENT_PORT        6868
#ifdef _WIN32
  /* Windows has no loopback broadcast route; the limited broadcast is
   * delivered to local sockets as well. Use -b 127.0.0.1 if offline.  */
  #define DEFAULT_BCAST    "255.255.255.255"
#else
  #define DEFAULT_BCAST    "127.255.255.255"   /* loopback broadcast   */
#endif

/* ------------------------------------------------------------------ */
/* BOOTP / DHCP constants (RFC 2131 / RFC 2132)                        */
/* ------------------------------------------------------------------ */
#define BOOTREQUEST        1
#define BOOTREPLY          2
#define HTYPE_ETHERNET     1
#define HLEN_ETHERNET      6
#define DHCP_MAGIC_COOKIE  0x63825363u
#define DHCP_FIXED_LEN     236          /* op .. file field            */
#define DHCP_OPTIONS_OFF   240          /* after the magic cookie      */
#define DHCP_MIN_PKT       300          /* classic BOOTP minimum       */
#define DHCP_MAX_PKT       576          /* RFC 2131 minimum MTU size   */
#define BOOTP_FLAG_BCAST   0x8000

/* DHCP message types (option 53) */
enum {
    DHCP_DISCOVER = 1,
    DHCP_OFFER    = 2,
    DHCP_REQUEST  = 3,
    DHCP_DECLINE  = 4,
    DHCP_ACK      = 5,
    DHCP_NAK      = 6,
    DHCP_RELEASE  = 7
};

/* Option codes */
#define OPT_PAD            0
#define OPT_SUBNET_MASK    1
#define OPT_ROUTER         3
#define OPT_DNS            6
#define OPT_REQUESTED_IP   50
#define OPT_LEASE_TIME     51
#define OPT_MSG_TYPE       53
#define OPT_SERVER_ID      54
#define OPT_T1_TIME        58
#define OPT_END            255

/* "present" bit flags for optional fields */
#define OPTF_SUBNET_MASK   (1u << 0)
#define OPTF_ROUTER        (1u << 1)
#define OPTF_DNS           (1u << 2)
#define OPTF_LEASE_TIME    (1u << 3)
#define OPTF_T1_TIME       (1u << 4)
#define OPTF_REQUESTED_IP  (1u << 5)
#define OPTF_SERVER_ID     (1u << 6)

/* ------------------------------------------------------------------ */
/* Structured packet (all multi-byte fields in HOST byte order)        */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  msg_type;       /* DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE */
    uint32_t present;        /* OPTF_* bitmask                         */
    uint32_t subnet_mask;    /* option 1                               */
    uint32_t router_ip;      /* option 3                               */
    uint32_t dns_ip;         /* option 6                               */
    uint32_t lease_time;     /* option 51 (seconds)                    */
    uint32_t t1_time;        /* option 58 (seconds)                    */
    uint32_t requested_ip;   /* option 50                              */
    uint32_t server_id;      /* option 54                              */
} dhcp_options_t;

typedef struct {
    uint8_t  op;             /* BOOTREQUEST / BOOTREPLY */
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;            /* transaction ID          */
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;         /* client IP (renew/release) */
    uint32_t yiaddr;         /* "your" IP (offered)       */
    uint32_t siaddr;         /* server IP                 */
    uint32_t giaddr;         /* relay agent IP            */
    uint8_t  chaddr[6];      /* client MAC                */
    dhcp_options_t opt;
} dhcp_packet_t;

/* ------------------------------------------------------------------ */
/* Big-endian (network order) byte helpers                             */
/* ------------------------------------------------------------------ */
static inline void wr16(uint8_t *b, uint16_t v)
{
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)(v);
}
static inline void wr32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}
static inline uint16_t rd16(const uint8_t *b)
{
    return (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
}
static inline uint32_t rd32(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
}

/* ------------------------------------------------------------------ */
/* Serialization: dhcp_packet_t -> wire bytes. Returns length or 0.    */
/* ------------------------------------------------------------------ */
static inline size_t put_ip_option(uint8_t *buf, size_t o, uint8_t code,
                                   uint32_t value)
{
    buf[o++] = code;
    buf[o++] = 4;
    wr32(buf + o, value);
    return o + 4;
}

static inline size_t dhcp_serialize(const dhcp_packet_t *p, uint8_t *buf,
                                    size_t cap)
{
    size_t o;
    const dhcp_options_t *opt = &p->opt;

    if (cap < DHCP_MAX_PKT)
        return 0;
    memset(buf, 0, cap);

    buf[0] = p->op;
    buf[1] = p->htype;
    buf[2] = p->hlen;
    buf[3] = p->hops;
    wr32(buf + 4,  p->xid);
    wr16(buf + 8,  p->secs);
    wr16(buf + 10, p->flags);
    wr32(buf + 12, p->ciaddr);
    wr32(buf + 16, p->yiaddr);
    wr32(buf + 20, p->siaddr);
    wr32(buf + 24, p->giaddr);
    memcpy(buf + 28, p->chaddr, 6);       /* chaddr is 16 bytes, rest 0 */
    /* sname[64] (44..107) and file[128] (108..235) remain zero        */
    wr32(buf + DHCP_FIXED_LEN, DHCP_MAGIC_COOKIE);

    o = DHCP_OPTIONS_OFF;
    buf[o++] = OPT_MSG_TYPE;
    buf[o++] = 1;
    buf[o++] = opt->msg_type;

    if (opt->present & OPTF_SUBNET_MASK)
        o = put_ip_option(buf, o, OPT_SUBNET_MASK, opt->subnet_mask);
    if (opt->present & OPTF_ROUTER)
        o = put_ip_option(buf, o, OPT_ROUTER, opt->router_ip);
    if (opt->present & OPTF_DNS)
        o = put_ip_option(buf, o, OPT_DNS, opt->dns_ip);
    if (opt->present & OPTF_LEASE_TIME)
        o = put_ip_option(buf, o, OPT_LEASE_TIME, opt->lease_time);
    if (opt->present & OPTF_T1_TIME)
        o = put_ip_option(buf, o, OPT_T1_TIME, opt->t1_time);
    if (opt->present & OPTF_REQUESTED_IP)
        o = put_ip_option(buf, o, OPT_REQUESTED_IP, opt->requested_ip);
    if (opt->present & OPTF_SERVER_ID)
        o = put_ip_option(buf, o, OPT_SERVER_ID, opt->server_id);

    buf[o++] = OPT_END;
    if (o < DHCP_MIN_PKT)
        o = DHCP_MIN_PKT;               /* pad with zeros (OPT_PAD)   */
    return o;
}

/* ------------------------------------------------------------------ */
/* Deserialization: wire bytes -> dhcp_packet_t. 0 = OK, -1 = invalid. */
/* ------------------------------------------------------------------ */
static inline int dhcp_deserialize(const uint8_t *buf, size_t len,
                                   dhcp_packet_t *p)
{
    size_t o;

    if (len < DHCP_OPTIONS_OFF)
        return -1;
    memset(p, 0, sizeof(*p));

    p->op     = buf[0];
    p->htype  = buf[1];
    p->hlen   = buf[2];
    p->hops   = buf[3];
    p->xid    = rd32(buf + 4);
    p->secs   = rd16(buf + 8);
    p->flags  = rd16(buf + 10);
    p->ciaddr = rd32(buf + 12);
    p->yiaddr = rd32(buf + 16);
    p->siaddr = rd32(buf + 20);
    p->giaddr = rd32(buf + 24);
    memcpy(p->chaddr, buf + 28, 6);

    if (rd32(buf + DHCP_FIXED_LEN) != DHCP_MAGIC_COOKIE)
        return -1;

    o = DHCP_OPTIONS_OFF;
    while (o < len) {
        uint8_t code = buf[o++];
        uint8_t olen;
        const uint8_t *v;

        if (code == OPT_PAD)
            continue;
        if (code == OPT_END)
            break;
        if (o >= len)
            return -1;
        olen = buf[o++];
        if (o + olen > len)
            return -1;                   /* truncated option          */
        v = buf + o;

        switch (code) {
        case OPT_MSG_TYPE:
            if (olen >= 1) p->opt.msg_type = v[0];
            break;
        case OPT_SUBNET_MASK:
            if (olen >= 4) { p->opt.subnet_mask = rd32(v);  p->opt.present |= OPTF_SUBNET_MASK; }
            break;
        case OPT_ROUTER:
            if (olen >= 4) { p->opt.router_ip = rd32(v);    p->opt.present |= OPTF_ROUTER; }
            break;
        case OPT_DNS:
            if (olen >= 4) { p->opt.dns_ip = rd32(v);       p->opt.present |= OPTF_DNS; }
            break;
        case OPT_LEASE_TIME:
            if (olen >= 4) { p->opt.lease_time = rd32(v);   p->opt.present |= OPTF_LEASE_TIME; }
            break;
        case OPT_T1_TIME:
            if (olen >= 4) { p->opt.t1_time = rd32(v);      p->opt.present |= OPTF_T1_TIME; }
            break;
        case OPT_REQUESTED_IP:
            if (olen >= 4) { p->opt.requested_ip = rd32(v); p->opt.present |= OPTF_REQUESTED_IP; }
            break;
        case OPT_SERVER_ID:
            if (olen >= 4) { p->opt.server_id = rd32(v);    p->opt.present |= OPTF_SERVER_ID; }
            break;
        default:
            break;                       /* unknown option: skip      */
        }
        o += olen;
    }
    return (p->opt.msg_type >= DHCP_DISCOVER &&
            p->opt.msg_type <= DHCP_RELEASE) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* MAC / IP / name helpers                                             */
/* ------------------------------------------------------------------ */
/* Parse "AA:BB:CC:DD:EE:FF". Returns 0 on success, -1 on error. */
static inline int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned int b[6];
    int consumed = 0;
    int i;

    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%n",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &consumed) != 6)
        return -1;
    if (s[consumed] != '\0')
        return -1;
    for (i = 0; i < 6; i++)
        mac[i] = (uint8_t)b[i];
    return 0;
}

static inline const char *format_mac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return out;
}

/* Host-order IPv4 -> dotted string */
static inline const char *ip_to_str(uint32_t ip_host, char out[INET_ADDRSTRLEN])
{
    struct in_addr a;
    a.s_addr = htonl(ip_host);
    if (!inet_ntop(AF_INET, &a, out, INET_ADDRSTRLEN))
        snprintf(out, INET_ADDRSTRLEN, "?");
    return out;
}

/* Dotted string -> host-order IPv4. Returns 0 on success. */
static inline int str_to_ip(const char *s, uint32_t *ip_host)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;
    *ip_host = ntohl(a.s_addr);
    return 0;
}

static inline const char *msg_type_name(uint8_t t)
{
    switch (t) {
    case DHCP_DISCOVER: return "DHCPDISCOVER";
    case DHCP_OFFER:    return "DHCPOFFER";
    case DHCP_REQUEST:  return "DHCPREQUEST";
    case DHCP_DECLINE:  return "DHCPDECLINE";
    case DHCP_ACK:      return "DHCPACK";
    case DHCP_NAK:      return "DHCPNAK";
    case DHCP_RELEASE:  return "DHCPRELEASE";
    default:            return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/* Time & logging                                                      */
/* ------------------------------------------------------------------ */
static inline int64_t mono_ms(void)
{
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static inline uint32_t proc_id(void)
{
#ifdef _WIN32
    return (uint32_t)GetCurrentProcessId();
#else
    return (uint32_t)getpid();
#endif
}

static inline void log_msg(const char *who, const char *fmt, ...) DHCP_PRINTF(2, 3);

static inline void log_msg(const char *who, const char *fmt, ...)
{
    time_t now = time(NULL);
    struct tm tmv;
    va_list ap;

#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    printf("[%02d:%02d:%02d] [%s] ", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, who);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

/* Unbuffered on Windows (MSVCRT has no real line buffering), line-buffered
 * elsewhere, so logs appear immediately even when redirected to a file.  */
static inline void setup_stdout(void)
{
#ifdef _WIN32
    setvbuf(stdout, NULL, _IONBF, 0);
#else
    setvbuf(stdout, NULL, _IOLBF, 0);
#endif
}

/* ------------------------------------------------------------------ */
/* Socket layer                                                        */
/* ------------------------------------------------------------------ */
static inline int sock_errno(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

/* select()/recv() interrupted by a signal: just retry */
static inline int sock_interrupted(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

static inline int net_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", rc);
        return -1;
    }
#endif
    return 0;
}

static inline void net_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static inline void sock_perror(const char *what)
{
    fprintf(stderr, "%s failed (error %d)\n", what, sock_errno());
}

/* UDP socket: SO_REUSEADDR (+ SO_REUSEPORT where available) + SO_BROADCAST,
 * bound to INADDR_ANY:<port>. Returns the socket or INVALID_SOCK.
 * Windows: SO_REUSEADDR alone lets several processes share the port and
 * each receives a copy of every broadcast datagram.                     */
static inline sock_t dhcp_open_socket(uint16_t port)
{
    sock_t fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCK) {
        sock_perror("socket");
        return INVALID_SOCK;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   (const char *)&one, sizeof(one)) < 0) {
        sock_perror("setsockopt(SO_REUSEADDR)");
        close_socket(fd);
        return INVALID_SOCK;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                   (const char *)&one, sizeof(one)) < 0) {
        sock_perror("setsockopt(SO_REUSEPORT)");
        close_socket(fd);
        return INVALID_SOCK;
    }
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
                   (const char *)&one, sizeof(one)) < 0) {
        sock_perror("setsockopt(SO_BROADCAST)");
        close_socket(fd);
        return INVALID_SOCK;
    }

#ifdef _WIN32
    {
        /* Windows quirk: an ICMP "port unreachable" makes the NEXT recv()
         * on a UDP socket fail with WSAECONNRESET. Turn that off.        */
        #ifndef SIO_UDP_CONNRESET
        #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
        #endif
        BOOL off = FALSE;
        DWORD ret = 0;
        WSAIoctl(fd, SIO_UDP_CONNRESET, &off, sizeof(off), NULL, 0, &ret,
                 NULL, NULL);
    }
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sock_perror("bind");
        close_socket(fd);
        return INVALID_SOCK;
    }
    return fd;
}

/* sendto/recv wrappers hiding the int-vs-size_t and char*-vs-void* API
 * differences between Winsock and BSD sockets.                          */
static inline long sock_sendto(sock_t s, const uint8_t *buf, size_t len,
                               const struct sockaddr_in *to)
{
    return (long)sendto(s, (const char *)buf, (int)len, 0,
                        (const struct sockaddr *)to, (int)sizeof(*to));
}

static inline long sock_recv(sock_t s, uint8_t *buf, size_t cap)
{
    return (long)recv(s, (char *)buf, (int)cap, 0);
}

/* Wait until s is readable or timeout_ms passes. 1 = readable, 0 = timeout,
 * -1 = error (interrupted calls return 0 so callers simply loop).        */
static inline int sock_wait_readable(sock_t s, int64_t timeout_ms)
{
    fd_set rfds;
    struct timeval tv;
    int n;

    if (timeout_ms < 0)
        timeout_ms = 0;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    tv.tv_sec  = (long)(timeout_ms / 1000);
    tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
    n = select((int)(s + 1), &rfds, NULL, NULL, &tv);  /* nfds ignored on Win */
    if (n < 0)
        return sock_interrupted() ? 0 : -1;
    return n > 0 ? 1 : 0;
}

/* Build a broadcast destination address. Returns 0 on success. */
static inline int make_bcast_addr(const char *ip, uint16_t port,
                                  struct sockaddr_in *out)
{
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port   = htons(port);
    return inet_pton(AF_INET, ip, &out->sin_addr) == 1 ? 0 : -1;
}

#endif /* DHCP_COMMON_H */
