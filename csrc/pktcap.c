/* pktcap: the C fast path for pktan.
 *
 * Captures from an AF_PACKET socket through a TPACKET_V3 memory-mapped ring
 * (the kernel fills blocks of packets; we read them without a syscall per
 * packet), or reads a classic pcap file. Every packet is parsed by hand down to
 * TCP/UDP and summarised as a fixed-size record on stdout. Only packets that
 * need a full decode (DNS, DHCP, ARP, TLS client hellos, anything unusual) also
 * carry their raw bytes, so Python does deep parsing for a small fraction of
 * traffic. Per-source byte and packet counts live in an open-addressing hash
 * table, and a size-K min-heap picks the top talkers for each snapshot.
 *
 *   pktcap -i wlan0            live capture (needs CAP_NET_RAW)
 *   pktcap -r file.pcap        read a capture
 *   options: -a  send every frame   -k N  top-K size (default 10)
 *            -P  no promiscuous     -n  parse only, no output (benchmark)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "pktcap.h"

/* ------------------------------------------------------------------ options */

static int opt_all_frames, opt_no_output, opt_no_promisc;
static unsigned opt_k = 10;
static volatile sig_atomic_t stop_requested;

static void on_signal(int sig) { (void)sig; stop_requested = 1; }

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

static double mono_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

/* ------------------------------------------------------------------ output */

static int output_broken;

static void emit(uint16_t type, const void *body, uint32_t len)
{
    if (opt_no_output || output_broken)
        return;
    struct rec_hdr h = { .type = type, .reserved = 0, .len = len };
    if (fwrite(&h, sizeof h, 1, stdout) != 1 || (len && fwrite(body, len, 1, stdout) != 1)) {
        output_broken = 1;              /* reader went away (EPIPE): stop quietly */
        stop_requested = 1;
    }
}

static void flush_output(void)
{
    if (!opt_no_output && !output_broken && fflush(stdout) != 0) {
        output_broken = 1;
        stop_requested = 1;
    }
}

/* ------------------------------------------------------------------ source table
 *
 * Open addressing with linear probing, keyed by (ip version, 16-byte address).
 * Capacity is a power of two. When the table reaches 3/4 full we keep the most
 * recently seen half and rehash, so memory stays fixed no matter how many
 * addresses go by (a scan of a /16 can't grow it).
 */

#define TABLE_CAP 8192u                 /* must be a power of two */

struct src_entry {
    uint8_t  ip[16];
    uint8_t  version;                   /* 0 = empty slot */
    uint8_t  pad[7];
    uint64_t packets;
    uint64_t bytes;
    double   last_seen;
};

static struct src_entry table[TABLE_CAP];
static unsigned table_used;

static uint32_t hash_ip(const uint8_t *ip, uint8_t version)
{
    uint32_t h = 2166136261u ^ version;  /* FNV-1a */
    for (int i = 0; i < 16; i++) {
        h ^= ip[i];
        h *= 16777619u;
    }
    return h;
}

static struct src_entry *table_slot(const uint8_t *ip, uint8_t version)
{
    uint32_t i = hash_ip(ip, version) & (TABLE_CAP - 1);
    for (;;) {
        struct src_entry *e = &table[i];
        if (!e->version || (e->version == version && !memcmp(e->ip, ip, 16)))
            return e;
        i = (i + 1) & (TABLE_CAP - 1);
    }
}

static int by_last_seen_desc(const void *a, const void *b)
{
    double x = ((const struct src_entry *)a)->last_seen, y = ((const struct src_entry *)b)->last_seen;
    return (x < y) - (x > y);
}

static void table_shrink(void)
{
    static struct src_entry live[TABLE_CAP];
    unsigned n = 0;
    for (unsigned i = 0; i < TABLE_CAP; i++)
        if (table[i].version)
            live[n++] = table[i];
    qsort(live, n, sizeof live[0], by_last_seen_desc);
    memset(table, 0, sizeof table);
    table_used = 0;
    for (unsigned i = 0; i < n / 2; i++) {
        *table_slot(live[i].ip, live[i].version) = live[i];
        table_used++;
    }
}

static void table_add(const uint8_t *ip, uint8_t version, uint32_t bytes, double ts)
{
    struct src_entry *e = table_slot(ip, version);
    if (!e->version) {
        if (table_used + 1 > TABLE_CAP / 4 * 3) {
            table_shrink();
            e = table_slot(ip, version);
        }
        memcpy(e->ip, ip, 16);
        e->version = version;
        table_used++;
    }
    e->packets++;
    e->bytes += bytes;
    e->last_seen = ts;
}

/* ------------------------------------------------------------------ top-K min-heap */

static struct src_entry *heap[256];
static unsigned heap_n;

static void heap_sift_down(unsigned i)
{
    for (;;) {
        unsigned l = 2 * i + 1, r = l + 1, m = i;
        if (l < heap_n && heap[l]->bytes < heap[m]->bytes) m = l;
        if (r < heap_n && heap[r]->bytes < heap[m]->bytes) m = r;
        if (m == i) return;
        struct src_entry *t = heap[i]; heap[i] = heap[m]; heap[m] = t;
        i = m;
    }
}

static void heap_sift_up(unsigned i)
{
    while (i && heap[(i - 1) / 2]->bytes > heap[i]->bytes) {
        struct src_entry *t = heap[i]; heap[i] = heap[(i - 1) / 2]; heap[(i - 1) / 2] = t;
        i = (i - 1) / 2;
    }
}

/* Fill heap[] with the k largest sources by bytes, then sort it largest first. */
static void top_k(unsigned k)
{
    heap_n = 0;
    for (unsigned i = 0; i < TABLE_CAP; i++) {
        struct src_entry *e = &table[i];
        if (!e->version) continue;
        if (heap_n < k) {
            heap[heap_n++] = e;
            heap_sift_up(heap_n - 1);
        } else if (e->bytes > heap[0]->bytes) {
            heap[0] = e;                /* evict the smallest of the current top-K */
            heap_sift_down(0);
        }
    }
    /* heap-sort in place: repeatedly move the min to the end -> descending order */
    unsigned n = heap_n;
    while (heap_n > 1) {
        struct src_entry *t = heap[0]; heap[0] = heap[heap_n - 1]; heap[heap_n - 1] = t;
        heap_n--;
        heap_sift_down(0);
    }
    heap_n = n;
}

/* ------------------------------------------------------------------ snapshot */

static uint64_t total_packets, total_bytes, kernel_drops;

static void emit_snapshot(double ts)
{
    top_k(opt_k);
    struct {
        struct rec_snap s;
        struct snap_src top[256];
    } __attribute__((packed)) out;
    memset(&out, 0, sizeof out);
    out.s.ts = ts;
    out.s.packets = total_packets;
    out.s.bytes = total_bytes;
    out.s.kernel_drops = kernel_drops;
    out.s.sources = table_used;
    out.s.k = heap_n;
    for (unsigned i = 0; i < heap_n; i++) {
        memcpy(out.top[i].ip, heap[i]->ip, 16);
        out.top[i].ip_version = heap[i]->version;
        out.top[i].packets = heap[i]->packets;
        out.top[i].bytes = heap[i]->bytes;
    }
    emit(REC_SNAP, &out, sizeof out.s + heap_n * sizeof out.top[0]);
}

/* ------------------------------------------------------------------ parsing
 *
 * Mirrors pktan/decode.py for the common case: Ethernet (+802.1Q) or raw IP,
 * IPv4/IPv6, TCP/UDP. Anything that needs more than that, or looks unusual,
 * gets PKT_FRAME so Python decodes it in full; that keeps the two engines'
 * output identical (tests/test_cengine.py checks it).
 */

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static int is_http_method(const uint8_t *p, size_t n)
{
    static const char *m[] = { "GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "PATC" };
    if (n < 4) return 0;
    for (size_t i = 0; i < sizeof m / sizeof m[0]; i++)
        if (!memcmp(p, m[i], 4)) return 1;
    return 0;
}

static int port_in(uint16_t a, uint16_t b, uint16_t p) { return a == p || b == p; }

/* returns PKT_* flags to add */
static uint8_t parse_l4(struct rec_pkt *r, const uint8_t *b, size_t n)
{
    if (r->l4proto == 6) {              /* TCP */
        if (n < 20) return PKT_FRAME;
        r->sport = be16(b);
        r->dport = be16(b + 2);
        uint16_t off_flags = be16(b + 12);
        size_t hlen = (size_t)(off_flags >> 12) * 4;
        r->tcp_flags = (uint8_t)(off_flags & 0xff);
        const uint8_t *pl = b + hlen;
        size_t pn = (hlen >= 20 && hlen < n) ? n - hlen : 0;
        uint8_t f = PKT_HAS_L4;
        if (pn) {
            if (pl[0] == 0x16 || is_http_method(pl, pn) ||
                port_in(r->sport, r->dport, 53) || port_in(r->sport, r->dport, 5353))
                f |= PKT_FRAME;
        }
        return f;
    }
    if (r->l4proto == 17) {             /* UDP */
        if (n < 8) return PKT_FRAME;
        r->sport = be16(b);
        r->dport = be16(b + 2);
        const uint8_t *pl = b + 8;
        size_t pn = n - 8;
        uint16_t s = r->sport, d = r->dport;
        if (port_in(s, d, 53) || port_in(s, d, 5353) || port_in(s, d, 5355) ||
            port_in(s, d, 67) || port_in(s, d, 68))
            return PKT_HAS_L4 | PKT_FRAME;
        if (port_in(s, d, 443) && pn && (pl[0] & 0x80))
            return PKT_HAS_L4 | PKT_QUIC;
        return PKT_HAS_L4;
    }
    return PKT_FRAME;                   /* ICMP, IGMP, GRE, ...: rare, let Python label them */
}

static uint8_t parse_ipv4(struct rec_pkt *r, const uint8_t *b, size_t n)
{
    if (n < 20) return PKT_FRAME;
    size_t ihl = (size_t)(b[0] & 0x0f) * 4;
    if (ihl < 20 || n < ihl) return PKT_FRAME;
    uint16_t total = be16(b + 2), frag = be16(b + 6);
    r->ip_version = 4;
    r->ttl = b[8];
    r->l4proto = b[9];
    memcpy(r->src_ip, b + 12, 4);
    memcpy(r->dst_ip, b + 16, 4);
    size_t end = (total >= ihl && total < n) ? total : n;
    if (frag & 0x1fff) return PKT_IPFRAG;
    return parse_l4(r, b + ihl, end - ihl);
}

static uint8_t parse_ipv6(struct rec_pkt *r, const uint8_t *b, size_t n)
{
    if (n < 40) return PKT_FRAME;
    uint16_t plen = be16(b + 4);
    uint8_t nxt = b[6];
    r->ip_version = 6;
    r->ttl = b[7];
    r->l4proto = nxt;
    memcpy(r->src_ip, b + 8, 16);
    memcpy(r->dst_ip, b + 24, 16);
    if (nxt == 0 || nxt == 43 || nxt == 44 || nxt == 60)
        return PKT_FRAME;               /* extension headers: rare, Python walks them */
    size_t end = plen ? (40 + (size_t)plen < n ? 40 + (size_t)plen : n) : n;
    return parse_l4(r, b + 40, end - 40);
}

static void handle_packet(const uint8_t *data, size_t caplen, uint32_t wirelen,
                          int linktype, double ts, uint32_t ifindex)
{
    struct rec_pkt r;
    memset(&r, 0, sizeof r);
    r.ts = ts;
    r.wirelen = wirelen;
    r.ifindex = ifindex;
    r.vlan = 0xffff;
    r.linktype = (uint8_t)linktype;
    uint8_t f = 0;

    if (linktype == LINK_RAW) {
        uint8_t v = caplen ? data[0] >> 4 : 0;
        if (v == 4)      { r.ethertype = 0x0800; f = parse_ipv4(&r, data, caplen); }
        else if (v == 6) { r.ethertype = 0x86dd; f = parse_ipv6(&r, data, caplen); }
        else f = PKT_FRAME;
    } else if (caplen < 14) {
        f = PKT_FRAME;
    } else {
        memcpy(r.dst_mac, data, 6);
        memcpy(r.src_mac, data + 6, 6);
        f = PKT_HAS_MAC;
        uint16_t et = be16(data + 12);
        size_t off = 14;
        while ((et == 0x8100 || et == 0x88a8) && caplen >= off + 4) {
            r.vlan = be16(data + off) & 0x0fff;
            et = be16(data + off + 2);
            off += 4;
        }
        r.ethertype = et;
        if (et == 0x0800)      f |= parse_ipv4(&r, data + off, caplen - off);
        else if (et == 0x86dd) f |= parse_ipv6(&r, data + off, caplen - off);
        else                   f |= PKT_FRAME;   /* ARP, LLDP, EAPOL, ... */
    }
    if (f & PKT_FRAME) f |= PKT_DECODE;     /* parsing needs Python */
    if (opt_all_frames) f |= PKT_FRAME;     /* bytes for saving, not for decoding */
    r.flags = f;

    total_packets++;
    total_bytes += wirelen;
    if (r.ip_version)
        table_add(r.src_ip, r.ip_version, wirelen, ts);

    emit(REC_PKT, &r, sizeof r);
    if (f & PKT_FRAME)
        emit(REC_FRAME, data, (uint32_t)caplen);
}

/* ------------------------------------------------------------------ pcap files */

static uint32_t rd32(const uint8_t *p, int swap)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return swap ? __builtin_bswap32(v) : v;
}

static int read_pcap(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "pktcap: %s: %s\n", path, strerror(errno)); return 2; }
    uint8_t gh[24];
    if (fread(gh, 1, 24, f) != 24) { fprintf(stderr, "pktcap: %s: not a pcap file\n", path); fclose(f); return 2; }
    uint32_t magic;
    memcpy(&magic, gh, 4);
    int swap, nano;
    if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) swap = 0;
    else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) swap = 1;
    else { fprintf(stderr, "pktcap: %s: not a classic pcap file\n", path); fclose(f); return 2; }
    nano = (swap ? __builtin_bswap32(magic) : magic) == 0xa1b23c4d;
    uint32_t lt = rd32(gh + 20, swap) & 0x0fffffff;

    static uint8_t buf[262144 + 16];
    uint8_t rh[16];
    uint64_t since_snap = 0;
    double last_ts = 0;
    while (!stop_requested && fread(rh, 1, 16, f) == 16) {
        uint32_t sec = rd32(rh, swap), frac = rd32(rh + 4, swap);
        uint32_t incl = rd32(rh + 8, swap), orig = rd32(rh + 12, swap);
        if (incl > 262144) { fprintf(stderr, "pktcap: %s: oversized record\n", path); break; }
        if (fread(buf + 16, 1, incl, f) != incl) break;   /* truncated file: stop like Python */
        double ts = sec + frac / (nano ? 1e9 : 1e6);
        last_ts = ts;
        const uint8_t *data = buf + 16;
        size_t n = incl;
        int link = LINK_ETHERNET;
        if (lt == 113) {                    /* Linux cooked: fake an Ethernet header */
            if (n >= 16) {
                uint8_t *p = buf + 16 + 2;  /* 12 zero MAC bytes + 2-byte proto, then data[16:] */
                uint8_t proto[2] = { data[14], data[15] };
                memset(p, 0, 12);
                p[12] = proto[0]; p[13] = proto[1];
                data = p;                   /* length: 14 + (n - 16) */
                n = n - 2;
            }
        } else if (lt == 101 || lt == 12 || lt == 14 || lt == 228 || lt == 229) {
            link = LINK_RAW;
        }
        handle_packet(data, n, orig, link, ts, 0);
        if (++since_snap >= 65536) { emit_snapshot(ts); since_snap = 0; }
    }
    fclose(f);
    emit_snapshot(last_ts);
    flush_output();
    return 0;
}

/* ------------------------------------------------------------------ live capture */

#define BLOCK_SIZE (1u << 20)               /* 1 MiB blocks */
#define BLOCK_NR   8u                       /* 8 MiB ring */
#define FRAME_SIZE 2048u

static void read_drops(int fd)
{
    struct tpacket_stats_v3 st;
    socklen_t len = sizeof st;
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0)
        kernel_drops += st.tp_drops;        /* the kernel resets these on read */
}

static int live_capture(const char *iface)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            fprintf(stderr, "pktcap: live capture needs root or CAP_NET_RAW\n");
            return 3;
        }
        fprintf(stderr, "pktcap: socket: %s\n", strerror(errno));
        return 2;
    }
    int ver = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0) {
        fprintf(stderr, "pktcap: TPACKET_V3 not supported: %s\n", strerror(errno));
        return 2;
    }
    struct tpacket_req3 req;
    memset(&req, 0, sizeof req);
    req.tp_block_size = BLOCK_SIZE;
    req.tp_block_nr = BLOCK_NR;
    req.tp_frame_size = FRAME_SIZE;
    req.tp_frame_nr = BLOCK_SIZE / FRAME_SIZE * BLOCK_NR;
    req.tp_retire_blk_tov = 100;            /* hand a block over after 100 ms even if not full */
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) < 0) {
        fprintf(stderr, "pktcap: PACKET_RX_RING: %s\n", strerror(errno));
        return 2;
    }
    uint8_t *ring = mmap(NULL, (size_t)BLOCK_SIZE * BLOCK_NR, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_LOCKED, fd, 0);
    if (ring == MAP_FAILED)                 /* MAP_LOCKED needs RLIMIT_MEMLOCK; retry without */
        ring = mmap(NULL, (size_t)BLOCK_SIZE * BLOCK_NR, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        fprintf(stderr, "pktcap: mmap: %s\n", strerror(errno));
        return 2;
    }

    if (iface && strcmp(iface, "any")) {
        unsigned idx = if_nametoindex(iface);
        if (!idx) { fprintf(stderr, "pktcap: no such interface: %s\n", iface); return 2; }
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof sll);
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = (int)idx;
        if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
            fprintf(stderr, "pktcap: bind %s: %s\n", iface, strerror(errno));
            return 2;
        }
        if (!opt_no_promisc) {
            struct packet_mreq mr;
            memset(&mr, 0, sizeof mr);
            mr.mr_ifindex = (int)idx;
            mr.mr_type = PACKET_MR_PROMISC;
            setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr);  /* best effort */
        }
    }

    unsigned block = 0;
    double next_snap = mono_s() + 1.0;
    while (!stop_requested) {
        struct tpacket_block_desc *bd = (struct tpacket_block_desc *)(ring + (size_t)block * BLOCK_SIZE);
        if (!(bd->hdr.bh1.block_status & TP_STATUS_USER)) {
            struct pollfd p = { .fd = fd, .events = POLLIN | POLLERR };
            poll(&p, 1, 200);
            flush_output();
        } else {
            uint32_t n = bd->hdr.bh1.num_pkts;
            struct tpacket3_hdr *ph = (struct tpacket3_hdr *)((uint8_t *)bd + bd->hdr.bh1.offset_to_first_pkt);
            for (uint32_t i = 0; i < n; i++) {
                const struct sockaddr_ll *sll =
                    (const struct sockaddr_ll *)((uint8_t *)ph + TPACKET_ALIGN(sizeof(struct tpacket3_hdr)));
                const uint8_t *data = (const uint8_t *)ph + ph->tp_mac;
                int link = LINK_ETHERNET;
                if (sll->sll_hatype != 1 && sll->sll_hatype != 772 && ph->tp_snaplen &&
                    (data[0] >> 4 == 4 || data[0] >> 4 == 6))
                    link = LINK_RAW;        /* tun/WireGuard/Tailscale: bare IP */
                handle_packet(data, ph->tp_snaplen, ph->tp_len, link,
                              ph->tp_sec + ph->tp_nsec / 1e9, (uint32_t)sll->sll_ifindex);
                ph = (struct tpacket3_hdr *)((uint8_t *)ph + ph->tp_next_offset);
            }
            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;   /* give the block back */
            block = (block + 1) % BLOCK_NR;
            flush_output();
        }
        if (mono_s() >= next_snap) {
            read_drops(fd);
            emit_snapshot(now_s());
            flush_output();
            next_snap = mono_s() + 1.0;
        }
    }
    munmap(ring, (size_t)BLOCK_SIZE * BLOCK_NR);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ main */

int main(int argc, char **argv)
{
    const char *iface = NULL, *file = NULL;
    int c;
    while ((c = getopt(argc, argv, "i:r:ak:Pnh")) != -1) {
        switch (c) {
        case 'i': iface = optarg; break;
        case 'r': file = optarg; break;
        case 'a': opt_all_frames = 1; break;
        case 'k': opt_k = (unsigned)atoi(optarg); if (opt_k < 1) opt_k = 1; if (opt_k > 256) opt_k = 256; break;
        case 'P': opt_no_promisc = 1; break;
        case 'n': opt_no_output = 1; break;
        default:
            fprintf(stderr, "usage: pktcap (-i IFACE | -r FILE.pcap) [-a] [-k N] [-P] [-n]\n");
            return c == 'h' ? 0 : 2;
        }
    }
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    static char outbuf[1 << 20];
    setvbuf(stdout, outbuf, _IOFBF, sizeof outbuf);

    double t0 = mono_s();
    int rc = file ? read_pcap(file) : live_capture(iface);
    if (opt_no_output) {
        double dt = mono_s() - t0;
        fprintf(stderr, "pktcap: %llu packets in %.3f s (%.0f packets/s), %u sources\n",
                (unsigned long long)total_packets, dt, dt > 0 ? total_packets / dt : 0.0, table_used);
    }
    return rc;
}
