/* pktcap wire format, shared with pktan/cengine.py.
 *
 * pktcap writes a stream of records to stdout. Every record starts with a
 * rec_hdr; all integers are little-endian (x86-64 and the Pi's aarch64 both are).
 *
 *   REC_PKT    one per packet, fixed size: the L2-L4 fields pktcap parsed.
 *   REC_FRAME  the raw frame, sent right after a REC_PKT whose PKT_FRAME flag
 *              is set: packets Python must decode fully (also flagged
 *              PKT_DECODE: DNS, DHCP, ARP, TLS hellos, anything unusual), or
 *              every packet with -a, so the caller can save it.
 *   REC_SNAP   about once a second: capture totals and the top-K sources by bytes.
 */
#ifndef PKTCAP_H
#define PKTCAP_H

#include <stdint.h>

enum { REC_PKT = 1, REC_FRAME = 2, REC_SNAP = 3 };

struct __attribute__((packed)) rec_hdr {
    uint16_t type;
    uint16_t reserved;
    uint32_t len;               /* bytes of body that follow */
};

/* flags in rec_pkt.flags */
#define PKT_FRAME     0x01      /* a REC_FRAME with the raw bytes follows */
#define PKT_IPFRAG    0x02      /* non-first IP fragment: no L4 header */
#define PKT_QUIC      0x04      /* UDP/443 with the QUIC long-header bit set */
#define PKT_HAS_MAC   0x08      /* src/dst MAC fields are valid */
#define PKT_HAS_L4    0x10      /* sport/dport are valid */
#define PKT_DECODE    0x20      /* Python must decode the frame fully (DNS, ARP, ...);
                                   without it, a REC_FRAME (from -a) is only for saving */

/* link types, same numbers as pcap (and pktan.decode) */
#define LINK_ETHERNET 1
#define LINK_RAW      101

struct __attribute__((packed)) rec_pkt {
    double   ts;                /* seconds since the epoch */
    uint32_t wirelen;           /* original length on the wire */
    uint32_t ifindex;           /* 0 when reading a file */
    uint16_t ethertype;
    uint16_t vlan;              /* 0xffff = no tag */
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  ip_version;        /* 0, 4 or 6 */
    uint8_t  l4proto;           /* IP protocol number */
    uint8_t  tcp_flags;
    uint8_t  ttl;
    uint8_t  flags;
    uint8_t  linktype;
    uint16_t pad;
    uint8_t  src_ip[16];        /* IPv4 is stored in the first 4 bytes */
    uint8_t  dst_ip[16];
    uint16_t sport;
    uint16_t dport;
};

struct __attribute__((packed)) snap_src {
    uint8_t  ip[16];
    uint8_t  ip_version;
    uint8_t  pad[7];
    uint64_t packets;
    uint64_t bytes;
};

struct __attribute__((packed)) rec_snap {
    double   ts;
    uint64_t packets;           /* totals since start */
    uint64_t bytes;
    uint64_t kernel_drops;      /* from PACKET_STATISTICS (live only) */
    uint32_t sources;           /* entries in the source table */
    uint32_t k;                 /* number of snap_src entries that follow */
    /* struct snap_src top[k], largest first */
};

#endif
