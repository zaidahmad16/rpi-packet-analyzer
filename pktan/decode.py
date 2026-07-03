"""Protocol decoder: raw frame bytes -> Packet.

Stdlib only. Every parser is defensive: a truncated or malformed header stops
decoding at that layer instead of raising, so one bad frame never kills a capture.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

# Link types (pcap LINKTYPE_* values; also what capture.py normalises to)
LINK_ETHERNET = 1
LINK_RAW = 101          # bare IPv4/IPv6, e.g. tailscale0 / tun devices

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_IPV6 = 0x86DD

IP_ICMP = 1
IP_TCP = 6
IP_UDP = 17
IP_ICMPV6 = 58

TCP_FLAGS = "FSRPAUEC"  # bit 0 .. bit 7

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 123: "NTP", 137: "NETBIOS", 138: "NETBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    546: "DHCPv6", 547: "DHCPv6", 587: "SMTP", 853: "DoT", 993: "IMAPS",
    1883: "MQTT", 1900: "SSDP", 3389: "RDP", 3478: "STUN", 5353: "mDNS",
    5355: "LLMNR", 5900: "VNC", 6443: "K8S-API", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    8883: "MQTTS", 41641: "TAILSCALE", 51820: "WIREGUARD",
}


@dataclass
class Packet:
    ts: float
    length: int                     # original length on the wire
    iface: str = ""
    src_mac: str | None = None
    dst_mac: str | None = None
    vlan: int | None = None
    ethertype: int | None = None
    src: str | None = None          # IP (or ARP sender IP)
    dst: str | None = None
    ip_version: int | None = None
    ttl: int | None = None
    proto: str = "OTHER"            # transport-ish: TCP/UDP/ICMP/ICMPv6/ARP/...
    sport: int | None = None
    dport: int | None = None
    tcp_flags: str = ""
    app: str | None = None          # application label: DNS, HTTPS, DHCP, ...
    info: str = ""                  # one-line human summary
    dns_query: str | None = None
    dns_answers: list[tuple[str, str]] = field(default_factory=list)  # (name, ip)
    hostname: str | None = None     # learned from DHCP option 12
    sni: str | None = None
    http_host: str | None = None

    def summary(self) -> str:
        if self.proto == "ARP":
            return f"ARP {self.info}"
        s = self.src or self.src_mac or "?"
        d = self.dst or self.dst_mac or "?"
        if self.sport is not None:
            s = f"{_fmt_host(s)}:{self.sport}"
            d = f"{_fmt_host(d)}:{self.dport}"
        label = self.app or self.proto
        extra = f" {self.info}" if self.info else ""
        return f"{label:<9} {s} -> {d} len={self.length}{extra}"


def _fmt_host(ip: str) -> str:
    return f"[{ip}]" if ":" in ip and not ip.count(".") else ip


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode(data: bytes, ts: float = 0.0, length: int | None = None,
           linktype: int = LINK_ETHERNET, iface: str = "") -> Packet:
    p = Packet(ts=ts, length=length if length is not None else len(data), iface=iface)
    try:
        if linktype == LINK_RAW:
            _decode_raw_ip(p, data)
        else:
            _decode_ethernet(p, data)
    except (struct.error, IndexError, ValueError):
        p.info = (p.info + " [malformed]").strip()
    return p


def _decode_raw_ip(p: Packet, data: bytes) -> None:
    if not data:
        return
    v = data[0] >> 4
    if v == 4:
        p.ethertype = ETH_IPV4
        _decode_ipv4(p, data)
    elif v == 6:
        p.ethertype = ETH_IPV6
        _decode_ipv6(p, data)


def _decode_ethernet(p: Packet, data: bytes) -> None:
    if len(data) < 14:
        return
    p.dst_mac = mac_str(data[0:6])
    p.src_mac = mac_str(data[6:12])
    etype = struct.unpack_from("!H", data, 12)[0]
    off = 14
    while etype in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4:
        tci, etype = struct.unpack_from("!HH", data, off)
        p.vlan = tci & 0x0FFF
        off += 4
    p.ethertype = etype
    body = data[off:]
    if etype == ETH_IPV4:
        _decode_ipv4(p, body)
    elif etype == ETH_IPV6:
        _decode_ipv6(p, body)
    elif etype == ETH_ARP:
        _decode_arp(p, body)
    elif etype == 0x88CC:
        p.proto = "LLDP"
    elif etype == 0x888E:
        p.proto = "EAPOL"
    elif etype < 0x0600:
        p.proto = "802.3"
    else:
        p.proto = f"0x{etype:04x}"


def _decode_arp(p: Packet, b: bytes) -> None:
    p.proto = "ARP"
    if len(b) < 28:
        return
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", b, 0)
    if hlen != 6 or plen != 4:
        return
    sha, spa = b[8:14], b[14:18]
    tpa = b[24:28]
    p.src = str(ipaddress.IPv4Address(spa))
    p.dst = str(ipaddress.IPv4Address(tpa))
    if op == 1:
        p.info = f"who-has {p.dst} tell {p.src}"
    elif op == 2:
        p.info = f"{p.src} is-at {mac_str(sha)}"
    else:
        p.info = f"op={op}"


def _decode_ipv4(p: Packet, b: bytes) -> None:
    if len(b) < 20:
        return
    vihl, _tos, total, _ident, frag, ttl, proto = struct.unpack_from("!BBHHHBB", b, 0)
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(b) < ihl:
        return
    p.ip_version = 4
    p.ttl = ttl
    p.src = str(ipaddress.IPv4Address(b[12:16]))
    p.dst = str(ipaddress.IPv4Address(b[16:20]))
    end = min(len(b), total) if total >= ihl else len(b)
    if frag & 0x1FFF:          # non-first fragment: no transport header
        p.proto = "IP-FRAG"
        return
    _decode_transport(p, proto, b[ihl:end])


def _decode_ipv6(p: Packet, b: bytes) -> None:
    if len(b) < 40:
        return
    payload_len, nxt, hop = struct.unpack_from("!HBB", b, 4)
    p.ip_version = 6
    p.ttl = hop
    p.src = str(ipaddress.IPv6Address(b[8:24]))
    p.dst = str(ipaddress.IPv6Address(b[24:40]))
    off = 40
    # walk the common extension headers
    for _ in range(8):
        if nxt in (0, 43, 60) and len(b) >= off + 8:   # hop-by-hop, routing, dest opts
            nxt, hlen = b[off], b[off + 1]
            off += (hlen + 1) * 8
        elif nxt == 44 and len(b) >= off + 8:          # fragment
            nxt = b[off]
            frag_off = struct.unpack_from("!H", b, off + 2)[0] >> 3
            off += 8
            if frag_off:
                p.proto = "IP-FRAG"
                return
        else:
            break
    _decode_transport(p, nxt, b[off:40 + payload_len] if payload_len else b[off:])


def _decode_transport(p: Packet, proto: int, b: bytes) -> None:
    if proto == IP_TCP:
        _decode_tcp(p, b)
    elif proto == IP_UDP:
        _decode_udp(p, b)
    elif proto == IP_ICMP:
        p.proto = "ICMP"
        if len(b) >= 2:
            p.info = ICMP_TYPES.get(b[0], f"type={b[0]} code={b[1]}")
    elif proto == IP_ICMPV6:
        p.proto = "ICMPv6"
        if len(b) >= 2:
            p.info = ICMPV6_TYPES.get(b[0], f"type={b[0]} code={b[1]}")
    elif proto == 2:
        p.proto = "IGMP"
    elif proto == 47:
        p.proto = "GRE"
    elif proto == 50:
        p.proto = "ESP"
    else:
        p.proto = f"IP/{proto}"


ICMP_TYPES = {0: "echo reply", 3: "dest unreachable", 5: "redirect", 8: "echo request",
              11: "time exceeded"}
ICMPV6_TYPES = {1: "dest unreachable", 3: "time exceeded", 128: "echo request",
                129: "echo reply", 133: "router solicit", 134: "router advert",
                135: "neighbor solicit", 136: "neighbor advert", 143: "MLDv2 report"}


def _app_for(sport: int, dport: int) -> str | None:
    # prefer the lower (more likely server) port
    for port in sorted((sport, dport)):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return None


def _decode_tcp(p: Packet, b: bytes) -> None:
    p.proto = "TCP"
    if len(b) < 20:
        return
    sport, dport, _seq, _ack, off_flags = struct.unpack_from("!HHIIH", b, 0)
    hlen = (off_flags >> 12) * 4
    flags = off_flags & 0xFF
    p.sport, p.dport = sport, dport
    p.tcp_flags = "".join(c for i, c in enumerate(TCP_FLAGS) if flags & (1 << i))
    p.app = _app_for(sport, dport)
    payload = b[hlen:] if hlen >= 20 else b""
    p.info = f"[{p.tcp_flags}]" if p.tcp_flags else ""
    if payload:
        if payload[0] == 0x16:
            sni = parse_tls_sni(payload)
            if sni:
                p.sni = sni
                p.app = p.app or "TLS"
                p.info += f" SNI={sni}"
        elif payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC"):
            host = parse_http_host(payload)
            p.app = "HTTP"
            line = payload.split(b"\r\n", 1)[0][:80].decode("latin-1")
            p.info += f" {line}"
            if host:
                p.http_host = host
        elif sport in (53, 5353) or dport in (53, 5353):
            if len(payload) > 2:
                _decode_dns(p, payload[2:])


def _decode_udp(p: Packet, b: bytes) -> None:
    p.proto = "UDP"
    if len(b) < 8:
        return
    sport, dport, _ulen, _ck = struct.unpack_from("!HHHH", b, 0)
    p.sport, p.dport = sport, dport
    p.app = _app_for(sport, dport)
    payload = b[8:]
    if 53 in (sport, dport) or 5353 in (sport, dport) or 5355 in (sport, dport):
        _decode_dns(p, payload)
    elif {67, 68} & {sport, dport}:
        _decode_dhcp(p, payload)
    elif 443 in (sport, dport) and payload and payload[0] & 0x80:
        p.app = "QUIC"


# ---------- DNS ----------

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
             28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


def _dns_name(b: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    while True:
        if off >= len(b) or depth > 20:
            raise ValueError("bad dns name")
        n = b[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack_from("!H", b, off)[0] & 0x3FFF
            if jumped_end is None:
                jumped_end = off + 2
            off = ptr
            depth += 1
            continue
        labels.append(b[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels) or ".", (jumped_end if jumped_end is not None else off)


def _decode_dns(p: Packet, b: bytes) -> None:
    if len(b) < 12:
        return
    _id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", b, 0)
    is_resp = bool(flags & 0x8000)
    off = 12
    qname, qtype = None, None
    for _ in range(min(qd, 16)):
        qname, off = _dns_name(b, off)
        qtype = struct.unpack_from("!H", b, off)[0]
        off += 4
    if qname:
        p.dns_query = qname
    answers = []
    if is_resp:
        # mDNS puts A/AAAA records in the additional section, so walk all three
        for _ in range(min(an + ns + ar, 48)):
            name, off = _dns_name(b, off)
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", b, off)
            off += 10
            rdata = b[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                answers.append((name, str(ipaddress.IPv4Address(rdata))))
            elif rtype == 28 and rdlen == 16:
                answers.append((name, str(ipaddress.IPv6Address(rdata))))
    p.dns_answers = answers
    if p.app not in ("mDNS", "LLMNR"):
        p.app = "DNS"
    if qname is None and answers:          # mDNS announcements have no question
        qname, qtype = answers[0][0], 1 if "." in answers[0][1] else 28
    t = DNS_TYPES.get(qtype or 0, str(qtype)) if qtype is not None else "-"
    if is_resp:
        rcode = flags & 0x0F
        ans = ", ".join(ip for _, ip in answers[:3])
        p.info = f"response {t} {qname or ''}".rstrip() + (f" -> {ans}" if ans else "") + \
                 (f" rcode={rcode}" if rcode else "")
    else:
        p.info = f"query {t} {qname}"


# ---------- DHCP ----------

DHCP_MSG = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK",
            7: "RELEASE", 8: "INFORM"}


def _decode_dhcp(p: Packet, b: bytes) -> None:
    p.app = "DHCP"
    if len(b) < 240 or b[236:240] != b"\x63\x82\x53\x63":
        return
    yiaddr = str(ipaddress.IPv4Address(b[16:20]))
    chaddr = mac_str(b[28:34])
    off = 240
    msg = None
    while off < len(b):
        code = b[off]
        if code == 255:
            break
        if code == 0:
            off += 1
            continue
        ln = b[off + 1]
        val = b[off + 2:off + 2 + ln]
        if code == 53 and val:
            msg = DHCP_MSG.get(val[0], str(val[0]))
        elif code == 12:
            p.hostname = val.decode("utf-8", "replace").strip("\x00")
        off += 2 + ln
    p.info = f"{msg or '?'} client={chaddr}"
    if yiaddr != "0.0.0.0":
        p.info += f" ip={yiaddr}"
    if p.hostname:
        p.info += f" host={p.hostname}"
    p.src_mac = p.src_mac or chaddr


# ---------- TLS / HTTP ----------

def parse_tls_sni(b: bytes) -> str | None:
    """Return the SNI from a TLS ClientHello record, or None."""
    try:
        if len(b) < 43 or b[0] != 0x16 or b[5] != 0x01:
            return None
        off = 5 + 4 + 2 + 32            # record hdr, handshake hdr, version, random
        sid_len = b[off]
        off += 1 + sid_len
        cs_len = struct.unpack_from("!H", b, off)[0]
        off += 2 + cs_len
        comp_len = b[off]
        off += 1 + comp_len
        ext_total = struct.unpack_from("!H", b, off)[0]
        off += 2
        end = min(len(b), off + ext_total)
        while off + 4 <= end:
            etype, elen = struct.unpack_from("!HH", b, off)
            off += 4
            if etype == 0:              # server_name
                # list len(2) type(1) name len(2) name
                nlen = struct.unpack_from("!H", b, off + 3)[0]
                return b[off + 5:off + 5 + nlen].decode("ascii", "replace")
            off += elen
    except (struct.error, IndexError):
        return None
    return None


def parse_http_host(b: bytes) -> str | None:
    head = b.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            return line[5:].strip().decode("latin-1")
    return None
