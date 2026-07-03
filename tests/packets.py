"""Helpers that build real wire-format frames for the tests (no capture needed)."""
import ipaddress
import struct

MAC_PI = bytes.fromhex("2ccf67000099")
MAC_PHONE = bytes.fromhex("3c22fb000001")
MAC_ROUTER = bytes.fromhex("50c7bf000002")
BCAST = b"\xff" * 6


def eth(dst, src, etype, payload):
    return dst + src + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload, ttl=64):
    total = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, ttl, proto, 0,
                       ipaddress.IPv4Address(src).packed,
                       ipaddress.IPv4Address(dst).packed) + payload


def ipv6(src, dst, nxt, payload):
    return struct.pack("!IHBB", 6 << 28, len(payload), nxt, 64) + \
        ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, flags="S", payload=b""):
    bits = sum(1 << "FSRPAUEC".index(c) for c in flags)
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | bits, 65535, 0, 0) + payload


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(name, qtype=1, ident=0x1234):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(name, ips, ident=0x1234):
    body = struct.pack("!HHHHHH", ident, 0x8180, 1, len(ips), 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)
    for ip in ips:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ipaddress.IPv4Address(ip).packed
    return body


def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + ipaddress.IPv4Address(spa).packed + \
        tha + ipaddress.IPv4Address(tpa).packed


def tls_client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = sni_ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + \
        struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def dhcp_request(mac, hostname):
    b = bytearray(240)
    b[0], b[1], b[2] = 1, 1, 6
    b[28:34] = mac
    b[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, 3]) + bytes([12, len(hostname)]) + hostname.encode() + b"\xff"
    return bytes(b) + opts


def sample_frames():
    """A small, realistic conversation: ARP, DHCP, DNS, HTTPS, HTTP, ICMP, IPv6."""
    pi, phone, router = "192.168.1.50", "192.168.1.23", "192.168.1.1"
    return [
        eth(BCAST, MAC_PHONE, 0x0806, arp(1, MAC_PHONE, phone, b"\0" * 6, router)),
        eth(MAC_PHONE, MAC_ROUTER, 0x0806, arp(2, MAC_ROUTER, router, MAC_PHONE, phone)),
        eth(BCAST, MAC_PHONE, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17,
                                           udp(68, 67, dhcp_request(MAC_PHONE, "my-iphone")))),
        eth(MAC_ROUTER, MAC_PHONE, 0x0800, ipv4(phone, router, 17, udp(53000, 53, dns_query("example.com")))),
        eth(MAC_PHONE, MAC_ROUTER, 0x0800, ipv4(router, phone, 17,
                                                udp(53, 53000, dns_response("example.com", ["93.184.215.14"])))),
        eth(MAC_ROUTER, MAC_PHONE, 0x0800, ipv4(phone, "93.184.215.14", 6, tcp(50000, 443, "S"))),
        eth(MAC_ROUTER, MAC_PHONE, 0x0800, ipv4(phone, "93.184.215.14", 6,
                                                tcp(50000, 443, "PA", tls_client_hello("example.com")))),
        eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4(pi, "93.184.215.14", 6,
                                             tcp(40000, 80, "PA", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))),
        eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4(pi, "1.1.1.1", 1, b"\x08\x00\x00\x00\x00\x01\x00\x01")),
        eth(MAC_ROUTER, MAC_PI, 0x86DD, ipv6("fe80::1", "ff02::1", 58, b"\x87\x00\x00\x00" + b"\x00" * 20)),
    ]
