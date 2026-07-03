"""Packet sources (live AF_PACKET socket or pcap file) and the display filter."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import time
from typing import Callable, Iterator

from .decode import LINK_ETHERNET, LINK_RAW, Packet
from .pcap import read_pcap

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4
ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772

Frame = tuple[float, bytes, int, int, str]   # ts, data, orig_len, linktype, iface


class CaptureError(RuntimeError):
    pass


def list_interfaces() -> list[dict]:
    out = []
    for _idx, name in socket.if_nameindex():
        base = f"/sys/class/net/{name}"
        info = {"name": name, "state": "?", "mac": "", "type": ""}
        try:
            info["state"] = open(f"{base}/operstate").read().strip()
            info["mac"] = open(f"{base}/address").read().strip()
            t = int(open(f"{base}/type").read())
            info["type"] = {1: "ethernet", 772: "loopback", 65534: "tunnel"}.get(t, str(t))
            if os.path.isdir(f"{base}/wireless"):
                info["type"] = "wifi"
            elif os.path.exists(f"{base}/bridge"):
                info["type"] = "bridge"
            elif os.path.islink(f"{base}/device") is False and info["type"] == "ethernet":
                info["type"] = "virtual"
        except OSError:
            pass
        out.append(info)
    return out


def default_interface() -> str | None:
    """Interface carrying the default route, else first up non-loopback."""
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                parts = line.split()
                if parts[1] == "00000000" and int(parts[3], 16) & 2:
                    return parts[0]
    except (OSError, StopIteration, IndexError, ValueError):
        pass
    for i in list_interfaces():
        if i["state"] == "up" and i["type"] != "loopback":
            return i["name"]
    return None


def live_frames(iface: str | None, promisc: bool = True,
                stop: Callable[[], bool] = lambda: False) -> Iterator[Frame]:
    """Yield frames from a raw socket. iface=None or 'any' captures every interface."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        raise CaptureError(
            "Live capture needs root or CAP_NET_RAW. Run with sudo, or once:\n"
            "  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))\n"
            "(or analyse a file instead with --read capture.pcap)") from None
    except AttributeError:
        raise CaptureError("Live capture uses AF_PACKET and only works on Linux.") from None
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        if iface and iface != "any":
            try:
                s.bind((iface, 0))
            except OSError as e:
                raise CaptureError(f"cannot capture on {iface!r}: {e.strerror}") from None
            if promisc:
                idx = socket.if_nametoindex(iface)
                mreq = struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b"")
                try:
                    s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
                except OSError:
                    pass   # not fatal; promisc is best-effort and reverts on close
        s.settimeout(0.5)
        while not stop():
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except InterruptedError:
                continue
            ts = time.time()
            name, _proto, _pkttype, hatype = addr[0], addr[1], addr[2], addr[3]
            if hatype in (ARPHRD_ETHER, ARPHRD_LOOPBACK):
                lt = LINK_ETHERNET
            elif data and data[0] >> 4 in (4, 6):
                lt = LINK_RAW        # tun/wireguard/tailscale: bare IP
            else:
                lt = LINK_ETHERNET
            yield ts, data, len(data), lt, name
    finally:
        s.close()


def file_frames(path: str, realtime: bool = False,
                stop: Callable[[], bool] = lambda: False) -> Iterator[Frame]:
    """Yield frames from a pcap. realtime=True replays at the original pacing."""
    first_ts = start = None
    for ts, data, orig, lt in read_pcap(path):
        if stop():
            return
        if realtime:
            if first_ts is None:
                first_ts, start = ts, time.time()
            delay = (ts - first_ts) - (time.time() - start)
            if delay > 0:
                time.sleep(min(delay, 2.0))
        yield ts, data, orig, lt, os.path.basename(path)


# ---------------------------------------------------------------- filter

class FilterError(ValueError):
    pass


_TOKEN = re.compile(r"\s*(\(|\)|!|&&|\|\||[^\s()!]+)")
_PROTO_WORDS = {"tcp", "udp", "icmp", "icmpv6", "arp", "ip", "ip6", "ipv4", "ipv6"}


def compile_filter(expr: str | None) -> Callable[[Packet], bool]:
    """Compile a small tcpdump-like expression into a predicate.

    Grammar:  expr := term (('or'|'||') term)*
              term := factor (('and'|'&&')? factor)*
              factor := ('not'|'!') factor | '(' expr ')' | primitive
              primitive := tcp|udp|icmp|arp|ip|ip6|<app name e.g. dns, https>
                         | [src|dst] host ADDR | [src|dst] port N | [src|dst] net CIDR
                         | port N-M (portrange) | mac ADDR
    """
    if not expr or not expr.strip():
        return lambda p: True
    toks = _TOKEN.findall(expr.strip())
    pos = 0

    def peek():
        return toks[pos].lower() if pos < len(toks) else None

    def take():
        nonlocal pos
        if pos >= len(toks):
            raise FilterError(f"unexpected end of filter: {expr!r}")
        t = toks[pos]
        pos += 1
        return t

    def parse_expr():
        left = parse_term()
        while peek() in ("or", "||"):
            take()
            right = parse_term()
            left = (lambda a, b: lambda p: a(p) or b(p))(left, right)
        return left

    def parse_term():
        left = parse_factor()
        while peek() is not None and peek() not in ("or", "||", ")"):
            if peek() in ("and", "&&"):
                take()
            right = parse_factor()
            left = (lambda a, b: lambda p: a(p) and b(p))(left, right)
        return left

    def parse_factor():
        t = peek()
        if t in ("not", "!"):
            take()
            f = parse_factor()
            return lambda p: not f(p)
        if t == "(":
            take()
            f = parse_expr()
            if take() != ")":
                raise FilterError("missing ')'")
            return f
        return parse_primitive()

    def parse_primitive():
        t = take().lower()
        direction = None
        if t in ("src", "dst"):
            direction, t = t, take().lower()
        if t == "host":
            val = take()
            return _addr_pred(direction, lambda a: a == val)
        if t == "net":
            try:
                net = ipaddress.ip_network(take(), strict=False)
            except ValueError as e:
                raise FilterError(str(e)) from None

            def in_net(a):
                try:
                    return ipaddress.ip_address(a) in net
                except ValueError:
                    return False
            return _addr_pred(direction, in_net)
        if t in ("port", "portrange"):
            raw = take()
            try:
                if "-" in raw:
                    lo, hi = (int(x) for x in raw.split("-", 1))
                else:
                    lo = hi = int(raw)
            except ValueError:
                raise FilterError(f"bad port {raw!r}") from None
            return _port_pred(direction, lambda n: n is not None and lo <= n <= hi)
        if t in ("mac", "ether"):
            if peek() == "host":
                take()
            val = take().lower()
            return _mac_pred(direction, val)
        if direction:
            raise FilterError(f"'{direction}' must be followed by host/net/port")
        if t in _PROTO_WORDS:
            return _proto_pred(t)
        # application label, e.g. dns, https, dhcp, mdns, quic, ssh
        return lambda p, t=t: (p.app or "").lower() == t
    f = parse_expr()
    if pos != len(toks):
        raise FilterError(f"unexpected {toks[pos]!r} in filter")
    return f


def _addr_pred(direction, test):
    if direction == "src":
        return lambda p: p.src is not None and test(p.src)
    if direction == "dst":
        return lambda p: p.dst is not None and test(p.dst)
    return lambda p: (p.src is not None and test(p.src)) or (p.dst is not None and test(p.dst))


def _port_pred(direction, test):
    if direction == "src":
        return lambda p: test(p.sport)
    if direction == "dst":
        return lambda p: test(p.dport)
    return lambda p: test(p.sport) or test(p.dport)


def _mac_pred(direction, val):
    if direction == "src":
        return lambda p: p.src_mac == val
    if direction == "dst":
        return lambda p: p.dst_mac == val
    return lambda p: val in (p.src_mac, p.dst_mac)


def _proto_pred(t):
    if t in ("ip", "ipv4"):
        return lambda p: p.ip_version == 4
    if t in ("ip6", "ipv6"):
        return lambda p: p.ip_version == 6
    up = {"icmpv6": "ICMPv6"}.get(t, t.upper())
    return lambda p: p.proto == up
