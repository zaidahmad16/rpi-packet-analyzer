"""Bridge to the C engine (csrc/pktcap): spawn it and turn its records into Packets.

pktcap parses every packet down to TCP/UDP and sends a fixed-size summary. For
those, a Packet is built straight from the summary with no Python parsing.
Packets that need a full decode (DNS, DHCP, ARP, TLS hellos, anything odd) come
with their raw bytes and go through pktan.decode, exactly like the Python engine.
The record layout must match csrc/pktcap.h.
"""
from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
from pathlib import Path
from typing import Callable, Iterator

from .capture import CaptureError
from .decode import TCP_FLAGS, Packet, _app_for, decode, mac_str

CSRC = Path(__file__).resolve().parent.parent / "csrc"
REC_PKT, REC_FRAME, REC_SNAP = 1, 2, 3
PKT_FRAME, PKT_IPFRAG, PKT_QUIC, PKT_HAS_MAC, PKT_HAS_L4, PKT_DECODE = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

HDR = struct.Struct("<HHI")                                 # struct rec_hdr
PKT = struct.Struct("<dIIHH6s6sBBBBBBH16s16sHH")            # struct rec_pkt
SNAP = struct.Struct("<dQQQII")                             # struct rec_snap
SRC = struct.Struct("<16sB7xQQ")                            # struct snap_src
assert (HDR.size, PKT.size, SNAP.size, SRC.size) == (8, 76, 40, 40)

_FLAG_STR = [""] * 256
for _bits in range(256):
    _FLAG_STR[_bits] = "".join(c for i, c in enumerate(TCP_FLAGS) if _bits & (1 << i))


def binary_path() -> Path:
    return Path(os.environ.get("PKTAN_PKTCAP") or CSRC / "pktcap")


def ensure_built() -> Path | None:
    """Return the pktcap binary, building it with make if it's missing or stale."""
    binary = binary_path()
    src = [CSRC / "pktcap.c", CSRC / "pktcap.h"]
    stale = not binary.exists() or (
        all(s.exists() for s in src) and max(s.stat().st_mtime for s in src) > binary.stat().st_mtime)
    if stale and "PKTAN_PKTCAP" not in os.environ:
        if not (shutil.which("make") and shutil.which("cc") and os.access(CSRC, os.W_OK)):
            return binary if binary.exists() else None
        r = subprocess.run(["make", "-s", "-C", str(CSRC), "pktcap"], capture_output=True, text=True)
        if r.returncode != 0:
            return binary if binary.exists() else None
    return binary if binary.exists() and os.access(binary, os.X_OK) else None


class _Names:
    """Bounded caches for the strings every packet needs (IPs, MACs, interfaces)."""

    def __init__(self, limit: int = 8192):
        self.limit = limit
        self.ip4: dict[bytes, str] = {}
        self.ip6: dict[bytes, str] = {}
        self.mac: dict[bytes, str] = {}
        self.ifname: dict[int, str] = {}

    def _get(self, cache: dict, key, make):
        v = cache.get(key)
        if v is None:
            if len(cache) >= self.limit:
                cache.clear()
            v = cache[key] = make(key)
        return v

    def ip(self, raw: bytes, version: int) -> str:
        if version == 4:
            return self._get(self.ip4, raw[:4], lambda b: socket.inet_ntop(socket.AF_INET, b))
        import ipaddress                       # same text form as pktan.decode
        return self._get(self.ip6, raw, lambda b: str(ipaddress.IPv6Address(b)))

    def mac_of(self, raw: bytes) -> str:
        return self._get(self.mac, raw, mac_str)

    def iface(self, index: int) -> str:
        def name(i):
            try:
                return socket.if_indextoname(i)
            except OSError:
                return str(i)
        return self._get(self.ifname, index, name)


def packet_from_record(rec: tuple, names: _Names, iface: str) -> Packet:
    """Build the same Packet pktan.decode would, from a summary record."""
    (ts, wirelen, _ifindex, ethertype, vlan, smac, dmac, ipv, l4, tflags, ttl,
     flags, _link, _pad, sip, dip, sport, dport) = rec
    p = Packet(ts=ts, length=wirelen, iface=iface)
    if flags & PKT_HAS_MAC:
        p.src_mac, p.dst_mac = names.mac_of(smac), names.mac_of(dmac)
    p.ethertype = ethertype
    if vlan != 0xFFFF:
        p.vlan = vlan
    if ipv:
        p.ip_version, p.ttl = ipv, ttl
        p.src, p.dst = names.ip(sip, ipv), names.ip(dip, ipv)
    if flags & PKT_IPFRAG:
        p.proto = "IP-FRAG"
    elif flags & PKT_HAS_L4:
        p.sport, p.dport = sport, dport
        p.app = _app_for(sport, dport)
        if l4 == 6:
            p.proto = "TCP"
            p.tcp_flags = _FLAG_STR[tflags]
            p.info = f"[{p.tcp_flags}]" if p.tcp_flags else ""
        else:
            p.proto = "UDP"
            if flags & PKT_QUIC:
                p.app = "QUIC"
    return p


def c_packets(iface: str | None = None, read: str | None = None, all_frames: bool = False,
              promisc: bool = True, stop: Callable[[], bool] = lambda: False,
              on_snapshot: Callable[[dict], None] | None = None,
              binary: Path | None = None) -> Iterator[tuple[Packet, bytes | None, int]]:
    """Yield (Packet, raw frame or None, linktype) from pktcap."""
    binary = binary or ensure_built()
    if binary is None:
        raise CaptureError("the C engine isn't built (run `make -C csrc`); use --engine python")
    cmd = [str(binary)]
    cmd += ["-r", read] if read else ["-i", iface or "any"]
    if all_frames:
        cmd.append("-a")
    if not promisc:
        cmd.append("-P")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    out = proc.stdout
    names = _Names()
    file_iface = os.path.basename(read) if read else None
    pending = None
    try:
        while not stop():
            head = out.read(HDR.size)
            if len(head) < HDR.size:
                break
            rtype, _, length = HDR.unpack(head)
            body = out.read(length) if length else b""
            if len(body) < length:
                break
            if rtype == REC_PKT:
                rec = PKT.unpack(body)
                name = file_iface or names.iface(rec[2])
                if rec[11] & PKT_FRAME:
                    pending = (rec, name)       # the raw bytes arrive in the next record
                    continue
                yield packet_from_record(rec, names, name), None, rec[12]
            elif rtype == REC_FRAME and pending is not None:
                rec, name = pending
                pending = None
                if rec[11] & PKT_DECODE:
                    p = decode(body, rec[0], rec[1], rec[12], name)
                else:                           # bytes only for saving (-a): keep the fast path
                    p = packet_from_record(rec, names, name)
                yield p, body, rec[12]
            elif rtype == REC_SNAP and on_snapshot:
                ts, pk, by, drops, nsrc, k = SNAP.unpack_from(body)
                top = []
                for i in range(k):
                    ip, ver, spk, sby = SRC.unpack_from(body, SNAP.size + i * SRC.size)
                    top.append({"ip": names.ip(ip, ver), "packets": spk, "bytes": sby})
                on_snapshot({"ts": ts, "packets": pk, "bytes": by, "kernel_drops": drops,
                             "sources": nsrc, "top": top})
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        err = ""
        if proc.stderr:
            err = proc.stderr.read().decode(errors="replace").strip()
            proc.stderr.close()
        out.close()
    if proc.returncode == 3:
        raise CaptureError(
            "Live capture needs root or CAP_NET_RAW. Run with sudo, or analyse a file with --read.")
    if proc.returncode not in (0, None, -15) and not stop():
        raise CaptureError(err or f"pktcap exited with code {proc.returncode}")
