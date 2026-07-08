"""Classic libpcap file reader/writer (no pcapng).

The writer has a hard size cap: once the file would exceed `max_bytes` it
rotates to a single `.1` backup, so disk use never exceeds ~2x the cap (or,
with on_rotate, hands the full file off, e.g. to the S3 archiver).
"""
from __future__ import annotations

import os
import struct
import time
from typing import BinaryIO, Callable, Iterator

from .decode import LINK_ETHERNET, LINK_RAW

MAGIC_US = 0xA1B2C3D4
MAGIC_NS = 0xA1B23C4D
LINKTYPE_LINUX_SLL = 113


def read_pcap(path: str) -> Iterator[tuple[float, bytes, int, int]]:
    """Yield (timestamp, data, original_length, linktype)."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise ValueError(f"{path}: not a pcap file (too short)")
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (MAGIC_US, MAGIC_NS):
            endian = "<"
        else:
            magic = struct.unpack(">I", hdr[:4])[0]
            if magic not in (MAGIC_US, MAGIC_NS):
                if hdr[:4] == b"\x0a\x0d\x0d\x0a":
                    raise ValueError(f"{path}: pcapng is not supported; "
                                     "convert with `editcap -F pcap in.pcapng out.pcap`")
                raise ValueError(f"{path}: not a pcap file")
            endian = ">"
        div = 1e9 if magic == MAGIC_NS else 1e6
        linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
        rec = struct.Struct(endian + "IIII")
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            sec, frac, incl, orig = rec.unpack(rh)
            data = f.read(incl)
            if len(data) < incl:
                return
            lt = linktype
            if lt == LINKTYPE_LINUX_SLL and len(data) >= 16:
                # cooked capture: 16-byte header, protocol at bytes 14..16
                proto = struct.unpack_from("!H", data, 14)[0]
                data = b"\x00" * 12 + struct.pack("!H", proto) + data[16:]
                lt = LINK_ETHERNET
            elif lt in (12, 14, 228, 229):   # other raw-IP linktypes
                lt = LINK_RAW
            yield sec + frac / div, data, orig, lt


class PcapWriter:
    """Writes Ethernet-linktype pcap; raw-IP frames get a synthetic Ethernet header."""

    def __init__(self, path: str, max_bytes: int = 50 * 1024 * 1024, snaplen: int = 65535,
                 on_rotate: Callable[[str], None] | None = None):
        """on_rotate: if set, each full file is renamed to a unique timestamped
        name and handed to this callback (e.g. to upload it) instead of
        becoming PATH.1."""
        self.path = path
        self.max_bytes = max_bytes
        self.snaplen = snaplen
        self.on_rotate = on_rotate
        self._f: BinaryIO | None = None
        self._size = 0
        self._open()

    def _open(self) -> None:
        self._f = open(self.path, "wb")
        self._f.write(struct.pack("<IHHiIII", MAGIC_US, 2, 4, 0, 0, self.snaplen, LINK_ETHERNET))
        self._size = 24

    def write(self, ts: float, data: bytes, orig_len: int, linktype: int = LINK_ETHERNET) -> None:
        if linktype == LINK_RAW and data:
            etype = 0x86DD if data[0] >> 4 == 6 else 0x0800
            data = b"\x00" * 12 + struct.pack("!H", etype) + data
            orig_len += 14
        data = data[: self.snaplen]
        if self._size + 16 + len(data) > self.max_bytes:
            self._rotate()
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        assert self._f is not None
        self._f.write(struct.pack("<IIII", sec, usec, len(data), orig_len))
        self._f.write(data)
        self._size += 16 + len(data)

    def _rotate(self) -> None:
        self.close()
        if self.on_rotate:
            self._hand_off()
        else:
            os.replace(self.path, self.path + ".1")
        self._open()

    def _hand_off(self) -> None:
        done = f"{self.path}.{time.strftime('%Y%m%dT%H%M%S')}"
        n = 1
        while os.path.exists(done):
            done = f"{self.path}.{time.strftime('%Y%m%dT%H%M%S')}-{n}"
            n += 1
        os.replace(self.path, done)
        assert self.on_rotate is not None
        self.on_rotate(done)

    def finish(self) -> None:
        """Close for good; with on_rotate, hand off the last file if it has packets."""
        had_packets = self._size > 24
        self.close()
        if self.on_rotate and had_packets and os.path.exists(self.path):
            self._hand_off()

    def flush(self) -> None:
        if self._f:
            self._f.flush()

    def close(self) -> None:
        if self._f:
            self._f.close()
            self._f = None
