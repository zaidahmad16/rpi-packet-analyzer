"""Per-device traffic features in 60-second windows, for the Isolation Forest.

Each device (MAC address) that sends anything in a window becomes one row of
counts: how much it sent and received, how many different hosts and ports it
reached, how many connections it opened and had refused, and so on. The model
learns what normal rows look like on this network and scores new ones.
"""
from __future__ import annotations

import csv
import math
import os
from dataclasses import dataclass, field
from typing import Callable

from .decode import Packet

WINDOW = 60                      # seconds
MAX_DEVICES_PER_WINDOW = 4096
FEATURES = ["pkts_out", "bytes_out", "bytes_in", "mean_size_out", "dst_ips", "dst_ports",
            "syn_out", "rst_in", "dns_queries", "arp_out"]


@dataclass
class _Acc:
    pkts_out: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    dst_ips: set = field(default_factory=set)
    dst_ports: set = field(default_factory=set)
    syn_out: int = 0
    rst_in: int = 0
    dns_queries: int = 0
    arp_out: int = 0
    ip: str | None = None

    def vector(self) -> list[float]:
        mean = self.bytes_out / self.pkts_out if self.pkts_out else 0.0
        raw = [self.pkts_out, self.bytes_out, self.bytes_in, mean, len(self.dst_ips),
               len(self.dst_ports), self.syn_out, self.rst_in, self.dns_queries, self.arp_out]
        return [math.log1p(v) for v in raw]       # counts are heavy-tailed; logs tame them


def _is_device(mac: str | None) -> bool:
    return bool(mac) and not int(mac[:2], 16) & 1 and mac != "00:00:00:00:00:00"


class WindowFeatures:
    """Accumulates packets and calls `on_rows(window_start, rows)` as each window closes.

    rows: list of (mac, ip, vector). Fed from Stats.add (under its lock), so it
    must stay cheap: a few dict and set operations per packet.
    """

    def __init__(self, on_rows: Callable[[int, list], None]):
        self.on_rows = on_rows
        self.window: int | None = None
        self.acc: dict[str, _Acc] = {}

    def _get(self, mac: str) -> _Acc | None:
        a = self.acc.get(mac)
        if a is None:
            if len(self.acc) >= MAX_DEVICES_PER_WINDOW:
                return None
            a = self.acc[mac] = _Acc()
        return a

    def add(self, p: Packet) -> None:
        w = int(p.ts) // WINDOW * WINDOW
        if self.window is None:
            self.window = w
        elif w > self.window:
            self.flush()
            self.window = w
        if _is_device(p.src_mac):
            a = self._get(p.src_mac)
            if a is not None:
                a.pkts_out += 1
                a.bytes_out += p.length
                if p.dst:
                    a.dst_ips.add(p.dst)
                    if a.ip is None and p.src and p.proto != "ARP":
                        a.ip = p.src
                if p.dport is not None and p.proto in ("TCP", "UDP"):
                    a.dst_ports.add(p.dport)
                if p.tcp_flags == "S":
                    a.syn_out += 1
                if p.dns_query and p.info.startswith("query"):
                    a.dns_queries += 1
                if p.proto == "ARP":
                    a.arp_out += 1
        if _is_device(p.dst_mac):
            b = self._get(p.dst_mac)
            if b is not None:
                b.bytes_in += p.length
                if "R" in p.tcp_flags:
                    b.rst_in += 1

    def flush(self) -> None:
        if self.window is None or not self.acc:
            self.acc = {}
            return
        rows = [(mac, a.ip, a.vector()) for mac, a in self.acc.items() if a.pkts_out]
        self.acc = {}
        if rows:
            self.on_rows(self.window, rows)


class FeatureLog:
    """Appends rows to a CSV capped at max_bytes, rotating once to CSV.1."""

    def __init__(self, path: str, max_bytes: int = 20 * 1024 * 1024):
        self.path, self.max_bytes = path, max_bytes

    def write(self, window: int, rows: list) -> None:
        try:
            new = not os.path.exists(self.path)
            if not new and os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".1")
                new = True
            with open(self.path, "a", newline="") as f:
                w = csv.writer(f)
                if new:
                    w.writerow(["window", "mac", "ip", *FEATURES])
                for mac, ip, vec in rows:
                    w.writerow([window, mac, ip or "", *(f"{v:.6g}" for v in vec)])
        except OSError:
            pass                       # features are best-effort; never break capture


def read_rows(paths: list[str]) -> list[tuple[int, str, list[float]]]:
    """Load (window, mac, vector) from feature CSVs, oldest first."""
    out = []
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                try:
                    out.append((int(r["window"]), r["mac"], [float(r[k]) for k in FEATURES]))
                except (KeyError, ValueError):
                    continue
    out.sort(key=lambda t: t[0])
    return out
