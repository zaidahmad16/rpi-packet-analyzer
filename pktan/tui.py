"""Terminal front ends: one-line-per-packet output and a live `top` dashboard."""
from __future__ import annotations

import re
import shutil
import sys
import time

from .decode import Packet

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
COLORS = {"TCP": "\033[36m", "UDP": "\033[34m", "DNS": "\033[35m", "mDNS": "\033[35m",
          "HTTPS": "\033[32m", "TLS": "\033[32m", "QUIC": "\033[32m", "HTTP": "\033[33m",
          "ARP": "\033[33m", "ICMP": "\033[31m", "ICMPv6": "\033[31m", "DHCP": "\033[95m",
          "SSH": "\033[96m"}


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_bits(bps: float) -> str:
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if bps < 1000 or unit == "Gbit/s":
            return f"{bps:.0f} {unit}" if unit == "bit/s" else f"{bps:.1f} {unit}"
        bps /= 1000
    return f"{bps:.1f} Gbit/s"


class LinePrinter:
    """`sniff` mode: print each packet as it arrives."""

    def __init__(self, color: bool | None = None, show_iface: bool = False):
        self.color = sys.stdout.isatty() if color is None else color
        self.show_iface = show_iface
        self.n = 0

    def __call__(self, p: Packet) -> None:
        self.n += 1
        t = time.strftime("%H:%M:%S", time.localtime(p.ts)) + f".{int(p.ts % 1 * 1e3):03d}"
        label = p.app or p.proto
        line = p.summary()
        iface = f"{p.iface:<8} " if self.show_iface else ""
        if self.color:
            c = COLORS.get(label, COLORS.get(p.proto, ""))
            print(f"{DIM}{t}{RESET} {iface}{c}{line}{RESET}", flush=True)
        else:
            print(f"{t} {iface}{line}", flush=True)


def _bar(frac: float, width: int) -> str:
    full = int(frac * width)
    return "█" * full + "·" * (width - full)


def _spark(values: list[float], width: int) -> str:
    blocks = " ▁▂▃▄▅▆▇█"
    values = values[-width:]
    hi = max(values) if values and max(values) > 0 else 1
    return "".join(blocks[min(8, int(v / hi * 8 + (0.5 if v else 0)))] for v in values)


def render_top(snap: dict, source: str) -> str:
    cols, rows = shutil.get_terminal_size((100, 30))
    cols = max(cols, 60)
    out = []
    up = time.time() - snap["started"]
    out.append(f"{BOLD}pktan{RESET} · {source} · up {int(up // 60)}m{int(up % 60):02d}s · "
               f"{snap['packets']:,} pkts · {human_bytes(snap['bytes'])} · "
               f"{BOLD}{human_bits(snap['bps'])}{RESET} {snap['pps']:.0f} pkt/s")
    out.append(f"{DIM}bandwidth (last {min(len(snap['history']), cols - 2)}s){RESET}")
    out.append("\033[32m" + _spark([h["b"] for h in snap["history"]], cols - 2) + RESET)
    out.append("")

    half = (cols - 3) // 2
    left = [f"{BOLD}{'PROTOCOL':<12}{'PKTS':>8} {'BYTES':>9}{RESET}"]
    total = max(1, snap["packets"])
    for r in snap["protocols"][:10]:
        frac = r["packets"] / total
        c = COLORS.get(r["name"], "")
        bar = _bar(frac, max(4, half - 32))
        left.append(f"{c}{r['name'][:11]:<12}{RESET}{r['packets']:>8} {human_bytes(r['bytes']):>9} "
                    f"{DIM}{bar}{RESET}")
    right = [f"{BOLD}{'TOP HOST':<{half - 20}}{'TX':>9} {'RX':>9}{RESET}"]
    for h in snap["hosts"][:10]:
        name = h["name"] or h["vendor"] or ""
        label = h["ip"] + (f" ({name})" if name else "")
        right.append(f"{label[:half - 21]:<{half - 20}}{human_bytes(h['tx']):>9} "
                     f"{human_bytes(h['rx']):>9}")
    for i in range(max(len(left), len(right))):
        lt = left[i] if i < len(left) else ""
        rt = right[i] if i < len(right) else ""
        out.append(_pad(lt, half) + " │ " + rt)
    out.append("")

    out.append(f"{BOLD}RECENT DNS{RESET}")
    for d in snap["dns"][:5]:
        t = time.strftime("%H:%M:%S", time.localtime(d["ts"]))
        out.append(f"  {DIM}{t}{RESET} {d['client'] or '?':<16} {d['type']:<5} {d['query']}"[:cols + 10])
    if snap["alerts"]:
        out.append(f"{BOLD}ALERTS{RESET}")
        for a in snap["alerts"][:4]:
            c = "\033[33m" if a["level"] == "warn" else "\033[36m"
            t = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
            out.append(f"  {DIM}{t}{RESET} {c}{a['msg']}{RESET}"[:cols + 20])

    remaining = rows - len(out) - 2
    if remaining > 2:
        out.append(f"{BOLD}LIVE{RESET}")
        for r in snap["recent"][-(remaining - 1):]:
            c = COLORS.get(r["label"], "")
            out.append(f"  {c}{r['text'][:cols - 3]}{RESET}")
    out = out[: rows - 1]
    out.append(f"{DIM}Ctrl+C to quit{RESET}")
    return "\n".join(out)


def _pad(s: str, width: int) -> str:
    visible = len(re.sub(r"\033\[[0-9;]*m", "", s))
    return s + " " * max(0, width - visible)


def run_top(engine, source: str, interval: float = 1.0) -> None:
    tty = sys.stdout.isatty()
    if tty:
        sys.stdout.write("\033[?1049h\033[?25l")
    try:
        while True:
            frame = render_top(engine.stats.snapshot(), source)
            sys.stdout.write(("\033[H\033[2J" if tty else "\n") + frame)
            sys.stdout.flush()
            if engine.done.wait(interval):
                if engine.error:
                    break
                if not tty:
                    break
                # pcap finished: keep showing final numbers until Ctrl+C
                while True:
                    time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        if tty:
            sys.stdout.write("\033[?25h\033[?1049l")
            sys.stdout.flush()
