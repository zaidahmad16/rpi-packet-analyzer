"""pktan command line: list | sniff | top | web."""
from __future__ import annotations

import argparse
import os
import signal
import sys

from . import __version__
from .capture import CaptureError, FilterError, compile_filter, default_interface, list_interfaces
from .engine import Engine


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pktan", description="Lightweight network packet analyzer (stdlib only).")
    ap.add_argument("--version", action="version", version=f"pktan {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list network interfaces")

    def common(p):
        p.add_argument("-i", "--iface", help="interface to capture on ('any' = all; "
                                             "default: the one with the default route)")
        p.add_argument("-r", "--read", metavar="FILE", help="analyse a .pcap file instead of live capture")
        p.add_argument("-f", "--filter", default="", help='filter, e.g. "tcp port 443", '
                       '"dns or arp", "host 192.168.1.5 and not port 22"')
        p.add_argument("-w", "--write", metavar="FILE", help="also save matching packets to a .pcap")
        p.add_argument("--max-mb", type=float, default=50,
                       help="cap for --write; rotates to FILE.1 when full (default 50)")
        p.add_argument("--no-promisc", action="store_true", help="don't enable promiscuous mode")
        return p

    sn = common(sub.add_parser("sniff", help="print packets one per line"))
    sn.add_argument("-c", "--count", type=int, default=0, help="stop after N packets")
    sn.add_argument("--no-color", action="store_true")
    sn.add_argument("--stats", action="store_true", help="print a summary when finished")

    tp = common(sub.add_parser("top", help="live dashboard in the terminal"))
    tp.add_argument("--realtime", action="store_true", help="with --read: replay at original speed")

    wb = common(sub.add_parser("web", help="live dashboard in the browser"))
    wb.add_argument("--port", type=int, default=8080)
    wb.add_argument("--bind", default="0.0.0.0", help="address to listen on (default all)")
    wb.add_argument("--realtime", action="store_true", help="with --read: replay at original speed")
    wb.add_argument("--include-self", action="store_true",
                    help="don't hide the dashboard's own HTTP traffic")

    args = ap.parse_args(argv)

    if args.cmd == "list":
        default = default_interface()
        for i in list_interfaces():
            mark = "*" if i["name"] == default else " "
            print(f"{mark} {i['name']:<18} {i['state']:<8} {i['type']:<9} {i['mac']}")
        print("\n* = default capture interface")
        return 0

    flt_expr = args.filter
    if args.cmd == "web" and not args.include_self and not args.read:
        own = f"not port {args.port}"
        flt_expr = f"({flt_expr}) and {own}" if flt_expr else own
    try:
        flt = compile_filter(flt_expr)
    except FilterError as e:
        print(f"pktan: bad filter: {e}", file=sys.stderr)
        return 2

    if args.read:
        if not os.path.exists(args.read):
            print(f"pktan: {args.read}: no such file", file=sys.stderr)
            return 2
        source = os.path.basename(args.read)
    else:
        args.iface = args.iface or default_interface() or "any"
        source = args.iface

    printer = None
    if args.cmd == "sniff":
        from .tui import LinePrinter
        printer = LinePrinter(color=False if args.no_color else None,
                              show_iface=args.iface == "any")

    engine = Engine(iface=args.iface, read=args.read, flt=flt, write=args.write,
                    max_mb=args.max_mb, count=getattr(args, "count", 0),
                    realtime=getattr(args, "realtime", False),
                    promisc=not args.no_promisc, on_packet=printer).start()
    signal.signal(signal.SIGTERM, _raise_interrupt)   # systemd stop -> clean shutdown

    try:
        if args.cmd == "sniff":
            if not args.read and sys.stderr.isatty():
                print(f"capturing on {source} (Ctrl+C to stop)", file=sys.stderr)
            while not engine.done.wait(0.2):
                pass
        elif args.cmd == "top":
            from .tui import run_top
            engine.done.wait(0.3)   # surface permission errors before taking the screen
            if not engine.error:
                run_top(engine, source)
        elif args.cmd == "web":
            from .web import serve
            engine.done.wait(0.3)
            if not engine.error:
                serve(engine, source, args.bind, args.port)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        engine.join(2)

    if engine.error:
        if isinstance(engine.error, (CaptureError, ValueError)):
            print(f"pktan: {engine.error}", file=sys.stderr)
            return 1
        raise engine.error

    if args.cmd == "sniff" and args.stats:
        _print_summary(engine.stats.snapshot())
    return 0


def _raise_interrupt(*_):
    raise KeyboardInterrupt


def _print_summary(s: dict) -> None:
    from .tui import human_bytes
    print(f"\n{s['packets']:,} packets, {human_bytes(s['bytes'])}", file=sys.stderr)
    for r in s["protocols"][:8]:
        print(f"  {r['name']:<10} {r['packets']:>7}  {human_bytes(r['bytes']):>9}", file=sys.stderr)
    for a in s["alerts"][:5]:
        print(f"  ! {a['msg']}", file=sys.stderr)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:      # e.g. `pktan sniff | head`
        sys.exit(0)
