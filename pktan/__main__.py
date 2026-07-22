"""pktan command line: list | sniff | top | web | aws-check."""
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
        p.add_argument("--engine", choices=("auto", "c", "python"), default="auto",
                       help="capture engine: c (csrc/pktcap), python (stdlib only), "
                            "or auto: c when it's built (default)")
        p.add_argument("--state-dir", metavar="DIR",
                       help="remember known devices here across restarts "
                            "(default: $STATE_DIRECTORY, which systemd sets)")
        aws = p.add_argument_group("AWS (credentials from env vars or ~/.aws/credentials)")
        aws.add_argument("--sns-topic", metavar="ARN", help="send alerts to this SNS topic")
        aws.add_argument("--alerts-per-hour", type=int, default=20,
                         help="cap on SNS messages per hour (default 20)")
        aws.add_argument("--s3-bucket", metavar="NAME",
                         help="with --write: upload each full pcap to this bucket, then delete it locally")
        aws.add_argument("--s3-prefix", default="pktan/", help="key prefix in the bucket (default pktan/)")
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

    bn = sub.add_parser("bench", help="time the Python and C engines on the same capture")
    bn.add_argument("file", help="a .pcap to replay")
    bn.add_argument("--repeat", type=int, default=1, help="replay the capture N times (default 1)")

    ft = sub.add_parser("features", help="turn saved captures into anomaly-model feature rows")
    ft.add_argument("pcaps", nargs="+")
    ft.add_argument("--out", required=True, help="CSV to append rows to")

    tr = sub.add_parser("train", help="fit the Isolation Forest on logged features (needs scikit-learn)")
    tr.add_argument("--state-dir", help="where features.csv lives and iforest.json goes "
                                        "(default: $STATE_DIRECTORY)")
    tr.add_argument("--features", nargs="*", default=[], help="extra feature CSVs to include")

    ev = sub.add_parser("evaluate", help="fixed thresholds vs the Isolation Forest on held-out data")
    ev.add_argument("--state-dir")
    ev.add_argument("--features", nargs="*", default=[])
    ev.add_argument("--attack", nargs=3, action="append", default=[], metavar=("NAME", "CSV", "MAC"),
                    help="feature rows from an attack capture, for the device doing the attack")

    ck = sub.add_parser("aws-check", help="send a test alert and upload a test file to check AWS setup")
    ck.add_argument("--sns-topic", metavar="ARN")
    ck.add_argument("--s3-bucket", metavar="NAME")
    ck.add_argument("--s3-prefix", default="pktan/")

    args = ap.parse_args(argv)

    if args.cmd == "aws-check":
        return _aws_check(args)
    if args.cmd == "bench":
        return _bench(args.file, args.repeat)
    if args.cmd == "features":
        return _features(args.pcaps, args.out)
    if args.cmd in ("train", "evaluate"):
        return _train_or_evaluate(args)

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

    if args.s3_bucket and not args.write:
        print("pktan: --s3-bucket needs --write FILE (the capture that gets uploaded)", file=sys.stderr)
        return 2
    notifier = archiver = None
    if args.sns_topic or args.s3_bucket:
        from .aws import AlertNotifier, AwsError, S3Archiver, load_credentials
        try:
            load_credentials()          # fail now, not on the first alert
        except AwsError as e:
            print(f"pktan: {e}", file=sys.stderr)
            return 2
        if args.sns_topic:
            notifier = AlertNotifier(args.sns_topic, args.alerts_per_hour, source)
        if args.s3_bucket:
            archiver = S3Archiver(args.s3_bucket, args.s3_prefix, source)

    known = feature_log = forest = None
    state_dir = _state_dir(args.state_dir)
    if state_dir and not args.read:
        from .features import FeatureLog
        from .stats import KnownDevices
        own = [i["mac"] for i in list_interfaces() if i["mac"] and i["mac"] != "00:00:00:00:00:00"]
        known = KnownDevices(os.path.join(state_dir, "known-devices.json"), own)
        feature_log = FeatureLog(os.path.join(state_dir, "features.csv"))
        model = os.path.join(state_dir, "iforest.json")
        if os.path.exists(model):
            from .iforest import Forest
            try:
                forest = Forest.load(model)
            except (OSError, ValueError, KeyError) as e:
                print(f"pktan: ignoring unreadable model {model}: {e}", file=sys.stderr)

    printer = None
    if args.cmd == "sniff":
        from .tui import LinePrinter
        printer = LinePrinter(color=False if args.no_color else None,
                              show_iface=args.iface == "any")

    engine_name = _pick_engine(args.engine, getattr(args, "realtime", False))
    if engine_name is None:
        return 2

    engine = Engine(iface=args.iface, read=args.read, flt=flt, write=args.write,
                    max_mb=args.max_mb, count=getattr(args, "count", 0),
                    realtime=getattr(args, "realtime", False),
                    promisc=not args.no_promisc, on_packet=printer,
                    notifier=notifier, archiver=archiver, known=known,
                    engine=engine_name, feature_log=feature_log, forest=forest).start()
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
        engine.join(120 if archiver else 2)   # let the last upload finish

    if engine.error:
        if isinstance(engine.error, (CaptureError, ValueError)):
            print(f"pktan: {engine.error}", file=sys.stderr)
            return 1
        raise engine.error

    if args.cmd == "sniff" and args.stats:
        _print_summary(engine.stats.snapshot())
    return 0


def _aws_check(args) -> int:
    """Prove the AWS setup works end to end, one step at a time."""
    import tempfile

    from .aws import AwsError, default_region, load_credentials, s3_key, s3_put_file, sns_publish
    if not (args.sns_topic or args.s3_bucket):
        print("pktan: give --sns-topic ARN and/or --s3-bucket NAME to check", file=sys.stderr)
        return 2
    ok = True
    try:
        creds = load_credentials()
        print(f"credentials   ok   (access key {creds.access_key[:4]}…{creds.access_key[-4:]})")
    except AwsError as e:
        print(f"credentials   FAIL {e}")
        return 1
    if args.sns_topic:
        try:
            mid = sns_publish(args.sns_topic, "pktan: test alert",
                              "This is a test from `pktan aws-check`. "
                              "If you got it, alerts are set up.", creds)
            print(f"sns publish   ok   (message {mid})")
        except AwsError as e:
            ok = False
            print(f"sns publish   FAIL {e}")
    if args.s3_bucket:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            from .pcap import PcapWriter
            path = f.name
        PcapWriter(path).close()                      # a valid, empty capture
        key = s3_key(args.s3_prefix, "aws-check")
        try:
            region = default_region()
            s3_put_file(args.s3_bucket, key, path, region, creds)
            print(f"s3 upload     ok   (s3://{args.s3_bucket}/{key}, region {region})")
        except AwsError as e:
            ok = False
            print(f"s3 upload     FAIL {e}")
        finally:
            os.remove(path)
    return 0 if ok else 1


def _state_dir(given: str | None) -> str:
    return given or os.environ.get("STATE_DIRECTORY", "").split(":")[0]


def _features(pcaps: list[str], out: str) -> int:
    from .features import FeatureLog
    log = FeatureLog(out, max_bytes=1 << 40)
    for path in pcaps:
        e = Engine(read=path, engine=_pick_engine("auto", False) or "python",
                   feature_log=log, flush_windows=True).start()
        e.join()
        if e.error:
            print(f"pktan: {path}: {e.error}", file=sys.stderr)
            return 1
        print(f"{path}: {e.stats.packets:,} packets")
    return 0


def _train_or_evaluate(args) -> int:
    from .features import read_rows
    from .iforest import Forest, evaluate, train
    state = _state_dir(args.state_dir)
    if not state:
        print("pktan: say where the features live with --state-dir", file=sys.stderr)
        return 2
    csvs = [os.path.join(state, "features.csv.1"), os.path.join(state, "features.csv"), *args.features]
    rows = read_rows(csvs)
    model_path = os.path.join(state, "iforest.json")
    hours = (rows[-1][0] - rows[0][0]) / 3600 + 1 / 60 if rows else 0
    if args.cmd == "train":
        r = train(rows, model_path)
        print(f"trained on {len(r['train']):,} device-minutes ({hours:.1f} h of data, "
              f"{len({m for _, m, _ in r['train']})} devices); {len(r['holdout']):,} held out")
        print(f"alert threshold {r['threshold']:.3f}; model saved to {model_path}")
        if hours < 72:
            print(f"note: {hours:.1f} h is too little to know what normal looks like across nights "
                  "and weekends; retrain after a few days of logging")
        return 0
    forest = Forest.load(model_path)
    cut = forest.meta["trained_rows"]
    holdout = rows[cut:]
    attacks = []
    for name, csv_path, mac in args.attack:
        attacks += [(name, v) for _, m, v in read_rows([csv_path]) if m.lower() == mac.lower()]
    res = evaluate(forest, holdout, attacks)
    n = res["holdout_rows"]
    pct = lambda k: f"{res[k]:,} ({100 * res[k] / n:.1f}%)" if n else "n/a"
    print(f"held-out normal device-minutes: {n:,}")
    print(f"  flagged by fixed thresholds:  {pct('fixed_flagged')}")
    print(f"  flagged by Isolation Forest:  {pct('forest_flagged')}")
    for a in res.get("attacks", []):
        print(f"  attack {a['name']:<16} fixed={'caught' if a['fixed'] else 'missed':<7} "
              f"forest={'caught' if a['forest'] else 'missed':<7} score={a['score']}")
    print(f"model trained on {forest.meta['trained_rows']:,} device-minutes "
          f"(threshold {forest.threshold:.3f})")
    return 0


def _bench(path: str, repeat: int) -> int:
    """Packets/second for each engine on one capture, plus peak memory."""
    import resource
    import subprocess
    import tempfile
    import time

    from .cengine import c_packets, ensure_built
    from .decode import decode
    from .pcap import read_pcap
    from .stats import Stats

    records = list(read_pcap(path))
    if not records:
        print(f"pktan: {path} has no packets", file=sys.stderr)
        return 2
    span = records[-1][0] - records[0][0] + 1
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        work = tmp.name
    from .pcap import PcapWriter
    w = PcapWriter(work, max_bytes=1 << 40)
    for r in range(repeat):
        for ts, data, orig, lt in records:
            w.write(ts + r * span, data, orig, lt)
    w.close()
    n = len(records) * repeat
    results = []
    from .stats import vendor_of
    vendor_of("00:00:00:00:00:01")       # load the vendor database before timing anything
    try:
        t = time.perf_counter()
        st = Stats()
        for ts, data, orig, lt in read_pcap(work):
            st.add(decode(data, ts, orig, lt, "bench"))
        results.append(("python engine (decode + stats)", time.perf_counter() - t))

        binary = ensure_built()
        if binary:
            t = time.perf_counter()
            st = Stats()
            for p, _, _ in c_packets(read=work, binary=binary):
                st.add(p)
            results.append(("c engine (pktcap + stats)", time.perf_counter() - t))
            t = time.perf_counter()
            subprocess.run([str(binary), "-r", work, "-n"], check=True, capture_output=True)
            results.append(("c parsing only (pktcap -n)", time.perf_counter() - t))
    finally:
        os.remove(work)
    print(f"{n:,} packets ({len(records):,} x {repeat}) from {os.path.basename(path)}")
    base = results[0][1]
    for name, secs in results:
        print(f"  {name:<32} {n / secs:>12,.0f} packets/s   {base / secs:>5.1f}x")
    me = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    kids = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024
    print(f"  peak memory: pktan {me:.0f} MB, pktcap {kids:.1f} MB")
    return 0


def _pick_engine(choice: str, realtime: bool) -> str | None:
    if choice == "python" or (choice == "auto" and realtime):
        return "python"                     # --realtime pacing lives in the Python reader
    from .cengine import ensure_built
    if ensure_built():
        return "c"
    if choice == "c":
        print("pktan: the C engine isn't built and couldn't be built (needs make and cc); "
              "try `make -C csrc` or --engine python", file=sys.stderr)
        return None
    return "python"


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
