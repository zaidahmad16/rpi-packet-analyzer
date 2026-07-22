import math
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from packets import MAC_PHONE, MAC_PI, MAC_ROUTER, eth, ipv4, tcp, udp  # noqa: E402
from pktan.decode import decode  # noqa: E402
from pktan.features import FEATURES, FeatureLog, WindowFeatures, read_rows  # noqa: E402
from pktan.iforest import (Forest, average_path_length, evaluate,  # noqa: E402
                           fixed_threshold_flags)
from pktan.stats import Stats  # noqa: E402

try:
    import numpy  # noqa: F401
    import sklearn  # noqa: F401
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False

PHONE, PI = "3c:22:fb:00:00:01", "2c:cf:67:00:00:99"


def pkt(src_mac, dst_mac, src, dst, l4, ts):
    return decode(eth(dst_mac, src_mac, 0x0800, ipv4(src, dst, 6 if l4[0] == "t" else 17, l4[1])), ts=ts)


class FeatureTests(unittest.TestCase):
    def test_window_counts(self):
        rows = []
        w = WindowFeatures(lambda win, r: rows.append((win, r)))
        for port in range(1, 31):                          # phone SYNs 30 ports on the Pi
            w.add(pkt(MAC_PHONE, MAC_PI, "192.168.1.23", "192.168.1.50", ("t", tcp(40000, port, "S")), 120 + port))
        w.add(pkt(MAC_PI, MAC_PHONE, "192.168.1.50", "192.168.1.23", ("t", tcp(22, 40000, "RA")), 150))
        w.add(pkt(MAC_PHONE, MAC_ROUTER, "192.168.1.23", "1.1.1.1", ("u", udp(5000, 53, b"")), 185))  # next window
        self.assertEqual(len(rows), 1)
        win, r = rows[0]
        self.assertEqual(win, 120)
        by_mac = {mac: dict(zip(FEATURES, (math.expm1(v) for v in vec))) for mac, _, vec in r}
        phone = by_mac[PHONE]
        self.assertAlmostEqual(phone["pkts_out"], 30)
        self.assertAlmostEqual(phone["dst_ports"], 30)
        self.assertAlmostEqual(phone["syn_out"], 30)
        self.assertAlmostEqual(phone["rst_in"], 1)
        self.assertAlmostEqual(phone["dst_ips"], 1)
        self.assertIn(PI, by_mac)                          # the Pi sent the RST, so it's a row too

    def test_feature_log_roundtrip_and_cap(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "f.csv")
            log = FeatureLog(path, max_bytes=2000)
            for i in range(60):
                log.write(i * 60, [("aa:bb:cc:dd:ee:ff", "10.0.0.5", [float(i)] * len(FEATURES))])
            self.assertTrue(os.path.exists(path + ".1"))
            self.assertLessEqual(os.path.getsize(path), 2500)
            rows = read_rows([path + ".1", path])
            self.assertEqual([r[0] for r in rows], sorted(r[0] for r in rows))
            self.assertEqual(rows[-1][2][0], 59.0)


class ForestTests(unittest.TestCase):
    def test_average_path_length(self):
        self.assertEqual(average_path_length(1), 0.0)
        self.assertEqual(average_path_length(2), 1.0)
        self.assertAlmostEqual(average_path_length(256), 10.24477092, places=7)

    def test_fixed_thresholds(self):
        quiet = [math.log1p(v) for v in (10, 5000, 8000, 500, 2, 2, 0, 0, 1, 0)]
        scan = [math.log1p(v) for v in (300, 20000, 15000, 66, 1, 250, 250, 240, 0, 0)]
        self.assertEqual(fixed_threshold_flags(quiet), [])
        self.assertEqual(sorted(fixed_threshold_flags(scan)), ["dst_ports", "rst_in", "syn_out"])

    @unittest.skipUnless(HAVE_SKLEARN, "scikit-learn not installed")
    def test_pure_python_scores_match_sklearn(self):
        import numpy as np
        from pktan.iforest import train
        rng = random.Random(5)
        rows = [(i * 60, "aa", [rng.lognormvariate(0, 1) for _ in FEATURES]) for i in range(1500)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "m.json")
            r = train(rows, path)
            forest = Forest.load(path)
        probe = [v for _, _, v in rows[::7]] + [[rng.uniform(-3, 12) for _ in FEATURES] for _ in range(300)]
        sk = -r["model"].score_samples(np.array(probe))
        for a, b in zip(sk, (forest.score(v) for v in probe)):
            self.assertAlmostEqual(a, b, delta=1e-9)
        self.assertGreaterEqual(forest.threshold, 0.5)
        self.assertEqual(forest.meta["trained_rows"], 1050)          # time-ordered 70%

    def test_anomaly_alert_needs_two_windows(self):
        class Fake:                        # scores whatever the dst_ports feature says
            threshold = 0.6
            def score(self, vec):
                return 0.9 if math.expm1(vec[FEATURES.index("dst_ports")]) > 20 else 0.3
            def explain(self, vec):
                return ["dst_ports high"]
        s = Stats(forest=Fake())
        t = 1000 * 60
        for minute in range(4):
            for port in range(1, 41 if minute in (1, 2) else 3):
                s.add(pkt(MAC_PHONE, MAC_PI, "192.168.1.23", "192.168.1.50",
                          ("t", tcp(40000, port, "S")), t + minute * 60 + port * 0.1))
        alerts = [a for a in s.snapshot()["alerts"] if a["kind"] == "anomaly"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("3c:22:fb:00:00:01 (Apple) at 192.168.1.23", alerts[0]["msg"])
        self.assertIn("dst_ports high", alerts[0]["msg"])
        self.assertAlmostEqual(s.anomaly[PHONE]["score"], 0.9)

    def test_evaluate_counts(self):
        class Fake:
            threshold = 0.5
            def score(self, vec):
                return 0.8 if vec[0] > 5 else 0.4
        quiet = [math.log1p(v) for v in (10, 5000, 8000, 500, 2, 2, 0, 0, 1, 0)]
        loud = [math.log1p(v) for v in (900, 2_000_000, 8000, 2000, 2, 2, 0, 0, 1, 0)]
        res = evaluate(Fake(), [(0, "a", quiet)] * 8 + [(0, "a", loud)] * 2, [("scan", loud)])
        self.assertEqual((res["holdout_rows"], res["fixed_flagged"], res["forest_flagged"]), (10, 2, 2))
        self.assertEqual(res["attacks"][0]["forest"], True)


if __name__ == "__main__":
    unittest.main()
