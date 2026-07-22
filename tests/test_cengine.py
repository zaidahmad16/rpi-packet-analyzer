"""The C engine must agree with the Python decoder field for field, and survive bad input."""
import dataclasses
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from packets import (MAC_PHONE, MAC_PI, MAC_ROUTER, eth, ipv4, ipv6, sample_frames,  # noqa: E402
                     tcp, tls_client_hello, udp)
from pktan import cengine  # noqa: E402
from pktan.decode import LINK_ETHERNET, LINK_RAW, decode  # noqa: E402
from pktan.stats import Stats  # noqa: E402

CSRC = cengine.CSRC
HAVE_CC = bool(shutil.which("make") and shutil.which("cc"))


def write_pcap(path, frames, linktype=LINK_ETHERNET, t0=1000.0):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            ts = t0 + i * 0.25
            f.write(struct.pack("<IIII", int(ts), int(ts % 1 * 1e6), len(fr), len(fr) + (i % 3)))
            f.write(fr)


def tricky_frames():
    """Cases where a careless parser would disagree with pktan.decode."""
    frames = list(sample_frames())
    vlan = MAC_ROUTER + MAC_PI + struct.pack("!HHHHH", 0x88A8, 7, 0x8100, 42, 0x0800)
    frames.append(vlan + ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 22, "PA", b"x")))       # QinQ
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("10.0.0.1", "8.8.8.8", 17,
                                                      udp(51000, 443, b"\xc3quic"))))      # QUIC
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("10.0.0.1", "8.8.8.8", 17,
                                                      udp(51000, 443, b"\x40short"))))     # not QUIC
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("10.0.0.1", "8.8.8.8", 17, udp(5000, 6000, b""))))
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("10.0.0.1", "1.1.1.1", 6,
                                                      tcp(50001, 8443, "PA", tls_client_hello("a.example")))))
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("10.0.0.1", "1.1.1.1", 6,
                                                      tcp(50002, 9999, "SAEC"))))           # odd flags
    frag = bytearray(ipv4("10.0.0.1", "10.0.0.9", 17, udp(1, 2, b"abcdefgh")))
    frag[6:8] = struct.pack("!H", 0x0010)                                                # offset != 0
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x0800, bytes(frag)))
    hop = bytes([6, 0]) + b"\x00" * 6                                                    # hop-by-hop ext hdr
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x86DD, ipv6("2001:db8::1", "2001:db8::2", 0, hop + tcp(1, 80))))
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x86DD, ipv6("2001:db8::1", "2001:db8::2", 17, udp(4000, 4001, b"hi"))))
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x86DD, ipv6("fe80::1", "ff02::1", 6, tcp(5000, 443, "S"))))
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("10.0.0.1", "10.0.0.2", 47, b"gre")))  # GRE
    frames.append(eth(MAC_ROUTER, MAC_PI, 0x88CC, b"lldp"))
    frames.append(eth(MAC_ROUTER, MAC_PHONE, 0x0800, ipv4("10.0.0.1", "1.1.1.1", 6,
                                                         tcp(40000, 80, "PA", b"POST /x HTTP/1.1\r\n\r\n"))))
    frames.append(b"\x01\x02\x03")                                                         # runt
    # every sample cut short at several points
    for fr in list(sample_frames())[:6]:
        for cut in (15, 30, 40, 50, 60):
            if cut < len(fr):
                frames.append(fr[:cut])
    return frames


@unittest.skipUnless(HAVE_CC, "needs make and cc to build csrc/pktcap")
class CEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = cengine.ensure_built()
        assert cls.bin, "pktcap failed to build"
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def pcap(self, name, frames, linktype=LINK_ETHERNET):
        path = os.path.join(self.tmp.name, name)
        write_pcap(path, frames, linktype)
        return path

    def assert_parity(self, frames, linktype=LINK_ETHERNET):
        path = self.pcap(f"p{len(frames)}-{linktype}.pcap", frames, linktype)
        got = [p for p, _, _ in cengine.c_packets(read=path, binary=self.bin)]
        self.assertEqual(len(got), len(frames))
        name = os.path.basename(path)
        for i, (fr, cp) in enumerate(zip(frames, got)):
            ts = 1000.0 + i * 0.25
            ref = decode(fr, ts, len(fr) + (i % 3), linktype, name)
            a, b = dataclasses.asdict(ref), dataclasses.asdict(cp)
            self.assertAlmostEqual(a.pop("ts"), b.pop("ts"), places=5)
            self.assertEqual(a, b, f"frame {i}: {fr[:40].hex()}")
        return got

    def test_parity_ethernet(self):
        self.assert_parity(tricky_frames())

    def test_parity_raw_ip_link(self):
        raw = [ipv4("100.64.0.1", "100.64.0.2", 17, udp(41641, 41641, b"x")),
               ipv4("100.64.0.1", "100.64.0.2", 6, tcp(5555, 22, "A")),
               ipv6("fd7a::1", "fd7a::2", 6, tcp(1, 443, "S")), b"\x00junk"]
        self.assert_parity(raw, LINK_RAW)

    def test_fast_path_skips_python_decode(self):
        frames = [eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("10.0.0.1", "1.1.1.1", 6, tcp(40000 + i, 443, "A")))
                  for i in range(50)]
        path = self.pcap("fast.pcap", frames)
        raw = [data for _, data, _ in cengine.c_packets(read=path, binary=self.bin)]
        self.assertEqual(raw.count(None), 50)            # no frame bytes crossed the pipe

    def test_all_frames_keeps_fast_path(self):
        frames = tricky_frames()
        path = self.pcap("allframes.pcap", frames)
        normal = [p for p, _, _ in cengine.c_packets(read=path, binary=self.bin)]
        got = list(cengine.c_packets(read=path, all_frames=True, binary=self.bin))
        self.assertEqual([dataclasses.asdict(p) for p in normal], [dataclasses.asdict(p) for p, _, _ in got])
        self.assertEqual([d for _, d, _ in got], frames)      # every raw frame, for --write

    def test_stats_identical(self):
        frames = tricky_frames()
        path = self.pcap("stats.pcap", frames)
        py, c = Stats(), Stats()
        for i, fr in enumerate(frames):
            py.add(decode(fr, 1000.0 + i * 0.25, len(fr) + (i % 3), LINK_ETHERNET, "stats.pcap"))
        for p, _, _ in cengine.c_packets(read=path, binary=self.bin):
            c.add(p)
        a, b = py.snapshot(), c.snapshot()
        for k in ("packets", "bytes", "protocols", "ports", "hosts", "flows", "dns", "alerts"):
            self.assertEqual(a[k], b[k], k)

    def test_top_k_heap(self):
        rng = random.Random(7)
        sizes = {f"10.1.{i // 250}.{i % 250 + 1}": rng.randint(1, 40) for i in range(300)}
        frames = []
        for ip, n in sizes.items():
            frames += [eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4(ip, "10.0.0.1", 17, udp(1, 2, b"z" * 10)))] * n
        rng.shuffle(frames)
        snaps = []
        list(cengine.c_packets(read=self.pcap("topk.pcap", frames), binary=self.bin,
                               on_snapshot=snaps.append))
        top = snaps[-1]["top"]
        want = sorted(sizes.items(), key=lambda kv: -kv[1])[:10]
        self.assertEqual([t["packets"] for t in top], [n for _, n in want])
        self.assertEqual(snaps[-1]["sources"], 300)
        self.assertEqual(snaps[-1]["packets"], len(frames))

    def test_table_stays_bounded(self):
        frames = [eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}",
                                                     "10.255.255.254", 17, udp(1, 2, b"")))
                  for i in range(20000)]
        snaps = []
        list(cengine.c_packets(read=self.pcap("flood.pcap", frames), binary=self.bin,
                               on_snapshot=snaps.append))
        self.assertLessEqual(snaps[-1]["sources"], 6144)    # 3/4 of 8192
        self.assertGreater(snaps[-1]["sources"], 0)

    def test_asan_fuzz(self):
        r = subprocess.run(["make", "-s", "-C", str(CSRC), "pktcap-asan"], capture_output=True)
        if r.returncode != 0:
            self.skipTest("no AddressSanitizer toolchain")
        rng = random.Random(1)
        base = tricky_frames()
        fuzzed = []
        for _ in range(3000):
            fr = bytearray(rng.choice(base))
            for _ in range(rng.randint(1, 6)):
                if fr:
                    fr[rng.randrange(len(fr))] = rng.randrange(256)
            fuzzed.append(bytes(fr[: rng.randint(0, len(fr))]))
        for lt in (LINK_ETHERNET, LINK_RAW, 113):
            path = self.pcap(f"fuzz{lt}.pcap", fuzzed, lt)
            for extra in ([], ["-n"], ["-a"]):
                r = subprocess.run([str(CSRC / "pktcap-asan"), "-r", path, *extra],
                                   capture_output=True, timeout=120)
                self.assertEqual(r.returncode, 0, r.stderr.decode()[-2000:])
                self.assertNotIn(b"AddressSanitizer", r.stderr)
                self.assertNotIn(b"runtime error", r.stderr)


if __name__ == "__main__":
    unittest.main()
