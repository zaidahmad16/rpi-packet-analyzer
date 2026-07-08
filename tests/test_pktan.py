import io
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from packets import (MAC_PHONE, MAC_PI, MAC_ROUTER, arp, eth, ipv4, sample_frames,  # noqa: E402
                     tcp, udp)
from pktan.__main__ import main  # noqa: E402
from pktan.capture import FilterError, compile_filter  # noqa: E402
from pktan.decode import LINK_RAW, decode, parse_tls_sni  # noqa: E402
from pktan.pcap import PcapWriter, read_pcap  # noqa: E402
from pktan.stats import Stats, vendor_of  # noqa: E402


def decoded():
    return [decode(f, ts=1000.0 + i) for i, f in enumerate(sample_frames())]


class DecodeTests(unittest.TestCase):
    def test_arp(self):
        req, rep = decoded()[:2]
        self.assertEqual(req.proto, "ARP")
        self.assertEqual(req.info, "who-has 192.168.1.1 tell 192.168.1.23")
        self.assertEqual(rep.info, "192.168.1.1 is-at 50:c7:bf:00:00:02")

    def test_dhcp_hostname(self):
        p = decoded()[2]
        self.assertEqual(p.app, "DHCP")
        self.assertEqual(p.hostname, "my-iphone")
        self.assertIn("REQUEST", p.info)

    def test_dns_query_and_answer(self):
        q, r = decoded()[3:5]
        self.assertEqual((q.app, q.dns_query), ("DNS", "example.com"))
        self.assertEqual(q.info, "query A example.com")
        self.assertEqual(r.dns_answers, [("example.com", "93.184.215.14")])

    def test_tcp_flags_and_tls_sni(self):
        syn, hello = decoded()[5:7]
        self.assertEqual((syn.proto, syn.app, syn.tcp_flags), ("TCP", "HTTPS", "S"))
        self.assertEqual(hello.sni, "example.com")

    def test_http_host(self):
        p = decoded()[7]
        self.assertEqual((p.app, p.http_host), ("HTTP", "example.com"))
        self.assertIn("GET / HTTP/1.1", p.info)

    def test_icmp_and_ipv6(self):
        icmp, v6 = decoded()[8:10]
        self.assertEqual((icmp.proto, icmp.info), ("ICMP", "echo request"))
        self.assertEqual((v6.ip_version, v6.proto, v6.info), (6, "ICMPv6", "neighbor solicit"))

    def test_raw_ip_linktype(self):
        p = decode(ipv4("100.64.0.1", "100.64.0.2", 17, udp(41641, 41641, b"x")), linktype=LINK_RAW)
        self.assertEqual((p.src, p.app, p.src_mac), ("100.64.0.1", "TAILSCALE", None))

    def test_vlan(self):
        frame = MAC_ROUTER + MAC_PI + struct.pack("!HHH", 0x8100, 42, 0x0800) + \
            ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 22))
        p = decode(frame)
        self.assertEqual((p.vlan, p.app), (42, "SSH"))

    def test_truncated_never_raises(self):
        for f in sample_frames():
            for cut in range(0, len(f), 7):
                decode(f[:cut])   # must not raise

    def test_dns_pointer_loop_is_safe(self):
        bad = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c"
        p = decode(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("1.1.1.1", "2.2.2.2", 17, udp(5000, 53, bad))))
        self.assertIn("malformed", p.info)

    def test_mdns_additional_records(self):
        # mDNS announcement: PTR answer, A record in the additional section
        name = b"\x0bZaids-Phone\x05local\x00"
        body = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 1)
        body += b"\x05_http\x04_tcp\x05local\x00" + struct.pack("!HHIH", 12, 1, 120, len(name)) + name
        body += name + struct.pack("!HHIH", 1, 0x8001, 120, 4) + bytes([192, 168, 1, 23])
        p = decode(eth(MAC_ROUTER, MAC_PHONE, 0x0800, ipv4("192.168.1.23", "224.0.0.251", 17,
                                                          udp(5353, 5353, body))))
        self.assertEqual(p.app, "mDNS")
        self.assertEqual(p.dns_answers, [("Zaids-Phone.local", "192.168.1.23")])

    def test_sni_rejects_garbage(self):
        self.assertIsNone(parse_tls_sni(b"\x16\x03\x01\x00\x05garbage" * 4))


class FilterTests(unittest.TestCase):
    def match(self, expr):
        f = compile_filter(expr)
        return [i for i, p in enumerate(decoded()) if f(p)]

    def test_basic(self):
        self.assertEqual(self.match("arp"), [0, 1])
        self.assertEqual(self.match("dns"), [3, 4])
        self.assertEqual(self.match("tcp port 443"), [5, 6])
        self.assertEqual(self.match("icmp or icmpv6"), [8, 9])

    def test_host_net_not(self):
        self.assertEqual(self.match("src host 192.168.1.50"), [7, 8])
        self.assertEqual(self.match("net 93.184.0.0/16 and not port 80"), [5, 6])
        self.assertEqual(self.match("ip6"), [9])
        self.assertEqual(self.match("!(tcp or udp or arp)"), [8, 9])

    def test_errors(self):
        for bad in ("port", "src tcp", "port abc", "(tcp", "net nope"):
            with self.assertRaises(FilterError, msg=bad):
                compile_filter(bad)


class StatsTests(unittest.TestCase):
    def test_counts_names_devices(self):
        s = Stats()
        for p in decoded():
            s.add(p)
        snap = s.snapshot()
        self.assertEqual(snap["packets"], 10)
        protos = {r["name"]: r["packets"] for r in snap["protocols"]}
        self.assertEqual(protos["ARP"], 2)
        self.assertEqual(protos["DNS"], 2)
        names = {h["ip"]: h["name"] for h in snap["hosts"]}
        self.assertEqual(names["93.184.215.14"], "example.com")
        devs = {d["mac"]: d for d in snap["devices"]}
        self.assertEqual(devs["3c:22:fb:00:00:01"]["vendor"], "Apple")
        self.assertEqual(devs["3c:22:fb:00:00:01"]["hostname"], "my-iphone")
        self.assertEqual(devs["2c:cf:67:00:00:99"]["vendor"], "Raspberry Pi")
        self.assertEqual(snap["dns"][0]["query"], "example.com")

    def test_port_scan_alert(self):
        s = Stats()
        for port in range(1, 40):
            s.add(decode(eth(MAC_PI, MAC_PHONE, 0x0800,
                             ipv4("192.168.1.66", "192.168.1.50", 6, tcp(40000, port))), ts=2000 + port * 0.01))
        kinds = [a["kind"] for a in s.snapshot()["alerts"]]
        self.assertEqual(kinds.count("port-scan"), 1)

    def test_new_device_alert_after_grace(self):
        s = Stats()
        s.add(decode(eth(MAC_ROUTER, MAC_PI, 0x0800, ipv4("192.168.1.50", "1.1.1.1", 17, udp(1, 53, b""))), ts=100))
        s.add(decode(eth(MAC_ROUTER, MAC_ROUTER, 0x0800, ipv4("192.168.1.1", "1.1.1.1", 17, udp(1, 53, b""))), ts=150))
        s.add(decode(eth(MAC_ROUTER, MAC_PHONE, 0x0800, ipv4("192.168.1.23", "1.1.1.1", 17, udp(1, 53, b""))), ts=300))
        alerts = s.snapshot()["alerts"]
        self.assertEqual([a["kind"] for a in alerts], ["new-device"])
        self.assertIn("3c:22:fb:00:00:01 (Apple) at 192.168.1.23", alerts[0]["msg"])

    def test_plaintext_alert_only_when_accepted(self):
        s = Stats()
        cli, srv = "192.168.1.23", "192.168.1.50"
        s.add(decode(eth(MAC_PI, MAC_PHONE, 0x0800, ipv4(cli, srv, 6, tcp(40000, 23, "S")))))
        s.add(decode(eth(MAC_PI, MAC_PHONE, 0x0800, ipv4(srv, cli, 6, tcp(21, 40001, "RA")))))
        self.assertEqual(s.snapshot()["alerts"], [])        # attempt + refused: no alert
        s.add(decode(eth(MAC_PHONE, MAC_PI, 0x0800, ipv4(srv, cli, 6, tcp(23, 40000, "SA")))))
        (a,) = s.snapshot()["alerts"]
        self.assertEqual(a["msg"], "Unencrypted TELNET connection 192.168.1.23 -> 192.168.1.50")

    def test_arp_change_alert(self):
        s = Stats()
        s.add(decode(eth(BC, MAC_ROUTER, 0x0806, arp(2, MAC_ROUTER, "192.168.1.1", MAC_PI, "192.168.1.50"))))
        s.add(decode(eth(BC, MAC_PHONE, 0x0806, arp(2, MAC_PHONE, "192.168.1.1", MAC_PI, "192.168.1.50"))))
        self.assertEqual(s.snapshot()["alerts"][0]["kind"], "arp-change")

    def test_bounded_memory(self):
        s = Stats()
        for i in range(10000):
            ip = f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}"
            s.add(decode(eth(MAC_PI, MAC_ROUTER, 0x0800, ipv4(ip, "10.255.0.1", 17, udp(1000, 2000, b""))),
                         ts=3000 + i * 0.001))
        self.assertLessEqual(len(s.hosts), 4000)
        self.assertLessEqual(len(s.flows), 4000)

    def test_system_oui_formats(self):
        import pktan.stats as st
        samples = {
            "ieee": "A4-01-DE   (hex)\t\tExample Networks, Inc.\nA40-junk\n",
            "nmap": "# comment\nA401DE Example Networks Corporation\n",
            "wireshark": "A4:01:DE\tExampleN\tExample Networks Ltd.\n",
        }
        for fmt, text in samples.items():
            with tempfile.NamedTemporaryFile("w", suffix=fmt, delete=False) as f:
                f.write(text)
            try:
                saved, st.OUI_FILES, st._system_oui = st.OUI_FILES, (f.name,), None
                self.assertEqual(st.vendor_of("a4:01:de:00:00:01"), "Example Networks", fmt)
            finally:
                st.OUI_FILES, st._system_oui = saved, None
                os.unlink(f.name)

    def test_vendor(self):
        self.assertEqual(vendor_of("ff:ff:ff:ff:ff:ff"), "broadcast")
        self.assertEqual(vendor_of("01:00:5e:00:00:fb"), "multicast")
        self.assertEqual(vendor_of("da:00:00:00:00:01"), "random/local")


BC = b"\xff" * 6


class PcapTests(unittest.TestCase):
    def test_roundtrip_and_cap(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.pcap")
            w = PcapWriter(path, max_bytes=2000)
            frames = sample_frames() * 5
            for i, f in enumerate(frames):
                w.write(1000 + i * 0.5, f, len(f))
            w.close()
            self.assertLessEqual(os.path.getsize(path), 2000)
            self.assertTrue(os.path.exists(path + ".1"))
            got = list(read_pcap(path)) + list(read_pcap(path + ".1"))
            # rotation keeps only the newest two files, and every kept frame is intact
            self.assertTrue(0 < len(got) <= len(frames))
            self.assertTrue(all(g[1] in frames for g in got))
            for ts, data, orig, lt in read_pcap(path):
                self.assertEqual((lt, orig), (1, len(data)))

    def test_raw_ip_gets_ethernet_header(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.pcap")
            w = PcapWriter(path)
            pkt = ipv4("100.64.0.1", "100.64.0.2", 6, tcp(1, 22))
            w.write(1.0, pkt, len(pkt), LINK_RAW)
            w.close()
            (_, data, orig, lt), = read_pcap(path)
            self.assertEqual(decode(data, linktype=lt).app, "SSH")
            self.assertEqual(orig, len(pkt) + 14)


class CliTests(unittest.TestCase):
    def test_sniff_reads_pcap_with_filter(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.pcap")
            w = PcapWriter(path)
            for i, f in enumerate(sample_frames()):
                w.write(1700000000 + i, f, len(f))
            w.close()
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["sniff", "-r", path, "-f", "dns or http", "--no-color", "--stats"])
            self.assertEqual(rc, 0)
            lines = out.getvalue().strip().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertIn("query A example.com", lines[0])
            self.assertIn("3 packets", err.getvalue())

    def test_bad_filter_exit_code(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["sniff", "-r", "/nonexistent", "-f", "port"]), 2)


if __name__ == "__main__":
    unittest.main()
