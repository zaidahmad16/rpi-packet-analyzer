import os
import re
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from packets import MAC_PHONE, MAC_PI, eth, ipv4, sample_frames, tcp  # noqa: E402
from pktan import aws  # noqa: E402
from pktan.aws import (AlertNotifier, AwsError, Credentials, S3Archiver, s3_key,  # noqa: E402
                       sign, sns_publish)
from pktan.decode import decode  # noqa: E402
from pktan.metrics import render  # noqa: E402
from pktan.pcap import PcapWriter, read_pcap  # noqa: E402
from pktan.stats import Stats  # noqa: E402

EXAMPLE = Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")


class SigV4Tests(unittest.TestCase):
    """Vectors from AWS's Signature Version 4 test suite and IAM docs example."""

    def test_get_vanilla(self):
        h = sign("GET", "example.amazonaws.com", "/", None, {}, aws.EMPTY_SHA256, EXAMPLE,
                 "us-east-1", "service", "20150830T123600Z")
        self.assertEqual(h["authorization"],
                         "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/"
                         "aws4_request, SignedHeaders=host;x-amz-date, Signature="
                         "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")

    def test_iam_list_users(self):
        h = sign("GET", "iam.amazonaws.com", "/", {"Action": "ListUsers", "Version": "2010-05-08"},
                 {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                 aws.EMPTY_SHA256, EXAMPLE, "us-east-1", "iam", "20150830T123600Z")
        self.assertTrue(h["authorization"].endswith(
            "SignedHeaders=content-type;host;x-amz-date, "
            "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"))

    def test_session_token_is_signed(self):
        h = sign("GET", "example.amazonaws.com", "/", None, {}, aws.EMPTY_SHA256,
                 Credentials("AK", "SK", "TOKEN"), "us-east-1", "s3", "20150830T123600Z")
        self.assertEqual(h["x-amz-security-token"], "TOKEN")
        self.assertIn("x-amz-security-token", h["authorization"])


class FakeHttp:
    def __init__(self, response=b"<PublishResponse><PublishResult><MessageId>abc-123</MessageId>"
                                b"</PublishResult></PublishResponse>"):
        self.calls = []
        self.response = response

    def __call__(self, method, host, path, headers, body, timeout=30):
        if hasattr(body, "read"):
            body = body.read()
        self.calls.append((method, host, path, headers, body))
        return self.response


class AwsRequestTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeHttp()
        self._orig, aws._request = aws._request, self.fake

    def tearDown(self):
        aws._request = self._orig

    def test_sns_publish(self):
        arn = "arn:aws:sns:ca-central-1:123456789012:pktan-alerts"
        mid = sns_publish(arn, "pktan: new-device\non pi ✓", "hello", EXAMPLE)
        self.assertEqual(mid, "abc-123")
        method, host, path, headers, body = self.fake.calls[0]
        self.assertEqual((method, host, path), ("POST", "sns.ca-central-1.amazonaws.com", "/"))
        form = dict(urllib.parse.parse_qsl(body.decode()))
        self.assertEqual(form["Action"], "Publish")
        self.assertEqual(form["TopicArn"], arn)
        self.assertEqual(form["Subject"], "pktan: new-deviceon pi ")   # SNS rejects newlines/non-ASCII
        self.assertIn("/ca-central-1/sns/aws4_request", headers["authorization"])

    def test_bad_arn(self):
        with self.assertRaises(AwsError):
            sns_publish("arn:aws:s3:::bucket", "s", "m", EXAMPLE)

    def test_s3_put_streams_file_with_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"pcap bytes")
        try:
            aws.s3_put_file("my-bucket", "pktan/pi/2026/07/01/wlan0 x.pcap", f.name,
                            "ca-central-1", EXAMPLE)
        finally:
            os.remove(f.name)
        method, host, path, headers, body = self.fake.calls[0]
        self.assertEqual((method, host), ("PUT", "my-bucket.s3.ca-central-1.amazonaws.com"))
        self.assertEqual(path, "/pktan/pi/2026/07/01/wlan0%20x.pcap")
        self.assertEqual(body, b"pcap bytes")
        self.assertEqual(headers["content-length"], "10")
        import hashlib
        self.assertEqual(headers["x-amz-content-sha256"], hashlib.sha256(b"pcap bytes").hexdigest())

    def test_error_message_parsed(self):
        def failing(*a, **k):
            raise AwsError("sns.x: HTTP 403: " + aws._error_message(
                b"<ErrorResponse><Error><Code>AuthorizationError</Code>"
                b"<Message>not allowed</Message></Error></ErrorResponse>"))
        aws._request = failing
        with self.assertRaisesRegex(AwsError, "AuthorizationError: not allowed"):
            sns_publish("arn:aws:sns:us-east-1:1:t", "s", "m", EXAMPLE)

    def test_s3_key_layout(self):
        key = s3_key("pktan/", "wlan0", when=1783000000)
        self.assertRegex(key, r"^pktan/[^/]+/2026/07/0\d/wlan0-2026070\dT\d{6}Z\.pcap$")


class NotifierTests(unittest.TestCase):
    def test_rate_limit_and_suppressed_note(self):
        sent = []
        n = AlertNotifier("arn:aws:sns:us-east-1:1:t", per_hour=2,
                          publish=lambda arn, subj, body: sent.append((subj, body)))
        for i in range(5):
            n.notify({"ts": time.time(), "kind": "port-scan", "level": "warn", "msg": f"scan {i}"})
        n.close()
        self.assertEqual(len(sent), 2)
        self.assertEqual(n.suppressed, 3)
        self.assertIn("scan 0", sent[0][1])

    def test_publish_errors_dont_crash(self):
        def boom(*a):
            raise AwsError("down")
        n = AlertNotifier("arn:aws:sns:us-east-1:1:t", publish=boom)
        n.notify({"ts": time.time(), "kind": "x", "level": "warn", "msg": "m"})
        n.close()
        self.assertEqual(n.errors, 1)

    def test_stats_feeds_notifier(self):
        got = []
        s = Stats(on_alert=got.append)
        for port in range(1, 40):
            s.add(decode(eth(MAC_PI, MAC_PHONE, 0x0800,
                             ipv4("192.168.1.66", "192.168.1.50", 6, tcp(40000, port))), ts=2000 + port * 0.01))
        self.assertEqual([a["kind"] for a in got], ["port-scan"])
        self.assertEqual(s.alert_counts["port-scan"], 1)


class ArchiverTests(unittest.TestCase):
    def test_rotation_uploads_and_deletes(self):
        uploads = []
        with tempfile.TemporaryDirectory() as d:
            arch = S3Archiver("b", "pktan/", "wlan0",
                              upload=lambda bucket, key, path, region: uploads.append(
                                  (key, len(list(read_pcap(path))))))
            w = PcapWriter(os.path.join(d, "cap.pcap"), max_bytes=1500, on_rotate=arch.queue)
            for i, f in enumerate(sample_frames() * 3):
                w.write(1000 + i, f, len(f))
            w.on_rotate = arch.queue
            w.finish()
            arch.drain()
            self.assertGreaterEqual(len(uploads), 2)
            self.assertEqual(sum(n for _, n in uploads), 30)       # every packet archived once
            self.assertEqual(os.listdir(d), [])                    # nothing left on disk
            self.assertTrue(all(k.startswith("pktan/") and "wlan0-" in k for k, _ in uploads))

    def test_failed_uploads_are_kept_but_capped(self):
        def fail(*a):
            raise AwsError("offline")
        with tempfile.TemporaryDirectory() as d:
            arch = S3Archiver("b", upload=fail, keep_pending=2)
            for i in range(4):
                p = os.path.join(d, f"f{i}.pcap")
                open(p, "wb").write(b"x")
                arch.queue(p)
                arch.drain()
            self.assertEqual(sorted(os.listdir(d)), ["f2.pcap", "f3.pcap"])


class MetricsTests(unittest.TestCase):
    def test_exposition_format(self):
        s = Stats()
        for i, f in enumerate(sample_frames()):
            s.add(decode(f, ts=1000.0 + i))
        text = render(s, "wlan0")
        self.assertIn('pktan_info{version="', text)
        self.assertIn("pktan_packets_total 10\n", text)
        self.assertIn('pktan_protocol_packets_total{protocol="DNS"} 2\n', text)
        self.assertIn("pktan_dns_queries_total 1\n", text)
        self.assertIn('pktan_alerts_total{kind="port-scan"} 0\n', text)
        # every non-comment line is "name{labels} value" or "name value"
        for line in text.splitlines():
            if not line.startswith("#"):
                self.assertRegex(line, r'^[a-z_]+(\{[a-z_]+="[^"]*"(,[a-z_]+="[^"]*")*\})? [0-9.e+-]+$')
        for name in re.findall(r"^# TYPE (\S+) (\S+)$", text, re.M):
            self.assertTrue(name[0].startswith("pktan_"))

    def test_label_escaping_and_cardinality(self):
        s = Stats()
        for i in range(60):
            s.proto_pkts[f'p"{i}'] += 1
            s.proto_bytes[f'p"{i}'] += 10
        text = render(s, "a\\b")
        self.assertIn('source="a\\\\b"', text)
        self.assertIn('protocol="p\\"0"', text)
        self.assertEqual(text.count("pktan_protocol_packets_total{"), 31)   # 30 + "other"


if __name__ == "__main__":
    unittest.main()
