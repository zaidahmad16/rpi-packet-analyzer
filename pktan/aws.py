"""AWS integration, stdlib only: SNS for alerts, S3 for capture archives.

Requests are signed with AWS Signature Version 4 implemented here (hmac +
hashlib), so pktan still needs nothing from pip. Credentials are looked up the
way the AWS CLI does: environment variables first, then ~/.aws/credentials.
Network calls run on background threads so a slow or unreachable AWS never
stalls packet capture.
"""
from __future__ import annotations

import configparser
import datetime as dt
import hashlib
import hmac
import http.client
import os
import queue
import socket
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import BinaryIO

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class AwsError(RuntimeError):
    pass


# ---------------------------------------------------------------- credentials

@dataclass
class Credentials:
    access_key: str
    secret_key: str
    token: str | None = None


def load_credentials(profile: str | None = None) -> Credentials:
    env = os.environ
    if env.get("AWS_ACCESS_KEY_ID") and env.get("AWS_SECRET_ACCESS_KEY"):
        return Credentials(env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"],
                           env.get("AWS_SESSION_TOKEN") or None)
    profile = profile or env.get("AWS_PROFILE") or "default"
    path = env.get("AWS_SHARED_CREDENTIALS_FILE") or os.path.expanduser("~/.aws/credentials")
    cp = configparser.ConfigParser()
    if cp.read(path) and cp.has_section(profile):
        sec = cp[profile]
        if sec.get("aws_access_key_id") and sec.get("aws_secret_access_key"):
            return Credentials(sec["aws_access_key_id"], sec["aws_secret_access_key"],
                               sec.get("aws_session_token") or None)
    raise AwsError("no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY "
                   f"or add a [{profile}] section to {path}")


def default_region() -> str:
    env = os.environ
    region = env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
    if region:
        return region
    cp = configparser.ConfigParser()
    profile = env.get("AWS_PROFILE") or "default"
    cp.read(env.get("AWS_CONFIG_FILE") or os.path.expanduser("~/.aws/config"))
    for sec in (profile, f"profile {profile}"):
        if cp.has_section(sec) and cp[sec].get("region"):
            return cp[sec]["region"]
    return "us-east-1"


# ---------------------------------------------------------------- SigV4

def _uri_encode(s: str, safe: str = "-_.~") -> str:
    return urllib.parse.quote(s, safe=safe)


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign(method: str, host: str, path: str, query: dict[str, str] | None, headers: dict[str, str],
         payload_hash: str, creds: Credentials, region: str, service: str,
         amz_date: str | None = None) -> dict[str, str]:
    """Return `headers` plus x-amz-date, (security token) and Authorization.

    `path` must already be URI-encoded the way the service expects.
    """
    amz_date = amz_date or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    hdrs = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    hdrs["host"] = host
    hdrs["x-amz-date"] = amz_date
    if creds.token:
        hdrs["x-amz-security-token"] = creds.token
    canonical_query = "&".join(
        f"{_uri_encode(k)}={_uri_encode(v)}" for k, v in sorted((query or {}).items()))
    signed = ";".join(sorted(hdrs))
    canonical_headers = "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs))
    canonical_request = "\n".join([method, path or "/", canonical_query, canonical_headers,
                                   signed, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + creds.secret_key).encode(), date), region),
                      service), "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    hdrs["authorization"] = (f"AWS4-HMAC-SHA256 Credential={creds.access_key}/{scope}, "
                             f"SignedHeaders={signed}, Signature={signature}")
    return hdrs


def _request(method: str, host: str, path: str, headers: dict[str, str],
             body: bytes | BinaryIO | None, timeout: float = 30) -> bytes:
    conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
    except (OSError, http.client.HTTPException) as e:
        raise AwsError(f"{host}: {e}") from None
    finally:
        conn.close()
    if resp.status >= 300:
        raise AwsError(f"{host} {method} {path}: HTTP {resp.status}: {_error_message(data)}")
    return data


def _error_message(xml_body: bytes) -> str:
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return xml_body[:200].decode("utf-8", "replace")
    code = next((e.text for e in root.iter() if e.tag.endswith("Code")), None)
    msg = next((e.text for e in root.iter() if e.tag.endswith("Message")), None)
    return ": ".join(x for x in (code, msg) if x) or "unknown error"


# ---------------------------------------------------------------- SNS

def sns_publish(topic_arn: str, subject: str, message: str,
                creds: Credentials | None = None) -> str:
    """Publish to an SNS topic and return the MessageId."""
    parts = topic_arn.split(":")
    if len(parts) < 6 or parts[2] != "sns":
        raise AwsError(f"not an SNS topic ARN: {topic_arn!r}")
    region = parts[3]
    creds = creds or load_credentials()
    host = f"sns.{region}.amazonaws.com"
    # SNS subjects: <=100 printable ASCII chars, no newlines
    subject = "".join(c for c in subject if 32 <= ord(c) < 127)[:100] or "pktan"
    body = urllib.parse.urlencode({"Action": "Publish", "Version": "2010-03-31",
                                   "TopicArn": topic_arn, "Subject": subject,
                                   "Message": message}).encode()
    headers = sign("POST", host, "/", None,
                   {"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
                   hashlib.sha256(body).hexdigest(), creds, region, "sns")
    data = _request("POST", host, "/", headers, body)
    root = ET.fromstring(data)
    return next((e.text or "" for e in root.iter() if e.tag.endswith("MessageId")), "")


# ---------------------------------------------------------------- S3

def s3_put_file(bucket: str, key: str, path: str, region: str | None = None,
                creds: Credentials | None = None, content_type: str = "application/vnd.tcpdump.pcap") -> None:
    """Upload a local file to s3://bucket/key with a single signed PUT (fine up to 5 GB)."""
    region = region or default_region()
    creds = creds or load_credentials()
    host = f"{bucket}.s3.{region}.amazonaws.com"
    uri = "/" + "/".join(_uri_encode(seg) for seg in key.split("/"))
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    headers = sign("PUT", host, uri, None,
                   {"content-type": content_type, "content-length": str(size),
                    "x-amz-content-sha256": h.hexdigest()},
                   h.hexdigest(), creds, region, "s3")
    with open(path, "rb") as f:          # streamed, never fully in memory
        _request("PUT", host, uri, headers, f, timeout=120)


def s3_key(prefix: str, iface: str, when: float | None = None) -> str:
    t = time.gmtime(when if when is not None else time.time())
    host = socket.gethostname().split(".")[0]
    prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""
    return (f"{prefix}{host}/{time.strftime('%Y/%m/%d', t)}/"
            f"{iface or 'capture'}-{time.strftime('%Y%m%dT%H%M%SZ', t)}.pcap")


# ---------------------------------------------------------------- workers

def _log(msg: str) -> None:
    print(f"pktan: {msg}", file=sys.stderr, flush=True)


class AlertNotifier:
    """Sends alerts to SNS from a background thread.

    Stats calls `notify` while holding its lock, so it only enqueues. A rolling
    hourly cap keeps a noisy event (say, a port scan) from spamming your phone;
    anything suppressed is counted and mentioned in the next message.
    """

    def __init__(self, topic_arn: str, per_hour: int = 20, source: str = "",
                 publish=sns_publish):
        self.topic_arn, self.per_hour, self.source = topic_arn, per_hour, source
        self.publish = publish
        self.sent: list[float] = []
        self.suppressed = 0
        self.errors = 0
        self._q: queue.Queue = queue.Queue(maxsize=200)
        self._t = threading.Thread(target=self._run, name="pktan-sns", daemon=True)
        self._t.start()

    def notify(self, alert: dict) -> None:
        try:
            self._q.put_nowait(alert)
        except queue.Full:
            self.suppressed += 1

    def close(self, timeout: float = 10) -> None:
        self._q.put(None)
        self._t.join(timeout)

    def _run(self) -> None:
        host = socket.gethostname().split(".")[0]
        while True:
            alert = self._q.get()
            if alert is None:
                return
            now = time.time()
            self.sent = [t for t in self.sent if now - t < 3600]
            if len(self.sent) >= self.per_hour:
                self.suppressed += 1
                continue
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert["ts"]))
            body = f"{alert['msg']}\n\nSeen by pktan on {host}"
            body += f" ({self.source})" if self.source else ""
            body += f" at {when}."
            if self.suppressed:
                body += (f"\n\n{self.suppressed} more alert(s) were held back by the "
                         f"{self.per_hour}/hour limit. Check the dashboard for details.")
            try:
                self.publish(self.topic_arn, f"pktan: {alert['kind']} on {host}", body)
                self.sent.append(now)
                self.suppressed = 0
            except AwsError as e:
                self.errors += 1
                if self.errors <= 3 or self.errors % 50 == 0:
                    _log(f"SNS publish failed ({self.errors}x): {e}")


class S3Archiver:
    """Uploads rotated pcap files to S3, then deletes the local copy.

    Files that fail to upload stay on disk and are retried at the next rotation,
    but at most `keep_pending` are kept so an outage can't fill the SD card.
    """

    def __init__(self, bucket: str, prefix: str = "pktan/", iface: str = "",
                 region: str | None = None, keep_pending: int = 3, upload=s3_put_file):
        self.bucket, self.prefix, self.iface = bucket, prefix, iface
        self.region = region
        self.keep_pending = keep_pending
        self.upload = upload
        self.uploaded: list[str] = []
        self._pending: list[str] = []
        self._lock = threading.Lock()
        self._busy = threading.Lock()

    def queue(self, path: str) -> None:
        """Add a finished file to the upload backlog without starting an upload."""
        with self._lock:
            self._pending.append(path)
            while len(self._pending) > self.keep_pending:
                old = self._pending.pop(0)
                _log(f"S3 upload backlog full, deleting {old}")
                _silent_remove(old)

    def rotated(self, path: str) -> None:
        """PcapWriter callback: queue the finished file and upload it in the background."""
        self.queue(path)
        threading.Thread(target=self.drain, name="pktan-s3", daemon=True).start()

    def drain(self) -> None:
        if not self._busy.acquire(blocking=False):
            return                       # another thread is already uploading
        try:
            while True:
                with self._lock:
                    if not self._pending:
                        return
                    path = self._pending[0]
                key = s3_key(self.prefix, self.iface, _mtime(path))
                try:
                    self.upload(self.bucket, key, path, self.region)
                except (AwsError, OSError) as e:
                    _log(f"S3 upload of {os.path.basename(path)} failed, will retry: {e}")
                    return
                with self._lock:
                    if self._pending and self._pending[0] == path:
                        self._pending.pop(0)
                self.uploaded.append(f"s3://{self.bucket}/{key}")
                _log(f"archived {os.path.basename(path)} to s3://{self.bucket}/{key}")
                _silent_remove(path)
        finally:
            self._busy.release()


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return time.time()


def _silent_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
