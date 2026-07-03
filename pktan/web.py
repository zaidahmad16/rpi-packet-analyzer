"""Browser dashboard: stdlib HTTP server, JSON API and Server-Sent Events."""
from __future__ import annotations

import json
import socket
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from .capture import list_interfaces


def make_handler(engine, source: str):
    index_html = resources.files("pktan").joinpath("static/index.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        server_version = "pktan"

        def log_message(self, fmt, *args):   # keep the console quiet
            pass

        def _send(self, body: bytes, ctype: str, status=HTTPStatus.OK):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status=HTTPStatus.OK):
            self._send(json.dumps(obj).encode(), "application/json", status)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(index_html, "text/html; charset=utf-8")
            elif path == "/api/stats":
                snap = engine.stats.snapshot()
                snap["source"] = source
                snap["error"] = str(engine.error) if engine.error else None
                self._json(snap)
            elif path == "/api/interfaces":
                self._json(list_interfaces())
            elif path == "/events":
                self._sse()
            elif path == "/favicon.ico":
                self._send(b"", "image/x-icon", HTTPStatus.NO_CONTENT)
            else:
                self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def _sse(self):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            seq = 0
            try:
                while True:
                    snap = engine.stats.snapshot(since_seq=seq)
                    seq = snap["seq"]
                    snap["source"] = source
                    snap["error"] = str(engine.error) if engine.error else None
                    snap["finished"] = engine.done.is_set()
                    self.wfile.write(b"data: " + json.dumps(snap).encode() + b"\n\n")
                    self.wfile.flush()
                    time.sleep(1.0)
            except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
                return

    return Handler


def serve(engine, source: str, bind: str = "0.0.0.0", port: int = 8080) -> None:
    srv = ThreadingHTTPServer((bind, port), make_handler(engine, source))
    srv.daemon_threads = True
    urls = [f"http://{h}:{port}" for h in _reachable_hosts(bind)]
    print("pktan dashboard on " + "  ".join(urls), flush=True)
    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def _reachable_hosts(bind: str) -> list[str]:
    if bind not in ("0.0.0.0", "::", ""):
        return [bind]
    hosts = ["localhost"]
    host = socket.gethostname()
    hosts.append(host if "." in host else f"{host}.local")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))   # no packet is sent; just picks the LAN source IP
            hosts.append(s.getsockname()[0])
    except OSError:
        pass
    return hosts
