"""Thread-safe rolling statistics and simple anomaly alerts.

All tables are bounded (pruned by least-recently-seen), so memory stays flat
no matter how long the analyzer runs.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import threading
import time
from collections import Counter, deque
from typing import Callable, Iterable

from .decode import WELL_KNOWN_PORTS, Packet

MAX_HOSTS = 4000
MAX_NAMES = 8000
HISTORY_SECONDS = 300
SCAN_WINDOW = 10.0        # seconds
SCAN_PORTS = 25           # distinct dst ports from one source within the window
NEW_DEVICE_LEARN = 600.0  # with no saved device list, learn this long before new-device alerts
MAX_KNOWN_DEVICES = 20000

# Small built-in OUI table: just enough to label common home-network devices.
OUI = {
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi", "2c:cf:67": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "3c:22:fb": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple", "ac:bc:32": "Apple",
    "bc:d0:74": "Apple", "f4:0f:24": "Apple", "88:66:5a": "Apple", "14:7d:da": "Apple",
    "00:1a:11": "Google", "f4:f5:d8": "Google", "3c:5a:b4": "Google", "d8:6c:63": "Google",
    "44:07:0b": "Google", "f8:0f:f9": "Google", "1c:f2:9a": "Google",
    "18:b4:30": "Nest", "64:16:66": "Nest",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "50:dc:e7": "Amazon", "fc:65:de": "Amazon", "44:65:0d": "Amazon", "74:c2:46": "Amazon",
    "f0:27:2d": "Amazon", "68:54:fd": "Amazon",
    "00:04:4b": "Nvidia", "48:b0:2d": "Nvidia",
    "80:38:fb": "Intel", "3c:a9:f4": "Intel", "a4:4c:c8": "Intel", "8c:8d:28": "Intel",
    "f8:63:3f": "Intel", "dc:21:48": "Intel", "60:f2:62": "Intel", "9c:b6:d0": "Intel",
    "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "02:42:00": "Docker",
    "00:1b:63": "Apple", "34:97:f6": "ASUS", "04:d9:f5": "ASUS", "2c:fd:a1": "ASUS",
    "c8:3a:35": "Tenda", "50:c7:bf": "TP-Link", "98:da:c4": "TP-Link", "ec:08:6b": "TP-Link",
    "b0:be:76": "TP-Link", "60:32:b1": "TP-Link", "00:1d:7e": "Cisco", "00:1e:58": "D-Link",
    "e0:63:da": "Ubiquiti", "24:5a:4c": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    "94:10:3e": "Belkin", "00:24:e4": "Withings", "5c:cf:7f": "Espressif", "24:0a:c4": "Espressif",
    "30:ae:a4": "Espressif", "a4:cf:12": "Espressif", "84:f3:eb": "Espressif",
    "10:52:1c": "Espressif", "b4:e6:2d": "Espressif", "c4:4f:33": "Espressif",
    "00:09:b0": "Onkyo", "a8:23:fe": "LG", "c4:36:6c": "LG", "f8:3f:51": "Samsung",
    "8c:79:f5": "Samsung", "5c:49:7d": "Samsung", "a0:10:81": "Samsung", "ec:9b:f3": "Samsung",
    "00:1f:a7": "Sony", "fc:0f:e6": "Sony", "70:2a:d5": "Samsung", "c0:97:27": "Samsung",
    "28:6c:07": "Xiaomi", "64:09:80": "Xiaomi", "78:11:dc": "Xiaomi",
    "b4:2e:99": "Gigabyte", "00:d8:61": "MSI", "d8:bb:c1": "Micro-Star", "18:c0:4d": "Gigabyte",
    "70:85:c2": "ASRock", "e8:9c:25": "ASUS", "40:b0:76": "ASUS",
    "cc:2d:e0": "Routerboard", "48:8f:5a": "Routerboard", "00:14:22": "Dell",
    "f8:bc:12": "Dell", "54:bf:64": "Dell", "3c:52:82": "HP", "f4:39:09": "HP",
    "00:21:5a": "HP", "fc:3f:db": "HP", "e8:6a:64": "LCFC (Lenovo)", "54:e1:ad": "Lenovo",
    "98:fa:9b": "Lenovo", "8c:16:45": "Lenovo", "b0:a4:60": "Intel", "00:15:5d": "Hyper-V",
}


# Full vendor databases that are often already installed (ieee-data, nmap, wireshark).
OUI_FILES = ("/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt",
             "/usr/share/nmap/nmap-mac-prefixes", "/usr/share/wireshark/manuf")
_VENDOR_SUFFIX = re.compile(
    r"[,.]?\s+(inc|incorporated|co|corp|corporation|ltd|limited|llc|gmbh|ag|sa|bv|"
    r"technologies|technology|electronics|international|holdings|trading|company)\b\.?.*$", re.I)
_system_oui: dict[str, str] | None = None


def _load_system_oui() -> dict[str, str]:
    table: dict[str, str] = {}
    for path in OUI_FILES:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "(hex)" in line:                       # ieee: "A4-01-DE   (hex)\t\tVendor"
                        prefix, _, name = line.partition("(hex)")
                        key = prefix.strip().replace("-", "").lower()
                    elif line[:1] in "#\n":
                        continue
                    elif "\t" in line:                        # wireshark: "A4:01:DE\tShort\tLong"
                        parts = line.rstrip("\n").split("\t")
                        key, name = parts[0].replace(":", "").lower(), parts[-1]
                    else:                                     # nmap: "A401DE Vendor"
                        key, _, name = line.partition(" ")
                        key = key.lower()
                    if len(key) == 6 and key not in table:
                        table[key] = _VENDOR_SUFFIX.sub("", name.strip()).strip(" ,.")[:32]
        except OSError:
            continue
        if table:
            break
    return table


def vendor_of(mac: str | None) -> str:
    global _system_oui
    if not mac:
        return ""
    first = int(mac[:2], 16)
    if first & 0x01:
        return "multicast" if mac != "ff:ff:ff:ff:ff:ff" else "broadcast"
    v = OUI.get(mac[:8])
    if v:
        return v
    if _system_oui is None:
        _system_oui = _load_system_oui()
    v = _system_oui.get(mac[:8].replace(":", ""))
    if v:
        return v
    if first & 0x02:
        return "random/local"   # phones with MAC randomisation, VMs, containers
    return ""


def is_local_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_link_local or a.is_loopback or a in _CGNAT


_CGNAT = ipaddress.ip_network("100.64.0.0/10")   # tailscale lives here


def _is_unicast_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified or ip.endswith(".255"))


class KnownDevices:
    """MAC addresses pktan has ever seen, kept across restarts.

    Without this, every restart forgot the network, and quiet devices (cameras,
    plugs) that spoke a few minutes later were reported as "new". With a saved
    list, only a MAC never seen before raises an alert; on a first run with no
    list yet, pktan learns for NEW_DEVICE_LEARN seconds before alerting.
    """

    def __init__(self, path: str | None = None, own: Iterable[str] = ()):
        self.path = path
        self.first_seen: dict[str, float] = {}
        self.loaded = False                       # True if a saved list existed
        self._dirty = False
        self._saved_at = 0.0
        if path:
            try:
                with open(path) as f:
                    data = json.load(f)
                self.first_seen = {str(k).lower(): float(v) for k, v in data.get("devices", {}).items()}
                self.loaded = True
            except FileNotFoundError:
                pass
            except (OSError, ValueError, AttributeError) as e:
                print(f"pktan: ignoring unreadable device list {path}: {e}", file=sys.stderr)
        for mac in own:                           # our own interfaces are never "new"
            self.first_seen.setdefault(mac.lower(), 0.0)

    def __contains__(self, mac: str) -> bool:
        return mac in self.first_seen

    def add(self, mac: str, ts: float) -> None:
        self.first_seen[mac] = ts
        if len(self.first_seen) > MAX_KNOWN_DEVICES:
            for old in sorted(self.first_seen, key=self.first_seen.get)[: MAX_KNOWN_DEVICES // 10]:
                del self.first_seen[old]
        self._dirty = True

    def save(self, force: bool = False) -> None:
        """Write atomically; at most every 30 s unless forced."""
        if not (self.path and self._dirty) or (not force and time.time() - self._saved_at < 30):
            return
        tmp = f"{self.path}.tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"version": 1, "devices": self.first_seen}, f)
            os.replace(tmp, self.path)
            self._dirty, self._saved_at = False, time.time()
        except OSError as e:
            print(f"pktan: could not save device list {self.path}: {e}", file=sys.stderr)


class Stats:
    def __init__(self, recent: int = 300, dns_log: int = 300, alerts: int = 200,
                 on_alert: Callable[[dict], None] | None = None,
                 known: KnownDevices | None = None):
        self.lock = threading.Lock()
        self.on_alert = on_alert                  # called (under the lock) for every alert
        self.started = time.time()
        self.packets = 0
        self.bytes = 0
        self.dropped = 0
        self.proto_pkts: Counter = Counter()
        self.proto_bytes: Counter = Counter()
        self.port_pkts: Counter = Counter()
        self.hosts: dict[str, dict] = {}          # ip -> counters
        self.devices: dict[str, dict] = {}        # mac -> info
        self.names: dict[str, str] = {}           # ip -> hostname/domain
        self.flows: dict[tuple, dict] = {}        # (a, b, label) -> counters
        self.history: deque = deque(maxlen=HISTORY_SECONDS)  # (sec, packets, bytes)
        self.recent: deque = deque(maxlen=recent)
        self.dns_log: deque = deque(maxlen=dns_log)
        self.alerts: deque = deque(maxlen=alerts)
        self.alert_counts: Counter = Counter()    # kind -> total, for /metrics
        self.dns_queries = 0
        self._arp: dict[str, str] = {}            # ip -> mac
        self._scan: dict[str, deque] = {}         # src ip -> deque[(ts, dport)]
        self._scan_alerted: dict[str, float] = {}
        self._seq = 0
        self._first_ts: float | None = None
        self.known = known or KnownDevices()

    # ------------------------------------------------------------ ingest
    def add(self, p: Packet) -> None:
        with self.lock:
            if self._first_ts is None:
                self._first_ts = p.ts
            self._seq += 1
            self.packets += 1
            self.bytes += p.length
            label = p.app or p.proto
            self.proto_pkts[label] += 1
            self.proto_bytes[label] += p.length
            self._bucket(p.ts, p.length)
            self.recent.append((self._seq, p.ts, p.iface, label, p.summary()))

            if p.proto in ("TCP", "UDP") and p.sport is not None:
                known = _known_ports()
                if p.dport in known:
                    server = p.dport
                elif p.sport in known:
                    server = p.sport
                else:
                    server = min(p.sport, p.dport)
                self.port_pkts[f"{p.proto.lower()}/{server}"] += 1

            self._host(p.src, p, out=True)
            self._host(p.dst, p, out=False)
            self._device(p.src_mac, p.src, p)
            self._flow(p, label)
            self._learn_names(p)
            self._detect(p)

    def _bucket(self, ts: float, length: int) -> None:
        sec = int(ts)
        if self.history and self.history[-1][0] == sec:
            s, n, b = self.history[-1]
            self.history[-1] = (s, n + 1, b + length)
        elif self.history and sec < self.history[-1][0]:
            # out-of-order timestamp (multi-iface); fold into the latest second
            s, n, b = self.history[-1]
            self.history[-1] = (s, n + 1, b + length)
        else:
            if self.history:
                # fill silent seconds with zeros so the chart has a real time axis
                last = self.history[-1][0]
                for gap in range(last + 1, min(sec, last + HISTORY_SECONDS)):
                    self.history.append((gap, 0, 0))
            self.history.append((sec, 1, length))

    def _host(self, ip: str | None, p: Packet, out: bool) -> None:
        if not _is_unicast_ip(ip):
            return
        h = self.hosts.get(ip)
        if h is None:
            if len(self.hosts) >= MAX_HOSTS:
                self._prune(self.hosts, MAX_HOSTS // 10)
            h = self.hosts[ip] = {"tx_bytes": 0, "rx_bytes": 0, "packets": 0,
                                  "first": p.ts, "last": p.ts, "mac": None}
        h["packets"] += 1
        h["last"] = p.ts
        if out:
            h["tx_bytes"] += p.length
            if p.src_mac and is_local_ip(ip):
                h["mac"] = p.src_mac
        else:
            h["rx_bytes"] += p.length

    def _device(self, mac: str | None, ip: str | None, p: Packet) -> None:
        if not mac or int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
            return
        d = self.devices.get(mac)
        if d is None:
            if len(self.devices) >= MAX_HOSTS:
                self._prune(self.devices, MAX_HOSTS // 10)
            d = self.devices[mac] = {"vendor": vendor_of(mac), "ips": [], "hostname": None,
                                     "first": p.ts, "last": p.ts, "packets": 0, "bytes": 0,
                                     "iface": p.iface}
            if mac not in self.known:
                self.known.add(mac, p.ts)
                learning = not self.known.loaded and p.ts - self._first_ts < NEW_DEVICE_LEARN
                if not learning:
                    self._alert(p.ts, "info", "new-device",
                                f"New device {mac} ({d['vendor'] or 'unknown vendor'})"
                                + (f" at {ip}" if ip else ""))
            self.known.save()
        d["last"] = p.ts
        d["packets"] += 1
        d["bytes"] += p.length
        if ip and is_local_ip(ip) and _is_unicast_ip(ip) and ip not in d["ips"]:
            d["ips"] = (d["ips"] + [ip])[-6:]
        if p.hostname and p.app == "DHCP":
            d["hostname"] = p.hostname

    def _flow(self, p: Packet, label: str) -> None:
        if not p.src or not p.dst:
            return
        a, b = sorted(((p.src, p.sport), (p.dst, p.dport)), key=str)
        key = (a[0], b[0], label)
        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= MAX_HOSTS:
                self._prune(self.flows, MAX_HOSTS // 10)
            f = self.flows[key] = {"packets": 0, "bytes": 0, "first": p.ts, "last": p.ts}
        f["packets"] += 1
        f["bytes"] += p.length
        f["last"] = p.ts

    def _learn_names(self, p: Packet) -> None:
        if p.dns_answers:
            for name, ip in p.dns_answers:
                self._name(ip, name)   # includes mDNS ("Zaids-MacBook.local")
        if p.dns_query and not p.dns_answers and p.app == "DNS" and p.info.startswith("query"):
            self.dns_queries += 1
            self.dns_log.append({"ts": p.ts, "client": p.src, "query": p.dns_query,
                                 "type": p.info.split()[1] if len(p.info.split()) > 1 else ""})
        if p.hostname and p.src_mac:
            dev = self.devices.get(p.src_mac)
            for ip in (dev or {}).get("ips", []):
                self._name(ip, p.hostname)
        if p.sni and p.dst:
            self._name(p.dst, p.sni, weak=True)
        if p.http_host and p.dst:
            self._name(p.dst, p.http_host, weak=True)

    def _name(self, ip: str, name: str, weak: bool = False) -> None:
        if weak and ip in self.names:
            return
        if len(self.names) >= MAX_NAMES:
            for k in list(self.names)[: MAX_NAMES // 10]:
                del self.names[k]
        self.names[ip] = name

    # ------------------------------------------------------------ alerts
    def _detect(self, p: Packet) -> None:
        # ARP: an IP suddenly claimed by a different MAC (possible spoofing / IP conflict)
        if p.proto == "ARP" and p.src and p.src_mac and p.src != "0.0.0.0":
            old = self._arp.get(p.src)
            if old and old != p.src_mac:
                self._alert(p.ts, "warn", "arp-change",
                            f"{p.src} moved from {old} to {p.src_mac} (IP conflict or ARP spoofing?)")
            self._arp[p.src] = p.src_mac
            if len(self._arp) > MAX_HOSTS:
                self._arp.pop(next(iter(self._arp)))
        # Port scan: one source SYN-ing many distinct ports in a short window
        if p.proto == "TCP" and p.tcp_flags == "S" and p.src:
            dq = self._scan.setdefault(p.src, deque(maxlen=SCAN_PORTS * 4))
            dq.append((p.ts, p.dport))
            while dq and p.ts - dq[0][0] > SCAN_WINDOW:
                dq.popleft()
            ports = {d for _, d in dq}
            if len(ports) >= SCAN_PORTS and p.ts - self._scan_alerted.get(p.src, 0) > 60:
                self._scan_alerted[p.src] = p.ts
                self._alert(p.ts, "warn", "port-scan",
                            f"{p.src} tried {len(ports)} ports on {p.dst} in "
                            f"{SCAN_WINDOW:.0f}s (port scan?)")
            if len(self._scan) > MAX_HOSTS:
                self._scan.pop(next(iter(self._scan)))
        # Plaintext protocols that leak credentials. Alert on the server's SYN-ACK,
        # i.e. a connection that was accepted, so scans of port 21/23 don't count.
        if p.app in ("TELNET", "FTP") and p.tcp_flags == "SA" and p.sport in (21, 23):
            self._alert(p.ts, "warn", "plaintext",
                        f"Unencrypted {p.app} connection {p.dst} -> {p.src}")

    def _alert(self, ts: float, level: str, kind: str, msg: str) -> None:
        alert = {"ts": ts, "level": level, "kind": kind, "msg": msg}
        self.alerts.append(alert)
        self.alert_counts[kind] += 1
        if self.on_alert:
            self.on_alert(alert)

    @staticmethod
    def _prune(d: dict, n: int) -> None:
        for k, _ in sorted(d.items(), key=lambda kv: kv[1]["last"])[:n]:
            del d[k]

    # ------------------------------------------------------------ views
    def snapshot(self, top: int = 15, since_seq: int = 0) -> dict:
        with self.lock:
            now = time.time()
            last_ts = self.history[-1][0] if self.history else int(now)
            hist = list(self.history)[-120:]
            rate_window = [h for h in self.history if h[0] > last_ts - 5]
            bps = sum(h[2] for h in rate_window) * 8 / 5 if rate_window else 0
            pps = sum(h[1] for h in rate_window) / 5 if rate_window else 0

            def host_row(ip, h):
                return {"ip": ip, "name": self.names.get(ip), "local": is_local_ip(ip),
                        "tx": h["tx_bytes"], "rx": h["rx_bytes"], "packets": h["packets"],
                        "last": h["last"], "mac": h["mac"],
                        "vendor": vendor_of(h["mac"]) if h["mac"] else ""}

            hosts = sorted(self.hosts.items(), key=lambda kv: -(kv[1]["tx_bytes"] + kv[1]["rx_bytes"]))
            devices = sorted(self.devices.items(), key=lambda kv: -kv[1]["bytes"])
            flows = sorted(self.flows.items(), key=lambda kv: -kv[1]["bytes"])
            return {
                "now": now,
                "started": self.started,
                "packets": self.packets,
                "bytes": self.bytes,
                "dropped": self.dropped,
                "bps": bps,
                "pps": pps,
                "history": [{"t": t, "p": n, "b": b} for t, n, b in hist],
                "protocols": [{"name": k, "packets": v, "bytes": self.proto_bytes[k]}
                              for k, v in self.proto_pkts.most_common(top)],
                "ports": [{"port": k, "packets": v} for k, v in self.port_pkts.most_common(top)],
                "hosts": [host_row(ip, h) for ip, h in hosts[:top]],
                "devices": [{"mac": m, **{k: v for k, v in d.items()},
                             "name": d["hostname"] or next(
                                 (self.names[i] for i in d["ips"] if i in self.names), None)}
                            for m, d in devices[:top * 2]],
                "flows": [{"a": k[0], "b": k[1], "label": k[2],
                           "a_name": self.names.get(k[0]), "b_name": self.names.get(k[1]), **v}
                          for k, v in flows[:top]],
                "dns": list(self.dns_log)[-top * 2:][::-1],
                "alerts": list(self.alerts)[-top * 2:][::-1],
                "recent": [{"seq": s, "ts": ts, "iface": i, "label": lb, "text": t}
                           for s, ts, i, lb, t in self.recent if s > since_seq][-100:],
                "seq": self._seq,
            }


def _known_ports() -> set[int]:
    return _KNOWN


_KNOWN = set(WELL_KNOWN_PORTS)
