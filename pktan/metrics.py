"""Prometheus exposition (text format 0.0.4) for GET /metrics.

Written by hand instead of with prometheus_client to keep pktan dependency-free.
Counters only ever go up, so Grafana can use rate()/increase() on them; label
sets are capped so an odd protocol mix can't explode Prometheus's cardinality.
"""
from __future__ import annotations

import time

from . import __version__
from .stats import Stats, is_local_ip

MAX_PROTOCOL_LABELS = 30


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**kv) -> str:
    return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in kv.items()) + "}"


def render(stats: Stats, source: str) -> str:
    out: list[str] = []

    def metric(name: str, kind: str, help_: str, samples: list[tuple[str, float]]) -> None:
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            out.append(f"{name}{labels} {value:.17g}" if isinstance(value, float)
                       else f"{name}{labels} {value}")

    with stats.lock:
        now = time.time()
        proto = stats.proto_pkts.most_common()
        top, rest = proto[:MAX_PROTOCOL_LABELS], proto[MAX_PROTOCOL_LABELS:]
        proto_pkts = [(_labels(protocol=k), v) for k, v in top]
        proto_bytes = [(_labels(protocol=k), stats.proto_bytes[k]) for k, _ in top]
        if rest:
            proto_pkts.append((_labels(protocol="other"), sum(v for _, v in rest)))
            proto_bytes.append((_labels(protocol="other"), sum(stats.proto_bytes[k] for k, _ in rest)))
        lan_hosts = sum(1 for ip in stats.hosts if is_local_ip(ip))
        recent_devices = sum(1 for d in stats.devices.values() if now - d["last"] < 300)
        alert_kinds = {"new-device", "arp-change", "port-scan", "plaintext", "anomaly"} | set(stats.alert_counts)
        alerts = [(_labels(kind=k), stats.alert_counts.get(k, 0)) for k in sorted(alert_kinds)]
        packets, nbytes, dns = stats.packets, stats.bytes, stats.dns_queries
        devices, hosts, flows = len(stats.devices), len(stats.hosts), len(stats.flows)
        started = stats.started
        snap = stats.engine_snapshot
        dropped = stats.dropped
        # scores from the last couple of windows only, most anomalous first, capped
        recent = [(mac, a) for mac, a in stats.anomaly.items() if now - a["ts"] < 180]
        recent.sort(key=lambda kv: -kv[1]["score"])
        anomaly = [(_labels(device=mac), round(a["score"], 4)) for mac, a in recent[:50]]
        has_model = stats.forest is not None
        threshold = stats.forest.threshold if has_model else None

    metric("pktan_info", "gauge", "Build and capture source.",
           [(_labels(version=__version__, source=source), 1)])
    metric("pktan_start_time_seconds", "gauge", "Unix time pktan started.", [("", float(started))])
    metric("pktan_packets_total", "counter", "Packets that passed the filter.", [("", packets)])
    metric("pktan_bytes_total", "counter", "Bytes on the wire for those packets.", [("", nbytes)])
    metric("pktan_protocol_packets_total", "counter",
           "Packets by application or transport protocol.", proto_pkts)
    metric("pktan_protocol_bytes_total", "counter",
           "Bytes by application or transport protocol.", proto_bytes)
    metric("pktan_dns_queries_total", "counter", "DNS queries seen.", [("", dns)])
    metric("pktan_alerts_total", "counter", "Alerts raised, by kind.", alerts)
    metric("pktan_devices", "gauge", "Devices (MAC addresses) currently tracked.", [("", devices)])
    metric("pktan_devices_active", "gauge", "Devices seen in the last 5 minutes.", [("", recent_devices)])
    metric("pktan_hosts", "gauge", "IP addresses currently tracked.", [("", hosts)])
    metric("pktan_hosts_lan", "gauge", "Tracked IP addresses that are on the LAN.", [("", lan_hosts)])
    metric("pktan_flows", "gauge", "Conversations currently tracked.", [("", flows)])
    metric("pktan_kernel_drops_total", "counter",
           "Packets the kernel dropped because capture fell behind.", [("", dropped)])
    if has_model:
        metric("pktan_anomaly_threshold", "gauge",
               "Isolation Forest score above which a device-minute counts as unusual.",
               [("", threshold)])
        metric("pktan_anomaly_score", "gauge",
               "Isolation Forest anomaly score per device for the last minute (0-1).", anomaly)
    if snap is not None:
        metric("pktan_engine_sources", "gauge",
               "Source addresses in the C engine's hash table.", [("", snap["sources"])])
        metric("pktan_source_bytes", "gauge",
               "Bytes sent by each of the top-K sources (C engine min-heap).",
               [(_labels(src=t["ip"]), t["bytes"]) for t in snap["top"]])
        metric("pktan_source_packets", "gauge",
               "Packets sent by each of the top-K sources (C engine min-heap).",
               [(_labels(src=t["ip"]), t["packets"]) for t in snap["top"]])
    return "\n".join(out) + "\n"
