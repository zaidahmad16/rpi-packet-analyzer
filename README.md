# pktan: Raspberry Pi network packet analyzer

A small network packet analyzer for the Raspberry Pi: a C capture engine on raw sockets, a Python core with no third-party dependencies, and an Isolation Forest that learns what normal traffic looks like on your network. It captures traffic, decodes the common protocols, and shows you what's going on through a terminal UI or a live web dashboard.

```
$ sudo python3 -m pktan sniff -f "dns or (tcp port 443 and not port 22)"
12:34:16.889 DNS       [2001:db8:1::47c4]:33813 -> [2001:db8:ffff::53]:53 len=101 query A github.com
12:34:16.905 HTTPS     10.0.0.249:49126 -> 140.82.114.4:443 len=74 [S]
12:34:16.918 DNS       [2001:db8:ffff::53]:53 -> [2001:db8:1::47c4]:33813 len=117 response A github.com -> 140.82.113.4
12:34:16.939 HTTPS     140.82.114.4:443 -> 10.0.0.249:49126 len=74 [SA]
12:34:16.943 HTTPS     10.0.0.249:49126 -> 140.82.114.4:443 len=1490 [A] SNI=github.com
```

## Features

- **Live capture** with a raw `AF_PACKET` socket. Works on Ethernet, Wi-Fi, VLAN-tagged and tunnel interfaces (Tailscale/WireGuard), or on `any`.
- **C capture engine** (`csrc/pktcap.c`): a TPACKET_V3 memory-mapped ring, hand-written Ethernet/802.1Q/IPv4/IPv6/TCP/UDP parsing, a bounded open-addressing hash table of per-source traffic, and a min-heap for the top-K talkers. Python only fully decodes the packets that carry names or alerts. It produces the same output as the pure-Python engine, field for field, and the tests check that.
- **Anomaly detection:** per-device traffic features every minute, an **Isolation Forest** trained with scikit-learn, and scoring in pure Python at runtime, so the always-on service never loads numpy or scikit-learn.
- **Decoders:** Ethernet, 802.1Q, ARP, IPv4, IPv6 (with extension headers), TCP, UDP, ICMP/ICMPv6, DNS/mDNS/LLMNR, DHCP (including client hostnames), TLS SNI, HTTP Host, and QUIC detection.
- **Statistics:** throughput over time, protocol mix, top hosts, top conversations, top ports, DNS lookups, and the devices on the LAN, each with vendor (from the MAC prefix) plus hostnames learned from DNS, mDNS, DHCP and SNI.
- **Alerts:** new device joined (remembered across restarts, so a reboot doesn't re-announce every quiet device), an IP address claimed by a different MAC (ARP spoofing or IP conflict), port scans, and unencrypted Telnet/FTP.
- **Filters** in a tcpdump-like syntax: `tcp port 443`, `dns or arp`, `host 10.0.0.5 and not port 22`, `net 192.168.1.0/24`, `src port 1000-2000`, `ip6`.
- **pcap in and out:** analyse captures from Wireshark/tcpdump (`--read`), or save traffic (`--write`) with a hard size cap.
- **Bounded memory:** every table is pruned, so it can run for weeks on a Pi.
- **Prometheus metrics** at `/metrics`, plus a ready-made **Grafana** dashboard, deployed to k3s next to pktan.
- **AWS:** alerts go to your phone or email through **SNS**, and saved captures upload to **S3**. AWS requests are signed with a hand-written Signature Version 4, so there's still nothing to install.
- **Tested:** 59 unit tests built from hand-made packets, AWS's own SigV4 test vectors, C/Python parity checks, and an AddressSanitizer fuzz run of the C engine. No capture privileges or AWS account are needed to run them.

## Quick start (on the Pi)

```bash
git clone https://github.com/zaidahmad16/rpi-packet-analyzer.git
cd rpi-packet-analyzer

python3 -m pktan list                 # interfaces (* = default)
sudo python3 -m pktan sniff -f "not port 22"   # one line per packet
sudo python3 -m pktan top             # live terminal dashboard
sudo python3 -m pktan web             # browser dashboard on :8080
```

Then open **http://raspberrypi.local:8080** from any device on the network.

Requirements: Linux and Python 3.10+. Nothing to `pip install`.

### Without sudo
Live capture needs `CAP_NET_RAW`. You can grant it to the Python binary once:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
```
Analysing a saved file never needs privileges:
```bash
python3 -m pktan top --read capture.pcap
```

### Run on boot
```bash
./install-pi.sh pi@raspberrypi.local --service
```
This copies the code to `/opt/pktan` and installs `systemd/pktan.service`. The service runs as its own throwaway system user (`DynamicUser`) with only the raw-capture capabilities and a 200 MB memory cap. Extra options (interface, AWS) go in `/etc/pktan.env`; see the AWS section below.

## Commands

| Command | What it does |
|---|---|
| `pktan list` | List interfaces and show which one is the default |
| `pktan sniff [-c N] [--stats]` | Print packets as they arrive; `--stats` adds a summary at the end |
| `pktan top [--realtime]` | Full-screen terminal dashboard |
| `pktan web [--port 8080] [--bind ADDR]` | Web dashboard (JSON at `/api/stats`, live stream at `/events`, Prometheus at `/metrics`) |
| `pktan aws-check [--sns-topic ARN] [--s3-bucket NAME]` | Send a test alert and upload a test file to prove the AWS setup works |
| `pktan bench FILE.pcap [--repeat N]` | Packets per second for the Python engine, the C engine, and C parsing alone, plus peak memory |
| `pktan features FILE.pcap... --out F.csv` | Turn saved captures into per-device feature rows |
| `pktan train [--state-dir DIR]` | Fit the Isolation Forest on logged features (needs `python3-sklearn`) |
| `pktan evaluate [--attack NAME CSV MAC]` | Fixed thresholds vs the Isolation Forest on held-out data and attack captures |

Shared options: `--engine auto|c|python` (default `auto`: C when `csrc/pktcap` is built), `-i IFACE` (or `any`), `-r FILE.pcap`, `-f FILTER`, `-w FILE.pcap --max-mb 50`, `--no-promisc`, and the AWS options `--sns-topic ARN`, `--alerts-per-hour N`, `--s3-bucket NAME`, `--s3-prefix P`.

`web` hides its own dashboard traffic automatically (`--include-self` turns that off).

## Prometheus and Grafana

`pktan web` serves Prometheus metrics at `/metrics`: packet and byte counters (total and per protocol), DNS queries, alerts by kind, and gauges for devices, LAN hosts and conversations. Protocol labels are capped at 30 so an odd mix can't blow up Prometheus.

`deploy/k8s/` runs Prometheus and Grafana on the Pi's k3s, next to pktan:

```bash
sudo ./deploy/k8s/install.sh          # prints the Grafana admin password once
```

- Grafana at **http://raspberrypi.local:30300** opens on the provisioned *pktan network overview* dashboard. Anyone on the LAN can view it; editing needs the admin login.
- Prometheus keeps 30 days of data, capped at 1.5 GB.
- Prometheus uses host networking and scrapes `127.0.0.1:8080`, so pktan has to be running as the service (see *Run on boot*).
- `sudo ./deploy/k8s/install.sh --remove` deletes all of it.

## AWS: alerts by SNS, captures to S3

pktan can push alerts (new device, ARP change, port scan, plaintext login) to an **SNS topic**, so they reach your phone or email. With `--write`, it can also upload each full capture file to **S3** and then delete it locally, so the SD card never fills.

Setup in the AWS console:

1. **SNS:** create a Standard topic called `pktan-alerts`, add a subscription (email or SMS), and confirm it.
2. **S3:** create a bucket (private, all public access blocked). Optionally add a lifecycle rule that expires `pktan/` objects after 30 days.
3. **IAM:** create a user with no console access, attach an inline policy from [`deploy/aws/iam-policy.json`](deploy/aws/iam-policy.json) (fill in region, account ID and bucket), and create an access key for it. The policy only allows publishing to that one topic and uploading under `pktan/` in that one bucket.
4. On the Pi, put the settings in `/etc/pktan.env` and lock it down (`sudo chmod 600 /etc/pktan.env`):
   ```
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   AWS_REGION=ca-central-1
   PKTAN_ARGS="--sns-topic arn:aws:sns:ca-central-1:123456789012:pktan-alerts -w /var/lib/pktan/capture.pcap --max-mb 50 --s3-bucket YOUR-BUCKET"
   ```
5. Check it end to end, then restart the service:
   ```bash
   sudo bash -c 'set -a; . /etc/pktan.env; cd /opt/pktan && python3 -m pktan aws-check \
     --sns-topic "arn:aws:sns:...:pktan-alerts" --s3-bucket YOUR-BUCKET'
   sudo systemctl restart pktan
   ```

Alerts are capped at 20 per hour (`--alerts-per-hour`); the next message says how many were held back. SNS and S3 calls run on background threads, so a slow or missing connection never stalls capture. Failed uploads are retried at the next rotation, with at most 3 files kept waiting. On a home network this stays within the AWS free tier.

## The C engine

```bash
make -C csrc            # builds csrc/pktcap; pktan also builds it on first use if cc is there
python3 -m pktan bench capture.pcap --repeat 100
```

`pktcap` reads packets from a TPACKET_V3 ring that the kernel fills in 1 MiB blocks, so there's no system call per packet. It parses Ethernet, 802.1Q, IPv4, IPv6, TCP and UDP itself and sends Python a fixed 76-byte summary per packet. The raw bytes only go along when Python has to look deeper: DNS, DHCP, ARP, TLS client hellos, HTTP requests, ICMP, or anything malformed. Per-source counters live in an 8,192-slot open-addressing table; when it's three-quarters full the least recently seen half is dropped, so a scan of a /16 can't grow it. Every second a size-K min-heap picks the top talkers, and they appear in `/metrics` as `pktan_source_bytes`.

On a Raspberry Pi 5 with a real home-network capture replayed 100 times (133,900 packets):

| | packets/s |
|---|---|
| Python engine (decode + stats) | 34,668 |
| C engine end to end (pktcap + Python stats) | 52,157 |
| C parsing alone (`pktcap -n`) | 3,780,082 |

C parses about 109 times faster than Python. End to end the gain is 1.5x, because Python's per-packet bookkeeping (stats, flows, names) is now the slow part. Either way it's far beyond what a home network sends. The live service uses about 9 MB for `pktcap` and 39 MB for Python.

## Anomaly detection

Every minute pktan turns each active device's traffic into ten numbers: packets and bytes out, bytes in, average packet size, distinct destinations, distinct ports, SYNs sent, resets received, DNS queries and ARP requests. They're log-scaled and appended to `$STATE_DIRECTORY/features.csv`, which is capped at 20 MB.

```bash
sudo apt install python3-sklearn        # only training needs it
cd /opt/pktan && sudo python3 -m pktan train --state-dir /var/lib/pktan
sudo systemctl restart pktan            # the service loads iforest.json on start
```

`train` fits scikit-learn's `IsolationForest` on the earliest 70% of rows, in time order. The alert threshold is the higher of 0.5 and the score that only 0.5% of training rows exceed. The trees are exported to `iforest.json`, and the service scores each device-minute in pure Python; a test checks the scores match scikit-learn's to 1e-9. A device has to score above the threshold for two minutes in a row before it raises an `anomaly` alert, which goes through SNS like the others. The alert names the features that are furthest from normal. Scores appear in `/metrics` as `pktan_anomaly_score` and on the Grafana dashboard.

`pktan evaluate` compares this with a typical fixed-threshold detector (static limits on packets, bytes, destinations, ports, SYNs, resets and DNS queries per minute) on the held-out rows and on recorded attacks.

## What the Pi can actually see

A packet analyzer only sees traffic that physically reaches its network card:

- **On Wi-Fi or a normal switch port**, the Pi sees its own traffic plus broadcast and multicast: ARP, DHCP, mDNS, SSDP, IPv6 neighbor discovery. That's enough to discover devices and names, but you won't see other devices' web browsing.
- **To see everything**, put the Pi in the path. You can:
  - plug it into a switch's mirror/SPAN port;
  - make it the network's router or access point (e.g. `hostapd` on `wlan0` with `eth0` as uplink, then capture on `wlan0`);
  - bridge `eth0` to a USB Ethernet adapter, sit it inline between the router and a device, and capture on `br0`.

When you watch it over SSH, add `-f "not port 22"`, or the analyzer ends up mostly watching its own output.

## Layout

```
pktan/
  decode.py    protocol decoders -> Packet
  capture.py   AF_PACKET + pcap sources, interface discovery, filter compiler
  engine.py    capture thread: decode -> filter -> stats / pcap writer
  stats.py     rolling counters, device/name tracking, alerts
  pcap.py      pcap reader/writer (size-capped)
  tui.py       sniff + top terminal views
  web.py       HTTP server, JSON API, Server-Sent Events, /metrics
  metrics.py   Prometheus text exposition
  aws.py       SigV4 signing, SNS alerts, S3 capture archiving
  cengine.py   runs csrc/pktcap and turns its records into Packets
  features.py  per-device feature windows and the capped CSV log
  iforest.py   Isolation Forest training (sklearn), export, pure-Python scoring, evaluation
csrc/          pktcap.c, the C capture engine, and its Makefile (make asan for a sanitizer build)
  static/index.html  dashboard (vanilla JS, no CDN, works offline)
deploy/k8s/    Prometheus + Grafana manifests and install script for k3s
deploy/grafana/  the provisioned dashboard
deploy/aws/    least-privilege IAM policy
tests/         python3 -m unittest discover -s tests
```

## Limitations

- Linux only (raw sockets use `AF_PACKET`). On other systems, `--read` still works.
- Reads classic `.pcap`, not `.pcapng`. Convert with `editcap -F pcap in.pcapng out.pcap`.
- No TCP stream reassembly: SNI and HTTP Host come from the first segment, which covers almost all real traffic.
- The anomaly model is only as good as the "normal" it was trained on. A model trained on a few hours hasn't seen nights, weekends or updates; retrain after a few days of logging.
- The filter is applied in Python, after capture. At several hundred Mbit/s on a Pi, expect drops. It's built for home and lab networks.
