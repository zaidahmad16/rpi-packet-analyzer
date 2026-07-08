# pktan: Raspberry Pi network packet analyzer

A small network packet analyzer written in pure Python (standard library only), built to run on a Raspberry Pi. It captures traffic, decodes the common protocols, and shows you what's going on through a terminal UI or a live web dashboard.

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
- **Decoders:** Ethernet, 802.1Q, ARP, IPv4, IPv6 (with extension headers), TCP, UDP, ICMP/ICMPv6, DNS/mDNS/LLMNR, DHCP (including client hostnames), TLS SNI, HTTP Host, and QUIC detection.
- **Statistics:** throughput over time, protocol mix, top hosts, top conversations, top ports, DNS lookups, and the devices on the LAN, each with vendor (from the MAC prefix) plus hostnames learned from DNS, mDNS, DHCP and SNI.
- **Alerts:** new device joined, an IP address claimed by a different MAC (ARP spoofing or IP conflict), port scans, and unencrypted Telnet/FTP.
- **Filters** in a tcpdump-like syntax: `tcp port 443`, `dns or arp`, `host 10.0.0.5 and not port 22`, `net 192.168.1.0/24`, `src port 1000-2000`, `ip6`.
- **pcap in and out:** analyse captures from Wireshark/tcpdump (`--read`), or save traffic (`--write`) with a hard size cap.
- **Bounded memory:** every table is pruned, so it can run for weeks on a Pi.
- **Prometheus metrics** at `/metrics`, plus a ready-made **Grafana** dashboard, deployed to k3s next to pktan.
- **AWS:** alerts go to your phone or email through **SNS**, and saved captures upload to **S3**. AWS requests are signed with a hand-written Signature Version 4, so there's still nothing to install.
- **Tested:** 42 unit tests built from hand-made packets (and AWS's own SigV4 test vectors), so no capture privileges or AWS account are needed to run them.

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

Shared options: `-i IFACE` (or `any`), `-r FILE.pcap`, `-f FILTER`, `-w FILE.pcap --max-mb 50`, `--no-promisc`, and the AWS options `--sns-topic ARN`, `--alerts-per-hour N`, `--s3-bucket NAME`, `--s3-prefix P`.

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
- The filter is applied in Python, after capture. At several hundred Mbit/s on a Pi, expect drops. It's built for home and lab networks.
