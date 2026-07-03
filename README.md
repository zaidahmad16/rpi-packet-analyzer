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
- **Tested:** 26 unit tests built from hand-made packets, so no capture privileges are needed to run them.

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
This copies the code to `/opt/pktan` and installs `systemd/pktan.service`. The service runs as `nobody` with only the raw-capture capabilities and a 200 MB memory cap.

## Commands

| Command | What it does |
|---|---|
| `pktan list` | List interfaces and show which one is the default |
| `pktan sniff [-c N] [--stats]` | Print packets as they arrive; `--stats` adds a summary at the end |
| `pktan top [--realtime]` | Full-screen terminal dashboard |
| `pktan web [--port 8080] [--bind ADDR]` | Web dashboard (JSON at `/api/stats`, live stream at `/events`) |

Shared options: `-i IFACE` (or `any`), `-r FILE.pcap`, `-f FILTER`, `-w FILE.pcap --max-mb 50`, `--no-promisc`.

`web` hides its own dashboard traffic automatically (`--include-self` turns that off).

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
  web.py       HTTP server, JSON API, Server-Sent Events
  static/index.html  dashboard (vanilla JS, no CDN, works offline)
tests/         python3 -m unittest discover -s tests
```

## Limitations

- Linux only (raw sockets use `AF_PACKET`). On other systems, `--read` still works.
- Reads classic `.pcap`, not `.pcapng`. Convert with `editcap -F pcap in.pcapng out.pcap`.
- No TCP stream reassembly: SNI and HTTP Host come from the first segment, which covers almost all real traffic.
- The filter is applied in Python, after capture. At several hundred Mbit/s on a Pi, expect drops. It's built for home and lab networks.
