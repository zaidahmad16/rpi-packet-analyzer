#!/usr/bin/env bash
# Copy pktan to a Raspberry Pi (or any Linux host) and optionally install the
# dashboard as a systemd service.
#
#   ./install-pi.sh                       # copy to $USER@raspberrypi.local:~/pktan
#   ./install-pi.sh pi@192.168.1.40       # different host
#   ./install-pi.sh pi@host --service     # also install + start the service on :8080
#
# Uninstall the service:  ssh HOST 'sudo systemctl disable --now pktan; sudo rm -rf /opt/pktan /etc/systemd/system/pktan.service'
set -euo pipefail

HOST="${1:-${PKTAN_HOST:-$USER@raspberrypi.local}}"
SERVICE="${2:-}"
cd "$(dirname "$0")"

echo "==> copying to $HOST:~/pktan"
tar --exclude='__pycache__' --exclude='*.pcap*' -czf - pktan tests systemd README.md \
  | ssh "$HOST" 'rm -rf ~/pktan && mkdir -p ~/pktan && tar -xzf - -C ~/pktan'

echo "==> running tests on $HOST"
ssh "$HOST" 'cd ~/pktan && python3 -m unittest discover -s tests 2>&1 | tail -1'

if [[ "$SERVICE" == "--service" ]]; then
  echo "==> installing systemd service (needs sudo on $HOST)"
  ssh -t "$HOST" 'sudo rm -rf /opt/pktan && sudo cp -r ~/pktan /opt/pktan &&
    sudo cp /opt/pktan/systemd/pktan.service /etc/systemd/system/ &&
    sudo systemctl daemon-reload && sudo systemctl enable --now pktan &&
    sleep 2 && systemctl --no-pager status pktan | head -5'
  echo "==> dashboard: http://${HOST#*@}:8080"
else
  echo "==> done. On the Pi:  cd ~/pktan && sudo python3 -m pktan top"
fi
