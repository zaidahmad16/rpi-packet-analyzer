#!/usr/bin/env bash
# Install Prometheus + Grafana for pktan into k3s (run on the Pi, from the repo root).
#
#   sudo ./deploy/k8s/install.sh            # install / update
#   sudo ./deploy/k8s/install.sh --remove   # delete everything, including stored metrics
#
# pktan's web mode must be running on the host on port 8080 (see systemd/pktan.service);
# that's where Prometheus scrapes /metrics.
set -euo pipefail
cd "$(dirname "$0")/../.."
KUBECTL="${KUBECTL:-kubectl}"
command -v "$KUBECTL" >/dev/null || KUBECTL="k3s kubectl"

if [[ "${1:-}" == "--remove" ]]; then
  $KUBECTL delete namespace pktan --ignore-not-found
  exit 0
fi

$KUBECTL apply -f deploy/k8s/monitoring.yaml

$KUBECTL -n pktan create configmap grafana-dashboards \
  --from-file=pktan.json=deploy/grafana/pktan.json --dry-run=client -o yaml | $KUBECTL apply -f -

if ! $KUBECTL -n pktan get secret grafana-admin >/dev/null 2>&1; then
  PASS="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
  $KUBECTL -n pktan create secret generic grafana-admin --from-literal=password="$PASS"
  echo "Grafana admin password (shown once): $PASS"
  echo "Read it again later with:"
  echo "  $KUBECTL -n pktan get secret grafana-admin -o jsonpath='{.data.password}' | base64 -d"
fi

# pick up dashboard/config changes on re-runs
$KUBECTL -n pktan rollout restart deployment/grafana deployment/prometheus >/dev/null
$KUBECTL -n pktan rollout status deployment/prometheus --timeout=180s
$KUBECTL -n pktan rollout status deployment/grafana --timeout=180s
echo "Grafana:    http://$(hostname).local:30300"
echo "Prometheus: http://$(hostname).local:9090"
