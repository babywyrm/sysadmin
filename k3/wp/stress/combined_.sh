#!/usr/bin/env bash
#
# stress.sh – simple bash/curl stress tester for k3s workloads
#
# Usage:
#   bash stress.sh {baseline|burst|sustained|sweeper|post|internal} [workload]
#
# Examples:
#   bash stress.sh baseline wordpress
#   bash stress.sh burst cms
#   bash stress.sh post nginx
#   bash stress.sh internal wordpress
#

set -euo pipefail

# Map of workloads → external URLs (for Ingress/LB)
declare -A WORKLOADS=(
  ["wordpress"]="http://wordpress.local"
  ["cms"]="http://cms.local"
  ["nginx"]="http://nginx.local"
)

MODE="${1:-}"
WORKLOAD="${2:-wordpress}"

# --- resolve workload target ---
if [[ "$MODE" == "internal" ]]; then
  # Grab ClusterIP service endpoint
  TARGET=$(kubectl get svc "$WORKLOAD" -o jsonpath='{.spec.clusterIP}:{.spec.ports[0].port}' 2>/dev/null || true)
  if [[ -z "$TARGET" ]]; then
    echo "[!] Could not resolve ClusterIP for workload '$WORKLOAD'"
    echo "    Run: kubectl get svc -A"
    exit 1
  fi
  TARGET="http://$TARGET"
else
  TARGET=${WORKLOADS[$WORKLOAD]:-}
  if [[ -z "$TARGET" ]]; then
    echo "[!] Unknown workload: $WORKLOAD"
    echo "Available workloads: ${!WORKLOADS[@]}"
    exit 1
  fi
fi

echo "[*] Mode=$MODE Workload=$WORKLOAD Target=$TARGET"
echo

# --- modes ---
function baseline() {
  while true; do
    ts=$(date +"%H:%M:%S")
    curl -s -o /dev/null -w "[$ts] Total=%{time_total}s\n" "$TARGET"
    sleep 1
  done
}

function burst() {
  for i in {1..50}; do
    curl -s -o /dev/null -w "[BURST] Code=%{http_code} Total=%{time_total}s\n" "$TARGET" &
  done
  wait
}

function sustained() {
  for i in {1..300}; do
    curl -s -o /dev/null -w "[SUSTAINED] Code=%{http_code} Total=%{time_total}s\n" "$TARGET" &
    sleep 0.2
  done
  wait
}

function sweeper() {
  WORDS=(admin wp-login dashboard api assets uploads)
  for w in "${WORDS[@]}"; do
    curl -s -o /dev/null -w "[SWEEP] /$w Code=%{http_code} Total=%{time_total}s\n" "$TARGET/$w"
  done
}

function post() {
  for i in {1..50}; do
    curl -s -X POST \
      -d "action=test&id=$i" \
      -o /dev/null -s \
      -w "[POST] %{http_code} Total=%{time_total}s\n" \
      "$TARGET/wp-admin/admin-ajax.php" &
  done
  wait
}

# --- dispatcher ---
case "$MODE" in
  baseline)   baseline ;;
  burst)      burst ;;
  sustained)  sustained ;;
  sweeper)    sweeper ;;
  post)       post ;;
  internal)   baseline ;;  # default to baseline test inside cluster
  *)
    echo "Usage: $0 {baseline|burst|sustained|sweeper|post|internal} [workload]"
    echo "Available workloads: ${!WORKLOADS[@]}"
    exit 1
    ;;
esac
