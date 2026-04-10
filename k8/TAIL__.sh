#!/usr/bin/env bash
# tail-k8s-logs.sh - Lightweight alternative to stern/kail using kubectl

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NAMESPACE="default"
SELECTOR=""
FILTER=""
ALL_NAMESPACES=false
TAIL_LINES=100
SINCE=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Tail logs from one or more running Kubernetes pods.

Options:
  -n NAMESPACE    Namespace to search (default: default)
  -l SELECTOR     Label selector (e.g. app=nginx)
  -g FILTER       Grep filter applied to log output (e.g. ERROR)
  -s SINCE        Only return logs newer than a relative duration (e.g. 5m, 1h)
  -t LINES        Number of tail lines per pod (default: 100)
  -a              Search across all namespaces
  -h              Show this help message

Examples:
  $(basename "$0") -n production -l app=api -g ERROR
  $(basename "$0") -a -l app=worker -t 50 -s 10m
EOF
  exit 0
}

require_cmd() {
  command -v "$1" &>/dev/null || die "'$1' is required but not installed."
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
while getopts ":n:l:g:s:t:ah" opt; do
  case $opt in
    n) NAMESPACE="$OPTARG" ;;
    l) SELECTOR="$OPTARG" ;;
    g) FILTER="$OPTARG" ;;
    s) SINCE="$OPTARG" ;;
    t) TAIL_LINES="$OPTARG" ;;
    a) ALL_NAMESPACES=true ;;
    h) usage ;;
    :) die "Option -${OPTARG} requires an argument." ;;
    *) die "Unknown option: -${OPTARG}. Run with -h for usage." ;;
  esac
done

# Validate TAIL_LINES is a positive integer
[[ "$TAIL_LINES" =~ ^[0-9]+$ ]] || die "-t requires a positive integer."

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
require_cmd kubectl
require_cmd jq

# ---------------------------------------------------------------------------
# Discover pods
# ---------------------------------------------------------------------------
log "Gathering pods..."

JQ_FILTER='.items[] | select(.status.phase=="Running") | [.metadata.namespace, .metadata.name] | @tsv'

if $ALL_NAMESPACES; then
  kubectl_args=(get pods --all-namespaces -o json)
else
  kubectl_args=(get pods -n "$NAMESPACE" -o json)
  [[ -n "$SELECTOR" ]] && kubectl_args+=(-l "$SELECTOR")
fi

PODS=$(kubectl "${kubectl_args[@]}" | jq -r "$JQ_FILTER") \
  || die "kubectl failed. Check your context and permissions."

[[ -z "$PODS" ]] && die "No running pods found matching the given criteria."

log "Matched pods:"
awk '{printf "  %s/%s\n", $1, $2}' <<< "$PODS"
echo ""

# ---------------------------------------------------------------------------
# Build shared kubectl logs flags
# ---------------------------------------------------------------------------
LOG_FLAGS=(--tail="$TAIL_LINES" -f)
[[ -n "$SINCE" ]] && LOG_FLAGS+=(--since="$SINCE")

# ---------------------------------------------------------------------------
# Tail logs
# ---------------------------------------------------------------------------
tail_pod() {
  local ns="$1" pod="$2"
  local prefix="[$ns/$pod]"

  kubectl logs -n "$ns" "$pod" "${LOG_FLAGS[@]}" 2>&1 | \
    while IFS= read -r line; do
      if [[ -z "$FILTER" ]] || echo "$line" | grep -q "$FILTER"; then
        echo "$prefix $line"
      fi
    done
}

while IFS=$'\t' read -r NS POD; do
  tail_pod "$NS" "$POD" &
done <<< "$PODS"

# ---------------------------------------------------------------------------
# Wait / cleanup
# ---------------------------------------------------------------------------
cleanup() {
  echo ""
  log "Shutting down..."
  # Kill all child processes spawned by this script
  pkill -P $$ 2>/dev/null || true
}

trap cleanup SIGINT SIGTERM
wait
