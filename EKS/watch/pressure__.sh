#!/usr/bin/env bash
#
# k8s-node-memory-watchdog.sh (v2) ..beta edition..
#
# Node-level memory watchdog for Kubernetes nodes
# EKS / k3s / kubeadm compatible
#

set -euo pipefail

VERSION="2.0"

# -------------------------------
# Defaults (overridable via CLI)
# -------------------------------

MIN_MEM_AVAILABLE_PCT=10
MAX_CONTAINERD_RSS_KB=1500000
PSI_FULL_AVG10_THRESHOLD=1.0
PSI_SOME_AVG10_THRESHOLD=10.0
INTERVAL=0
MODE="log"          # log | stdout | json
VERBOSE=0

LOG_TAG="k8s-node-watchdog"

# -------------------------------
# Helpers
# -------------------------------

usage() {
  cat <<EOF
k8s-node-memory-watchdog v${VERSION}

Usage:
  $0 [options]

Modes:
  --stdout        Print human-readable output
  --json          Print JSON output
  --log           Log only (default, for cron/systemd)

Options:
  --interval N    Run every N seconds (loop mode)
  --min-mem-pct N Minimum MemAvailable percentage (default: 10)
  --max-containerd-rss-kb N
                  containerd RSS threshold (default: 1500000)
  --psi-full N    PSI full avg10 threshold (default: 1.0)
  --psi-some N    PSI some avg10 threshold (default: 10.0)
  -v              Verbose output
  -h              Help

Examples:
  One-shot CLI check:
    $0 --stdout

  Watch node degrade live:
    $0 --stdout --interval 2

  JSON for automation:
    $0 --json

  Cron / systemd:
    $0
EOF
}

log() {
  logger -p daemon.crit -t "$LOG_TAG" "$1"
}

read_meminfo() {
  awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print t, a}' /proc/meminfo
}

read_psi_memory() {
  awk '
    /some/ {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {gsub("avg10=","",$i); some=$i}}
    /full/ {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {gsub("avg10=","",$i); full=$i}}
    END {printf "%.2f %.2f", some, full}
  ' /proc/pressure/memory 2>/dev/null || echo "0.0 0.0"
}

containerd_rss_kb() {
  ps -o rss= -C containerd 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

# -------------------------------
# Argument parsing
# -------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stdout) MODE="stdout" ;;
    --json) MODE="json" ;;
    --log) MODE="log" ;;
    --interval) INTERVAL="$2"; shift ;;
    --min-mem-pct) MIN_MEM_AVAILABLE_PCT="$2"; shift ;;
    --max-containerd-rss-kb) MAX_CONTAINERD_RSS_KB="$2"; shift ;;
    --psi-full) PSI_FULL_AVG10_THRESHOLD="$2"; shift ;;
    --psi-some) PSI_SOME_AVG10_THRESHOLD="$2"; shift ;;
    -v) VERBOSE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

# -------------------------------
# Core check
# -------------------------------

check_once() {
  read MEM_TOTAL_KB MEM_AVAIL_KB <<< "$(read_meminfo)"
  MEM_AVAIL_PCT=$(( MEM_AVAIL_KB * 100 / MEM_TOTAL_KB ))

  read PSI_SOME_AVG10 PSI_FULL_AVG10 <<< "$(read_psi_memory)"
  CONTAINERD_RSS_KB="$(containerd_rss_kb)"

  CRITICAL=0
  REASONS=()

  (( MEM_AVAIL_PCT < MIN_MEM_AVAILABLE_PCT )) && {
    CRITICAL=1; REASONS+=("low_mem_pct")
  }

  awk -v v="$PSI_FULL_AVG10" -v t="$PSI_FULL_AVG10_THRESHOLD" 'BEGIN{exit !(v>t)}' && {
    CRITICAL=1; REASONS+=("psi_full")
  }

  awk -v v="$PSI_SOME_AVG10" -v t="$PSI_SOME_AVG10_THRESHOLD" 'BEGIN{exit !(v>t)}' && {
    CRITICAL=1; REASONS+=("psi_some")
  }

  (( CONTAINERD_RSS_KB > MAX_CONTAINERD_RSS_KB )) && {
    CRITICAL=1; REASONS+=("containerd_rss")
  }

  case "$MODE" in
    stdout)
      printf "%s mem_avail=%d%% psi_some=%.2f psi_full=%.2f containerd_rss=%dKB status=%s\n" \
        "$(date -Is)" "$MEM_AVAIL_PCT" "$PSI_SOME_AVG10" "$PSI_FULL_AVG10" \
        "$CONTAINERD_RSS_KB" \
        "$([[ $CRITICAL -eq 1 ]] && echo CRITICAL || echo OK)"
      ;;
    json)
      jq -n \
        --arg time "$(date -Is)" \
        --argjson mem_avail_pct "$MEM_AVAIL_PCT" \
        --argjson psi_some "$PSI_SOME_AVG10" \
        --argjson psi_full "$PSI_FULL_AVG10" \
        --argjson containerd_rss_kb "$CONTAINERD_RSS_KB" \
        --arg status "$([[ $CRITICAL -eq 1 ]] && echo CRITICAL || echo OK)" \
        '{time:$time,mem_avail_pct:$mem_avail_pct,psi_some:$psi_some,psi_full:$psi_full,containerd_rss_kb:$containerd_rss_kb,status:$status}'
      ;;
    log)
      (( CRITICAL == 1 )) && \
        log "CRITICAL mem_avail_pct=${MEM_AVAIL_PCT} psi_some=${PSI_SOME_AVG10} psi_full=${PSI_FULL_AVG10} containerd_rss_kb=${CONTAINERD_RSS_KB}"
      ;;
  esac
}

# -------------------------------
# Run
# -------------------------------

if (( INTERVAL > 0 )); then
  while true; do
    check_once
    sleep "$INTERVAL"
  done
else
  check_once
fi
