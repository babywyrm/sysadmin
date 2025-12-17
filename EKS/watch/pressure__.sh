#!/usr/bin/env bash
#
# k8s-node-memory-watchdog.sh
#
# Node-level memory watchdog for Kubernetes (EKS / k3s / kubeadm)
# Detects memory pressure, containerd leaks, and kernel stall conditions
#
# Safe: logs only (no remediation)
#

set -euo pipefail

# -------------------------------
# Tunables (safe defaults)
# -------------------------------

MIN_MEM_AVAILABLE_PCT=10        # % MemAvailable threshold
MAX_CONTAINERD_RSS_KB=1500000  # ~1.5GB
PSI_FULL_AVG10_THRESHOLD=1.0
PSI_SOME_AVG10_THRESHOLD=10.0

LOG_TAG="k8s-node-watchdog"
NOW="$(date -Is)"

# -------------------------------
# Helpers
# -------------------------------

log() {
  logger -p daemon.crit -t "$LOG_TAG" "$1"
}

read_meminfo() {
  awk '
    /MemTotal/ {t=$2}
    /MemAvailable/ {a=$2}
    END {printf "%d %d", t, a}
  ' /proc/meminfo
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

top_rss_processes() {
  ps -eo pid,ppid,rss,cmd --sort=-rss | head -10
}

# -------------------------------
# Collect metrics
# -------------------------------

read MEM_TOTAL_KB MEM_AVAIL_KB <<< "$(read_meminfo)"
MEM_AVAIL_PCT=$(( MEM_AVAIL_KB * 100 / MEM_TOTAL_KB ))

read PSI_SOME_AVG10 PSI_FULL_AVG10 <<< "$(read_psi_memory)"
CONTAINERD_RSS_KB="$(containerd_rss_kb)"

# -------------------------------
# Evaluate conditions
# -------------------------------

CRITICAL=0
REASONS=()

if (( MEM_AVAIL_PCT < MIN_MEM_AVAILABLE_PCT )); then
  CRITICAL=1
  REASONS+=("low_mem_available=${MEM_AVAIL_PCT}%")
fi

awk -v v="$PSI_FULL_AVG10" -v t="$PSI_FULL_AVG10_THRESHOLD" 'BEGIN{exit !(v>t)}' && {
  CRITICAL=1
  REASONS+=("psi_full_avg10=${PSI_FULL_AVG10}")
}

awk -v v="$PSI_SOME_AVG10" -v t="$PSI_SOME_AVG10_THRESHOLD" 'BEGIN{exit !(v>t)}' && {
  CRITICAL=1
  REASONS+=("psi_some_avg10=${PSI_SOME_AVG10}")
}

if (( CONTAINERD_RSS_KB > MAX_CONTAINERD_RSS_KB )); then
  CRITICAL=1
  REASONS+=("containerd_rss_kb=${CONTAINERD_RSS_KB}")
fi

# -------------------------------
# Log if critical
# -------------------------------

if (( CRITICAL == 1 )); then
  log "CRITICAL memory condition detected time=${NOW} reasons=$(IFS=,; echo "${REASONS[*]}") mem_avail_pct=${MEM_AVAIL_PCT} containerd_rss_kb=${CONTAINERD_RSS_KB}"
  log "Top RSS processes:"
  top_rss_processes | logger -p daemon.crit -t "$LOG_TAG"
fi

exit 0
