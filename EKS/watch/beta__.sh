#!/usr/bin/env bash
#
# k8s-node-memory-watchdog.sh (v2.1) ..enhanced edition..
#
# Node-level memory watchdog for Kubernetes nodes
# EKS / k3s / kubeadm compatible
#

set -euo pipefail

VERSION="2.1"

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
HOSTNAME="${HOSTNAME:-$(hostname -s)}"

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

die() {
  echo "ERROR: $1" >&2
  exit 1
}

log() {
  if command -v systemd-cat &>/dev/null; then
    echo "$1" | systemd-cat -t "$LOG_TAG" -p crit
  else
    logger -p daemon.crit -t "$LOG_TAG" "$1"
  fi
}

read_meminfo() {
  [[ -r /proc/meminfo ]] || die "/proc/meminfo not readable"
  awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {
    if (t=="" || a=="") exit 1
    print t, a
  }' /proc/meminfo
}

read_psi_memory() {
  if [[ ! -r /proc/pressure/memory ]]; then
    [[ $VERBOSE -eq 1 ]] && echo "PSI not available" >&2
    echo "0.0 0.0"
    return
  fi
  
  awk '
    /some/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^avg10=/) {
          gsub("avg10=","",$i)
          some=$i
        }
      }
    }
    /full/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^avg10=/) {
          gsub("avg10=","",$i)
          full=$i
        }
      }
    }
    END {
      if (some=="") some="0.0"
      if (full=="") full="0.0"
      printf "%.2f %.2f", some, full
    }
  ' /proc/pressure/memory
}

containerd_rss_kb() {
  if ! pgrep -x containerd >/dev/null 2>&1; then
    [[ $VERBOSE -eq 1 ]] && echo "containerd not running" >&2
    echo "0"
    return
  fi
  
  ps -o rss= -C containerd 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

validate_thresholds() {
  [[ $MIN_MEM_AVAILABLE_PCT =~ ^[0-9]+$ ]] || \
    die "Invalid --min-mem-pct: must be integer"
  [[ $MAX_CONTAINERD_RSS_KB =~ ^[0-9]+$ ]] || \
    die "Invalid --max-containerd-rss-kb: must be integer"
  [[ $INTERVAL =~ ^[0-9]+$ ]] || \
    die "Invalid --interval: must be integer"
}

# Signal handling for clean shutdown
cleanup() {
  [[ $MODE == "stdout" ]] && echo -e "\nShutdown requested"
  exit 0
}

trap cleanup SIGINT SIGTERM

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

validate_thresholds

# -------------------------------
# Core check
# -------------------------------

check_once() {
  local timestamp="$(date -Iseconds)"
  
  read MEM_TOTAL_KB MEM_AVAIL_KB <<< "$(read_meminfo)"
  MEM_AVAIL_PCT=$(( MEM_AVAIL_KB * 100 / MEM_TOTAL_KB ))

  read PSI_SOME_AVG10 PSI_FULL_AVG10 <<< "$(read_psi_memory)"
  CONTAINERD_RSS_KB="$(containerd_rss_kb)"

  CRITICAL=0
  REASONS=()

  # Check conditions
  if (( MEM_AVAIL_PCT < MIN_MEM_AVAILABLE_PCT )); then
    CRITICAL=1
    REASONS+=("low_mem:${MEM_AVAIL_PCT}%<${MIN_MEM_AVAILABLE_PCT}%")
  fi

  if awk -v v="$PSI_FULL_AVG10" -v t="$PSI_FULL_AVG10_THRESHOLD" \
    'BEGIN{exit !(v>t)}'; then
    CRITICAL=1
    REASONS+=("psi_full:${PSI_FULL_AVG10}>${PSI_FULL_AVG10_THRESHOLD}")
  fi

  if awk -v v="$PSI_SOME_AVG10" -v t="$PSI_SOME_AVG10_THRESHOLD" \
    'BEGIN{exit !(v>t)}'; then
    CRITICAL=1
    REASONS+=("psi_some:${PSI_SOME_AVG10}>${PSI_SOME_AVG10_THRESHOLD}")
  fi

  if (( CONTAINERD_RSS_KB > MAX_CONTAINERD_RSS_KB )); then
    CRITICAL=1
    REASONS+=("containerd_rss:${CONTAINERD_RSS_KB}KB>${MAX_CONTAINERD_RSS_KB}KB")
  fi

  STATUS="OK"
  [[ $CRITICAL -eq 1 ]] && STATUS="CRITICAL"

  # Format reasons
  REASONS_STR=""
  if [[ ${#REASONS[@]} -gt 0 ]]; then
    REASONS_STR="$(IFS=,; echo "${REASONS[*]}")"
  fi

  # Output based on mode
  case "$MODE" in
    stdout)
      printf "[%s] %s mem_avail=%d%% psi_some=%.2f psi_full=%.2f containerd_rss=%dKB status=%s" \
        "$timestamp" "$HOSTNAME" "$MEM_AVAIL_PCT" "$PSI_SOME_AVG10" \
        "$PSI_FULL_AVG10" "$CONTAINERD_RSS_KB" "$STATUS"
      [[ -n "$REASONS_STR" ]] && printf " reasons=%s" "$REASONS_STR"
      printf "\n"
      ;;
    
    json)
      jq -n \
        --arg time "$timestamp" \
        --arg hostname "$HOSTNAME" \
        --argjson mem_avail_pct "$MEM_AVAIL_PCT" \
        --argjson mem_total_kb "$MEM_TOTAL_KB" \
        --argjson mem_avail_kb "$MEM_AVAIL_KB" \
        --argjson psi_some "$PSI_SOME_AVG10" \
        --argjson psi_full "$PSI_FULL_AVG10" \
        --argjson containerd_rss_kb "$CONTAINERD_RSS_KB" \
        --arg status "$STATUS" \
        --arg reasons "$REASONS_STR" \
        '{
          time: $time,
          hostname: $hostname,
          memory: {
            total_kb: $mem_total_kb,
            available_kb: $mem_avail_kb,
            available_pct: $mem_avail_pct
          },
          psi: {
            some_avg10: $psi_some,
            full_avg10: $psi_full
          },
          containerd_rss_kb: $containerd_rss_kb,
          status: $status,
          reasons: ($reasons | split(","))
        }'
      ;;
    
    log)
      if (( CRITICAL == 1 )); then
        log "CRITICAL node=${HOSTNAME} mem_avail_pct=${MEM_AVAIL_PCT} psi_some=${PSI_SOME_AVG10} psi_full=${PSI_FULL_AVG10} containerd_rss_kb=${CONTAINERD_RSS_KB} reasons=[${REASONS_STR}]"
      elif (( VERBOSE == 1 )); then
        log "OK node=${HOSTNAME} mem_avail_pct=${MEM_AVAIL_PCT}"
      fi
      ;;
  esac

  return $CRITICAL
}

# -------------------------------
# Run
# -------------------------------

if (( INTERVAL > 0 )); then
  [[ $MODE == "stdout" ]] && echo "Starting watchdog (interval=${INTERVAL}s, Ctrl+C to stop)..."
  
  while true; do
    check_once || true  # Don't exit on critical
    sleep "$INTERVAL"
  done
else
  check_once
  exit $?
fi
