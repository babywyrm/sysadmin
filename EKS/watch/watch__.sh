#!/usr/bin/env bash
set -euo pipefail

VERSION="3.3"

# -----------------------------
# Defaults
# -----------------------------
MODE="check"              # check | watch | doctor
OUTPUT="stdout"           # stdout | json | log
INTERVAL=0
ONCE=0
EXIT_ON_CRITICAL=0
INTERNAL=0

MIN_MEM_AVAILABLE_PCT=10
MAX_CONTAINERD_RSS_KB=1500000
PSI_FULL_AVG10_THRESHOLD=1.0
PSI_SOME_AVG10_THRESHOLD=10.0

LOG_TAG="k8s-node-watchdog"
STOP=0

# -----------------------------
# Signal Handling (CLI-friendly)
# -----------------------------
on_signal() {
  STOP=1
}
trap on_signal INT TERM

# -----------------------------
# Helpers
# -----------------------------
usage() {
cat <<EOF
k8s-node-memory-watchdog v${VERSION}

Usage:
  $0 [mode] [options]

Modes:
  check        One-shot health check (default)
  watch        Continuous monitoring
  doctor       Deep diagnostic snapshot

Options:
  --interval N                 Watch interval (seconds)
  --once                       Force one-shot execution
  --stdout | --json | --log    Output mode
  --exit-nonzero-on-critical   Exit 2 if CRITICAL
  --internal                   Extra diagnostics (safe, noisy)
  -h, --help                   Help

Examples:
  $0
  $0 watch
  $0 --interval 2 --json
  $0 doctor
EOF
}

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

log() {
  logger -p daemon.crit -t "$LOG_TAG" "$1"
}

ts() {
  date -Is
}

meta() {
  curl -s --max-time 1 http://169.254.169.254/latest/meta-data/$1 2>/dev/null || echo "unknown"
}

node_metadata() {
  cat <<EOF
hostname=$(hostname)
instance_id=$(meta instance-id)
instance_type=$(meta instance-type)
availability_zone=$(meta placement/availability-zone)
EOF
}

read_meminfo() {
  awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print t, a}' /proc/meminfo
}

read_psi() {
  awk '
    /some/ {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/){gsub("avg10=","",$i); s=$i}}
    /full/ {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/){gsub("avg10=","",$i); f=$i}}
    END {printf "%.2f %.2f", s, f}
  ' /proc/pressure/memory 2>/dev/null || echo "0.00 0.00"
}

containerd_rss() {
  ps -o rss= -C containerd 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

top_processes() {
  ps -eo pid,ppid,rss,cmd --sort=-rss | head -10
}

# -----------------------------
# Core Check
# -----------------------------
check_health() {
  read MEM_TOTAL MEM_AVAIL <<< "$(read_meminfo)"
  MEM_PCT=$(( MEM_AVAIL * 100 / MEM_TOTAL ))
  read PSI_SOME PSI_FULL <<< "$(read_psi)"
  CONTAINERD_RSS="$(containerd_rss)"

  STATUS="OK"
  EXIT=0
  REASONS=()

  (( MEM_PCT < MIN_MEM_AVAILABLE_PCT )) && {
    STATUS="CRITICAL"; EXIT=2; REASONS+=("low_mem")
  }

  awk -v v="$PSI_FULL" -v t="$PSI_FULL_AVG10_THRESHOLD" 'BEGIN{exit !(v>t)}' && {
    STATUS="CRITICAL"; EXIT=2; REASONS+=("psi_full")
  }

  (( CONTAINERD_RSS > MAX_CONTAINERD_RSS_KB )) && {
    STATUS="CRITICAL"; EXIT=2; REASONS+=("containerd_rss")
  }

  echo "$STATUS|$EXIT|$MEM_PCT|$PSI_SOME|$PSI_FULL|$CONTAINERD_RSS|${REASONS[*]}"
}

emit() {
  IFS='|' read STATUS EXIT MEM PSI_SOME PSI_FULL RSS REASONS <<< "$1"

  case "$OUTPUT" in
    stdout)
      echo "$(ts) status=$STATUS mem_avail=${MEM}% psi_some=$PSI_SOME psi_full=$PSI_FULL containerd_rss=${RSS}KB"
      ;;
    json)
      jq -n \
        --arg time "$(ts)" \
        --arg status "$STATUS" \
        --argjson mem_avail_pct "$MEM" \
        --argjson psi_some "$PSI_SOME" \
        --argjson psi_full "$PSI_FULL" \
        --argjson containerd_rss_kb "$RSS" \
        '{time:$time,status:$status,mem_avail_pct:$mem_avail_pct,psi_some:$psi_some,psi_full:$psi_full,containerd_rss_kb:$containerd_rss_kb}'
      ;;
    log)
      [[ "$STATUS" == "CRITICAL" ]] && \
        log "CRITICAL mem=${MEM}% psi_full=${PSI_FULL} containerd_rss=${RSS}"
      ;;
  esac

  (( EXIT_ON_CRITICAL && EXIT == 2 )) && exit 2
}

# -----------------------------
# Modes
# -----------------------------
run_check() {
  emit "$(check_health)"
}

run_watch() {
  set +e
  while [[ "$STOP" -eq 0 ]]; do
    RESULT="$(check_health 2>/dev/null || true)"
    emit "$RESULT" || true
    sleep "$INTERVAL"
  done
}

run_doctor() {
  echo "=== NODE METADATA ==="
  node_metadata
  echo
  echo "=== MEMORY ==="
  free -h
  echo
  echo "=== PSI ==="
  cat /proc/pressure/memory
  echo
  echo "=== CONTAINERD ==="
  ps -o pid,rss,cmd -C containerd || true
  echo
  echo "=== TOP PROCESSES ==="
  top_processes

  [[ "$INTERNAL" -eq 1 ]] && {
    echo
    echo "=== VMSTAT ==="
    vmstat 1 5
  }
}

# -----------------------------
# Argument Parsing
# -----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    check|watch|doctor) MODE="$1" ;;
    --interval) INTERVAL="$2"; shift ;;
    --once) ONCE=1 ;;
    --stdout) OUTPUT="stdout" ;;
    --json) OUTPUT="json" ;;
    --log) OUTPUT="log" ;;
    --exit-nonzero-on-critical) EXIT_ON_CRITICAL=1 ;;
    --internal) INTERNAL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
  shift
done

# -----------------------------
# Normalize Behavior
# -----------------------------
if [[ "$INTERVAL" -gt 0 && "$ONCE" -eq 0 ]]; then
  MODE="watch"
fi

[[ "$MODE" == "watch" && "$INTERVAL" -eq 0 ]] && INTERVAL=2

# -----------------------------
# Execute
# -----------------------------
case "$MODE" in
  doctor) run_doctor ;;
  watch) run_watch ;;
  check) run_check ;;
esac
