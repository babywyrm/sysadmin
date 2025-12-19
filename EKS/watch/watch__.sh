#!/usr/bin/env bash
set -euo pipefail

VERSION="3.7.1"

MODE="check"          # check | watch
OUTPUT="stdout"       # stdout | json
INTERVAL=5
PODS=0
TOP_N=5

MIN_MEM_AVAILABLE_PCT=10
PSI_FULL_THRESHOLD=1.0

STOP=0
trap 'STOP=1' INT TERM

ts() { date -Is; }

# -----------------------------
# Node metrics
# -----------------------------
read_meminfo() {
  awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print t, a}' /proc/meminfo
}

read_psi_full() {
  awk '
    /full/ {
      for (i=1;i<=NF;i++)
        if ($i ~ /^avg10=/) {gsub("avg10=","",$i); print $i}
    }
  ' /proc/pressure/memory 2>/dev/null || echo 0
}

containerd_rss() {
  ps -o rss= -C containerd 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

# -----------------------------
# Pod metadata
# -----------------------------
resolve_pod_metadata() {
  local pod_uid="$1"
  for d in /var/log/pods/*_"$pod_uid"; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    echo "${base%%_*}|$(echo "$base" | cut -d_ -f2)"
    return
  done
  echo "unknown|unknown"
}

# -----------------------------
# Pod memory (numeric, no sentinels)
# -----------------------------
collect_pod_memory() {
  declare -gA POD_USED_BYTES POD_LIMIT_BYTES POD_HAS_LIMIT

  POD_USED_BYTES=()
  POD_LIMIT_BYTES=()
  POD_HAS_LIMIT=()

  for cg in /sys/fs/cgroup/kubepods.slice/kubepods-*/*/*; do
    [[ -f "$cg/memory.current" ]] || continue

    used="$(cat "$cg/memory.current")"
    raw_limit="$(cat "$cg/memory.max")"

    slice="$(basename "$(dirname "$cg")")"
    pod_uid="$(echo "$slice" | sed 's/.*pod//;s/\.slice//;s/_/-/g')"

    POD_USED_BYTES["$pod_uid"]=$(( ${POD_USED_BYTES["$pod_uid"]:-0} + used ))

    if [[ "$raw_limit" == "max" ]]; then
      POD_HAS_LIMIT["$pod_uid"]=0
    else
      POD_HAS_LIMIT["$pod_uid"]=1
      if [[ -z "${POD_LIMIT_BYTES["$pod_uid"]:-}" || "$raw_limit" -lt "${POD_LIMIT_BYTES["$pod_uid"]}" ]]; then
        POD_LIMIT_BYTES["$pod_uid"]="$raw_limit"
      fi
    fi
  done
}

classify_pod() {
  local used_mi="$1"
  local has_limit="$2"
  local limit_bytes="$3"

  if [[ "$has_limit" -eq 0 ]]; then
    echo "RISK|∞|NO LIMIT"
    return
  fi

  limit_mi=$(( limit_bytes / 1024 / 1024 ))
  pct=$(( used_mi * 100 / limit_mi ))

  if (( pct >= 90 )); then
    echo "CRITICAL|${limit_mi}Mi|${pct}%"
  elif (( pct >= 70 )); then
    echo "WARN|${limit_mi}Mi|${pct}%"
  else
    echo "OK|${limit_mi}Mi|${pct}%"
  fi
}

print_pods() {
  collect_pod_memory

  rows=()
  risks=()

  for pod_uid in "${!POD_USED_BYTES[@]}"; do
    used_mi=$(( POD_USED_BYTES["$pod_uid"] / 1024 / 1024 ))
    has_limit="${POD_HAS_LIMIT["$pod_uid"]:-0}"
    limit_bytes="${POD_LIMIT_BYTES["$pod_uid"]:-0}"

    IFS='|' read ns name <<< "$(resolve_pod_metadata "$pod_uid")"
    IFS='|' read sev limit pct <<< "$(classify_pod "$used_mi" "$has_limit" "$limit_bytes")"

    line=$(printf "%-9s %-12s %-35s used=%4sMi limit=%-6s %s" \
      "$sev" "$ns" "$name" "$used_mi" "$limit" "$pct")

    rows+=("$used_mi|$line")

    if [[ "$sev" == "RISK" ]]; then
      risks+=("$line")
    fi
  done

  echo "=== TOP POD MEMORY OFFENDERS ==="
  printf "%s\n" "${rows[@]}" | sort -nr | head -"$TOP_N" | cut -d'|' -f2- || true

  if (( ${#risks[@]} > 0 )); then
    echo
    echo "=== POLICY RISKS (NO MEMORY LIMITS) ==="
    printf "%s\n" "${risks[@]}"
  fi
}

# -----------------------------
# Node health
# -----------------------------
check_node() {
  read total avail <<< "$(read_meminfo)"
  mem_pct=$(( avail * 100 / total ))
  psi_full="$(read_psi_full)"
  rss="$(containerd_rss)"

  status="OK"
  if (( mem_pct < MIN_MEM_AVAILABLE_PCT )); then
    status="CRITICAL"
  fi
  if awk -v p="$psi_full" -v t="$PSI_FULL_THRESHOLD" 'BEGIN{exit !(p>t)}'; then
    status="CRITICAL"
  fi

  if [[ "$OUTPUT" == "json" ]]; then
    jq -n \
      --arg time "$(ts)" \
      --arg status "$status" \
      --argjson mem_avail_pct "$mem_pct" \
      --argjson psi_full "$psi_full" \
      --argjson containerd_rss_kb "$rss" \
      '{time:$time,status:$status,mem_avail_pct:$mem_avail_pct,psi_full:$psi_full,containerd_rss_kb:$containerd_rss_kb}'
  else
    echo "$(ts) status=$status mem_avail=${mem_pct}% psi_full=${psi_full} containerd_rss=${rss}KB"
  fi
}

run_once() {
  echo "=== NODE HEALTH ==="
  check_node

  if [[ "$PODS" -eq 1 ]]; then
    echo
    print_pods
  fi
}

run_watch() {
  while [[ "$STOP" -eq 0 ]]; do
    run_once
    sleep "$INTERVAL"
    echo
  done
}

# -----------------------------
# Args
# -----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    check|watch) MODE="$1" ;;
    --interval) INTERVAL="$2"; shift ;;
    --json) OUTPUT="json" ;;
    --pods) PODS=1 ;;
    --top) TOP_N="$2"; shift ;;
    -h|--help)
      echo "Usage: $0 [check|watch] [--interval N] [--pods] [--top N] [--json]"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

case "$MODE" in
  watch) run_watch ;;
  *) run_once ;;
esac
