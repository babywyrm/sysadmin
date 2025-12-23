#!/usr/bin/env bash
set -euo pipefail

VERSION="3.7.2"

MODE="check"          # check | watch
OUTPUT="stdout"       # stdout | json
INTERVAL=5
PODS=0
TOP_N=5

MIN_MEM_AVAILABLE_PCT=10
PSI_FULL_THRESHOLD=1.0

# Dependencies check
if [[ "$OUTPUT" == "json" ]] && ! command -v jq &>/dev/null; then
    echo "Error: 'jq' is required for JSON output." >&2
    exit 1
fi

# Cgroup V2 Check
if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
    echo "Error: This script requires Cgroup V2 mounted at /sys/fs/cgroup" >&2
    exit 1
fi

STOP=0
trap 'STOP=1' INT TERM

# Caching for Pod Metadata to reduce IO in watch mode
declare -gA POD_META_CACHE

# Colors
RED=""
YELLOW=""
GREEN=""
RESET=""
BOLD=""

if [[ -t 1 ]] && [[ "$OUTPUT" != "json" ]]; then
    RED=$(tput setaf 1)
    YELLOW=$(tput setaf 3)
    GREEN=$(tput setaf 2)
    RESET=$(tput sgr0)
    BOLD=$(tput bold)
fi

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
  # Looking for containerd or containerd-shim
  ps -o rss= -C containerd,containerd-shim 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

# -----------------------------
# Pod metadata
# -----------------------------
resolve_pod_metadata() {
  local pod_uid="$1"
  
  # Return cached if exists
  if [[ -n "${POD_META_CACHE[$pod_uid]:-}" ]]; then
      echo "${POD_META_CACHE[$pod_uid]}"
      return
  fi

  local meta="unknown|unknown"
  # Standard Kubelet path
  for d in /var/log/pods/*_"$pod_uid"_*; do
    if [[ -d "$d" ]]; then
      base="$(basename "$d")"
      # Format: namespace_name_uid
      # We just want namespace|name
      local ns="${base%%_*}"
      local rest="${base#*_}"
      local name="${rest%_*}"
      meta="${ns}|${name}"
      break
    fi
  done

  # Update Cache
  POD_META_CACHE["$pod_uid"]="$meta"
  echo "$meta"
}

# -----------------------------
# Pod memory logic
# -----------------------------
collect_pod_data() {
  # Global arrays to store data for this iteration
  declare -gA POD_STATS_USED
  declare -gA POD_STATS_LIMIT
  declare -gA POD_STATS_HAS_LIMIT
  
  POD_STATS_USED=()
  POD_STATS_LIMIT=()
  POD_STATS_HAS_LIMIT=()

  # Iterate over Systemd slices for Kubepods
  # Path usually: /sys/fs/cgroup/kubepods.slice/kubepods-*.slice/kubepods-*-pod[UID].slice/
  local cgroup_root="/sys/fs/cgroup/kubepods.slice"

  # Use find to locate memory.current efficiently maxdepth 4 to avoid container level
  while IFS= read -r file; do
    local cg dir
    dir=$(dirname "$file")
    
    # Extract UID from directory name (systemd encoding uses underscores for dashes, etc)
    # Expected: ...-pod<UID>.slice
    local dirname_base
    dirname_base=$(basename "$dir")
    
    # Very basic filter to ensure we are at pod level (contains "pod") and not a container
    if [[ "$dirname_base" != *".slice" ]] || [[ "$dirname_base" != *"pod"* ]]; then
        continue
    fi

    # Extract UID: Remove "kubepods-...", remove ".slice", replace _ with -
    # This logic is brittle but standard for systemd driver
    local pod_uid
    pod_uid=$(echo "$dirname_base" | sed -E 's/.*pod//;s/\.slice//;s/_/-/g')
    
    local used
    used=$(cat "$file")
    
    # Aggregate (though usually one cgroup per pod, redundancy check)
    POD_STATS_USED["$pod_uid"]=$(( ${POD_STATS_USED["$pod_uid"]:-0} + used ))

    # Limits
    local limit_file="$dir/memory.max"
    if [[ -f "$limit_file" ]]; then
        local raw_limit
        raw_limit=$(cat "$limit_file")
        
        if [[ "$raw_limit" == "max" ]]; then
             POD_STATS_HAS_LIMIT["$pod_uid"]=0
        else
             POD_STATS_HAS_LIMIT["$pod_uid"]=1
             # If multiple containers, take the pod level. 
             # Note: logic here assumes we are reading the POD slice, which sums children.
             POD_STATS_LIMIT["$pod_uid"]="$raw_limit"
        fi
    else
        POD_STATS_HAS_LIMIT["$pod_uid"]=0
    fi

  done < <(find "$cgroup_root" -mindepth 3 -maxdepth 4 -name memory.current 2>/dev/null)
}

classify_pod() {
  local used_mi="$1"
  local has_limit="$2"
  local limit_bytes="$3"

  if [[ "$has_limit" -eq 0 ]]; then
    # Severity | LimitStr | PctStr | RawPct
    echo "RISK|∞|NO LIMIT|0"
    return
  fi

  local limit_mi=$(( limit_bytes / 1024 / 1024 ))
  
  # Use awk for float comparison/calculation
  local pct
  pct=$(awk -v u="$used_mi" -v l="$limit_mi" 'BEGIN { if(l==0) print 0; else printf "%.0f", (u/l)*100 }')

  if (( pct >= 90 )); then
    echo "CRITICAL|${limit_mi}Mi|${pct}%|${pct}"
  elif (( pct >= 75 )); then
    echo "WARN|${limit_mi}Mi|${pct}%|${pct}"
  else
    echo "OK|${limit_mi}Mi|${pct}%|${pct}"
  fi
}

# -----------------------------
# Main Logic
# -----------------------------
generate_report() {
  # 1. Gather Node Metrics
  read total avail <<< "$(read_meminfo)"
  mem_pct=$(( avail * 100 / total ))
  psi_full="$(read_psi_full)"
  rss="$(containerd_rss)"

  # Node Status
  local node_status="OK"
  if (( mem_pct < MIN_MEM_AVAILABLE_PCT )); then node_status="CRITICAL"; fi
  if awk -v p="$psi_full" -v t="$PSI_FULL_THRESHOLD" 'BEGIN{exit !(p>t)}'; then node_status="CRITICAL"; fi

  # 2. Gather Pod Metrics (if enabled)
  local pod_json_array="[]"
  local text_rows=()
  local text_risks=()

  if [[ "$PODS" -eq 1 ]]; then
    collect_pod_data

    # Use a temp file for sorting text output
    local temp_sort_file
    temp_sort_file=$(mktemp)

    for pod_uid in "${!POD_STATS_USED[@]}"; do
      used_mi=$(( POD_STATS_USED["$pod_uid"] / 1024 / 1024 ))
      has_limit="${POD_STATS_HAS_LIMIT["$pod_uid"]:-0}"
      limit_bytes="${POD_STATS_LIMIT["$pod_uid"]:-0}"

      IFS='|' read ns name <<< "$(resolve_pod_metadata "$pod_uid")"
      IFS='|' read sev limit_str pct_str raw_pct <<< "$(classify_pod "$used_mi" "$has_limit" "$limit_bytes")"

      # JSON Accumulation
      if [[ "$OUTPUT" == "json" ]]; then
        # Inefficient but safe bash JSON construction loop
         pod_json_array=$(jq -n \
            --argjson list "$pod_json_array" \
            --arg ns "$ns" \
            --arg name "$name" \
            --argjson used_mi "$used_mi" \
            --arg limit "$limit_str" \
            --arg sev "$sev" \
            --arg pct "$raw_pct" \
            '$list + [{ns:$ns, name:$name, used_mi:$used_mi, limit:$limit, severity:$sev, usage_pct:$pct}]')
      else
        # Text Formatting
        local color="$GREEN"
        [[ "$sev" == "WARN" ]] && color="$YELLOW"
        [[ "$sev" == "CRITICAL" ]] && color="$RED${BOLD}"
        [[ "$sev" == "RISK" ]] && color="$YELLOW${BOLD}"
        
        # Format: SortKey|DisplayString
        # We sort by usage (used_mi) descending
        local line
        line=$(printf "%s%-9s%s %-12s %-35s used=%4sMi limit=%-6s %s" \
          "$color" "$sev" "$RESET" "$ns" "$name" "$used_mi" "$limit_str" "$pct_str")
        
        echo "$used_mi|$line" >> "$temp_sort_file"

        if [[ "$sev" == "RISK" ]]; then
           text_risks+=("$line")
        fi
      fi
    done
    
    if [[ "$OUTPUT" != "json" ]]; then
        mapfile -t text_rows < <(sort -nr "$temp_sort_file" | cut -d'|' -f2- | head -"$TOP_N")
        rm -f "$temp_sort_file"
    fi
  fi

  # 3. Output
  if [[ "$OUTPUT" == "json" ]]; then
    jq -n \
      --arg time "$(ts)" \
      --arg status "$node_status" \
      --argjson mem_avail_pct "$mem_pct" \
      --argjson psi_full "$psi_full" \
      --argjson containerd_rss_kb "$rss" \
      --argjson pods "$pod_json_array" \
      '{time:$time,status:$status,mem_avail_pct:$mem_avail_pct,psi_full:$psi_full,containerd_rss_kb:$containerd_rss_kb, pods:$pods}'
  else
    # Header Color
    local status_color="$GREEN"
    [[ "$node_status" != "OK" ]] && status_color="$RED${BOLD}"
    
    echo "=== NODE HEALTH ==="
    echo "$(ts) status=${status_color}${node_status}${RESET} mem_avail=${mem_pct}% psi_full=${psi_full} containerd_rss=${rss}KB"

    if [[ "$PODS" -eq 1 ]]; then
      echo
      echo "=== TOP POD MEMORY OFFENDERS ==="
      printf "%s\n" "${text_rows[@]}"

      if (( ${#text_risks[@]} > 0 )); then
        echo
        echo "=== POLICY RISKS (NO MEMORY LIMITS) ==="
        printf "%s\n" "${text_risks[@]}"
      fi
    fi
  fi
}

run_watch() {
  while [[ "$STOP" -eq 0 ]]; do
    generate_report
    sleep "$INTERVAL"
    [[ "$OUTPUT" != "json" ]] && echo
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
  *) generate_report ;;
esac
