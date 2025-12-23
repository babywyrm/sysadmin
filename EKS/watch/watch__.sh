#!/usr/bin/env bash
set -euo pipefail

VERSION="4.0.1"

MODE="check"          # check | watch
OUTPUT="stdout"       # stdout | json
INTERVAL=2
PODS=0
TOP_N=10
FILTER_NS=""

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

# Caching
declare -gA POD_META_CACHE

# Visual settings
BAR_WIDTH=20

# Colors
RED=""
YELLOW=""
GREEN=""
BLUE=""
GREY=""
RESET=""
BOLD=""
CLEAR_SCREEN=""

setup_colors() {
    if [[ -t 1 ]] && [[ "$OUTPUT" != "json" ]]; then
        RED=$(tput setaf 1)
        YELLOW=$(tput setaf 3)
        GREEN=$(tput setaf 2)
        BLUE=$(tput setaf 4)
        GREY=$(tput setaf 8) # May not work on all terms, usually distinct
        RESET=$(tput sgr0)
        BOLD=$(tput bold)
        CLEAR_SCREEN=$(tput clear)
    fi
}

ts() { date -Is; }

# -----------------------------
# Graphics & Helpers
# -----------------------------
draw_bar() {
    local pct=$1
    local color=$2
    
    # Cap at 100 for drawing
    local draw_pct=$pct
    (( draw_pct > 100 )) && draw_pct=100
    
    local filled=$(( (draw_pct * BAR_WIDTH) / 100 ))
    local empty=$(( BAR_WIDTH - filled ))
    
    printf "%s[" "$RESET"
    printf "%s" "$color"
    for ((i=0; i<filled; i++)); do printf "|"; done
    printf "%s" "$GREY"
    for ((i=0; i<empty; i++)); do printf "."; done
    printf "%s]%s" "$RESET" "$RESET"
}

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
  ps -o rss= -C containerd,containerd-shim 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

# -----------------------------
# Pod metadata (Fixed for broad compatibility)
# -----------------------------
resolve_pod_metadata() {
  local pod_uid="$1"
  # Ensure strict dash format for FS lookups, regardless of how Cgroup presented it
  local pod_uid_dashed="${pod_uid//_/-}"

  # Check cache first
  if [[ -n "${POD_META_CACHE[$pod_uid]:-}" ]]; then
      echo "${POD_META_CACHE[$pod_uid]}"
      return
  fi

  local meta="unknown|unknown"
  local log_dir=""

  # Strategy 1: Fast Glob
  # Pattern: /var/log/pods/NAMESPACE_NAME_UID/
  # We look for the UID part.
  local matches=( /var/log/pods/*_"${pod_uid_dashed}"* )
  
  if [[ -d "${matches[0]:-}" ]]; then
      log_dir="${matches[0]}"
  else
      # Strategy 2: Fallback find (deeper search if glob failed)
      # Some distros nest differently or glob expansion fails on strict shells
      log_dir=$(find /var/log/pods -maxdepth 1 -type d -name "*${pod_uid_dashed}*" -print -quit 2>/dev/null)
  fi

  if [[ -n "$log_dir" && -d "$log_dir" ]]; then
      local base
      base="$(basename "$log_dir")"
      
      # Standard K8s format: namespace_name_uid
      # We parse from the left
      local ns="${base%%_*}"
      local rest="${base#*_}"
      
      # The 'name' is everything in the middle. 
      # Remove the UID from the end to get the name.
      local name_part="${rest%_$pod_uid_dashed}" 
      
      # Safety check if removal failed (e.g. UID format mismatch)
      if [[ "$name_part" == "$rest" ]]; then
         name_part="${rest%_*}"
      fi
      
      meta="${ns}|${name_part}"
  fi

  POD_META_CACHE["$pod_uid"]="$meta"
  echo "$meta"
}

# -----------------------------
# Data Collection
# -----------------------------
collect_pod_data() {
  declare -gA POD_STATS_USED POD_STATS_LIMIT POD_STATS_HAS_LIMIT POD_STATS_OOM
  
  POD_STATS_USED=()
  POD_STATS_LIMIT=()
  POD_STATS_HAS_LIMIT=()
  POD_STATS_OOM=()

  local cgroup_root="/sys/fs/cgroup/kubepods.slice"

  # Find memory.current files
  while IFS= read -r file; do
    local dir dirname_base pod_uid used
    dir=$(dirname "$file")
    dirname_base=$(basename "$dir")
    
    if [[ "$dirname_base" != *".slice" ]] || [[ "$dirname_base" != *"pod"* ]]; then continue; fi

    # Normalize UID to dashes immediately for internal keys
    pod_uid=$(echo "$dirname_base" | sed -E 's/.*pod//;s/\.slice//;s/_/-/g')
    
    used=$(cat "$file")
    POD_STATS_USED["$pod_uid"]=$(( ${POD_STATS_USED["$pod_uid"]:-0} + used ))

    # Read OOM Kills from memory.events
    local oom_count=0
    if [[ -f "$dir/memory.events" ]]; then
        # Format: low 0... oom_kill 5 ...
        oom_count=$(grep "oom_kill" "$dir/memory.events" | awk '{print $2}')
    fi
    
    local existing_oom=${POD_STATS_OOM["$pod_uid"]:-0}
    if (( oom_count > existing_oom )); then
         POD_STATS_OOM["$pod_uid"]=$oom_count
    fi

    # Read Limits
    local limit_file="$dir/memory.max"
    if [[ -f "$limit_file" ]]; then
        local raw_limit
        raw_limit=$(cat "$limit_file")
        if [[ "$raw_limit" == "max" ]]; then
             POD_STATS_HAS_LIMIT["$pod_uid"]=0
        else
             POD_STATS_HAS_LIMIT["$pod_uid"]=1
             POD_STATS_LIMIT["$pod_uid"]="$raw_limit"
        fi
    else
        POD_STATS_HAS_LIMIT["$pod_uid"]=0
    fi

  done < <(find "$cgroup_root" -mindepth 3 -maxdepth 4 -name memory.current 2>/dev/null)
}

# -----------------------------
# Main Logic
# -----------------------------
generate_report() {
  read total avail <<< "$(read_meminfo)"
  mem_pct=$(( avail * 100 / total ))
  psi_full="$(read_psi_full)"
  rss="$(containerd_rss)"

  # Determine Node Status
  local node_status="OK"
  if (( mem_pct < MIN_MEM_AVAILABLE_PCT )); then node_status="CRITICAL"; fi
  if awk -v p="$psi_full" -v t="$PSI_FULL_THRESHOLD" 'BEGIN{exit !(p>t)}'; then node_status="CRITICAL"; fi

  local pod_json_array="[]"
  local text_rows=()
  local text_risks=()

  if [[ "$PODS" -eq 1 ]]; then
    collect_pod_data

    # Temp file for sorting
    local temp_sort_file
    temp_sort_file=$(mktemp)

    for pod_uid in "${!POD_STATS_USED[@]}"; do
      IFS='|' read ns name <<< "$(resolve_pod_metadata "$pod_uid")"

      # Apply Namespace Filter
      if [[ -n "$FILTER_NS" && "$ns" != "$FILTER_NS" ]]; then continue; fi

      used_mi=$(( POD_STATS_USED["$pod_uid"] / 1024 / 1024 ))
      has_limit="${POD_STATS_HAS_LIMIT["$pod_uid"]:-0}"
      limit_bytes="${POD_STATS_LIMIT["$pod_uid"]:-0}"
      oom_kills="${POD_STATS_OOM["$pod_uid"]:-0}"

      # Calculations
      local sev="OK"
      local limit_str="∞"
      local limit_mi=0
      local pct=0
      local pct_str="---"
      
      if [[ "$has_limit" -eq 1 ]]; then
          limit_mi=$(( limit_bytes / 1024 / 1024 ))
          limit_str="${limit_mi}Mi"
          pct=$(awk -v u="$used_mi" -v l="$limit_mi" 'BEGIN { if(l==0) print 0; else printf "%.0f", (u/l)*100 }')
          pct_str="${pct}%"

          if (( pct >= 90 )); then sev="CRITICAL";
          elif (( pct >= 75 )); then sev="WARN"; fi
      else
          sev="RISK"
      fi

      if [[ "$OUTPUT" == "json" ]]; then
         # JSON construction
         pod_json_array=$(jq -n \
            --argjson list "$pod_json_array" \
            --arg ns "$ns" \
            --arg name "$name" \
            --argjson used_mi "$used_mi" \
            --arg limit "$limit_str" \
            --arg sev "$sev" \
            --arg pct "$pct" \
            --argjson ooms "$oom_kills" \
            '$list + [{ns:$ns, name:$name, used_mi:$used_mi, limit:$limit, severity:$sev, usage_pct:$pct, oom_kills:$ooms}]')
      else
        # Text Formatting
        local color="$GREEN"
        [[ "$sev" == "WARN" ]] && color="$YELLOW"
        [[ "$sev" == "CRITICAL" ]] && color="$RED${BOLD}"
        [[ "$sev" == "RISK" ]] && color="$BLUE"

        local bar=""
        if [[ "$has_limit" -eq 1 ]]; then
            bar=$(draw_bar "$pct" "$color")
        else
            bar=$(printf "%s[     UNBOUNDED      ]%s" "$BLUE" "$RESET")
        fi

        local oom_alert=""
        if (( oom_kills > 0 )); then
            oom_alert="${RED}${BOLD} [OOM: ${oom_kills}]${RESET}"
        fi
        
        # Format for sort: UsedMi | Line
        local line
        line=$(printf "%s%-35s %s%-15s %s%4sMi / %-7s %s %s%s" \
          "$RESET" "${name:0:34}" \
          "$GREY" "${ns:0:14}" \
          "$RESET" "$used_mi" "$limit_str" \
          "$bar" "$pct_str" "$oom_alert")
        
        echo "$used_mi|$line" >> "$temp_sort_file"
      fi
    done
    
    if [[ "$OUTPUT" != "json" ]]; then
        mapfile -t text_rows < <(sort -nr "$temp_sort_file" | cut -d'|' -f2- | head -"$TOP_N")
        rm -f "$temp_sort_file"
    fi
  fi

  # 3. Final Print
  if [[ "$OUTPUT" == "json" ]]; then
    jq -n \
      --arg time "$(ts)" \
      --arg status "$node_status" \
      --argjson mem_avail_pct "$mem_pct" \
      --argjson psi_full "$psi_full" \
      --argjson rss "$rss" \
      --argjson pods "$pod_json_array" \
      '{time:$time,status:$status,mem_avail_pct:$mem_avail_pct,psi_full:$psi_full,rss:$rss, pods:$pods}'
  else
    if [[ "$MODE" == "watch" ]]; then echo -n "$CLEAR_SCREEN"; fi

    local s_color="$GREEN"
    [[ "$node_status" != "OK" ]] && s_color="$RED${BOLD}"
    
    echo "=== NODE HEALTH ($MODE) ==="
    echo "Time: $(ts)"
    echo -e "Status: ${s_color}${node_status}${RESET} | Avail: ${mem_pct}% | PSI: ${psi_full} | RuntimeRSS: $((rss/1024))Mi"

    if [[ "$PODS" -eq 1 ]]; then
      echo
      # Header
      printf "%-35s %-15s %-16s %-22s %s\n" "POD" "NS" "MEM / LIM" "USAGE" "%"
      echo "------------------------------------------------------------------------------------------"
      if (( ${#text_rows[@]} == 0 )); then
          echo "No pods found (or no usage metrics available)."
      else
          printf "%s\n" "${text_rows[@]}"
      fi
    fi
  fi
}

run_watch() {
  setup_colors
  while [[ "$STOP" -eq 0 ]]; do
    generate_report
    sleep "$INTERVAL"
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
    --ns) FILTER_NS="$2"; shift ;;
    -h|--help)
      echo "Usage: $0 [check|watch] [--interval N] [--pods] [--ns namespace] [--top N] [--json]"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

setup_colors
case "$MODE" in
  watch) run_watch ;;
  *) generate_report ;;
esac
