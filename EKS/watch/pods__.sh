#!/usr/bin/env bash
# NODE-WATCHER v4.3.0 (Omni-Monitor)
set -euo pipefail

# --- Defaults ---
MODE="watch"          # watch | check
INTERVAL=2
PODS=1
TOP_N=10
FILTER_NS=""
BAR_WIDTH=20
VERBOSE=0
MIN_MEM_PCT=10
IO_WAIT_LIMIT=10.0
APISERVER_PORT=6443

# --- UI Setup ---
RED=""; YELLOW=""; GREEN=""; BLUE=""; GREY=""; RESET=""; BOLD=""; CLEAR_SCREEN=""; NC=""
setup_colors() {
    if [[ -t 1 ]]; then
        RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
        BLUE=$(tput setaf 4); GREY=$(tput setaf 8); RESET=$(tput sgr0)
        BOLD=$(tput bold); CLEAR_SCREEN=$(tput clear); NC="$RESET"
    fi
}

# --- Caching ---
declare -gA POD_META_CACHE

# --- Metrics Helpers ---
read_meminfo() { awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print t, a}' /proc/meminfo; }
read_psi_full() { awk '/full/ {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {gsub("avg10=","",$i); print $i}}' /proc/pressure/memory 2>/dev/null || echo 0; }
read_load_io() {
    local l1 l2 l3 rest
    read -r l1 l2 l3 rest < /proc/loadavg
    local iowait=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* wa.*/\1/" || echo 0)
    echo "$l1 $l2 $iowait"
}

# Maps Cgroup UID to Human-Readable Pod Info
resolve_pod_metadata() {
  local uid="$1"; local uid_d="${uid//_/-}"
  if [[ -n "${POD_META_CACHE[$uid]:-}" ]]; then echo "${POD_META_CACHE[$uid]}"; return; fi
  local meta="unknown|unknown"
  local matches=( /var/log/pods/*_"${uid_d}"* )
  if [[ -d "${matches[0]:-}" ]]; then
      local base=$(basename "${matches[0]}")
      local ns="${base%%_*}"; local rest="${base#*_}"; local name="${rest%_$uid_d}" 
      [[ "$name" == "$rest" ]] && name="${rest%_*}"
      meta="${ns}|${name}"
  fi
  POD_META_CACHE["$uid"]="$meta"; echo "$meta"
}

draw_bar() {
    local pct=$1; local color=$2; local d_pct=$pct
    (( d_pct > 100 )) && d_pct=100
    local filled=$(( (d_pct * BAR_WIDTH) / 100 )); local empty=$(( BAR_WIDTH - filled ))
    printf "%s[%s" "$RESET" "$color"
    for ((i=0; i<filled; i++)); do printf "|"; done
    printf "%s" "$GREY"
    for ((i=0; i<empty; i++)); do printf "."; done
    printf "%s]%s" "$NC" "$NC"
}

# --- Core Logic ---
generate_report() {
  read total avail <<< "$(read_meminfo)"
  read l1 l5 iowait <<< "$(read_load_io)"
  local mem_pct=$(( avail * 100 / total ))
  local psi="$(read_psi_full)"

  declare -A USED LIMIT HAS_LIMIT OOM THR
  local c_root="/sys/fs/cgroup/kubepods.slice"

  # Collect Stats
  while IFS= read -r file; do
    dir=$(dirname "$file"); base=$(basename "$dir")
    [[ "$base" != *".slice" || "$base" != *"pod"* ]] && continue
    
    uid=$(echo "$base" | sed -E 's/.*pod//;s/\.slice//;s/_/-/g')
    USED["$uid"]=$(( ${USED["$uid"]:-0} + $(cat "$file" 2>/dev/null || echo 0) ))
    [[ -f "$dir/memory.events" ]] && OOM["$uid"]=$(( ${OOM["$uid"]:-0} + $(grep "oom_kill" "$dir/memory.events" | awk '{print $2}' || echo 0) ))
    [[ -f "$dir/cpu.stat" ]] && THR["$uid"]=$(( ${THR["$uid"]:-0} + $(grep "nr_throttled" "$dir/cpu.stat" | awk '{print $2}' || echo 0) ))
    if [[ -f "$dir/memory.max" ]]; then
        raw=$(cat "$dir/memory.max")
        if [[ "$raw" != "max" ]]; then HAS_LIMIT["$uid"]=1; LIMIT["$uid"]="$raw"; else HAS_LIMIT["$uid"]=0; fi
    fi
  done < <(find "$c_root" -mindepth 3 -maxdepth 4 -name memory.current 2>/dev/null)

  # UI Refresh
  [[ "$MODE" == "watch" ]] && echo -n "$CLEAR_SCREEN"
  local s_col="$GREEN"; local status="OK"
  (( mem_pct < MIN_MEM_PCT )) && { status="CRITICAL"; s_col="$RED$BOLD"; }
  awk -v i="$iowait" -v t="$IO_WAIT_LIMIT" 'BEGIN{if(i>t)exit 1}' || { status="LATENCY"; s_col="$YELLOW"; }

  echo "${BOLD}=== NODE HEALTH ($MODE) ===${NC}"
  echo "Time: $(date -Is) | Status: ${s_col}${status}${NC}"
  echo -e "Load: ${l1} ${l5} | IO Wait: ${iowait}% | Mem Avail: ${mem_pct}% | PSI: ${psi}"
  echo
  printf "%-35s %-15s %-16s %-22s %s\n" "POD" "NS" "MEM / LIM" "USAGE" "OOM/THR"
  echo "------------------------------------------------------------------------------------------"

  local temp_sort=$(mktemp)
  for uid in "${!USED[@]}"; do
    IFS='|' read ns name <<< "$(resolve_pod_metadata "$uid")"
    [[ -n "$FILTER_NS" && "$ns" != "$FILTER_NS" ]] && continue
    u_mi=$(( USED[$uid] / 1024 / 1024 ))
    h_lim=${HAS_LIMIT[$uid]:-0}; l_mi=0; p=0; p_str="---"
    if [[ "$h_lim" -eq 1 ]]; then
        l_mi=$(( LIMIT[$uid] / 1024 / 1024 ))
        [[ "$l_mi" -gt 0 ]] && { p=$(( u_mi * 100 / l_mi )); p_str="${p}%"; }
    fi
    
    col="$GREEN"; (( p >= 75 )) && col="$YELLOW"; (( p >= 90 )) && col="$RED$BOLD"
    bar=$( [[ "$h_lim" -eq 1 ]] && draw_bar "$p" "$col" || printf "${BLUE}[     UNBOUNDED      ]${NC}" )
    
    o=${OOM[$uid]:-0}; t=${THR[$uid]:-0}
    alerts=""; [[ $o -gt 0 ]] && alerts+="${RED}OOM:$o ${NC}"; [[ $t -gt 0 ]] && alerts+="${YELLOW}THR:$t${NC}"
    
    printf "%s|%-35s %-15s %4sMi / %-7s %s %4s %b\n" \
      "$u_mi" "${name:0:34}" "${ns:0:14}" "$u_mi" "$([[ $h_lim -eq 1 ]] && echo ${l_mi}Mi || echo "∞")" \
      "$bar" "$p_str" "$alerts" >> "$temp_sort"
  done

  if [ -s "$temp_sort" ]; then
    sort -rn "$temp_sort" | head -n "$TOP_N" | cut -d'|' -f2-
  fi
  rm -f "$temp_sort"

  # --- Verbose/Logs Section ---
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo -e "\n${BOLD}--- RECENT POD EVENTS (Last 30s) ---${NC}"
    # This assumes we have kubectl access since we are root on the host
    kubectl get events -A --sort-by='.lastTimestamp' | tail -n 5 || echo "No kubectl events."
  fi
}

# --- Arg Handling ---
usage() {
    echo "Node-Watcher v4.3.0"
    echo "Usage: $0 [check|watch] [options]"
    echo "  --interval N  Update every N seconds (default: 2)"
    echo "  --top N       Show top N pods (default: 10)"
    echo "  --ns NAME     Filter by namespace"
    echo "  --verbose     Show recent cluster events"
    echo "  --json        [Legacy] Toggle JSON mode logic"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        check|watch) MODE="$1"; shift ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --top) TOP_N="$2"; shift 2 ;;
        --ns) FILTER_NS="$2"; shift 2 ;;
        --verbose) VERBOSE=1; shift ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

setup_colors
trap 'exit 0' INT TERM
while true; do 
    generate_report
    [[ "$MODE" == "check" ]] && exit 0
    sleep "$INTERVAL"
done
