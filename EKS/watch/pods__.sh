#!/usr/bin/env bash
# NODE-WATCHER v4.3.6 (beta..integrated..)
set -euo pipefail

# --- Configuration ---
MODE="watch" ; INTERVAL=2 ; TOP_N=8 ; VERBOSE=1 ; FILTER_NS=""
BAR_WIDTH=20 ; MIN_MEM_PCT=10 ; IO_WAIT_LIMIT=10.0

# Initialize all variables to prevent "unbound variable" errors
RED=""; YELLOW=""; GREEN=""; BLUE=""; GREY=""; CYAN=""; RESET=""; BOLD=""; CLEAR_SCREEN=""; NC=""
declare -gA POD_META_CACHE

setup_colors() {
    if [[ -t 1 ]]; then
        RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
        BLUE=$(tput setaf 4); GREY=$(tput setaf 8); CYAN=$(tput setaf 6)
        RESET=$(tput sgr0); BOLD=$(tput bold); CLEAR_SCREEN=$(tput clear); NC="$RESET"
    fi
}

# --- Metrics Helpers ---
read_meminfo() { awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print t, a}' /proc/meminfo; }
read_psi_full() { awk '/full/ {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {gsub("avg10=","",$i); print $i}}' /proc/pressure/memory 2>/dev/null || echo 0; }
read_load_io() {
    local l1 l2 l3 rest iowait
    read -r l1 l2 l3 rest < /proc/loadavg
    iowait=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* wa.*/\1/" || echo 0)
    echo "$l1 $l2 $iowait"
}

resolve_pod_metadata() {
  local uid="$1"; local uid_d="${uid//_/-}"
  if [[ -n "${POD_META_CACHE[$uid]:-}" ]]; then echo "${POD_META_CACHE[$uid]}"; return; fi
  local meta="unknown|unknown"; local matches=( /var/log/pods/*_"${uid_d}"* )
  if [[ -d "${matches[0]:-}" ]]; then
      local base=$(basename "${matches[0]}")
      local ns="${base%%_*}"; local rest="${base#*_}"; local name="${rest%_$uid_d}" 
      [[ "$name" == "$rest" ]] && name="${rest%_*}"
      meta="${ns}|${name}"
  fi
  POD_META_CACHE["$uid"]="$meta"; echo "$meta"
}

get_pod_logs() {
    local ns="$1" ; local name="$2"
    echo -e "${CYAN}Logs for ${name} [${ns}]:${NC}"
    kubectl logs -n "$ns" "$name" --tail=3 2>/dev/null | sed 's/^/  /' || echo "  (Logs unavailable)"
}

draw_bar() {
    local pct=$1; local bar_color=$2; local d_pct=$pct
    (( d_pct > 100 )) && d_pct=100
    local filled=$(( (d_pct * BAR_WIDTH) / 100 )); local empty=$(( BAR_WIDTH - filled ))
    printf "%s[%s" "$RESET" "$bar_color"
    for ((i=0; i<filled; i++)); do printf "|"; done
    printf "%s" "$GREY"
    for ((i=0; i<empty; i++)); do printf "."; done
    printf "%s]%s" "$NC" "$NC"
}

generate_report() {
  read total avail <<< "$(read_meminfo)"
  read l1 l5 iowait <<< "$(read_load_io)"
  local mem_pct=$(( avail * 100 / total ))
  local psi="$(read_psi_full)"

  declare -A USED LIMIT HAS_LIMIT OOM THR
  local c_root="/sys/fs/cgroup/kubepods.slice"

  # Walk Cgroups
  while IFS= read -r file; do
    dir=$(dirname "$file"); base=$(basename "$dir")
    [[ "$base" != *".slice" || "$base" != *"pod"* ]] && continue
    uid=$(echo "$base" | sed -E 's/.*pod//;s/\.slice//;s/_/-/g')
    USED["$uid"]=$(( ${USED["$uid"]:-0} + $(cat "$file" 2>/dev/null || echo 0) ))
    [[ -f "$dir/memory.events" ]] && OOM["$uid"]=$(( ${OOM["$uid"]:-0} + $(grep "oom_kill" "$dir/memory.events" | awk '{print $2}' || echo 0) ))
    [[ -f "$dir/cpu.stat" ]] && THR["$uid"]=$(( ${THR["$uid"]:-0} + $(grep "nr_throttled" "$dir/cpu.stat" | awk '{print $2}' || echo 0) ))
    if [[ -f "$dir/memory.max" ]]; then
        raw=$(cat "$dir/memory.max")
        if [[ "$raw" == "max" ]]; then HAS_LIMIT["$uid"]=1; LIMIT["$uid"]="max"; else HAS_LIMIT["$uid"]=1; LIMIT["$uid"]="$raw"; fi
    fi
  done < <(find "$c_root" -mindepth 3 -maxdepth 4 -name memory.current 2>/dev/null)

  [[ "$MODE" == "watch" ]] && echo -n "$CLEAR_SCREEN"
  local s_col="$GREEN"; local status="OK"
  (( mem_pct < MIN_MEM_PCT )) && { status="CRITICAL"; s_col="$RED$BOLD"; }
  awk -v i="$iowait" -v t="$IO_WAIT_LIMIT" 'BEGIN{if(i>t)exit 1}' || { status="LATENCY"; s_col="$YELLOW"; }

  echo -e "${BOLD}=== NODE HEALTH ($MODE) ===${NC}"
  echo -e "Time: $(date -Is) | Status: ${s_col}${status}${NC}"
  echo -e "Load: ${l1} ${l5} | IO Wait: ${iowait}% | Mem Avail: ${mem_pct}% | PSI: ${psi}"
  echo
  printf "%-35s %-15s %-16s %-22s %s\n" "POD" "NS" "MEM / LIM" "USAGE" "OOM/THR"
  echo "------------------------------------------------------------------------------------------"

  local temp_sort=$(mktemp)
  for uid in "${!USED[@]}"; do
    IFS='|' read ns name <<< "$(resolve_pod_metadata "$uid")"
    [[ -n "$FILTER_NS" && "$ns" != "$FILTER_NS" ]] && continue
    u_mi=$(( USED[$uid] / 1024 / 1024 ))
    h_lim=${HAS_LIMIT[$uid]:-0}; l_mi=0; p=0; p_str="---"; lim_text="∞"
    
    if [[ "$h_lim" -eq 1 && "${LIMIT[$uid]}" != "max" ]]; then
        l_mi=$(( LIMIT[$uid] / 1024 / 1024 ))
        lim_text="${l_mi}Mi"
        [[ "$l_mi" -gt 0 ]] && { p=$(( u_mi * 100 / l_mi )); p_str="${p}%"; }
    fi
    
    local line_color="$GREEN"
    (( p >= 75 )) && line_color="$YELLOW"
    (( p >= 90 )) && line_color="$RED$BOLD"
    
    local bar
    if [[ "$h_lim" -eq 1 && "${LIMIT[$uid]}" != "max" ]]; then
        bar=$(draw_bar "$p" "$line_color")
    else
        bar=$(printf "${BLUE}[     UNBOUNDED      ]${NC}")
    fi

    local o=${OOM[$uid]:-0}; local t=${THR[$uid]:-0}
    local alerts=""; [[ $o -gt 0 ]] && alerts+="${RED}OOM:$o ${NC}"; [[ $t -gt 0 ]] && alerts+="${YELLOW}THR:$t${NC}"

    printf "%s|%-35s %-15s %4sMi / %-7s %s %4s %b\n" \
      "$u_mi" "${name:0:34}" "${ns:0:14}" "$u_mi" "$lim_text" \
      "$bar" "$p_str" "$alerts" >> "$temp_sort"
  done

  if [ -s "$temp_sort" ]; then
    local top_data=$(sort -rn "$temp_sort" | head -n "$TOP_N")
    echo "$top_data" | cut -d'|' -f2-
    
    if [[ "$VERBOSE" -eq 1 ]]; then
      echo -e "\n${BOLD}--- LIVE POD LOGS (Targeting High Usage) ---${NC}"
      while IFS='|' read -r mi line; do
        p_name=$(echo "$line" | awk '{print $1}')
        p_ns=$(echo "$line" | awk '{print $2}')
        [[ -n "$p_name" && "$p_name" != "POD" ]] && get_pod_logs "$p_ns" "$p_name"
      done <<< "$top_data"

      echo -e "\n${BOLD}--- RECENT CLUSTER WARNINGS ---${NC}"
      kubectl get events -A --field-selector type=Warning --sort-by='.lastTimestamp' 2>/dev/null | tail -n 3 || echo "  (No warnings)"
    fi
  fi
  rm -f "$temp_sort"
}

# --- Arg Handling ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        check|watch) MODE="$1"; shift ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --top) TOP_N="$2"; shift 2 ;;
        --ns) FILTER_NS="$2"; shift 2 ;;
        --quiet) VERBOSE=0; shift ;;
        -h|--help) echo "Usage: $0 [check|watch] [--interval N] [--ns namespace] [--quiet]"; exit 0 ;;
        *) shift ;;
    esac
done

setup_colors
trap 'exit 0' INT TERM
if [[ "$MODE" == "watch" ]]; then
    while true; do generate_report; sleep "$INTERVAL"; done
else
    generate_report
fi
