#!/usr/bin/env bash
set -euo pipefail

# Config
MODE="watch"
INTERVAL=2
TOP_N=10
BAR_WIDTH=20

# Colors & Setup
RED=""; YELLOW=""; GREEN=""; BLUE=""; GREY=""; RESET=""; BOLD=""; CLEAR_SCREEN=""; NC=""
setup_colors() {
    if [[ -t 1 ]]; then
        RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
        BLUE=$(tput setaf 4); GREY=$(tput setaf 8); RESET=$(tput sgr0)
        BOLD=$(tput bold); CLEAR_SCREEN=$(tput clear); NC="$RESET"
    fi
}

declare -gA POD_META_CACHE

# Metrics Helpers
read_meminfo() { awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print t, a}' /proc/meminfo; }
read_psi_full() { awk '/full/ {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {gsub("avg10=","",$i); print $i}}' /proc/pressure/memory 2>/dev/null || echo 0; }
read_load_io() {
    local l1 l2 l3 rest
    read -r l1 l2 l3 rest < /proc/loadavg
    local iowait=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* wa.*/\1/" || echo 0)
    echo "$l1 $l2 $iowait"
}

resolve_pod_metadata() {
  local pod_uid="$1"; local pod_uid_dashed="${pod_uid//_/-}"
  if [[ -n "${POD_META_CACHE[$pod_uid]:-}" ]]; then echo "${POD_META_CACHE[$pod_uid]}"; return; fi
  local meta="unknown|unknown"; local matches=( /var/log/pods/*_"${pod_uid_dashed}"* )
  if [[ -d "${matches[0]:-}" ]]; then
      local base=$(basename "${matches[0]}")
      local ns="${base%%_*}"; local rest="${base#*_}"; local name_part="${rest%_$pod_uid_dashed}" 
      [[ "$name_part" == "$rest" ]] && name_part="${rest%_*}"
      meta="${ns}|${name_part}"
  fi
  POD_META_CACHE["$pod_uid"]="$meta"; echo "$meta"
}

draw_bar() {
    local pct=$1; local color=$2; local draw_pct=$pct
    (( draw_pct > 100 )) && draw_pct=100
    local filled=$(( (draw_pct * BAR_WIDTH) / 100 )); local empty=$(( BAR_WIDTH - filled ))
    printf "%s[" "$RESET"
    printf "%s" "$color"
    for ((i=0; i<filled; i++)); do printf "|"; done
    printf "%s" "$GREY"
    for ((i=0; i<empty; i++)); do printf "."; done
    printf "%s]%s" "$RESET" "$RESET"
}

generate_report() {
  read total avail <<< "$(read_meminfo)"
  read l1 l5 iowait <<< "$(read_load_io)"
  local mem_pct=$(( avail * 100 / total ))
  local psi="$(read_psi_full)"

  declare -A USED LIMIT HAS_LIMIT OOM THR
  local cgroup_root="/sys/fs/cgroup/kubepods.slice"

  while IFS= read -r file; do
    dir=$(dirname "$file"); dirname_base=$(basename "$dir")
    if [[ "$dirname_base" != *".slice" ]] || [[ "$dirname_base" != *"pod"* ]]; then continue; fi
    
    pod_uid=$(echo "$dirname_base" | sed -E 's/.*pod//;s/\.slice//;s/_/-/g')
    val=$(cat "$file" 2>/dev/null || echo 0)
    USED["$pod_uid"]=$(( ${USED["$pod_uid"]:-0} + val ))

    [[ -f "$dir/memory.events" ]] && \
      OOM["$pod_uid"]=$(( ${OOM["$pod_uid"]:-0} + $(grep "oom_kill" "$dir/memory.events" | awk '{print $2}') ))

    [[ -f "$dir/cpu.stat" ]] && \
      THR["$pod_uid"]=$(( ${THR["$pod_uid"]:-0} + $(grep "nr_throttled" "$dir/cpu.stat" | awk '{print $2}') ))

    if [[ -f "$dir/memory.max" ]]; then
        raw=$(cat "$dir/memory.max")
        if [[ "$raw" != "max" ]]; then 
          HAS_LIMIT["$pod_uid"]=1; LIMIT["$pod_uid"]="$raw"
        else HAS_LIMIT["$pod_uid"]=0; fi
    fi
  done < <(find "$cgroup_root" -mindepth 3 -maxdepth 4 -name memory.current 2>/dev/null)

  [[ "$MODE" == "watch" ]] && echo -n "$CLEAR_SCREEN"
  local s_col="$GREEN"
  (( mem_pct < 10 )) && s_col="$RED$BOLD"
  echo "=== NODE HEALTH ($MODE) ==="
  echo "Time: $(date -Is) | Status: ${s_col}OK${RESET} | Avail: ${mem_pct}% | PSI: ${psi}"
  echo -e "Load: ${l1} ${l5} | IO Wait: ${iowait}%"
  echo
  printf "%-35s %-15s %-16s %-22s %s\n" "POD" "NS" "MEM / LIM" "USAGE" "OOM/THR"
  echo "------------------------------------------------------------------------------------------"

  local temp_sort=$(mktemp)
  for uid in "${!USED[@]}"; do
    IFS='|' read ns name <<< "$(resolve_pod_metadata "$uid")"
    u_mi=$(( USED[$uid] / 1024 / 1024 ))
    h_lim=${HAS_LIMIT[$uid]:-0}; l_mi=0; p_str="---"; p=0
    if [[ "$h_lim" -eq 1 ]]; then
        l_mi=$(( LIMIT[$uid] / 1024 / 1024 ))
        [[ "$l_mi" -gt 0 ]] && p=$(( u_mi * 100 / l_mi )) && p_str="${p}%"
    fi
    
    col="$GREEN"; (( p >= 75 )) && col="$YELLOW"; (( p >= 90 )) && col="$RED$BOLD"
    bar=$( [[ "$h_lim" -eq 1 ]] && draw_bar "$p" "$col" || printf "${BLUE}[     UNBOUNDED      ]${NC}" )
    
    o=${OOM[$uid]:-0}; t=${THR[$uid]:-0}
    alerts=""; [[ $o -gt 0 ]] && alerts+="${RED}OOM:$o ${NC}"; [[ $t -gt 0 ]] && alerts+="${YELLOW}THR:$t${NC}"
    
    # Prefix for sort
    printf "%s|%-35s %-15s %4sMi / %-7s %s %4s %b\n" \
      "$u_mi" "${name:0:34}" "${ns:0:14}" "$u_mi" "$([[ $h_lim -eq 1 ]] && echo ${l_mi}Mi || echo "∞")" \
      "$bar" "$p_str" "$alerts" >> "$temp_sort"
  done

  if [ -s "$temp_sort" ]; then
    sort -rn "$temp_sort" | head -n "$TOP_N" | cut -d'|' -f2-
  else
    echo "No pod metrics found."
  fi
  rm -f "$temp_sort"
}

setup_colors
trap 'exit 0' INT TERM
while true; do generate_report; [[ "$MODE" == "check" ]] && exit 0; sleep "$INTERVAL"; done
