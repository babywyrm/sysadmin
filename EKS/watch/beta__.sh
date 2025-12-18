#!/usr/bin/env bash
#
# k8s-node-memory-watchdog.sh (v3.0) ..production edition..
#
# Comprehensive node-level monitoring for Kubernetes nodes
# EKS / k3s / kubeadm compatible
#

set -euo pipefail

VERSION="3.0"

# -------------------------------
# Defaults (overridable via CLI)
# -------------------------------

MIN_MEM_AVAILABLE_PCT=10
MAX_CONTAINERD_RSS_KB=1500000
PSI_FULL_AVG10_THRESHOLD=1.0
PSI_SOME_AVG10_THRESHOLD=10.0
SWAP_USAGE_PCT_THRESHOLD=50
INTERVAL=0
MODE="log"
VERBOSE=0
SHOW_TOP_PROCS=5
COLOR=0
HOSTNAME="${HOSTNAME:-$(hostname -s)}"

LOG_TAG="k8s-node-watchdog"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

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
  --summary       Show detailed summary report

Options:
  --interval N    Run every N seconds (loop mode)
  --min-mem-pct N Minimum MemAvailable percentage (default: 10)
  --max-containerd-rss-kb N
                  containerd RSS threshold (default: 1500000)
  --psi-full N    PSI full avg10 threshold (default: 1.0)
  --psi-some N    PSI some avg10 threshold (default: 10.0)
  --swap-pct N    Swap usage threshold (default: 50)
  --top-procs N   Show top N memory processes (default: 5)
  --color         Enable color output
  -v              Verbose output
  -h              Help

Examples:
  Quick check:
    $0 --stdout --color

  Detailed report:
    $0 --summary --color

  Live monitoring:
    $0 --stdout --interval 2 --color

  JSON for metrics:
    $0 --json --interval 10
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

colorize() {
  local color=$1
  shift
  if [[ $COLOR -eq 1 ]]; then
    echo -en "${color}$*${NC}"
  else
    echo -n "$*"
  fi
}

# -------------------------------
# Metric Collectors
# -------------------------------

read_meminfo_detailed() {
  awk '
    /MemTotal/ {total=$2}
    /MemFree/ {free=$2}
    /MemAvailable/ {avail=$2}
    /Buffers/ {buffers=$2}
    /Cached/ {cached=$2}
    /SwapTotal/ {swap_total=$2}
    /SwapFree/ {swap_free=$2}
    /Dirty/ {dirty=$2}
    /Slab/ {slab=$2}
    /SReclaimable/ {sreclaimable=$2}
    /SUnreclaim/ {sunreclaim=$2}
    /Mapped/ {mapped=$2}
    /Active/ {active=$2}
    /Inactive/ {inactive=$2}
    END {
      printf "%d %d %d %d %d %d %d %d %d %d %d %d %d %d", 
        total, free, avail, buffers, cached, 
        swap_total, swap_free, dirty, slab,
        sreclaimable, sunreclaim, mapped, active, inactive
    }
  ' /proc/meminfo
}

read_psi_detailed() {
  local psi_file=$1
  if [[ ! -r "$psi_file" ]]; then
    echo "0.0 0.0 0.0 0.0 0.0 0.0 0"
    return
  fi
  
  awk '
    /some/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^avg10=/) {gsub("avg10=","",$i); some10=$i}
        if ($i ~ /^avg60=/) {gsub("avg60=","",$i); some60=$i}
        if ($i ~ /^avg300=/) {gsub("avg300=","",$i); some300=$i}
        if ($i ~ /^total=/) {gsub("total=","",$i); some_total=$i}
      }
    }
    /full/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^avg10=/) {gsub("avg10=","",$i); full10=$i}
        if ($i ~ /^avg60=/) {gsub("avg60=","",$i); full60=$i}
        if ($i ~ /^avg300=/) {gsub("avg300=","",$i); full300=$i}
      }
    }
    END {
      printf "%.2f %.2f %.2f %.2f %.2f %.2f %d",
        some10+0, some60+0, some300+0,
        full10+0, full60+0, full300+0, some_total+0
    }
  ' "$psi_file"
}

get_load_avg() {
  awk '{printf "%.2f %.2f %.2f", $1, $2, $3}' /proc/loadavg
}

get_oom_kills() {
  dmesg | grep -i "killed process" | wc -l 2>/dev/null || echo "0"
}

get_process_metrics() {
  local process=$1
  if ! pgrep -x "$process" >/dev/null 2>&1; then
    echo "0 0 0"
    return
  fi
  
  ps -o rss=,vsz=,%mem= -C "$process" 2>/dev/null | \
    awk '{rss+=$1; vsz+=$2; mem+=$3} END {
      printf "%d %d %.2f", rss, vsz, mem
    }'
}

get_top_memory_procs() {
  local limit=$1
  ps aux --sort=-%mem | awk 'NR>1 {
    printf "%s|%s|%.1f|%d\n", $11, $2, $4, $6
  }' | head -n "$limit"
}

get_k8s_info() {
  local pod_count=0
  local node_pressure=""
  
  if command -v kubectl &>/dev/null; then
    pod_count=$(kubectl get pods --all-namespaces --field-selector spec.nodeName="$HOSTNAME" 2>/dev/null | wc -l)
    ((pod_count > 0)) && ((pod_count--))
    
    node_pressure=$(kubectl get node "$HOSTNAME" -o json 2>/dev/null | \
      jq -r '.status.conditions[] | 
        select(.type=="MemoryPressure") | .status' 2>/dev/null || echo "Unknown")
  fi
  
  echo "$pod_count $node_pressure"
}

get_fd_stats() {
  local allocated open_max
  allocated=$(cat /proc/sys/fs/file-nr 2>/dev/null | awk '{print $1}')
  open_max=$(cat /proc/sys/fs/file-max 2>/dev/null)
  local pct=0
  [[ -n "$allocated" && -n "$open_max" && $open_max -gt 0 ]] && \
    pct=$(( allocated * 100 / open_max ))
  echo "$allocated $open_max $pct"
}

bytes_to_human() {
  local kb=$1
  awk -v kb="$kb" 'BEGIN {
    units[0]="KB"; units[1]="MB"; units[2]="GB"; units[3]="TB"
    i=0; val=kb
    while (val >= 1024 && i < 3) {val/=1024; i++}
    printf "%.1f%s", val, units[i]
  }'
}

# -------------------------------
# Argument parsing
# -------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stdout) MODE="stdout" ;;
    --json) MODE="json" ;;
    --log) MODE="log" ;;
    --summary) MODE="summary" ;;
    --interval) INTERVAL="$2"; shift ;;
    --min-mem-pct) MIN_MEM_AVAILABLE_PCT="$2"; shift ;;
    --max-containerd-rss-kb) MAX_CONTAINERD_RSS_KB="$2"; shift ;;
    --psi-full) PSI_FULL_AVG10_THRESHOLD="$2"; shift ;;
    --psi-some) PSI_SOME_AVG10_THRESHOLD="$2"; shift ;;
    --swap-pct) SWAP_USAGE_PCT_THRESHOLD="$2"; shift ;;
    --top-procs) SHOW_TOP_PROCS="$2"; shift ;;
    --color) COLOR=1 ;;
    -v) VERBOSE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

# Signal handling
cleanup() {
  [[ $MODE == "stdout" || $MODE == "summary" ]] && echo -e "\nShutdown requested"
  exit 0
}
trap cleanup SIGINT SIGTERM

# -------------------------------
# Core check
# -------------------------------

check_once() {
  local timestamp="$(date -Iseconds)"
  
  # Memory metrics
  read MEM_TOTAL MEM_FREE MEM_AVAIL BUFFERS CACHED \
       SWAP_TOTAL SWAP_FREE DIRTY SLAB SRECLAIMABLE \
       SUNRECLAIM MAPPED ACTIVE INACTIVE <<< "$(read_meminfo_detailed)"
  
  MEM_USED=$((MEM_TOTAL - MEM_AVAIL))
  MEM_AVAIL_PCT=$(( MEM_AVAIL * 100 / MEM_TOTAL ))
  MEM_USED_PCT=$((100 - MEM_AVAIL_PCT))
  
  SWAP_USED=$((SWAP_TOTAL - SWAP_FREE))
  SWAP_USED_PCT=0
  [[ $SWAP_TOTAL -gt 0 ]] && SWAP_USED_PCT=$(( SWAP_USED * 100 / SWAP_TOTAL ))
  
  # PSI metrics
  read PSI_MEM_SOME10 PSI_MEM_SOME60 PSI_MEM_SOME300 \
       PSI_MEM_FULL10 PSI_MEM_FULL60 PSI_MEM_FULL300 \
       PSI_MEM_TOTAL <<< "$(read_psi_detailed /proc/pressure/memory)"
  
  read PSI_CPU_SOME10 PSI_CPU_SOME60 PSI_CPU_SOME300 \
       PSI_CPU_FULL10 PSI_CPU_FULL60 PSI_CPU_FULL300 \
       PSI_CPU_TOTAL <<< "$(read_psi_detailed /proc/pressure/cpu)"
  
  read PSI_IO_SOME10 PSI_IO_SOME60 PSI_IO_SOME300 \
       PSI_IO_FULL10 PSI_IO_FULL60 PSI_IO_FULL300 \
       PSI_IO_TOTAL <<< "$(read_psi_detailed /proc/pressure/io)"
  
  # Process metrics
  read CONTAINERD_RSS CONTAINERD_VSZ CONTAINERD_MEM_PCT <<< \
    "$(get_process_metrics containerd)"
  read KUBELET_RSS KUBELET_VSZ KUBELET_MEM_PCT <<< \
    "$(get_process_metrics kubelet)"
  
  # System metrics
  read LOAD1 LOAD5 LOAD15 <<< "$(get_load_avg)"
  OOM_KILLS=$(get_oom_kills)
  read FD_ALLOCATED FD_MAX FD_PCT <<< "$(get_fd_stats)"
  
  # K8s metrics
  read POD_COUNT NODE_MEM_PRESSURE <<< "$(get_k8s_info)"
  
  # Top processes
  TOP_PROCS=$(get_top_memory_procs "$SHOW_TOP_PROCS")
  
  # Evaluate conditions
  CRITICAL=0
  WARNING=0
  REASONS=()
  
  if (( MEM_AVAIL_PCT < MIN_MEM_AVAILABLE_PCT )); then
    CRITICAL=1
    REASONS+=("low_mem:${MEM_AVAIL_PCT}%<${MIN_MEM_AVAILABLE_PCT}%")
  elif (( MEM_AVAIL_PCT < MIN_MEM_AVAILABLE_PCT * 2 )); then
    WARNING=1
    REASONS+=("low_mem_warning:${MEM_AVAIL_PCT}%")
  fi
  
  if awk -v v="$PSI_MEM_FULL10" -v t="$PSI_FULL_AVG10_THRESHOLD" \
    'BEGIN{exit !(v>t)}'; then
    CRITICAL=1
    REASONS+=("psi_mem_full:${PSI_MEM_FULL10}>${PSI_FULL_AVG10_THRESHOLD}")
  fi
  
  if awk -v v="$PSI_MEM_SOME10" -v t="$PSI_SOME_AVG10_THRESHOLD" \
    'BEGIN{exit !(v>t)}'; then
    CRITICAL=1
    REASONS+=("psi_mem_some:${PSI_MEM_SOME10}>${PSI_SOME_AVG10_THRESHOLD}")
  fi
  
  if (( CONTAINERD_RSS > MAX_CONTAINERD_RSS_KB )); then
    CRITICAL=1
    REASONS+=("containerd_rss:$(bytes_to_human $CONTAINERD_RSS)>$(bytes_to_human $MAX_CONTAINERD_RSS_KB)")
  fi
  
  if (( SWAP_TOTAL > 0 && SWAP_USED_PCT > SWAP_USAGE_PCT_THRESHOLD )); then
    WARNING=1
    REASONS+=("swap_usage:${SWAP_USED_PCT}%")
  fi
  
  if [[ "$NODE_MEM_PRESSURE" == "True" ]]; then
    CRITICAL=1
    REASONS+=("k8s_memory_pressure")
  fi
  
  # Set status
  STATUS="OK"
  [[ $WARNING -eq 1 ]] && STATUS="WARNING"
  [[ $CRITICAL -eq 1 ]] && STATUS="CRITICAL"
  
  REASONS_STR=""
  [[ ${#REASONS[@]} -gt 0 ]] && REASONS_STR="$(IFS=,; echo "${REASONS[*]}")"
  
  # Output
  case "$MODE" in
    stdout)
      output_stdout
      ;;
    summary)
      output_summary
      ;;
    json)
      output_json
      ;;
    log)
      if (( CRITICAL == 1 )); then
        log "CRITICAL node=${HOSTNAME} mem_avail=${MEM_AVAIL_PCT}% swap=${SWAP_USED_PCT}% psi_mem_full=${PSI_MEM_FULL10} reasons=[${REASONS_STR}]"
      elif (( WARNING == 1 && VERBOSE == 1 )); then
        log "WARNING node=${HOSTNAME} ${REASONS_STR}"
      fi
      ;;
  esac
  
  return $CRITICAL
}

output_stdout() {
  local status_color=$GREEN
  [[ $STATUS == "WARNING" ]] && status_color=$YELLOW
  [[ $STATUS == "CRITICAL" ]] && status_color=$RED
  
  printf "[%s] %s " "$timestamp" "$HOSTNAME"
  colorize "$status_color" "$STATUS"
  printf "\n"
  
  printf "  Memory: "
  colorize "$BLUE" "%.1fGB" "$(awk -v kb=$MEM_USED 'BEGIN{printf "%.1f", kb/1024/1024}')"
  printf " used / "
  colorize "$BLUE" "%.1fGB" "$(awk -v kb=$MEM_TOTAL 'BEGIN{printf "%.1f", kb/1024/1024}')"
  printf " total (%d%% available)\n" "$MEM_AVAIL_PCT"
  
  if (( SWAP_TOTAL > 0 )); then
    printf "  Swap:   %s / %s (%d%%)\n" \
      "$(bytes_to_human $SWAP_USED)" \
      "$(bytes_to_human $SWAP_TOTAL)" \
      "$SWAP_USED_PCT"
  fi
  
  printf "  PSI:    mem=%.1f/%.1f cpu=%.1f io=%.1f (some/full avg10)\n" \
    "$PSI_MEM_SOME10" "$PSI_MEM_FULL10" "$PSI_CPU_SOME10" "$PSI_IO_SOME10"
  
  printf "  Load:   %.2f %.2f %.2f (1/5/15min)\n" "$LOAD1" "$LOAD5" "$LOAD15"
  
  if (( CONTAINERD_RSS > 0 )); then
    printf "  containerd: %s RSS (%.1f%%)\n" \
      "$(bytes_to_human $CONTAINERD_RSS)" "$CONTAINERD_MEM_PCT"
  fi
  
  if (( KUBELET_RSS > 0 )); then
    printf "  kubelet:    %s RSS (%.1f%%)\n" \
      "$(bytes_to_human $KUBELET_RSS)" "$KUBELET_MEM_PCT"
  fi
  
  if [[ $POD_COUNT -gt 0 ]]; then
    printf "  Pods:   %d running\n" "$POD_COUNT"
  fi
  
  if [[ -n "$REASONS_STR" ]]; then
    printf "  "
    colorize "$RED" "Alerts: %s" "$REASONS_STR"
    printf "\n"
  fi
}

output_summary() {
  local status_color=$GREEN
  [[ $STATUS == "WARNING" ]] && status_color=$YELLOW
  [[ $STATUS == "CRITICAL" ]] && status_color=$RED
  
  echo "╔════════════════════════════════════════════════════════════════════╗"
  printf "║ K8s Node Memory Watchdog - "
  colorize "$status_color" "%-38s" "$STATUS"
  printf "║\n"
  echo "╠════════════════════════════════════════════════════════════════════╣"
  printf "║ Node: %-60s ║\n" "$HOSTNAME"
  printf "║ Time: %-60s ║\n" "$timestamp"
  echo "╠════════════════════════════════════════════════════════════════════╣"
  echo "║ MEMORY OVERVIEW                                                    ║"
  printf "║   Total:       %10s                                        ║\n" \
    "$(bytes_to_human $MEM_TOTAL)"
  printf "║   Used:        %10s (%3d%%)                               ║\n" \
    "$(bytes_to_human $MEM_USED)" "$MEM_USED_PCT"
  printf "║   Available:   %10s (%3d%%)                               ║\n" \
    "$(bytes_to_human $MEM_AVAIL)" "$MEM_AVAIL_PCT"
  printf "║   Cached:      %10s                                        ║\n" \
    "$(bytes_to_human $CACHED)"
  printf "║   Buffers:     %10s                                        ║\n" \
    "$(bytes_to_human $BUFFERS)"
  printf "║   Slab:        %10s                                        ║\n" \
    "$(bytes_to_human $SLAB)"
  printf "║   Dirty:       %10s                                        ║\n" \
    "$(bytes_to_human $DIRTY)"
  
  if (( SWAP_TOTAL > 0 )); then
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║ SWAP                                                               ║"
    printf "║   Total:       %10s                                        ║\n" \
      "$(bytes_to_human $SWAP_TOTAL)"
    printf "║   Used:        %10s (%3d%%)                               ║\n" \
      "$(bytes_to_human $SWAP_USED)" "$SWAP_USED_PCT"
  fi
  
  echo "╠════════════════════════════════════════════════════════════════════╣"
  echo "║ PRESSURE STALL INFORMATION (PSI)                                   ║"
  printf "║   Memory:  some: %5.1f / %5.1f / %5.1f  full: %5.1f / %5.1f / %5.1f ║\n" \
    "$PSI_MEM_SOME10" "$PSI_MEM_SOME60" "$PSI_MEM_SOME300" \
    "$PSI_MEM_FULL10" "$PSI_MEM_FULL60" "$PSI_MEM_FULL300"
  printf "║   CPU:     some: %5.1f / %5.1f / %5.1f  full: %5.1f / %5.1f / %5.1f ║\n" \
    "$PSI_CPU_SOME10" "$PSI_CPU_SOME60" "$PSI_CPU_SOME300" \
    "$PSI_CPU_FULL10" "$PSI_CPU_FULL60" "$PSI_CPU_FULL300"
  printf "║   IO:      some: %5.1f / %5.1f / %5.1f  full: %5.1f / %5.1f / %5.1f ║\n" \
    "$PSI_IO_SOME10" "$PSI_IO_SOME60" "$PSI_IO_SOME300" \
    "$PSI_IO_FULL10" "$PSI_IO_FULL60" "$PSI_IO_FULL300"
  printf "║            (avg10 / avg60 / avg300)                                ║\n"
  
  echo "╠════════════════════════════════════════════════════════════════════╣"
  echo "║ SYSTEM METRICS                                                     ║"
  printf "║   Load Average:    %.2f / %.2f / %.2f                           ║\n" \
    "$LOAD1" "$LOAD5" "$LOAD15"
  printf "║   OOM Kills:       %-3d                                            ║\n" \
    "$OOM_KILLS"
  printf "║   File Handles:    %d / %d (%d%%)                          ║\n" \
    "$FD_ALLOCATED" "$FD_MAX" "$FD_PCT"
  
  echo "╠════════════════════════════════════════════════════════════════════╣"
  echo "║ KEY PROCESSES                                                      ║"
  if (( CONTAINERD_RSS > 0 )); then
    printf "║   containerd:  %10s RSS (%5.1f%%)                           ║\n" \
      "$(bytes_to_human $CONTAINERD_RSS)" "$CONTAINERD_MEM_PCT"
  fi
  if (( KUBELET_RSS > 0 )); then
    printf "║   kubelet:     %10s RSS (%5.1f%%)                           ║\n" \
      "$(bytes_to_human $KUBELET_RSS)" "$KUBELET_MEM_PCT"
  fi
  
  if [[ $POD_COUNT -gt 0 ]]; then
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║ KUBERNETES                                                         ║"
    printf "║   Pods Running:    %-3d                                           ║\n" \
      "$POD_COUNT"
    printf "║   Memory Pressure: %-10s                                     ║\n" \
      "$NODE_MEM_PRESSURE"
  fi
  
  echo "╠════════════════════════════════════════════════════════════════════╣"
  printf "║ TOP %d MEMORY CONSUMERS                                            ║\n" \
    "$SHOW_TOP_PROCS"
  echo "$TOP_PROCS" | while IFS='|' read -r cmd pid mem rss; do
    [[ -z "$cmd" ]] && continue
    printf "║   %-45s %5.1f%%  ║\n" \
      "$(basename "$cmd" | cut -c1-45)" "$mem"
  done
  
  if [[ -n "$REASONS_STR" ]]; then
    echo "╠════════════════════════════════════════════════════════════════════╣"
    echo "║ ALERTS                                                             ║"
    IFS=',' read -ra REASON_ARRAY <<< "$REASONS_STR"
    for reason in "${REASON_ARRAY[@]}"; do
      printf "║   • %-62s ║\n" "$reason"
    done
  fi
  
  echo "╚════════════════════════════════════════════════════════════════════╝"
}

output_json() {
  # Build top procs array
  local top_procs_json="[]"
  if [[ -n "$TOP_PROCS" ]]; then
    top_procs_json=$(echo "$TOP_PROCS" | awk -F'|' '{
      printf "{\"cmd\":\"%s\",\"pid\":%s,\"mem_pct\":%.1f,\"rss_kb\":%s},", 
        $1, $2, $3, $4
    }' | sed 's/,$//' | sed 's/^/[/' | sed 's/$/]/')
  fi
  
  jq -n \
    --arg time "$timestamp" \
    --arg hostname "$HOSTNAME" \
    --arg status "$STATUS" \
    --argjson mem_total "$MEM_TOTAL" \
    --argjson mem_used "$MEM_USED" \
    --argjson mem_avail "$MEM_AVAIL" \
    --argjson mem_avail_pct "$MEM_AVAIL_PCT" \
    --argjson mem_used_pct "$MEM_USED_PCT" \
    --argjson buffers "$BUFFERS" \
    --argjson cached "$CACHED" \
    --argjson dirty "$DIRTY" \
    --argjson slab "$SLAB" \
    --argjson swap_total "$SWAP_TOTAL" \
    --argjson swap_used "$SWAP_USED" \
    --argjson swap_used_pct "$SWAP_USED_PCT" \
    --argjson psi_mem_some10 "$PSI_MEM_SOME10" \
    --argjson psi_mem_some60 "$PSI_MEM_SOME60" \
    --argjson psi_mem_full10 "$PSI_MEM_FULL10" \
    --argjson psi_mem_full60 "$PSI_MEM_FULL60" \
    --argjson psi_cpu_some10 "$PSI_CPU_SOME10" \
    --argjson psi_io_some10 "$PSI_IO_SOME10" \
    --argjson containerd_rss "$CONTAINERD_RSS" \
    --argjson containerd_mem_pct "$CONTAINERD_MEM_PCT" \
    --argjson kubelet_rss "$KUBELET_RSS" \
    --argjson kubelet_mem_pct "$KUBELET_MEM_PCT" \
    --argjson load1 "$LOAD1" \
    --argjson load5 "$LOAD5" \
    --argjson load15 "$LOAD15" \
    --argjson oom_kills "$OOM_KILLS" \
    --argjson fd_allocated "$FD_ALLOCATED" \
    --argjson fd_max "$FD_MAX" \
    --argjson fd_pct "$FD_PCT" \
    --argjson pod_count "$POD_COUNT" \
    --arg node_mem_pressure "$NODE_MEM_PRESSURE" \
    --arg reasons "$REASONS_STR" \
    --argjson top_procs "$top_procs_json" \
    '{
      timestamp: $time,
      hostname: $hostname,
      status: $status,
      memory: {
        total_kb: $mem_total,
        used_kb: $mem_used,
        available_kb: $mem_avail,
        used_pct: $mem_used_pct,
        available_pct: $mem_avail_pct,
        buffers_kb: $buffers,
        cached_kb: $cached,
        dirty_kb: $dirty,
        slab_kb: $slab
      },
      swap: {
        total_kb: $swap_total,
        used_kb: $swap_used,
        used_pct: $swap_used_pct
      },
      psi: {
        memory: {
          some_avg10: $psi_mem_some10,
          some_avg60: $psi_mem_some60,
          full_avg10: $psi_mem_full10,
          full_avg60: $psi_mem_full60
        },
        cpu_some_avg10: $psi_cpu_some10,
        io_some_avg10: $psi_io_some10
      },
      processes: {
        containerd: {
          rss_kb: $containerd_rss,
          mem_pct: $containerd_mem_pct
        },
        kubelet: {
          rss_kb: $kubelet_rss,
          mem_pct: $kubelet_mem_pct
        }
      },
      system: {
        load: [$load1, $load5, $load15],
        oom_kills: $oom_kills,
        file_descriptors: {
          allocated: $fd_allocated,
          max: $fd_max,
          pct: $fd_pct
        }
      },
      kubernetes: {
        pod_count: $pod_count,
        memory_pressure: $node_mem_pressure
      },
      top_processes: $top_procs,
      reasons: ($reasons | split(",") | map(select(length > 0)))
    }'
}

# -------------------------------
# Run
# -------------------------------

if (( INTERVAL > 0 )); then
  [[ $MODE == "stdout" || $MODE == "summary" ]] && \
    echo "Starting watchdog (interval=${INTERVAL}s, Ctrl+C to stop)..."
  
  while true; do
    check_once || true
    [[ $MODE == "summary" ]] && sleep 1  # Brief pause for readability
    sleep "$INTERVAL"
    [[ $MODE == "summary" ]] && clear
  done
else
  check_once
  exit $?
fi
