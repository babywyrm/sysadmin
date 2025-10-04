#!/bin/bash
# Kubernetes Real-time Dashboard (ANSI-fixed, Wide Display) .. beta ..
# Version: 4.3-clean
# Author: Security Assessment Team

set -euo pipefail

SCRIPT_VERSION="4.3-clean"
REFRESH_INTERVAL=5
MODE="overview"
RUNNING=true

# === Color palette (ANSI-safe) ===
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;36m"
WHITE="\033[1;37m"
PLAIN="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"

HIDE_CURSOR="\033[?25l"
SHOW_CURSOR="\033[?25h"
CLEAR="\033[2J"
HOME="\033[H"

cleanup() {
  RUNNING=false
  printf "%b" "${SHOW_CURSOR}${PLAIN}\n"
  echo "Dashboard stopped at $(date)"
  exit 0
}
trap cleanup INT TERM

if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl not found."
  exit 1
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "ERROR: cannot connect to Kubernetes cluster."
  exit 1
fi

# === HEADER ===
draw_header() {
  local now context width line
  now=$(date '+%Y-%m-%d %H:%M:%S')
  context=$(kubectl config current-context 2>/dev/null || echo "unknown")
  width=$(tput cols 2>/dev/null || echo 120)
  ((width<100)) && width=100
  line=$(printf "%${width}s" | tr ' ' '=')
  printf "%b\n" "${WHITE}${BOLD}${line}${PLAIN}"
  printf "%b| K8s Dashboard v%-10s | Mode: %-12s | Time: %-19s |\n" \
    "${WHITE}${BOLD}" "$SCRIPT_VERSION" "$MODE" "$now"
  printf "| Context: %-40s | Refresh: %-3ss |\n" "$context" "$REFRESH_INTERVAL"
  printf "%b\n" "${line}${PLAIN}"
}

# === Helper print ===
print_title() {
  printf "\n%b%s%b\n%b%s%b\n" "$BOLD" "$1" "$PLAIN" "$BLUE" "$(printf -- '-%.0s' {1..80})" "$PLAIN"
}

# === Overview ===
dashboard_overview() {
  print_title "CLUSTER OVERVIEW"
  local nodes ready ns pods run fail svc ing
  nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
  ready=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo 0)
  ns=$(kubectl get ns --no-headers 2>/dev/null | wc -l | tr -d ' ')
  pods=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
  run=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -c " Running " || echo 0)
  fail=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -c -E "(Error|CrashLoopBackOff|Failed)" || echo 0)
  svc=$(kubectl get svc --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
  ing=$(kubectl get ingress --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ' || echo 0)

  printf "%-22s: %s total, %s ready\n" "Nodes" "$nodes" "$ready"
  printf "%-22s: %s\n" "Namespaces" "$ns"
  printf "%-22s: %s total, %s running, %s failed\n" "Pods" "$pods" "$run" "$fail"
  printf "%-22s: %s\n" "Services" "$svc"
  printf "%-22s: %s\n" "Ingresses" "$ing"

  print_title "NODE SUMMARY"
  kubectl get nodes -o wide 2>/dev/null || echo "No node data"

  print_title "TOP PODS (CPU)"
  if kubectl top pods --all-namespaces --sort-by=cpu >/dev/null 2>&1; then
    kubectl top pods --all-namespaces --sort-by=cpu | head -10
  else
    echo "Metrics unavailable (metrics-server missing)."
  fi

  print_title "RECENT EVENTS"
  kubectl get events --all-namespaces --sort-by=.lastTimestamp 2>/dev/null | tail -8 || true
}

# === Security ===
dashboard_security() {
  print_title "SECURITY CONTROLS"
  local np priv root
  np=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
  printf "%-28s: %s\n" "Network Policies" "$np"

  if command -v jq >/dev/null 2>&1; then
    local json
    json=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")
    priv=$(echo "$json" | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | .metadata.name' | wc -l)
    root=$(echo "$json" | jq -r '.items[] | select(.spec.containers[]?.securityContext?.runAsUser == 0) | .metadata.name' | wc -l)
  else
    priv="?"
    root="?"
  fi
  printf "%-28s: %s\n" "Privileged containers" "$priv"
  printf "%-28s: %s\n" "Containers running as root" "$root"

  print_title "HIGH-RISK ROLE BINDINGS"
  kubectl get clusterrolebindings -o wide 2>/dev/null | grep -E "(admin|edit|cluster-admin)" | head -10 || echo "None."

  print_title "SECURITY EVENTS"
  kubectl get events --all-namespaces --sort-by=.lastTimestamp 2>/dev/null | grep -i -E "(denied|forbidden|unauthorized)" | tail -10 || echo "None."
}

# === Performance ===
dashboard_performance() {
  print_title "NODE & POD METRICS"
  if kubectl top nodes >/dev/null 2>&1; then
    echo "Node Utilization:"
    kubectl top nodes 2>/dev/null
    echo
    echo "Top 10 Pods by Memory:"
    kubectl top pods --all-namespaces --sort-by=memory 2>/dev/null | head -10
  else
    echo "Metrics-server not available."
  fi
}

# === Events ===
dashboard_events() {
  print_title "RECENT CLUSTER EVENTS"
  kubectl get events --all-namespaces --sort-by=.lastTimestamp 2>/dev/null | tail -20 || echo "No events."
}

# === Footer ===
draw_footer() {
  local width line
  width=$(tput cols 2>/dev/null || echo 120)
  ((width<100)) && width=100
  line=$(printf "%${width}s" | tr ' ' '-')
  printf "%b\n" "${BLUE}${line}${PLAIN}"
  printf "Keys: [q] Quit | [1] Overview | [2] Security | [3] Performance | [4] Events | [+/-] Refresh rate\n"
  printf "%b\n" "${BLUE}${line}${PLAIN}"
}

# === Main loop ===
main_loop() {
  local key=""
  while $RUNNING; do
    printf "%b" "${CLEAR}${HOME}"
    draw_header
    case "$MODE" in
      overview)     dashboard_overview ;;
      security)     dashboard_security ;;
      performance)  dashboard_performance ;;
      events)       dashboard_events ;;
    esac
    draw_footer
    read -t "$REFRESH_INTERVAL" -n 1 key 2>/dev/null && case "$key" in
      q|Q) cleanup ;;
      1) MODE="overview" ;;
      2) MODE="security" ;;
      3) MODE="performance" ;;
      4) MODE="events" ;;
      +) ((REFRESH_INTERVAL>1)) && ((REFRESH_INTERVAL--)) ;;
      -) ((REFRESH_INTERVAL<30)) && ((REFRESH_INTERVAL++)) ;;
    esac
  done
}

printf "%b" "${CLEAR}${HOME}${HIDE_CURSOR}"
echo "Starting Kubernetes Dashboard v${SCRIPT_VERSION} ..."
sleep 1
main_loop
