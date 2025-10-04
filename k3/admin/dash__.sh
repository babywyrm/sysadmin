#!/bin/bash
# Kubernetes Dashboard - v4.5-Pro (Clean ASCII, journalctl-k3s support) ..beta..
# Stable interactive cluster dashboard for K8s/K3s
# Author: Security Assessment Team

set -euo pipefail

# Configurable defaults
SCRIPT_VERSION="4.5-Pro"
REFRESH_INTERVAL=5
MODE="overview"
RUNNING=true
JOURNAL_LINES=50
SHOW_EVENTS=true
NAMESPACE_FILTER=""
TEXT_FILTER=""
REPORT_MODE=false

# Colors (ANSI-safe)
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; BLUE="\033[0;36m"
WHITE="\033[1;37m"; PLAIN="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
HIDE_CURSOR="\033[?25l"; SHOW_CURSOR="\033[?25h"; CLEAR="\033[2J"; HOME="\033[H"

cleanup() {
  printf "%b" "${SHOW_CURSOR}${PLAIN}\n"
  tput cnorm 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

usage() {
  cat <<EOF
Kubernetes Dashboard ${SCRIPT_VERSION}
Usage: $0 [options]
Options:
  -n, --namespace <ns>   Only show this namespace
  -r, --refresh <sec>    Refresh interval (default 5)
  -j, --journal-lines N  Number of journalctl lines to display (default 50)
  --no-events            Skip Kubernetes Events output
  --report               Print one static report (no live refresh)
  --filter TEXT          Filter output lines containing TEXT
  -h, --help             Show this help
EOF
  exit 0
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--refresh) REFRESH_INTERVAL="$2"; shift 2 ;;
    -j|--journal-lines) JOURNAL_LINES="$2"; shift 2 ;;
    -n|--namespace) NAMESPACE_FILTER="$2"; shift 2 ;;
    --no-events) SHOW_EVENTS=false; shift ;;
    --report) REPORT_MODE=true; shift ;;
    --filter) TEXT_FILTER="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

# Dependency checks
if ! command -v kubectl >/dev/null; then
  echo "kubectl required"; exit 1
fi

# HEADER ======================================================================
draw_header() {
  local now context width line
  now=$(date '+%Y-%m-%d %H:%M:%S')
  context=$(kubectl config current-context 2>/dev/null || echo "unknown")
  width=$(tput cols 2>/dev/null || echo 120)
  ((width<100)) && width=100
  line=$(printf "%${width}s" | tr ' ' '=')
  printf "%b\n" "${WHITE}${BOLD}${line}${PLAIN}"
  printf "%b| K8s Dashboard %-12s | Mode: %-10s | %s |\n" \
    "${WHITE}${BOLD}" "$SCRIPT_VERSION" "$MODE" "$now"
  printf "| Context: %-40s | Refresh: %-3ss Lines: %-4s |\n" "$context" "$REFRESH_INTERVAL" "$JOURNAL_LINES"
  printf "%b\n" "${line}${PLAIN}"
}

# TITLE & HELPERS =============================================================
title() {
  printf "\n%b%s%b\n%b%s%b\n" "$BOLD" "$1" "$PLAIN" "$BLUE" "$(printf -- '-%.0s' {1..100})" "$PLAIN"
}

scoped() {
  if [[ -n "$NAMESPACE_FILTER" ]]; then
    echo "--namespace $NAMESPACE_FILTER"
  else
    echo "--all-namespaces"
  fi
}

# OVERVIEW ====================================================================
cluster_overview() {
  title "CLUSTER OVERVIEW"
  local ns nodes ready pods run fail svc ing
  ns=$(kubectl get ns --no-headers 2>/dev/null | wc -l | tr -d ' ')
  nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
  ready=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo 0)
  pods=$(kubectl get pods $(scoped) --no-headers 2>/dev/null | wc -l | tr -d ' ')
  run=$(kubectl get pods $(scoped) --no-headers 2>/dev/null | grep -c " Running " || echo 0)
  fail=$(kubectl get pods $(scoped) --no-headers 2>/dev/null | grep -c -E "(Error|CrashLoopBackOff|Failed)" || echo 0)
  svc=$(kubectl get svc $(scoped) --no-headers 2>/dev/null | wc -l | tr -d ' ')
  ing=$(kubectl get ingress $(scoped) --no-headers 2>/dev/null | wc -l | tr -d ' ' || echo 0)

  printf "%-22s: %s total, %s ready\n" "Nodes" "$nodes" "$ready"
  printf "%-22s: %s\n" "Namespaces" "$ns"
  printf "%-22s: %s total, %s running, %s failed\n" "Pods" "$pods" "$run" "$fail"
  printf "%-22s: %s\n" "Services" "$svc"
  printf "%-22s: %s\n" "Ingresses" "$ing"

  title "NODE STATUS"
  kubectl get nodes -o wide 2>/dev/null || echo "No node data"

  title "PODS (Top Memory)"
  if kubectl top pods $(scoped) --sort-by=memory >/dev/null 2>&1; then
    kubectl top pods $(scoped) --sort-by=memory | head -10
  else
    echo "Metrics unavailable."
  fi

  if $SHOW_EVENTS; then
    title "RECENT EVENTS"
    kubectl get events $(scoped) --sort-by=.lastTimestamp 2>/dev/null | tail -8 || true
  fi
}

# SECURITY ====================================================================
security_view() {
  title "SECURITY MONITORING"
  local np priv root
  np=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
  printf "%-25s: %s\n" "Network Policies" "$np"

  if command -v jq >/dev/null 2>&1; then
    local pods_json
    pods_json=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")
    priv=$(echo "$pods_json" | jq '.items[] | select(.spec.containers[]?.securityContext?.privileged == true)' | wc -l)
    root=$(echo "$pods_json" | jq '.items[] | select(.spec.containers[]?.securityContext?.runAsUser == 0)' | wc -l)
  else
    priv="?"
    root="?"
  fi

  printf "%-25s: %s\n" "Privileged containers" "$priv"
  printf "%-25s: %s\n" "Containers runAsRoot" "$root"

  title "SECURITY EVENTS"
  kubectl get events --all-namespaces --sort-by=.lastTimestamp 2>/dev/null \
    | grep -i -E "(denied|forbidden|unauthorized)" | tail -10 || echo "None."
}

# PERFORMANCE =================================================================
performance_view() {
  title "RESOURCE PERFORMANCE"
  if kubectl top nodes >/dev/null 2>&1; then
    echo "Node utilization:"
    kubectl top nodes
    echo
    echo "Top pods by CPU:"
    kubectl top pods --all-namespaces --sort-by=cpu | head -10
  else
    echo "metrics-server not running."
  fi
}

# JOURNALCTL / SYSTEM LOGS ====================================================
journal_tail() {
  title "SYSTEMD JOURNAL (last $JOURNAL_LINES lines)"
  local units=("k3s" "kubelet" "kube-apiserver" "kube-controller-manager" "etcd")
  local found=false

  if command -v journalctl >/dev/null 2>&1; then
    for unit in "${units[@]}"; do
      if sudo journalctl -u "$unit" -n 1 --no-pager 2>/dev/null | grep -q .; then
        printf "Showing last %s lines from systemd unit: %s\n\n" "$JOURNAL_LINES" "$unit"
        sudo journalctl -u "$unit" -n "$JOURNAL_LINES" --no-pager 2>/dev/null | tail -n "$JOURNAL_LINES"
        found=true
        break
      fi
    done
  fi

  if ! $found; then
    echo "No systemd logs found for units: ${units[*]}"
    echo "Falling back to container or syslog files..."
    if [ -d /var/log/containers ]; then
      tail -n "$JOURNAL_LINES" /var/log/containers/*kube*.log 2>/dev/null || \
      echo "No *kube* container logs found under /var/log/containers/."
    elif [ -f /var/log/syslog ]; then
      grep -E "kube|api|scheduler|etcd|k3s" /var/log/syslog | tail -n "$JOURNAL_LINES"
    elif [ -f /var/log/messages ]; then
      grep -E "kube|api|scheduler|etcd|k3s" /var/log/messages | tail -n "$JOURNAL_LINES"
    else
      echo "No usable log source found."
    fi
  fi
}

# FOOTER ======================================================================
footer() {
  local width line
  width=$(tput cols 2>/dev/null || echo 120)
  line=$(printf "%${width}s" | tr ' ' '-')
  printf "%b\n" "${BLUE}${line}${PLAIN}"
  printf "Keys: [q] Quit | [1] Overview | [2] Security | [3] Performance | [j] Journal | [+/-] Refresh | Namespace: ${NAMESPACE_FILTER:-all}\n"
  printf "%b\n" "${BLUE}${line}${PLAIN}"
}

# MAIN RENDERER ===============================================================
render() {
  printf "%b" "${CLEAR}${HOME}"
  draw_header
  case "$MODE" in
    overview)     cluster_overview ;;
    security)     security_view ;;
    performance)  performance_view ;;
    journal)      journal_tail ;;
  esac
  footer
}

# STATIC REPORT MODE ==========================================================
if $REPORT_MODE; then
  render
  exit 0
fi

printf "%b" "${HIDE_CURSOR}"
tput civis 2>/dev/null || true
echo "Starting Kubernetes Dashboard v${SCRIPT_VERSION}..."
sleep 1

# MAIN LOOP ===================================================================
key=""
while $RUNNING; do
  render
  read -t "$REFRESH_INTERVAL" -n 1 key 2>/dev/null && case "$key" in
    q|Q) cleanup ;;
    1) MODE="overview" ;;
    2) MODE="security" ;;
    3) MODE="performance" ;;
    j|J) MODE="journal" ;;
    +) ((REFRESH_INTERVAL>1)) && ((REFRESH_INTERVAL--)) ;;
    -) ((REFRESH_INTERVAL<30)) && ((REFRESH_INTERVAL++)) ;;
  esac
done
