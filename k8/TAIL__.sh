#!/usr/bin/env bash
# tail-k8s-logs.sh - Lightweight alternative to stern/kail using kubectl

set -euo pipefail

# Default values
NAMESPACE="default"
SELECTOR=""
FILTER=""
ALL_NAMESPACES=false
TAIL_LINES=100

usage() {
  echo "Usage: $0 [-n namespace] [-l label_selector] [-g grep_filter] [-a] [-t tail_lines]"
  echo ""
  echo "  -n NAMESPACE       Namespace to search (default: default)"
  echo "  -l SELECTOR        Label selector for pods (e.g. app=nginx)"
  echo "  -g FILTER          Grep filter for log content (e.g. ERROR)"
  echo "  -a                 Search across all namespaces"
  echo "  -t LINES           Number of log lines to tail (default: 100)"
  exit 1
}

while getopts ":n:l:g:at:" opt; do
  case $opt in
    n) NAMESPACE="$OPTARG" ;;
    l) SELECTOR="$OPTARG" ;;
    g) FILTER="$OPTARG" ;;
    a) ALL_NAMESPACES=true ;;
    t) TAIL_LINES="$OPTARG" ;;
    *) usage ;;
  esac
done

echo "🔍 Gathering pods..."

# Build base kubectl command
if $ALL_NAMESPACES; then
  PODS=$(kubectl get pods --all-namespaces -o json | jq -r \
    '.items[] | select(.status.phase=="Running") | [.metadata.namespace, .metadata.name] | @tsv')
else
  if [[ -n "$SELECTOR" ]]; then
    PODS=$(kubectl get pods -n "$NAMESPACE" -l "$SELECTOR" -o json | jq -r \
      '.items[] | select(.status.phase=="Running") | [.metadata.namespace, .metadata.name] | @tsv')
  else
    PODS=$(kubectl get pods -n "$NAMESPACE" -o json | jq -r \
      '.items[] | select(.status.phase=="Running") | [.metadata.namespace, .metadata.name] | @tsv')
  fi
fi

if [[ -z "$PODS" ]]; then
  echo "❌ No matching pods found."
  exit 1
fi

echo "📦 Tailing logs for pods:"
echo "$PODS" | awk '{printf "  - %s/%s\n", $1, $2}'
echo ""

# Tail logs for all matched pods in background
while IFS=$'\t' read -r NS POD; do
  (
    echo "📄 [$NS/$POD]"
    if [[ -n "$FILTER" ]]; then
      kubectl logs -n "$NS" "$POD" --tail="$TAIL_LINES" -f | grep --line-buffered "$FILTER"
    else
      kubectl logs -n "$NS" "$POD" --tail="$TAIL_LINES" -f
    fi
  ) &
done <<< "$PODS"

# Wait for background log tails to complete (Ctrl+C to exit)
trap "echo '✋ Cleaning up...'; pkill -P $$; exit" SIGINT
wait
##
