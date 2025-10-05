#!/bin/bash
# K8s / K3s real‑time dashboard (watch‑based)
# Version 1.2‑Power – usability improvements & extra toggles ..beta..

REFRESH_INTERVAL=5
JOURNAL_LINES=20
NAMESPACE=""
UNIT=""                # systemd unit (auto‑detected)
SHOW_LOGS=true
SHOW_EVENTS=true
SHOW_METRICS=true
SHOW_TOPN=5            # top pods count
WIDE=false

usage() {
cat <<EOF
Usage: $0 [options]
  -n <namespace>   Limit to namespace (default all)
  -r <seconds>     Refresh interval  [default 5]
  -l <lines>       Journal lines     [default 20]
  -t <count>       Top pods displayed [default 5]
  -u <unit>        Force systemd unit (e.g. k3s)
  --no-logs        Disable journal block
  --no-events      Disable events block
  --no-metrics     Disable metrics block
  --wide           Show wide node output
  -h               Help
EOF
exit 0
}

# ---- argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) NAMESPACE="--namespace $2"; shift 2 ;;
    -r) REFRESH_INTERVAL="$2"; shift 2 ;;
    -l) JOURNAL_LINES="$2"; shift 2 ;;
    -t) SHOW_TOPN="$2"; shift 2 ;;
    -u) UNIT="$2"; shift 2 ;;
    --no-logs)    SHOW_LOGS=false; shift ;;
    --no-events)  SHOW_EVENTS=false; shift ;;
    --no-metrics) SHOW_METRICS=false; shift ;;
    --wide)       WIDE=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown flag: $1"; usage ;;
  esac
done

# ---- detect journal unit when not given ------------------------------------
detect_unit() {
  for u in k3s kubelet kube-apiserver; do
    if sudo journalctl -u "$u" -n 1 --no-pager 2>/dev/null | grep -q .; then
      echo "$u"
      return
    fi
  done
}
[[ -z "$UNIT" ]] && UNIT=$(detect_unit)

# ---- build the watch command script ----------------------------------------
TMP=$(mktemp)
{
  echo 'date'
  echo 'echo'
  echo 'echo "==== CLUSTER STATUS ================================="'
  if $WIDE; then
    echo 'kubectl get nodes -o wide 2>/dev/null'
  else
    echo 'kubectl get nodes 2>/dev/null'
  fi
  echo 'echo'

  if [[ -z "$NAMESPACE" ]]; then
    echo "kubectl get pods -A --no-headers 2>/dev/null | awk '{c[\$4]++} END {for(s in c) printf \"%s: %s  \",s,c[s]; printf \"\\n\"}'"
  else
    echo "kubectl get pods $NAMESPACE --no-headers 2>/dev/null | awk '{c[\$3]++} END {for(s in c) printf \"%s: %s  \",s,c[s]; printf \"\\n\"}'"
  fi
  echo 'echo'

  if $SHOW_METRICS; then
    echo "echo '==== METRICS (top ${SHOW_TOPN} pods by memory) ================='"
    echo "kubectl top pods -A 2>/dev/null | head -n $((SHOW_TOPN+1)) || echo '(metrics‑server not available)'"
    echo 'echo'
  fi

  if $SHOW_EVENTS; then
    echo 'echo "==== RECENT EVENTS ==================================="'
    echo 'kubectl get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -n 8 || echo "(no events)"'
    echo 'echo'
  fi

  if $SHOW_LOGS; then
    if [[ -n "$UNIT" ]]; then
      echo "echo \"==== SYSTEMD LOGS ($UNIT, last $JOURNAL_LINES lines) ====\""
      echo "sudo journalctl -u $UNIT -n $JOURNAL_LINES --no-pager 2>/dev/null | tail -n $JOURNAL_LINES"
    else
      echo 'echo "(no known systemd unit for K3s/K8s detected)"'
    fi
  fi

  # Compact footer
  echo "echo"
  echo "echo '[ q = quit | r = faster | s = slower | c = clear screen ]'"
} >"$TMP"
chmod +x "$TMP"

# ---- run the dashboard ------------------------------------------------------
echo "Launching dashboard (refresh every $REFRESH_INTERVAL s; Ctrl‑C quits)..."
sleep 1
watch -c -n "$REFRESH_INTERVAL" bash "$TMP"

# ---- cleanup ----------------------------------------------------------------
trap 'rm -f "$TMP"' EXIT
