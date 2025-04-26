#!/usr/bin/env bash
#
# AD Time Sync (all-in-one)
# Usage: source ad-time-sync.sh <DC_IP> [<DOMAIN>] [<INTERVAL>]
#
# Example:
#   source ./ad-time-sync.sh 10.10.10.10 corp.local 30
#

DC_IP="$1"
DOMAIN="${2:-}"
INTERVAL="${3:-60}"
ENV_FILE="$HOME/.ad-time-sync-env"
LOG_FILE="/tmp/ad-time-sync.log"
MONITOR="/tmp/ad-time-sync-monitor.sh"

if [[ -z "$DC_IP" ]]; then
  echo "Usage: source $0 <DC_IP> [<DOMAIN>] [<INTERVAL>]" >&2
  return 1 2>/dev/null || exit 1
fi

# Write the background monitor
cat > "$MONITOR" << 'EOF'
#!/usr/bin/env bash
DC_IP="$1"; ENV_FILE="$2"; INTERVAL="$3"; LOG="$4"
while true; do
  # measure offset
  OFFSET=$(ntpdate -q "$DC_IP" 2>/dev/null \
    | grep -oP "offset \K[-0-9.]+" || echo 0)
  IOFF=$(printf "%.0f" "$OFFSET")
  # construct faketime string
  if (( IOFF > 0 )); then
    FT="+${IOFF}s"
  else
    FT="${IOFF}s"
  fi
  # write env
  cat >"$ENV_FILE" <<E
export FAKETIME="$FT"
export LD_PRELOAD="/usr/lib/faketime/libfaketime.so.1"
export LAST_OFFSET="$IOFF"
export LAST_UPDATE="\$(date)"
E
  echo "[$(date)] OFFSET=${IOFF}s" >>"$LOG"
  sleep "$INTERVAL"
done
EOF

chmod +x "$MONITOR"

# kill old monitor, start new one
pkill -f "$MONITOR" 2>/dev/null || true
nohup "$MONITOR" "$DC_IP" "$ENV_FILE" "$INTERVAL" "$LOG_FILE" >/dev/null 2>&1 &

# optional krb5.conf update
if [[ -n "$DOMAIN" ]]; then
  REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
  sudo tee /etc/krb5.conf >/dev/null <<KRB
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  clockskew = 300

[realms]
  $REALM = {
    kdc = $DC_IP
  }
KRB
fi

# define helper functions
ad_time_activate() {
  if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    echo "[*] Activated: offset=${LAST_OFFSET}s (updated $LAST_UPDATE)"
  else
    echo "[!] Env file not found: $ENV_FILE"
  fi
}

ad_time_deactivate() {
  unset FAKETIME LD_PRELOAD LAST_OFFSET LAST_UPDATE
  echo "[*] Deactivated: using real system time"
}

ad_time_status() {
  local pid
  pid=$(pgrep -f "$MONITOR" || echo "not running")
  echo "=== AD Time Sync Status ==="
  echo "DC_IP        : $DC_IP"
  echo "Interval     : ${INTERVAL}s"
  echo "Monitor PID  : $pid"
  if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    echo "Current offset: ${LAST_OFFSET}s"
    echo "Last update   : ${LAST_UPDATE}"
  else
    echo "Env file      : missing"
  fi
  echo "Log tail      :"
  tail -n3 "$LOG_FILE" 2>/dev/null || echo "  (no log)"
  echo "============================"
}

ad_time_run() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "[!] Env file missing. Source and activate first."
    return 1
  fi
  # run given command in a subshell with faketime
  (
    source "$ENV_FILE"
    exec "$@"
  )
}

# notify user
echo "[*] AD Time Sync monitor started (DC=$DC_IP, interval=${INTERVAL}s)"
echo "[*] Env file    : $ENV_FILE"
echo "[*] Log file    : $LOG_FILE"
echo "[*] Helper funcs: ad_time_activate, ad_time_deactivate, ad_time_status, ad_time_run"
