#!/usr/bin/env bash
# AD Time Sync Background Service
# Usage: source ./ad-time-sync-env.sh <DC_IP> [DOMAIN]

# Configuration
DC_IP="$1"
DOMAIN="${2:-}"
CLOCKSKEW=300
ENV_FILE="$HOME/.ad-time-sync-env"
POLL_INTERVAL=60  # Check time offset every 60 seconds

if [[ -z "$DC_IP" ]]; then
  echo "Usage: source ./ad-time-sync-env.sh <DC_IP> [DOMAIN]"
  return 1 2>/dev/null || exit 1
fi

# Stop any existing monitoring processes
pkill -f "ad-time-sync-monitor" 2>/dev/null || true

# Create the monitor script
cat > /tmp/ad-time-sync-monitor.sh << 'EOF'
#!/usr/bin/env bash
# AD Time Sync Background Monitor

DC_IP="$1"
ENV_FILE="$2"
POLL_INTERVAL="$3"

function update_time_offset() {
  # Get time offset
  OFFSET=$(ntpdate -q "$DC_IP" 2>/dev/null | grep -oP "offset \K[-0-9.]+" || echo "0")
  INT_OFFSET=$(printf "%.0f" "$OFFSET")
  
  # Create faketime string
  if [[ $INT_OFFSET -gt 0 ]]; then
    FAKETIME="+${INT_OFFSET}s"
  else
    FAKETIME="${INT_OFFSET}s"
  fi
  
  # Update environment file
  echo "export FAKETIME=\"$FAKETIME\"" > "$ENV_FILE"
  echo "export LD_PRELOAD=\"/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1\"" >> "$ENV_FILE"
  echo "export LAST_OFFSET=\"$INT_OFFSET\"" >> "$ENV_FILE"
  echo "export LAST_UPDATE=\"$(date)\"" >> "$ENV_FILE"
  
  # Log update
  echo "[$(date)] Updated time offset to $INT_OFFSET seconds" >> "/tmp/ad-time-sync.log"
}

# Run continuously
while true; do
  update_time_offset
  sleep "$POLL_INTERVAL"
done
EOF

chmod +x /tmp/ad-time-sync-monitor.sh

# Start the monitor process in background
/tmp/ad-time-sync-monitor.sh "$DC_IP" "$ENV_FILE" "$POLL_INTERVAL" &
MONITOR_PID=$!

# Update krb5.conf if domain provided
if [[ -n "$DOMAIN" ]]; then
  REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
  REALM_LOWER=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
  
  echo "[*] Updating /etc/krb5.conf with domain $DOMAIN"
  sudo tee /etc/krb5.conf > /dev/null << EOF
[libdefaults]
  default_realm = ${REALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  clockskew = ${CLOCKSKEW}

[realms]
  ${REALM} = {
    kdc = ${DC_IP}
    admin_server = ${DC_IP}
  }

[domain_realm]
  .${REALM_LOWER} = ${REALM}
  ${REALM_LOWER} = ${REALM}
EOF
fi

# Create activation/deactivation functions
cat > "$HOME/.ad-time-sync-functions" << EOF
# AD Time Sync Functions

ad_time_activate() {
  if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    echo "[*] AD Time Sync activated. Current offset: \$LAST_OFFSET seconds"
    echo "[*] Last updated: \$LAST_UPDATE"
    return 0
  else
    echo "[!] AD Time Sync environment not found. Run setup script first."
    return 1
  fi
}

ad_time_deactivate() {
  unset FAKETIME
  unset LD_PRELOAD
  unset LAST_OFFSET
  unset LAST_UPDATE
  echo "[*] AD Time Sync deactivated. System time will be used."
}

ad_time_status() {
  if [[ -n "\$FAKETIME" ]]; then
    echo "[*] AD Time Sync is ACTIVE"
    echo "[*] Current offset: \$LAST_OFFSET seconds"
    echo "[*] Last updated: \$LAST_UPDATE"
    echo "[*] Background service PID: \$(pgrep -f 'ad-time-sync-monitor' || echo 'Not running')"
  else
    echo "[*] AD Time Sync is INACTIVE"
    if [[ -f "$ENV_FILE" ]]; then
      source "$ENV_FILE"
      echo "[*] Available offset: \$LAST_OFFSET seconds"
      echo "[*] Last updated: \$LAST_UPDATE"
    fi
    echo "[*] Background service PID: \$(pgrep -f 'ad-time-sync-monitor' || echo 'Not running')"
  fi
}
EOF

# Wait for initial time sync
echo "[*] Waiting for initial time sync..."
sleep 3

# Source the functions
source "$HOME/.ad-time-sync-functions"

# Print setup information
echo "[*] AD Time Sync background service started for DC: $DC_IP"
echo "[*] Monitor PID: $MONITOR_PID"
echo "[*] Time offset will be checked every $POLL_INTERVAL seconds"
echo ""
echo "[*] To activate time sync in your current shell:"
echo "    source ~/.ad-time-sync-functions"
echo "    ad_time_activate"
echo ""
echo "[*] To deactivate:"
echo "    ad_time_deactivate"
echo ""
echo "[*] To check status:"
echo "    ad_time_status"
echo ""
echo "[*] To stop the background service:"
echo "    pkill -f 'ad-time-sync-monitor'"
echo ""
echo "[*] Add this to your .bashrc to enable functions in all shells:"
echo "    echo 'source ~/.ad-time-sync-functions' >> ~/.bashrc"
echo ""

# Activate time sync in current shell
ad_time_activate
