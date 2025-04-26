# Mastering Time: Faketime & Time-Sync Strategies for Active Directory Attacks

## 1. Introduction  
Active Directory’s Kerberos and Certificate Services rely on tightly synchronized clocks. 
Even a few seconds’ skew can break TGT requests, certificate enrollment, or Pass-The-Ticket. 
In pentests or CTFs you often can’t adjust the host’s global clock—enter faketime and smart NTP/LDAP/RPC timing strategies. 
This guide explains why time matters, how to measure and correct clock skew, and how to deploy an all-in-one faketime helper script.

---

## 2. Why Time Matters in AD  
- **Kerberos tickets** include “start” and “end” timestamps. If your clock differs from the KDC by more than the tolerance (default ±5 min), authentication fails (`KRB_AP_ERR_SKEW`).  
- **Certificate enrollment** (RPC/HTTP) uses timestamped requests—out-of-sync clients can’t negotiate endpoints or CSRA.  
- **Golden Tickets** and scheduled tasks require precise times to avoid detection or failure.

---

## 3. Measuring Clock Skew  

| Method               | Command/Technique                                                                      |
|----------------------|----------------------------------------------------------------------------------------|
| NTP query            | `ntpdate -q <DC_IP>`                                                                   |
| PowerShell           | `w32tm /stripchart /computer:<DC_HOST>`                                               |
| LDAP attribute check | Compare `pwdLastSet` vs. local `Get-Date`                                              |

```bash
$ ntpdate -q 192.168.1.10
server 192.168.1.10, stratum 2, offset 1.234, delay 0.02512
```

---

## 4. Sync vs. Faketime  

| Approach                | Pros                              | Cons                                  |
|-------------------------|-----------------------------------|---------------------------------------|
| `ntpdate -u <DC_IP>`    | Fixes system clock                | Requires root; affects all processes  |
| faketime (libfaketime)  | Per-process time shift            | Must `LD_PRELOAD`; per-shell only     |

**Faketime** lets you shift time only for the attack tools you run, leaving the host clock untouched.

---

## 5. Faketime Basics  

```bash
# Install (Debian/Ubuntu)
sudo apt-get install faketime

# Shift forward by 30s for a single command
FAKETIME="+30s" LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 \
  impacket-getTGT EXAMPLE.COM/user -hashes :<NTHASH> -dc-ip 192.168.1.10
```

Absolute times:

```bash
FAKETIME="2025-04-26 10:00:00" impacket-pth ...
```

---

## 6. All-In-One Faketime Helper Script  

Save as `ad-time-sync.sh`. **Source** it in your shell:

```bash
source ./ad-time-sync.sh <DC_IP> [<DOMAIN>] [<INTERVAL>]
```

### Features  
- Measures offset vs. DC every `INTERVAL` s  
- Writes `$HOME/.ad-time-sync-env` with `FAKETIME` & `LD_PRELOAD`  
- Background monitor auto-restarts; logs to `/tmp/ad-time-sync.log`  
- Optional `/etc/krb5.conf` update if you pass `<DOMAIN>`  
- Exposes shell functions:
  - `ad_time_activate`  
  - `ad_time_deactivate`  
  - `ad_time_status`  
  - `ad_time_run <cmd>`

---

### Script: `ad-time-sync.sh`  

```bash
#!/usr/bin/env bash
# AD Time Sync all-in-one
# Usage: source ad-time-sync.sh <DC_IP> [<DOMAIN>] [<INTERVAL>]

DC_IP="$1"; DOMAIN="${2:-}"; INTERVAL="${3:-60}"
ENV="$HOME/.ad-time-sync-env"; LOG="/tmp/ad-time-sync.log"
MON="/tmp/ad-time-sync-monitor.sh"

[[ -z "$DC_IP" ]] && echo "Usage: source $0 <DC_IP> [<DOMAIN>] [<INTERVAL>]" >&2 && return 1

# Write background monitor
cat >"$MON" << 'EOF'
#!/usr/bin/env bash
DC="$1"; ENV="$2"; INT="$3"; LOG="$4"
while true; do
  O=$(ntpdate -q "$DC" 2>/dev/null | grep -oP "offset \K[-0-9.]+" || echo 0)
  I=$(printf "%.0f" "$O")
  [[ $I -gt 0 ]] && FT="+${I}s" || FT="${I}s"
  cat >"$ENV"<<E
export FAKETIME="$FT"
export LD_PRELOAD="/usr/lib/faketime/libfaketime.so.1"
export LAST_OFFSET="$I"
export LAST_UPDATE="\$(date)"
E
  echo "[$(date)] OFFSET=${I}s" >>"$LOG"
  sleep "$INT"
done
EOF

chmod +x "$MON"

# Restart monitor
pkill -f "$MON" &>/dev/null || true
nohup "$MON" "$DC_IP" "$ENV" "$INTERVAL" "$LOG" &>/dev/null

# Optional krb5.conf update
if [[ -n "$DOMAIN" ]]; then
  REAL=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
  sudo tee /etc/krb5.conf >/dev/null <<KRB
[libdefaults]
  default_realm = $REAL
  dns_lookup_kdc = false
  clockskew = 300

[realms]
  $REAL = { kdc = $DC_IP }
KRB
fi

# Shell helpers
ad_time_activate() {
  [[ -f "$ENV" ]] && source "$ENV" \
    && echo "[*] Activated: offset=${LAST_OFFSET}s (updated ${LAST_UPDATE})" \
    || echo "[!] Env file missing: $ENV"
}

ad_time_deactivate() {
  unset FAKETIME LD_PRELOAD LAST_OFFSET LAST_UPDATE
  echo "[*] Deactivated: using real system time"
}

ad_time_status() {
  pid=$(pgrep -f "$MON"||echo "not running")
  echo "=== AD Time Sync Status ==="
  echo "DC_IP     : $DC_IP"
  echo "Interval  : ${INTERVAL}s"
  echo "Monitor   : $pid"
  [[ -f "$ENV" ]] && source "$ENV" \
    && echo "Offset    : ${LAST_OFFSET}s" && echo "Updated   : ${LAST_UPDATE}" \
    || echo "Env file  : missing"
  echo "Log tail  :" && tail -n3 "$LOG"
  echo "==========================="
}

ad_time_run() {
  [[ -f "$ENV" ]] || { echo "[!] Env missing"; return 1; }
  ( source "$ENV"; exec "$@" )
}

echo "[*] Monitor started: DC=${DC_IP}, interval=${INTERVAL}s"
echo "[*] Helpers: ad_time_activate, deactivate, status, run"
```

---

## 7. Usage Examples  

| Action                                | Command                                                                                   |
|---------------------------------------|-------------------------------------------------------------------------------------------|
| Start monitor & env (60 s interval)   | `source ./ad-time-sync.sh 192.168.1.10 example.com`                                       |
| Activate faketime in shell           | `ad_time_activate`                                                                        |
| Run Impacket under adjusted time      | `ad_time_run impacket-getTGT EXAMPLE.COM/user -hashes :<NTHASH> -dc-ip 192.168.1.10`       |
| Check status & recent logs            | `ad_time_status`                                                                          |
| Deactivate faketime                   | `ad_time_deactivate`                                                                       |

---

## 8. Best Practices  
- **Check offset** before critical steps: `ad_time_status`  
- Use tool debug flags (`-debug`) to spot “clock skew” errors early  
- Combine faketime with `clockskew = 300` in `krb5.conf` for CTFs  
- If RPC ports fail, try Web Enrollment (`-web`) or LDAP certificate requests  
- Tune `INTERVAL` to your environment drift: 5–60 s

---

## 9. Advanced Strategies  
- **Golden Tickets**: generate tickets with custom times; use faketime to validate before deployment  
- **Scheduled Tasks**: align triggers with DC time for stealth  
- **Log Correlation**: compare event logs to your adjusted time  

