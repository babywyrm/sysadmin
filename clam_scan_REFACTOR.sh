#!/bin/bash

set -euo pipefail

###########################################
## Configurable Variables
###########################################

####
FROM="clamscan@$(hostname)"
SUBJECT="ClamAV Scan Report - $(hostname) - $(date +'%Y-%m-%d %H:%M:%S')"
SCAN_PATHS=("/" )
EXCLUDED_DIRS=("/proc" "/dev" "/sys" "/var/lib/mysql")
LOG_FILE="/var/log/clamav_scan_$(date +'%Y%m%d_%H%M%S').log"
TMP_REPORT="/tmp/clamscan_report.$$"
LOCK_FILE="/var/lock/clamav_scan.lock"
CLAMSCAN_BIN="$(command -v clamscan)"
####

###########################################
## Ensure clamscan exists
###########################################
if [[ ! -x "$CLAMSCAN_BIN" ]]; then
  echo "[!] clamscan binary not found."
  exit 127
fi

###########################################
## Locking using flock
###########################################
exec 200>"$LOCK_FILE"
flock -n 200 || {
  echo "[!] Another scan is already in progress. Exiting."
  exit 1
}

###########################################
## Build exclusion args
###########################################
EXCLUDES=()
for dir in "${EXCLUDED_DIRS[@]}"; do
  EXCLUDES+=("--exclude-dir=$dir")
done

###########################################
## Cleanup function
###########################################
cleanup() {
  rm -f "$TMP_REPORT"
}
trap cleanup EXIT

###########################################
## Run clamscan
###########################################
{
  echo "ClamAV Scan Started: $(date)"
  echo "Scanning paths: ${SCAN_PATHS[*]}"
  echo "Excluded dirs: ${EXCLUDED_DIRS[*]}"
  echo ""

  "$CLAMSCAN_BIN" -ri "${EXCLUDES[@]}" "${SCAN_PATHS[@]}"
  echo ""
  echo "Scan Finished: $(date)"
} | tee "$TMP_REPORT" | tee "$LOG_FILE"

###########################################
## Determine if infection found
###########################################
if grep -q "Infected files: [1-9]" "$TMP_REPORT"; then
  SEVERITY="WARNING: Infections Detected"
else
  SEVERITY="OK: No infections found"
fi

###########################################
## Email Output
###########################################
if command -v mail >/dev/null; then
  {
    echo "To: ${TO[*]}"
    echo "Subject: $SUBJECT [$SEVERITY]"
    echo "From: $FROM"
    echo
    cat "$TMP_REPORT"
  } | mail -s "$SUBJECT [$SEVERITY]" -r "$FROM" "${TO[@]}"
elif command -v sendmail >/dev/null; then
  {
    echo "To: ${TO[*]}"
    echo "From: $FROM"
    echo "Subject: $SUBJECT [$SEVERITY]"
    echo
    cat "$TMP_REPORT"
    echo "."
  } | sendmail -t
else
  echo "[!] Warning: No mail/sendmail found. Skipping email."
fi

###########################################
## Exit based on infection status
###########################################
if grep -q "Infected files: [1-9]" "$TMP_REPORT"; then
  exit 2
else
  exit 0
fi

##
##
