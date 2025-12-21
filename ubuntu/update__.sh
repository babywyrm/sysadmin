#!/usr/bin/env bash
# ==============================================================================
# System Maintenance & Update Utility
# VERSION: 2.4.0
# ==============================================================================
#
# BEHAVIOR SUMMARY:
#   - Auto-detects Kali and enables safe full-upgrade
#   - Defaults to conservative server mode elsewhere
#   - No unsafe bash constructs under set -e
#   - Explicit logging of upgrade decisions
# ==============================================================================

set -Eeuo pipefail

# ==============================================================================
# CONFIGURATION
# ==============================================================================

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="2.4.0"

LOG_FILE="/var/log/system_update_$(date +%Y%m%d).log"
LOCK_FILE="/var/run/system_update.lock"

# Colors
TEXT_RESET='\e[0m'
TEXT_GREEN='\e[1;32m'
TEXT_YELLOW='\e[0;33m'
TEXT_RED='\e[1;31m'
TEXT_BLUE='\e[1;34m'

# Defaults
VERBOSE=0
QUIET=0
DRY_RUN=0

MODE="server"          # server | kali
ALLOW_AUTOREMOVE=0

export NEEDRESTART_MODE=a
export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical

# ==============================================================================
# AUTO-DETECT OS
# ==============================================================================

if [[ -f /etc/os-release ]]; then
    if grep -qi '^ID=kali' /etc/os-release; then
        MODE="kali"
        ALLOW_AUTOREMOVE=1
    fi
fi

# ==============================================================================
# LOGGING
# ==============================================================================

timestamp() { date +"%Y-%m-%d %H:%M:%S"; }
strip_colors() { sed 's/\x1b\[[0-9;]*m//g'; }

log() {
    local level="$1"; shift
    local msg="$*"
    local line="[$(timestamp)] [$level] $msg"

    echo -e "$line" | strip_colors >> "$LOG_FILE"

    [[ "$QUIET" -eq 1 ]] && return

    case "$level" in
        INFO)  echo -e "${TEXT_GREEN}$line${TEXT_RESET}" ;;
        WARN)  echo -e "${TEXT_YELLOW}$line${TEXT_RESET}" ;;
        ERROR) echo -e "${TEXT_RED}$line${TEXT_RESET}" ;;
        DEBUG)
            if [[ "$VERBOSE" -ge 2 ]]; then
                echo -e "${TEXT_BLUE}$line${TEXT_RESET}"
            fi
            ;;
    esac
}

run_cmd() {
    local cmd="$*"
    log DEBUG "Executing: $cmd"

    [[ "$DRY_RUN" -eq 1 ]] && return 0

    if [[ "$VERBOSE" -ge 1 ]]; then
        eval "$cmd" 2>&1 | tee -a "$LOG_FILE"
    else
        eval "$cmd" >> "$LOG_FILE" 2>&1
    fi
}

trap 'log ERROR "Failure at line $LINENO: $BASH_COMMAND"; exit 1' ERR

# ==============================================================================
# HELPERS
# ==============================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log ERROR "This script must be run as root"
        exit 1
    fi
}

check_lock() {
    exec 9>"$LOCK_FILE"
    flock -n 9 || { log ERROR "Another instance is running"; exit 1; }
}

check_disk_space() {
    local free
    free=$(df / --output=avail -BG | tail -1 | tr -dc '0-9')

    if [[ "$free" -lt 1 ]]; then
        log WARN "Low disk space (${free}GB available)"
        if [[ -t 1 ]]; then
            read -rp "Continue anyway? [y/N]: " yn
            [[ "$yn" =~ ^[Yy]$ ]] || exit 1
        else
            exit 1
        fi
    fi
}

check_network() {
    if ! ping -c1 -W2 archive.ubuntu.com &>/dev/null; then
        log ERROR "Network connectivity check failed"
        exit 1
    fi
}

# ==============================================================================
# ARGUMENT PARSING
# ==============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kali-mode)
            MODE="kali"
            ALLOW_AUTOREMOVE=1
            shift
            ;;
        --server-mode)
            MODE="server"
            ALLOW_AUTOREMOVE=0
            shift
            ;;
        --allow-autoremove)
            ALLOW_AUTOREMOVE=1
            shift
            ;;
        --no-autoremove)
            ALLOW_AUTOREMOVE=0
            shift
            ;;
        -v)
            VERBOSE=$((VERBOSE + 1))
            shift
            ;;
        -vv)
            VERBOSE=2
            shift
            ;;
        -q)
            QUIET=1
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            cat <<EOF
System Maintenance Utility v$SCRIPT_VERSION

USAGE:
  $SCRIPT_NAME [options]

OPTIONS:
  --kali-mode           Force Kali full-upgrade mode
  --server-mode         Force conservative server mode
  --allow-autoremove    Enable autoremove
  --no-autoremove       Disable autoremove
  -v                    Verbose output
  -vv                   Debug (bash tracing)
  -q                    Quiet (log only)
  -n, --dry-run         Dry run
  -h, --help            Show help

EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ "$VERBOSE" -ge 2 ]]; then
    set -x
fi

# ==============================================================================
# MAIN
# ==============================================================================

check_root
check_lock
check_disk_space
check_network

echo "Maintenance started: $(date)" > "$LOG_FILE"

log INFO "-----------------------------------"
log INFO "System Maintenance Started"
log INFO "Mode: $MODE"
log INFO "Autoremove: $ALLOW_AUTOREMOVE"
log INFO "Log file: $LOG_FILE"
log INFO "-----------------------------------"

log INFO "Updating package lists"
run_cmd "apt-get -qy update"

log INFO "Cleaning package cache"
run_cmd "apt-get -qy clean"

if [[ "$MODE" == "kali" ]]; then
    log INFO "Detected Kali — running full-upgrade (safe rolling behavior)"
    run_cmd "apt-get -qy \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        full-upgrade"
else
    log INFO "Running conservative server dist-upgrade"
    run_cmd "apt-get -qy \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        dist-upgrade"
fi

if [[ "$ALLOW_AUTOREMOVE" -eq 1 ]]; then
    log INFO "Running autoremove"
    run_cmd "apt-get -qy autoremove"
else
    log WARN "Autoremove skipped"
fi

log INFO "Remaining upgradable packages (if any):"
run_cmd "apt list --upgradable || true"

if command -v snap &>/dev/null; then
    log INFO "Refreshing snap packages"
    run_cmd "snap refresh"
fi

log INFO "Maintenance completed"

if [[ -f /var/run/reboot-required ]]; then
    log WARN "Reboot required"
    if [[ -t 1 ]]; then
        read -rp "Reboot now? [y/N]: " yn
        [[ "$yn" =~ ^[Yy]$ ]] && reboot
    fi
else
    log INFO "No reboot required"
fi

exit 0
