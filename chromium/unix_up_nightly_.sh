#!/usr/bin/env bash
# Chromium Updater – cross-platform (Linux/macOS) ..nice..

set -euo pipefail

SCRIPT="Chromium Updater"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/chromium-updater"
STATE_FILE="$CONFIG_DIR/build.number"
LOG_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/chromium-updater"
LOG_FILE="$LOG_DIR/updater.log"
INSTALL_DIR="${CHROMIUM_INSTALL_DIR:-$HOME/chromium}"

mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$INSTALL_DIR"

# cross-platform date (GNU vs BSD)
now_iso() {
    if date --iso-8601=seconds >/dev/null 2>&1; then
        date --iso-8601=seconds
    else
        date -u +"%Y-%m-%dT%H:%M:%SZ"
    fi
}

log() {
    echo "[$(now_iso)] $*" | tee -a "$LOG_FILE"
}

notify() {
    local msg="$1"
    if command -v notify-send >/dev/null 2>&1; then
        notify-send "$SCRIPT" "$msg"
    else
        log "$msg"
    fi
}

error() {
    notify "❌ $1"
    exit 1
}

# Detect platform
case "$(uname -s)" in
    Linux*)   PLATFORM="Linux_x64" ;;
    Darwin*)  PLATFORM="Mac" ;;
    *)        error "Unsupported platform $(uname -s)" ;;
esac

LATEST=$(curl -fsSL "https://commondatastorage.googleapis.com/chromium-browser-snapshots/$PLATFORM/LAST_CHANGE")
[ -n "$LATEST" ] || error "Could not fetch latest build number."

if [ -f "$STATE_FILE" ]; then
    CURRENT=$(<"$STATE_FILE")
else
    CURRENT=0
fi

log "Current: $CURRENT | Latest: $LATEST"

if [ "$LATEST" -gt "$CURRENT" ]; then
    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"

    # normalize lowercase without Bash 4
    platform_lc=$(echo "$PLATFORM" | tr '[:upper:]' '[:lower:]')

    ZIP_URL="https://commondatastorage.googleapis.com/chromium-browser-snapshots/$PLATFORM/$LATEST/chrome-${platform_lc}.zip"
    log "Downloading: $ZIP_URL"

    curl -# --retry 3 --fail -o chrome.zip "$ZIP_URL" || error "Download failed."
    unzip -q chrome.zip

    rm -rf "$INSTALL_DIR/chrome-${platform_lc}"*
    mv chrome-* "$INSTALL_DIR/"
    echo "$LATEST" > "$STATE_FILE"

    notify "✅ Chromium updated to $LATEST"
    log "Update successful -> $LATEST"
    rm -rf "$TMPDIR"
elif [ "$LATEST" -eq "$CURRENT" ]; then
    notify "Already on latest version ($CURRENT)"
else
    notify "Local build ($CURRENT) is newer than upstream ($LATEST)?"
fi


###########
##
##
