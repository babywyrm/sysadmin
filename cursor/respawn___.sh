#!/usr/bin/env bash
#
# cursor-clean-linux.sh — Safely clean Cursor app data on Debian/Ubuntu.
#
# Purpose:
#   - Stop Cursor-related processes
#   - Backup Cursor user config
#   - Remove Cursor cache/config/app data
#   - Optionally remove AppImage files from Downloads
#   - Optionally remove desktop entries/icons
#
# This script intentionally DOES NOT reset /etc/machine-id.
#
# Usage:
#   ./cursor-clean-linux.sh
#   ./cursor-clean-linux.sh --kill
#   ./cursor-clean-linux.sh --remove-appimage
#   ./cursor-clean-linux.sh --remove-desktop-files
#   ./cursor-clean-linux.sh --full
#   ./cursor-clean-linux.sh --dry-run
#   ./cursor-clean-linux.sh --yes --full
#

set -Eeuo pipefail

APP_NAME="Cursor"
DOWNLOADS_DIR="${DOWNLOADS_DIR:-$HOME/Downloads}"
BACKUP_ROOT="${BACKUP_ROOT:-$HOME/Desktop}"
BACKUP_DIR="$BACKUP_ROOT/cursor-linux-backup-$(date +%Y%m%d-%H%M%S)"

DO_KILL=false
REMOVE_APPIMAGE=false
REMOVE_DESKTOP_FILES=false
FULL=false
DRY_RUN=false
ASSUME_YES=false

# -----------------------------
# Output helpers
# -----------------------------

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[INFO]\033[0m %s\n' "$*"; }
ok()    { printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m[WARN]\033[0m %s\n' "$*"; }
err()   { printf '\033[31m[ERR ]\033[0m %s\n' "$*" >&2; }

usage() {
  cat <<EOF
Usage:
  $0 [options]

Options:
  --kill                  Kill Cursor-related processes.
  --remove-appimage       Remove Cursor AppImage files from Downloads.
  --remove-desktop-files  Remove Cursor desktop entries and icons.
  --full                  Backup and remove Cursor user config/cache/data.
  --dry-run               Show actions without changing anything.
  --yes, -y               Assume yes for prompts.
  --help, -h              Show this help.

Environment:
  DOWNLOADS_DIR           Defaults to: \$HOME/Downloads
  BACKUP_ROOT             Defaults to: \$HOME/Desktop

Examples:
  $0
  $0 --kill --full
  $0 --remove-appimage
  $0 --remove-desktop-files
  $0 --dry-run --full
  $0 --yes --kill --full --remove-appimage --remove-desktop-files
EOF
}

confirm() {
  local prompt="$1"

  if [[ "$ASSUME_YES" == true ]]; then
    return 0
  fi

  read -r -p "$prompt [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

run_cmd() {
  if [[ "$DRY_RUN" == true ]]; then
    printf '[DRY-RUN] '
    printf '%q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

safe_rm_rf() {
  local target="$1"

  if [[ -z "$target" || "$target" == "/" || "$target" == "$HOME" ]]; then
    err "Refusing unsafe delete target: '$target'"
    return 1
  fi

  if [[ ! -e "$target" ]]; then
    info "Not present: $target"
    return 0
  fi

  info "Removing: $target"
  run_cmd rm -rf -- "$target"
}

safe_rm_f() {
  local target="$1"

  if [[ -z "$target" || "$target" == "/" || "$target" == "$HOME" ]]; then
    err "Refusing unsafe delete target: '$target'"
    return 1
  fi

  if [[ ! -e "$target" ]]; then
    info "Not present: $target"
    return 0
  fi

  info "Removing file: $target"
  run_cmd rm -f -- "$target"
}

need_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    err "sudo not found. Run as root or install sudo."
    return 1
  fi
}

# -----------------------------
# Args
# -----------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kill)
      DO_KILL=true
      ;;
    --remove-appimage)
      REMOVE_APPIMAGE=true
      ;;
    --remove-desktop-files)
      REMOVE_DESKTOP_FILES=true
      ;;
    --full)
      FULL=true
      ;;
    --dry-run)
      DRY_RUN=true
      ;;
    --yes|-y)
      ASSUME_YES=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      err "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

bold "Cursor Linux cleanup utility"

if [[ "$DRY_RUN" == true ]]; then
  warn "Dry-run mode enabled. No changes will be made."
fi

# -----------------------------
# Paths
# -----------------------------

USER_DATA_PATHS=(
  "$HOME/.config/Cursor"
  "$HOME/.cache/Cursor"
  "$HOME/.local/share/Cursor"
  "$HOME/.cursor"
  "$HOME/.cursor-server"
)

BACKUP_CANDIDATES=(
  "$HOME/.config/Cursor/User/settings.json"
  "$HOME/.config/Cursor/User/keybindings.json"
  "$HOME/.config/Cursor/User/snippets"
  "$HOME/.config/Cursor/User/globalStorage"
)

USER_DESKTOP_PATTERNS=(
  "$HOME/.local/share/applications/cursor"*.desktop
  "$HOME/.local/share/applications/co.anysphere.cursor"*.desktop
  "$HOME/.local/share/icons/cursor"*.*
  "$HOME/.local/share/icons/co.anysphere.cursor"*.*
)

SYSTEM_DESKTOP_PATTERNS=(
  "/usr/share/applications/cursor"*.desktop
  "/usr/share/applications/co.anysphere.cursor"*.desktop
  "/usr/share/pixmaps/cursor"*.*
  "/usr/share/pixmaps/co.anysphere.cursor"*.*
  "/usr/share/icons/hicolor/"*"/apps/cursor".*
  "/usr/share/icons/hicolor/"*"/apps/co.anysphere.cursor".*
)

# -----------------------------
# Process cleanup
# -----------------------------

echo
bold "1. Checking Cursor processes"

PROCESS_PATTERN='Cursor|cursor|cursor-appimage|Cursor Helper'

if pgrep -af "$PROCESS_PATTERN" >/dev/null 2>&1; then
  warn "Found matching processes:"
  pgrep -af "$PROCESS_PATTERN" || true

  echo
  if [[ "$DO_KILL" == true ]] || confirm "Terminate Cursor-related processes?"; then
    info "Trying graceful termination first..."
    run_cmd pkill -TERM -f "$PROCESS_PATTERN" 2>/dev/null || true

    if [[ "$DRY_RUN" == false ]]; then
      sleep 2
    fi

    if pgrep -af "$PROCESS_PATTERN" >/dev/null 2>&1; then
      warn "Some processes are still running. Escalating to SIGKILL..."
      run_cmd pkill -KILL -f "$PROCESS_PATTERN" 2>/dev/null || true
    fi

    ok "Process cleanup complete."
  else
    info "Skipping process termination."
  fi
else
  ok "No Cursor processes found."
fi

# -----------------------------
# Backup
# -----------------------------

backup_cursor_data() {
  echo
  bold "2. Backing up Cursor user data"

  local found=false

  for item in "${BACKUP_CANDIDATES[@]}"; do
    if [[ -e "$item" ]]; then
      found=true
      break
    fi
  done

  if [[ "$found" == false ]]; then
    info "No common Cursor settings found to back up."
    return 0
  fi

  info "Backup directory: $BACKUP_DIR"
  run_cmd mkdir -p "$BACKUP_DIR"

  for item in "${BACKUP_CANDIDATES[@]}"; do
    if [[ -e "$item" ]]; then
      info "Backing up: $item"
      run_cmd cp -R -- "$item" "$BACKUP_DIR/"
    fi
  done

  ok "Backup complete: $BACKUP_DIR"
}

# -----------------------------
# User data cleanup
# -----------------------------

clean_user_data() {
  echo
  bold "3. Removing Cursor user config/cache/data"

  for path in "${USER_DATA_PATHS[@]}"; do
    safe_rm_rf "$path"
  done

  ok "User data cleanup complete."
}

if [[ "$FULL" == true ]] || confirm "Back up and remove Cursor user config/cache/data?"; then
  backup_cursor_data
  clean_user_data
else
  info "Skipping user data cleanup."
fi

# -----------------------------
# AppImage cleanup
# -----------------------------

echo
bold "4. Cursor AppImage cleanup"

if [[ "$REMOVE_APPIMAGE" == true ]] || confirm "Remove Cursor AppImage files from $DOWNLOADS_DIR?"; then
  shopt -s nullglob

  appimages=(
    "$DOWNLOADS_DIR"/Cursor-*.AppImage
    "$DOWNLOADS_DIR"/cursor-*.AppImage
  )

  if [[ ${#appimages[@]} -eq 0 ]]; then
    info "No Cursor AppImage files found in $DOWNLOADS_DIR."
  else
    for appimage in "${appimages[@]}"; do
      safe_rm_f "$appimage"
    done
    ok "AppImage cleanup complete."
  fi

  shopt -u nullglob
else
  info "Skipping AppImage cleanup."
fi

# -----------------------------
# Desktop/icon cleanup
# -----------------------------

echo
bold "5. Desktop entry and icon cleanup"

if [[ "$REMOVE_DESKTOP_FILES" == true ]] || confirm "Remove Cursor desktop entries and icons?"; then
  shopt -s nullglob

  for path in "${USER_DESKTOP_PATTERNS[@]}"; do
    safe_rm_f "$path"
  done

  for path in "${SYSTEM_DESKTOP_PATTERNS[@]}"; do
    if [[ -e "$path" ]]; then
      info "Removing system file: $path"
      if [[ "$DRY_RUN" == true ]]; then
        printf '[DRY-RUN] sudo rm -f %q\n' "$path"
      else
        need_sudo rm -f -- "$path"
      fi
    fi
  done

  if command -v update-desktop-database >/dev/null 2>&1; then
    info "Updating user desktop database..."
    run_cmd update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

    if [[ -d /usr/share/applications ]]; then
      info "Updating system desktop database..."
      if [[ "$DRY_RUN" == true ]]; then
        printf '[DRY-RUN] sudo update-desktop-database /usr/share/applications\n'
      else
        need_sudo update-desktop-database /usr/share/applications 2>/dev/null || true
      fi
    fi
  else
    info "update-desktop-database not installed; skipping database refresh."
  fi

  shopt -u nullglob
  ok "Desktop/icon cleanup complete."
else
  info "Skipping desktop/icon cleanup."
fi

# -----------------------------
# Explicitly skipped unsafe action
# -----------------------------

echo
bold "6. System identity"

ok "Skipped machine-id reset by design."
info "This cleanup script does not modify /etc/machine-id or /var/lib/dbus/machine-id."

echo
ok "Done. Reopen or reinstall Cursor when ready."
