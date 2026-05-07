#!/usr/bin/env bash
#
# cursor-reset.sh — Diagnose and repair a frozen Cursor install on macOS.
#
# Safe default behavior:
#   - Shows suspicious Cursor / ripgrep processes
#   - Asks before killing anything
#   - Clears known Cursor cache directories
#   - Asks before deleting a broken ~/.cursor file
#   - Asks before full factory reset
#
# Usage:
#   ./cursor-reset.sh
#   ./cursor-reset.sh --kill
#   ./cursor-reset.sh --full-reset
#   ./cursor-reset.sh --kill --full-reset
#   ./cursor-reset.sh --dry-run
#   ./cursor-reset.sh --yes --kill --full-reset
#

set -Eeuo pipefail

APP_NAME="Cursor"
CURSOR_SUPPORT_DIR="$HOME/Library/Application Support/Cursor"
CURSOR_USER_DIR="$CURSOR_SUPPORT_DIR/User"
CURSOR_DOT_PATH="$HOME/.cursor"

DO_KILL=false
DO_FULL_RESET=false
DRY_RUN=false
ASSUME_YES=false

# ---------- output helpers ----------

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
  --kill          Kill Cursor and ripgrep-related processes.
  --full-reset    Remove Cursor application support data after backing up settings.
  --dry-run       Show what would be done without changing anything.
  --yes, -y       Assume yes for prompts.
  --help, -h      Show this help.

Examples:
  $0
  $0 --kill
  $0 --full-reset
  $0 --kill --full-reset
  $0 --dry-run
  $0 --yes --kill --full-reset
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
  run_cmd rm -rf "$target"
}

# ---------- argument parsing ----------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kill)
      DO_KILL=true
      ;;
    --full-reset)
      DO_FULL_RESET=true
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

bold "Cursor macOS repair utility"

if [[ "$DRY_RUN" == true ]]; then
  warn "Dry-run mode enabled. No changes will be made."
fi

# ---------- process diagnostics ----------

echo
bold "1. Checking Cursor/ripgrep processes"

PROCESS_PATTERN='Cursor|Cursor Helper|ripgrep|(^|/)(rg)( |$)'

if pgrep -af "$PROCESS_PATTERN" >/dev/null 2>&1; then
  warn "Found matching processes:"
  pgrep -af "$PROCESS_PATTERN" || true

  echo
  if [[ "$DO_KILL" == true ]] || confirm "Kill Cursor and ripgrep-related processes?"; then
    info "Attempting graceful termination first..."

    run_cmd pkill -TERM -f 'Cursor' 2>/dev/null || true
    run_cmd pkill -TERM -f 'ripgrep' 2>/dev/null || true
    run_cmd pkill -TERM -f '(^|/)rg( |$)' 2>/dev/null || true

    if [[ "$DRY_RUN" == false ]]; then
      sleep 2
    fi

    if pgrep -af "$PROCESS_PATTERN" >/dev/null 2>&1; then
      warn "Some processes are still running. Escalating to SIGKILL..."
      run_cmd pkill -KILL -f 'Cursor' 2>/dev/null || true
      run_cmd pkill -KILL -f 'ripgrep' 2>/dev/null || true
      run_cmd pkill -KILL -f '(^|/)rg( |$)' 2>/dev/null || true
    fi

    ok "Process cleanup complete."
  else
    info "Skipping process kill."
  fi
else
  ok "No Cursor/ripgrep processes found."
fi

# ---------- cache cleanup ----------

echo
bold "2. Clearing Cursor caches"

CACHE_PATHS=(
  "$CURSOR_SUPPORT_DIR/GPUCache"
  "$CURSOR_SUPPORT_DIR/Cache"
  "$CURSOR_SUPPORT_DIR/CachedData"
  "$CURSOR_SUPPORT_DIR/Code Cache"
  "$CURSOR_SUPPORT_DIR/DawnCache"
  "$CURSOR_SUPPORT_DIR/ShaderCache"
  "$CURSOR_SUPPORT_DIR/User/workspaceStorage"
  "$CURSOR_SUPPORT_DIR/User/globalStorage/state.vscdb.backup"
)

for path in "${CACHE_PATHS[@]}"; do
  safe_rm_rf "$path"
done

ok "Cache cleanup complete."

# ---------- broken ~/.cursor check ----------

echo
bold "3. Checking ~/.cursor"

if [[ -f "$CURSOR_DOT_PATH" ]]; then
  warn "Found ~/.cursor as a regular file. Cursor usually expects this to be a directory."

  if confirm "Delete the broken ~/.cursor file?"; then
    safe_rm_rf "$CURSOR_DOT_PATH"
    ok "Deleted broken ~/.cursor file."
  else
    info "Leaving ~/.cursor file untouched."
  fi
elif [[ -d "$CURSOR_DOT_PATH" ]]; then
  ok "~/.cursor exists as a directory."
else
  ok "No ~/.cursor path found."
fi

# ---------- backup helper ----------

backup_cursor_settings() {
  local backup_dir="$HOME/Desktop/cursor-backup-$(date +%Y%m%d-%H%M%S)"

  info "Creating backup directory: $backup_dir"
  run_cmd mkdir -p "$backup_dir"

  local files_to_backup=(
    "$CURSOR_USER_DIR/settings.json"
    "$CURSOR_USER_DIR/keybindings.json"
    "$CURSOR_USER_DIR/snippets"
    "$CURSOR_USER_DIR/globalStorage"
  )

  for item in "${files_to_backup[@]}"; do
    if [[ -e "$item" ]]; then
      info "Backing up: $item"
      run_cmd cp -R "$item" "$backup_dir/"
    fi
  done

  ok "Backup complete: $backup_dir"
}

# ---------- full reset ----------

echo
bold "4. Full factory reset"

if [[ "$DO_FULL_RESET" == true ]] || confirm "Perform FULL reset? This deletes Cursor settings, extensions, global storage, and app support data."; then
  warn "Full reset selected."

  backup_cursor_settings

  echo
  warn "Removing Cursor application support directory and ~/.cursor."
  safe_rm_rf "$CURSOR_SUPPORT_DIR"
  safe_rm_rf "$CURSOR_DOT_PATH"

  ok "Full reset complete."
else
  info "Skipping full reset."
fi

echo
ok "Done. You can now reopen Cursor."
