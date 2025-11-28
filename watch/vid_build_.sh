#!/usr/bin/env bash

# ------------------------------------------------------------------------
# watch_build.sh — modern watcher and asset builder
# Requires: sass, terser, (optional) viddy or watch
# ------------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# Directories and outputs
JS_PATH="_js"
SASS_PATH="_sass"
FINAL_JS="scripts.js"
FINAL_CSS_DIR="."

GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${RED}Error:${RESET} Required command '$1' not found."
    echo "→ Try installing with: npm install -g sass terser"
    exit 1
  fi
}

check_deps() {
  require_cmd sass
  require_cmd terser
}

# ------------------------------------------------------------------------
# Build step
# ------------------------------------------------------------------------
build_assets() {
  echo "≫ Building and minifying assets..."
  [[ -f "$FINAL_JS" ]] && rm -f "$FINAL_JS"
  cat "$JS_PATH"/*.js > "$FINAL_JS"
  echo -e "  ${GREEN}$FINAL_JS${RESET}"

  sass --no-source-map --style=compressed "$SASS_PATH":"$FINAL_CSS_DIR"
  terser "$FINAL_JS" -o "$FINAL_JS" -c -m
  echo -e "  ${GREEN}Build complete.${RESET}"
}

# ------------------------------------------------------------------------
# Watch step
# ------------------------------------------------------------------------
watch_assets() {
  local watcher=""
  if command -v viddy >/dev/null 2>&1; then
    watcher="viddy"
  elif command -v watch >/dev/null 2>&1; then
    watcher="watch"
  fi

  if [[ -z "$watcher" ]]; then
    echo -e "${RED}No watcher (viddy or watch) found.${RESET}"
    echo "Running one-time build instead."
    build_assets
    return
  fi

  echo "≫ Watching for changes using $watcher ..."
  if [[ "$watcher" == "viddy" ]]; then
    viddy -d -n 1 --shell "$SHELL" "./watch_build.sh build"
  else
    watch -n 1 "./watch_build.sh build"
  fi
}

# ------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------
main() {
  check_deps
  local cmd="${1:-watch}"
  case "$cmd" in
    build) build_assets ;;
    watch) watch_assets ;;
    *) echo "Usage: $0 [build|watch]" ;;
  esac
}

main "$@"
