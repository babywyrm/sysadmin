#!/usr/bin/env bash
#
# watch_build.sh — Smart modern asset watcher for Linux/macOS
#
# Features:
#  - Watches _js and _sass directories
#  - Concatenates and minifies JS files into scripts.js
#  - Compiles and minifies SASS into CSS
#  - Supports viddy or watch
#  - Works with custom commands passed as arguments
#
# Usage:
#   ./watch_build.sh              # default build + watch
#   ./watch_build.sh build        # just build once
#   ./watch_build.sh viddy "npm run lint"   # watch and run custom command
#

set -euo pipefail

# ------------------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------------------
JS_PATH="_js"
SASS_PATH="_sass"
FINAL_JS="scripts.js"
FINAL_CSS_DIR="."

# Colors
GREEN="\033[0;32m"
RESET="\033[0m"

# ------------------------------------------------------------------------------
# Helper: check dependencies
# ------------------------------------------------------------------------------
check_deps() {
  local deps=("sass" "jsmin")
  for cmd in "${deps[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: Required command '$cmd' not found. Please install it."
      exit 1
    fi
  done
}

# ------------------------------------------------------------------------------
# Build logic
# ------------------------------------------------------------------------------
build_assets() {
  echo "≫ Building and minifying assets..."
  if [[ -f "$FINAL_JS" ]]; then
    rm -f "$FINAL_JS"
  fi

  touch "$FINAL_JS"
  cat "$JS_PATH"/*.js > "$FINAL_JS"
  echo -e "  ${GREEN}${FINAL_JS}${RESET}"

  sass --no-source-map --style=compressed "$SASS_PATH":"$FINAL_CSS_DIR"
  jsmin --overwrite "$FINAL_JS"
  echo -e "  ${GREEN}SASS & JS build complete.${RESET}"
}

# ------------------------------------------------------------------------------
# Watch logic (viddy or watch)
# ------------------------------------------------------------------------------
watch_assets() {
  local watcher=""
  if command -v viddy >/dev/null 2>&1; then
    watcher="viddy"
  elif command -v watch >/dev/null 2>&1; then
    watcher="watch"
  else
    echo "Error: Neither 'viddy' nor 'watch' command found. Please install one."
    exit 1
  fi

  echo "≫ Watching for changes using $watcher..."
  if [[ "$watcher" == "viddy" ]]; then
    viddy -d -n 1 --shell "$SHELL" "./watch_build.sh build"
  else
    watch -n 1 "./watch_build.sh build"
  fi
}

# ------------------------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------------------------
main() {
  check_deps

  local cmd="${1:-watch}"

  case "$cmd" in
  build)
    build_assets
    ;;
  viddy)
    shift || true
    local args="$*"
    if [[ -z "$args" ]]; then
      args="./watch_build.sh build"
    fi
    echo "≫ Watching using viddy → $args"
    viddy -d -n 1 --shell "$SHELL" "$args"
    ;;
  watch)
    watch_assets
    ;;
  *)
    echo "Usage: $0 [build|watch|viddy <command>]"
    exit 1
    ;;
  esac
}

main "$@"
