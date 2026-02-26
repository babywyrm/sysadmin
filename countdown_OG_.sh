#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# modern_timer.sh (Refactored 2026 Edition)
# A modern, safe, smooth CLI timer with progress bar.
# ==============================================================================

# --- Defaults -----------------------------------------------------------------

DEFAULT_DURATION=10
DEFAULT_WIDTH="auto"
DEFAULT_REPEAT=1
DEFAULT_SOUND="beep"
DEFAULT_CHAR="#"
DEFAULT_MESSAGE="Progress"
DEFAULT_COLOR=true

# --- Colors -------------------------------------------------------------------

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Helpers ------------------------------------------------------------------

die() {
  echo "Error: $*" >&2
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

term_width() {
  if [[ "$width" == "auto" ]]; then
    tput cols 2>/dev/null || echo 80
  else
    echo "$width"
  fi
}

cleanup() {
  printf "\n"
  exit 0
}

trap cleanup INT TERM

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -t SECONDS     Duration (supports decimals, e.g. 2.5)
  -c WIDTH       Width of progress bar or 'auto'
  -r COUNT|inf   Repeat count
  -s MODE        Sound: beep | alarm | mute
  -m MESSAGE     Display message
  -p CHAR        Progress character
  --no-color     Disable colors
  -h             Show help

Example:
  $0 -t 5 -m "Deploying..." -r 3
EOF
}

# --- Sound --------------------------------------------------------------------

play_sound() {
  [[ "$sound_mode" == "mute" ]] && return

  case "$sound_mode" in
    beep)
      printf "\a"
      ;;
    alarm)
      for _ in {1..3}; do
        printf "\a"
        sleep 0.2
      done
      ;;
  esac
}

# --- Progress Rendering -------------------------------------------------------

render_progress() {
  local elapsed=$1
  local total=$2
  local width=$3

  local percent
  percent=$(awk "BEGIN { printf \"%d\", ($elapsed/$total)*100 }")

  local filled
  filled=$(awk "BEGIN { printf \"%d\", ($elapsed/$total)*$width }")

  local empty=$((width - filled))

  local filled_bar empty_bar
  filled_bar=$(printf "%${filled}s" | tr ' ' "$progress_char")
  empty_bar=$(printf "%${empty}s")

  if $use_color; then
    printf "\r${YELLOW}[%s%s]${NC} ${GREEN}%3d%%${NC} | %s" \
      "$filled_bar" "$empty_bar" "$percent" "$message"
  else
    printf "\r[%s%s] %3d%% | %s" \
      "$filled_bar" "$empty_bar" "$percent" "$message"
  fi
}

# --- Timer Loop ---------------------------------------------------------------

run_timer() {
  local start now elapsed total bar_width

  total="$duration"
  bar_width=$(term_width)

  # Leave space for percentage + message
  bar_width=$((bar_width - ${#message} - 15))
  ((bar_width < 10)) && bar_width=10

  start=$(date +%s.%N)

  while :; do
    now=$(date +%s.%N)
    elapsed=$(awk "BEGIN { print $now - $start }")

    awk "BEGIN { exit !($elapsed >= $total) }" && break

    render_progress "$elapsed" "$total" "$bar_width"
    sleep 0.05
  done

  render_progress "$total" "$total" "$bar_width"
  play_sound
  printf "\n"
}

# --- Argument Parsing ---------------------------------------------------------

duration=$DEFAULT_DURATION
width=$DEFAULT_WIDTH
repeat_count=$DEFAULT_REPEAT
sound_mode=$DEFAULT_SOUND
message=$DEFAULT_MESSAGE
progress_char=$DEFAULT_CHAR
use_color=$DEFAULT_COLOR

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t) duration="$2"; shift 2 ;;
    -c) width="$2"; shift 2 ;;
    -r) repeat_count="$2"; shift 2 ;;
    -s) sound_mode="$2"; shift 2 ;;
    -m) message="$2"; shift 2 ;;
    -p) progress_char="$2"; shift 2 ;;
    --no-color) use_color=false; shift ;;
    -h) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

# --- Validation ---------------------------------------------------------------

[[ "$duration" =~ ^[0-9]+([.][0-9]+)?$ ]] || \
  die "Duration must be a positive number"

[[ "$sound_mode" =~ ^(beep|alarm|mute)$ ]] || \
  die "Sound must be: beep | alarm | mute"

if [[ "$repeat_count" != "inf" ]]; then
  [[ "$repeat_count" =~ ^[0-9]+$ ]] || \
    die "Repeat must be a positive integer or 'inf'"
fi

# --- Execution ----------------------------------------------------------------

if [[ "$repeat_count" == "inf" ]]; then
  echo "Running infinitely. Ctrl+C to stop."
  while :; do
    run_timer
  done
else
  for ((i = 1; i <= repeat_count; i++)); do
    ((repeat_count > 1)) &&
      echo "--- Iteration $i of $repeat_count ---"
    run_timer
  done
fi

printf "%sTimer finished.%s\n" \
  "${use_color:+$GREEN}" "${use_color:+$NC}"
