#!/bin/bash

# mac_hax.sh - macOS Hack Sheet Utility
# Author: TMS ++ SKYNET (no one cares, lol)
# License: MIT, lmao

set -euo pipefail
IFS=$'\n\t'

VERSION="v2.1.3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
REPORT_FILE="$SCRIPT_DIR/mac_hax_report.md"
LOG_FILE=""
ENABLE_LOGGING=false
ENABLE_MARKDOWN=false

mkdir -p "$LOG_DIR"

log() {
  echo "$1"
  [[ "$ENABLE_LOGGING" == true ]] && echo "$(date '+%F %T') $1" >> "$LOG_FILE"
  [[ "$ENABLE_MARKDOWN" == true ]] && echo "${1//$'\033'*/}" >> "$REPORT_FILE"
}

confirm() {
  read -rp "⚠️  Are you sure? Type YES to continue: " choice
  [[ "$choice" == "YES" ]] || { echo "Aborted."; return 1; }
}

print_header() {
  echo
  echo "mac_hax.sh - macOS Hack Sheet Utility ($VERSION)"
  echo "🔧 Red team + power user toolkit for macOS"
  echo
}

print_menu() {
  echo "Choose an option:
1) Prevent sleep / power hacks
2) System info & recon
3) Persistence / LaunchAgents
4) Network discovery
5) Security & evasion
6) Clean up / forensic wipe
7) Show interesting paths
8) Run all
9) Sensitive file / secrets scan
10) Secure erase mode (requires confirmation)
0) Exit"
}

prevent_sleep() {
  echo "[Power Settings]"
  sudo pmset -a disablesleep 1
  sudo pmset -a sleep 0
  caffeinate -dimsu &
}

system_info() {
  echo "[System Info]"
  system_profiler SPHardwareDataType
  sw_vers
  whoami && id
  dscl . list /Users
  last | head -n 5
}

persistence() {
  echo "[Persistence]"
  launchctl list | grep -v com.apple
  ls ~/Library/LaunchAgents 2>/dev/null || echo "None found"
}

network_discovery() {
  echo "[Network Info]"
  ifconfig | grep inet
  netstat -anv | grep LISTEN
  dns-sd -B _services._dns-sd._udp
  scutil --dns | grep nameserver
}

evasion() {
  echo "[Security & Evasion]"
  csrutil status
  spctl --status
  echo "Use xattr -d com.apple.quarantine ./file to unquarantine files."
}

cleanup() {
  echo "[Cleanup]"
  rm -rf ~/Library/Caches/*
  history -c && rm -f ~/.bash_history ~/.zsh_history
  sudo log erase --all --output /dev/null || echo "log erase requires Full Disk Access"
}

interesting_paths() {
  echo "[Interesting Paths]"
  echo "/Users/$(whoami)/Library/Logs/"
  echo "/Users/$(whoami)/Library/LaunchAgents/"
  echo "/Library/LaunchDaemons/"
  echo "/private/var/tmp/"
  echo "/System/Library/Extensions/"
}

sensitive_scan() {
  echo "[Secrets Recon]"
  find /Users /root -type f -name "id_*" 2>/dev/null
  find /Users /root -type f \( -name ".aws/credentials" -o -name ".npmrc" \) 2>/dev/null
  grep -riE 'password=|token=|secret=' /Users 2>/dev/null | head -n 10
}

secure_erase() {
  echo "[SECURE ERASE MODE]"
  confirm || return
  targets=(~/.ssh ~/.aws ~/.zsh_history ~/.bash_history)
  for t in "${targets[@]}"; do
    [[ -e $t ]] && { rm -rf "$t"; echo "Deleted: $t"; }
  done
}

show_changelog() {
  echo "[CHANGELOG]"
  echo "v2.1.3:"
  echo "- Fixed output bug on macOS (no ANSI/color codes)"
  echo "- Interactive menu now always displays correctly"
  echo "- Works in bash, zsh, Terminal, and iTerm2"
}

run_all() {
  prevent_sleep
  system_info
  persistence
  network_discovery
  evasion
  cleanup
  interesting_paths
  sensitive_scan
}

run_cli_mode() {
  local handled=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sleep) prevent_sleep; handled=true ;;
      --recon) system_info; handled=true ;;
      --persist) persistence; handled=true ;;
      --network) network_discovery; handled=true ;;
      --evasion) evasion; handled=true ;;
      --clean) cleanup; handled=true ;;
      --paths) interesting_paths; handled=true ;;
      --secrets) sensitive_scan; handled=true ;;
      --nuke) secure_erase; handled=true ;;
      --all) run_all; handled=true ;;
      --changelog) show_changelog; handled=true ;;
      --log) ENABLE_LOGGING=true; LOG_FILE="$LOG_DIR/mac_hax_$(date +%s).log"; shift ;;
      --log-to) ENABLE_LOGGING=true; LOG_FILE="$2"; shift 2 ;;
      --markdown) ENABLE_MARKDOWN=true; echo "# mac_hax Report $(date)" > "$REPORT_FILE"; shift ;;
      -h|--help)
        echo "Usage: $0 [--recon|--clean|--all|--evasion|--changelog|--log|--markdown]"
        exit 0
        ;;
      *) echo "[!] Unknown option: $1"; exit 1 ;;
    esac
    shift
  done

  if [[ "$handled" == true ]]; then
    [[ "$ENABLE_LOGGING" == true ]] && echo "[*] Log saved: $LOG_FILE"
    [[ "$ENABLE_MARKDOWN" == true ]] && echo "[*] Markdown saved: $REPORT_FILE"
    exit 0
  fi
}

main() {
  print_header

  if [[ $# -gt 0 ]]; then
    run_cli_mode "$@"
  fi

  while true; do
    print_menu
    read -rp "Choice: " option
    echo
    case "$option" in
      1) prevent_sleep ;;
      2) system_info ;;
      3) persistence ;;
      4) network_discovery ;;
      5) evasion ;;
      6) cleanup ;;
      7) interesting_paths ;;
      8) run_all ;;
      9) sensitive_scan ;;
      10) secure_erase ;;
      0) echo "Goodbye"; exit 0 ;;
      *) echo "Invalid option." ;;
    esac
    read -rp "Press ENTER to continue..." _
  done
}

main "$@"


