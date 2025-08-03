#!/bin/bash

# mac_hax.sh - macOS Hack Sheet Utility
# Author: TMS ++ SKYNET (no one cares, lol)
# License: MIT, lmao

set -euo pipefail
IFS=$'\n\t'

# Colors
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
  echo -e "${CYAN}mac_hax.sh - macOS Hack Sheet Utility${NC}"
  echo -e "🔧 Quick tools and recon commands for macOS"
  echo
}

print_menu() {
  echo -e "${YELLOW}Choose an option:${NC}"
  echo "1) Prevent sleep / power hacks"
  echo "2) System info & recon"
  echo "3) Persistence / LaunchAgents"
  echo "4) Network discovery"
  echo "5) Security & evasion"
  echo "6) Clean up / forensic wipe"
  echo "7) Show interesting paths"
  echo "8) Run all"
  echo "9) Sensitive file / secrets scan"
  echo "0) Exit"
  echo
}

prevent_sleep() {
  echo -e "${GREEN}[Prevent Sleep / Power Hacks]${NC}"
  sudo pmset -a disablesleep 1
  sudo pmset -a sleep 0
  echo "Running: caffeinate -dimsu (CTRL+C to stop)"
  caffeinate -dimsu &
}

system_info() {
  echo -e "${GREEN}[System Info & Recon]${NC}"
  system_profiler SPHardwareDataType
  sw_vers
  whoami && id
  dscl . list /Users
  last | head -n 5
}

persistence() {
  echo -e "${GREEN}[Persistence & LaunchAgents]${NC}"
  echo "launchctl list:"
  launchctl list | grep -v com.apple
  echo
  echo "User LaunchAgents:"
  ls ~/Library/LaunchAgents 2>/dev/null || echo "None found"
}

network_discovery() {
  echo -e "${GREEN}[Network Discovery]${NC}"
  ifconfig | grep inet
  netstat -anv | grep LISTEN
  dns-sd -B _services._dns-sd._udp
  scutil --dns | grep nameserver
}

evasion() {
  echo -e "${GREEN}[Security & Evasion]${NC}"
  csrutil status
  spctl --status
  echo
  echo "[Quarantine Removal] xattr -d com.apple.quarantine ./file"
  echo "[Hide File] chflags hidden filename"
  echo "[Immutable File] chflags uchg filename"
}

cleanup() {
  echo -e "${GREEN}[Cleanup / Wipe Logs]${NC}"
  echo "Wiping system caches and user history..."
  rm -rf ~/Library/Caches/*
  history -c && rm -f ~/.bash_history ~/.zsh_history
  sudo log erase --all --output /dev/null || echo "Log erase requires full disk access."
}

interesting_paths() {
  echo -e "${GREEN}[Interesting Paths]${NC}"
  echo "/Users/$(whoami)/Library/Logs/"
  echo "/Users/$(whoami)/Library/LaunchAgents/"
  echo "/Library/LaunchDaemons/"
  echo "/private/var/tmp/"
  echo "/System/Library/Extensions/"
}

sensitive_scan() {
  echo -e "${GREEN}[Sensitive File & Secrets Recon]${NC}"

  echo -e "\n${YELLOW}Searching for SSH private keys...${NC}"
  find /Users /root -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" \) 2>/dev/null

  echo -e "\n${YELLOW}Scanning for credential-related dotfiles...${NC}"
  find /Users /root -type f \( -name ".aws/credentials" -o -name ".netrc" -o -name ".pypirc" -o -name ".npmrc" -o -name ".git-credentials" \) 2>/dev/null

  echo -e "\n${YELLOW}Grepping for passwords, secrets, tokens in files...${NC}"
  grep -riE --color=always 'password=|pass:|pwd:|api[_-]?key=|secret=|token=' /Users 2>/dev/null | head -n 20 || echo "None found or permission denied."

  echo -e "\n${YELLOW}World-writable sensitive directories...${NC}"
  find /Users -type d -perm -0002 -ls 2>/dev/null | grep -v "/Volumes" || echo "No world-writable directories found."

  echo -e "\n${YELLOW}Looking for .env, .bak, .old config files...${NC}"
  find /Users -type f \( -name "*.env" -o -name "*.bak" -o -name "*.old" \) 2>/dev/null | head -n 20
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

# ----------- CLI Argument Support --------------
run_cli_mode() {
  case "$1" in
    --sleep|--power) prevent_sleep ;;
    --recon|--sysinfo) system_info ;;
    --persist|--persistence) persistence ;;
    --network|--net) network_discovery ;;
    --evasion|--sec) evasion ;;
    --clean|--cleanup) cleanup ;;
    --paths|--dirs) interesting_paths ;;
    --secrets|--sensitive|--creds) sensitive_scan ;;
    --all) run_all ;;
    -h|--help)
      echo "Usage: $0 [--recon|--clean|--all|--evasion|--paths|--sleep|--persist|--network|--secrets]"
      exit 0
      ;;
    *) echo -e "${RED}Invalid argument: $1${NC}" && exit 1 ;;
  esac
}

# ------------- Main Entry --------------------
main() {
  print_header

  if [[ $# -gt 0 ]]; then
    run_cli_mode "$1"
    exit 0
  fi

  while true; do
    print_menu
    read -rp "Option: " choice
    echo
    case "$choice" in
      1) prevent_sleep ;;
      2) system_info ;;
      3) persistence ;;
      4) network_discovery ;;
      5) evasion ;;
      6) cleanup ;;
      7) interesting_paths ;;
      8) run_all ;;
      9) sensitive_scan ;;
      0) echo "Goodbye"; exit 0 ;;
      *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    echo -e "\n${CYAN}Press ENTER to return to menu...${NC}"
    read -r
  done
}

main "$@"


