#!/bin/bash

# mac_hax.sh - macOS Power Tools and Hacks Menu
# a robot and a human made this, and no one cares, tbh
# License: MIT, (lol)

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

run_all() {
  prevent_sleep
  system_info
  persistence
  network_discovery
  evasion
  cleanup
  interesting_paths
}

main() {
  print_header
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
      0) echo "Goodbye"; exit 0 ;;
      *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    echo -e "\n${CYAN}Press ENTER to return to menu...${NC}"
    read -r
  done
}

main
