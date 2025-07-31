#!/bin/bash
# Author: Jose Delarosa (original) | Modified by TMS for Red Teams & CTFs .. beta ..
# License: Apache 2.0

set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

REQUIRED_TOOLS=(nmap ip awk grep sed jq column)

for bin in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo -e "${RED}[-] Missing required tool: $bin${NC}"
    exit 1
  fi
done

########################
## Default Settings
########################

LOGFILE="scan_results_$(date +%F_%H-%M-%S).json"
SCAN_TYPE="ping"  # Options: ping, tcp, stealth
NETWORK=""
INTERACTIVE=true

########################
## Help Message
########################
usage() {
  echo "Usage: $0 [-n <CIDR>] [-t <ping|tcp|stealth>] [-q]"
  echo
  echo "  -n <CIDR>       Network to scan (e.g., 192.168.1.0/24)"
  echo "  -t <type>       Scan type: ping, tcp, stealth"
  echo "  -q              Quiet mode (non-interactive)"
  echo
  exit 1
}

########################
## Arg Parsing
########################

while getopts "n:t:q" opt; do
  case $opt in
    n) NETWORK="$OPTARG" ;;
    t) SCAN_TYPE="$OPTARG" ;;
    q) INTERACTIVE=false ;;
    *) usage ;;
  esac
done

########################
## Choose Network (if not supplied)
########################

choose_network() {
  echo -e "${YELLOW}[i] No CIDR supplied. Choose a local network to scan:${NC}"
  interfaces=$(ip -o -f inet addr show | awk '{print $2" "$4}')
  select iface in $interfaces; do
    if [[ -n "$iface" ]]; then
      NETWORK=$(echo "$iface" | awk '{print $2}')
      break
    fi
  done
}

[[ -z "$NETWORK" && "$INTERACTIVE" == true ]] && choose_network
[[ -z "$NETWORK" ]] && echo -e "${RED}[-] No network specified. Exiting.${NC}" && exit 1

########################
## Determine Nmap Flags
########################

case "$SCAN_TYPE" in
  ping)    NMAP_FLAGS="-sn" ;;
  tcp)     NMAP_FLAGS="-sS -T4" ;;
  stealth) NMAP_FLAGS="-Pn -sS -T2" ;;
  *)       echo -e "${RED}[-] Invalid scan type: $SCAN_TYPE${NC}" && exit 1 ;;
esac

echo -e "${GREEN}[+] Scanning ${NETWORK} with ${SCAN_TYPE} scan...${NC}"
echo -e "${YELLOW}[i] Results will be saved to ${LOGFILE}${NC}"
echo

########################
## Perform Scan
########################

TEMP_XML=$(mktemp)
nmap $NMAP_FLAGS -oX "$TEMP_XML" "$NETWORK" >/dev/null

########################
## Parse XML Output
########################

echo -e "${GREEN}[+] Live Hosts Found:${NC}"
cat "$TEMP_XML" \
  | xmllint --xpath '//host[status/@state="up"]' - 2>/dev/null \
  | sed 's/<\/host>/<\/host>\n/g' \
  | while read -r block; do
      ip=$(echo "$block" | grep -oP '(?<=<address addr=").*?(?=" type="ipv4")')
      mac=$(echo "$block" | grep -oP '(?<=<address addr=").*?(?=" type="mac")' || true)
      hostname=$(echo "$block" | grep -oP '(?<=<hostname name=").*?(?=")' || echo "unknown")

      printf "%-16s %-18s %s\n" "$ip" "${mac:-N/A}" "${hostname:-N/A}"
  done | tee >(awk '{printf "{\"ip\":\"%s\",\"mac\":\"%s\",\"hostname\":\"%s\"}\n", $1,$2,$3}' > "$LOGFILE") | column -t

rm -f "$TEMP_XML"

##
##
