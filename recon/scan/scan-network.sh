#!/bin/bash
# Network Scanner - Red Team & CTF Edition
# Author: Jose Delarosa (original) | Modified by randoms, tbh
# License: Apache 2.0

set -euo pipefail

#########################
## Configuration
#########################

readonly SCRIPT_VERSION="2.0"
readonly REQUIRED_TOOLS=(nmap ip awk grep sed jq column xmllint)

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Defaults
LOGFILE="scan_$(date +%F_%H-%M-%S).json"
SCAN_TYPE="ping"
NETWORK=""
INTERACTIVE=true
VERBOSE=false
OUTPUT_FORMAT="json" # json, csv, or both

#########################
## Dependency Check
#########################

check_dependencies() {
  local missing=()
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
    echo -e "${YELLOW}[i] Install with: sudo apt install ${missing[*]}${NC}"
    exit 1
  fi
}

#########################
## Help
#########################

usage() {
  cat <<EOF
Network Scanner v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

OPTIONS:
  -n <CIDR>       Network to scan (e.g., 192.168.1.0/24)
  -t <type>       Scan type: ping, tcp, stealth, full
  -o <format>     Output format: json, csv, both (default: json)
  -f <file>       Custom output filename
  -q              Quiet mode (non-interactive)
  -v              Verbose output
  -h              Show this help

SCAN TYPES:
  ping            Host discovery only (fast)
  tcp             TCP SYN scan with service detection
  stealth         Stealth scan (slower, harder to detect)
  full            Comprehensive scan (OS, services, scripts)

EXAMPLES:
  $0 -n 192.168.1.0/24 -t tcp
  $0 -n 10.0.0.0/24 -t stealth -o both -f my_scan
  $0 -q -n 172.16.0.0/16 -t ping

EOF
  exit 0
}

#########################
## Argument Parsing
#########################

parse_args() {
  while getopts "n:t:o:f:qvh" opt; do
    case $opt in
      n) NETWORK="$OPTARG" ;;
      t) SCAN_TYPE="$OPTARG" ;;
      o) OUTPUT_FORMAT="$OPTARG" ;;
      f) LOGFILE="$OPTARG" ;;
      q) INTERACTIVE=false ;;
      v) VERBOSE=true ;;
      h) usage ;;
      *) usage ;;
    esac
  done

  # Validate scan type
  if [[ ! "$SCAN_TYPE" =~ ^(ping|tcp|stealth|full)$ ]]; then
    echo -e "${RED}[!] Invalid scan type: $SCAN_TYPE${NC}"
    exit 1
  fi

  # Validate output format
  if [[ ! "$OUTPUT_FORMAT" =~ ^(json|csv|both)$ ]]; then
    echo -e "${RED}[!] Invalid output format: $OUTPUT_FORMAT${NC}"
    exit 1
  fi
}

#########################
## Network Selection
#########################

choose_network() {
  echo -e "${BLUE}[*] Available networks:${NC}\n"
  
  local -a networks=()
  while IFS= read -r line; do
    networks+=("$line")
  done < <(ip -o -f inet addr show | awk '{print $2" "$4}')

  if [[ ${#networks[@]} -eq 0 ]]; then
    echo -e "${RED}[!] No network interfaces found${NC}"
    exit 1
  fi

  PS3=$'\n'"Select network to scan: "
  select choice in "${networks[@]}"; do
    if [[ -n "$choice" ]]; then
      NETWORK=$(echo "$choice" | awk '{print $2}')
      echo -e "${GREEN}[+] Selected: $NETWORK${NC}\n"
      break
    fi
  done
}

#########################
## Nmap Configuration
#########################

get_nmap_flags() {
  case "$SCAN_TYPE" in
    ping)
      echo "-sn -T4"
      ;;
    tcp)
      echo "-sS -sV -T4 --top-ports 1000"
      ;;
    stealth)
      echo "-Pn -sS -T2 -f --randomize-hosts"
      ;;
    full)
      echo "-sS -sV -O -A -T4 --script=default,discovery"
      ;;
  esac
}

#########################
## Scanning
#########################

perform_scan() {
  local nmap_flags
  nmap_flags=$(get_nmap_flags)
  
  echo -e "${BLUE}[*] Scan Details:${NC}"
  echo -e "    Network:  ${YELLOW}$NETWORK${NC}"
  echo -e "    Type:     ${YELLOW}$SCAN_TYPE${NC}"
  echo -e "    Output:   ${YELLOW}$LOGFILE${NC}"
  echo

  local temp_xml
  temp_xml=$(mktemp --suffix=.xml)
  
  echo -e "${GREEN}[+] Starting scan...${NC}"
  
  if [[ "$VERBOSE" == true ]]; then
    sudo nmap $nmap_flags -oX "$temp_xml" "$NETWORK"
  else
    sudo nmap $nmap_flags -oX "$temp_xml" "$NETWORK" >/dev/null 2>&1
  fi

  echo "$temp_xml"
}

#########################
## Output Parsing
#########################

parse_results() {
  local xml_file="$1"
  local -a results=()

  # Check if any hosts found
  if ! grep -q 'status state="up"' "$xml_file"; then
    echo -e "${YELLOW}[!] No live hosts found${NC}"
    rm -f "$xml_file"
    return 1
  fi

  echo -e "\n${GREEN}[+] Live Hosts Detected:${NC}\n"
  printf "%-18s %-20s %-25s %s\n" "IP ADDRESS" "MAC ADDRESS" \
    "HOSTNAME" "PORTS/SERVICES"
  printf "%s\n" "$(printf '%.0s-' {1..90})"

  # Parse XML and extract host info
  xmllint --xpath '//host[status/@state="up"]' "$xml_file" 2>/dev/null \
    | sed 's/<\/host>/\n/g' \
    | while IFS= read -r host_block; do
        [[ -z "$host_block" ]] && continue

        local ip mac hostname ports
        ip=$(echo "$host_block" \
          | grep -oP '(?<=address addr=")[^"]+(?=".*type="ipv4")' \
          || echo "N/A")
        mac=$(echo "$host_block" \
          | grep -oP '(?<=address addr=")[^"]+(?=".*type="mac")' \
          || echo "N/A")
        hostname=$(echo "$host_block" \
          | grep -oP '(?<=hostname name=")[^"]+' \
          || echo "unknown")
        
        # Extract open ports (if available)
        ports=$(echo "$host_block" \
          | grep -oP '(?<=portid=")[^"]+' \
          | head -3 | paste -sd ',' - || echo "N/A")

        printf "%-18s %-20s %-25s %s\n" \
          "$ip" "$mac" "$hostname" "$ports"

        # Store for JSON/CSV output
        results+=("{\"ip\":\"$ip\",\"mac\":\"$mac\",\"hostname\":\"$hostname\",\"ports\":\"$ports\"}")
      done

  # Save results
  save_results "${results[@]}"
  
  rm -f "$xml_file"
}

#########################
## Output Formatting
#########################

save_results() {
  local -a data=("$@")
  
  if [[ ${#data[@]} -eq 0 ]]; then
    return
  fi

  # JSON output
  if [[ "$OUTPUT_FORMAT" =~ (json|both) ]]; then
    local json_file="${LOGFILE%.json}.json"
    {
      echo "{"
      echo "  \"scan_time\": \"$(date -Iseconds)\","
      echo "  \"network\": \"$NETWORK\","
      echo "  \"scan_type\": \"$SCAN_TYPE\","
      echo "  \"hosts\": ["
      printf "    %s" "${data[0]}"
      for item in "${data[@]:1}"; do
        printf ",\n    %s" "$item"
      done
      echo
      echo "  ]"
      echo "}"
    } > "$json_file"
    echo -e "\n${GREEN}[+] JSON saved to: $json_file${NC}"
  fi

  # CSV output
  if [[ "$OUTPUT_FORMAT" =~ (csv|both) ]]; then
    local csv_file="${LOGFILE%.json}.csv"
    {
      echo "IP,MAC,Hostname,Ports"
      printf "%s\n" "${data[@]}" \
        | jq -r '[.ip,.mac,.hostname,.ports] | @csv'
    } > "$csv_file"
    echo -e "${GREEN}[+] CSV saved to: $csv_file${NC}"
  fi
}

#########################
## Main Execution
#########################

main() {
  echo -e "${BLUE}"
  cat <<'EOF'
╔═══════════════════════════════════════╗
║   Network Scanner - Red Team Edition  ║
╚═══════════════════════════════════════╝
EOF
  echo -e "${NC}"

  check_dependencies
  parse_args "$@"

  [[ -z "$NETWORK" && "$INTERACTIVE" == true ]] && choose_network
  
  if [[ -z "$NETWORK" ]]; then
    echo -e "${RED}[!] No network specified${NC}"
    exit 1
  fi

  # Ensure running as root for raw sockets
  if [[ $EUID -ne 0 && "$SCAN_TYPE" != "ping" ]]; then
    echo -e "${YELLOW}[!] This scan requires root privileges${NC}"
    exec sudo "$0" "$@"
  fi

  local xml_output
  xml_output=$(perform_scan)
  parse_results "$xml_output"

  echo -e "\n${GREEN}[✓] Scan complete!${NC}"
}

main "$@"
