#!/bin/bash
##
## slblacklist.sh - IPSet-based blacklist manager for country IP blocks (..revised..)
## https://github.com/tmschx/bash-sysadmin
## Updated: 2025-07-29
## Version: 2.0
##

set -euo pipefail

# -------------------------------[ Config ]------------------------------- #

ZONES="al by br cn in ir iq kp mx ng ro ru sa so su sy ye"
ZONEURL="http://www.ipdeny.com/ipblocks/data/countries"
IPFILE="/srv/etc/zones/blacklist"
BLACKLIST="slblacklist"
BLACKLISTSWAP="${BLACKLIST}-swap"

IPTABLES_DIR="/etc/iptables"
IPSET_RULES="$IPTABLES_DIR/rules.ipset"
IPTABLES_RULES="$IPTABLES_DIR/rules.v4"

# -------------------------------[ Colors ]------------------------------- #
RED=$(tput setaf 1)
GRN=$(tput setaf 2)
YEL=$(tput setaf 3)
BLU=$(tput setaf 4)
RST=$(tput sgr0)

# -----------------------------[ Functions ]----------------------------- #

check_continue() {
  read -rp "Continue (y/n)? " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "[${YEL}INFO${RST}] Aborting per user input."
    exit 1
  fi
}

print_help() {
  cat <<EOF
Usage: ${0##*/} -i | -d | -s | -l | -h

  -i   Initialise iptables/ipset rules (run once)
  -d   Download IP ranges from ${ZONEURL}
  -s   Set ipset blacklist using downloaded ranges
  -l   List blacklist entries
  -h   Show this help message

IP list is saved in: ${IPFILE}
Countries: ${ZONES}
EOF
}

ensure_root() {
  [[ $EUID -ne 0 ]] && {
    echo "[${RED}ERROR${RST}] Must be run as root." >&2
    exit 1
  }
}

check_dependencies() {
  command -v ipset >/dev/null || {
    echo "[${RED}ERROR${RST}] ipset not found. Install it first." >&2
    exit 1
  }
  command -v iptables >/dev/null || {
    echo "[${RED}ERROR${RST}] iptables not found. Install it first." >&2
    exit 1
  }
}

init_blacklist() {
  echo "[${GRN}+${RST}] Initializing ipset/iptables rules..."

  ipset create "$BLACKLIST" hash:net hashsize 4096 || true
  ipset create "$BLACKLISTSWAP" hash:net hashsize 4096 || true

  iptables -C INPUT -m set --match-set "$BLACKLIST" src -j DROP 2>/dev/null || \
    iptables -I INPUT -m set --match-set "$BLACKLIST" src -j DROP

  iptables -C FORWARD -m set --match-set "$BLACKLIST" src -j DROP 2>/dev/null || \
    iptables -I FORWARD -m set --match-set "$BLACKLIST" src -j DROP

  mkdir -p "$IPTABLES_DIR"
  ipset save > "$IPSET_RULES"
  iptables-save > "$IPTABLES_RULES"

  echo "[${GRN}+${RST}] Rules saved to $IPTABLES_DIR"
  echo "[${YEL}NOTE${RST}] Add the following lines to your network startup:"
  echo "  pre-up ipset restore < $IPSET_RULES"
  echo "  pre-up iptables-restore < $IPTABLES_RULES"
}

download_zones() {
  echo "[${GRN}+${RST}] Downloading zones: $ZONES"
  mkdir -p "$(dirname "$IPFILE")"
  {
    echo "## $(date)"
    echo "## Zones: $ZONES"
    for zone in $ZONES; do
      echo "[*] Fetching ${zone}..."
      echo "# $zone" 
      curl -sSf "${ZONEURL}/${zone}.zone" || {
        echo "[${RED}ERR${RST}] Failed to download: $zone" >&2
      }
    done
  } > "$IPFILE"
  echo "[${GRN}+${RST}] IP ranges saved to: $IPFILE"
}

set_blacklist() {
  [[ ! -f "$IPFILE" ]] && {
    echo "[${RED}ERROR${RST}] Missing IP list: $IPFILE"
    exit 1
  }

  echo "[${GRN}+${RST}] Loading IPs into swap set..."
  ipset flush "$BLACKLISTSWAP" || true
  count=0

  while read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    ipset -exist add "$BLACKLISTSWAP" "$line" && ((count++))
  done < "$IPFILE"

  echo "[${GRN}+${RST}] Loaded $count entries. Ready to swap..."
  check_continue

  ipset swap "$BLACKLIST" "$BLACKLISTSWAP"
  ipset flush "$BLACKLISTSWAP"
  ipset save > "$IPSET_RULES"
  echo "[${GRN}+${RST}] Swap complete and rules saved."
}

list_blacklists() {
  echo "[${GRN}+${RST}] ${BLACKLIST}:"
  ipset list "$BLACKLIST" -terse || echo "(not initialized)"
  echo
  echo "[${GRN}+${RST}] ${BLACKLISTSWAP}:"
  ipset list "$BLACKLISTSWAP" -terse || echo "(not initialized)"
}

# -----------------------------[ Entrypoint ]----------------------------- #

ensure_root
check_dependencies

[[ $# -eq 0 ]] && print_help && exit 1

while getopts "idslh" opt; do
  case "$opt" in
    i) init_blacklist ;;
    d) download_zones ;;
    s) set_blacklist ;;
    l) list_blacklists ;;
    h | *) print_help ;;
  esac
done

echo "[${GRN}DONE${RST}]"
exit 0

##
##
