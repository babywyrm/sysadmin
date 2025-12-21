#!/bin/bash

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Define Colors for visual feedback
TEXT_RESET='\e[0m'
TEXT_YELLOW='\e[0;33m'
TEXT_RED_B='\e[1;31m'
TEXT_BLUE='\e[1;34m'
TEXT_GREEN='\e[1;32m'
TEXT_BOLD='\e[1m'

# Logging
LOG_FILE="/var/log/system_update_$(date +%Y%m%d).log"

# Non-interactive settings to prevent "Config File Modified" prompts from hanging the script
export NEEDRESTART_MODE=a
export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log_message() {
    # Prints to stdout and appends to log file
    echo -e "$1"
    # Strip color codes for the log file
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${TEXT_RED_B}Error: This script must be run as root (use sudo).${TEXT_RESET}"
       exit 1
    fi
}

check_disk_space() {
    # Warn if root partition has less than 1GB free
    FREE_SPACE=$(df / . --output=avail -B 1G | tail -n 1)
    if [[ $FREE_SPACE -lt 1 ]]; then
        echo -e "${TEXT_RED_B}WARNING: Low disk space detected ($FREE_SPACE GB free).${TEXT_RESET}"
        read -p "Continue anyway? [y/N]: " confirm
        if [[ ! $confirm =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

check_root
check_disk_space

# Initialize Log
echo "System Maintenance Started: $(date)" > "$LOG_FILE"

log_message "${TEXT_BLUE}-----------------------------------${TEXT_RESET}"
log_message "${TEXT_BLUE}  Begin System Maintenance         ${TEXT_RESET}"
log_message "${TEXT_BLUE}  Log file: $LOG_FILE      ${TEXT_RESET}"
log_message "${TEXT_BLUE}-----------------------------------${TEXT_RESET}"

# 1. Update Package Lists
log_message "${TEXT_GREEN}[+] Updating package lists (apt-get update)...${TEXT_RESET}"
apt-get -qy update >> "$LOG_FILE" 2>&1

# 2. Clean Local Repository
log_message "${TEXT_GREEN}[+] Cleaning local repository (apt-get clean)...${TEXT_RESET}"
apt-get -qy clean >> "$LOG_FILE" 2>&1

# 3. Perform Distribution Upgrade
# Uses Dpkg options to keep old config files if conflicts arise (preventing hangs)
log_message "${TEXT_GREEN}[+] Performing smart upgrade (apt-get dist-upgrade)...${TEXT_RESET}"
apt-get -qy -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" dist-upgrade >> "$LOG_FILE" 2>&1

# 4. Remove Unused Dependencies
log_message "${TEXT_GREEN}[+] Pruning unused packages (apt-get autoremove)...${TEXT_RESET}"
apt-get autoremove -y >> "$LOG_FILE" 2>&1

# 5. Optional: Snap Refresh (if Snap is installed)
if command -v snap &> /dev/null; then
    log_message "${TEXT_GREEN}[+] Refreshing Snap packages...${TEXT_RESET}"
    snap refresh >> "$LOG_FILE" 2>&1
fi

# 6. Final Status Check
log_message "${TEXT_BLUE}-----------------------------------${TEXT_RESET}"
log_message "${TEXT_BLUE}       Maintenance Complete        ${TEXT_RESET}"
log_message "${TEXT_BLUE}-----------------------------------${TEXT_RESET}"

# Check for reboot requirements
if [ -f /var/run/reboot-required ]; then
    log_message "${TEXT_RED_B}${TEXT_BOLD}!!! A SYSTEM REBOOT IS REQUIRED !!!${TEXT_RESET}"
    
    # Check if a specific package requested the reboot
    if [ -f /var/run/reboot-required.pkgs ]; then
        PACKAGES=$(cat /var/run/reboot-required.pkgs)
        log_message "${TEXT_YELLOW}Triggered by: $PACKAGES${TEXT_RESET}"
    fi

    # Interactive Prompt
    while true; do
        read -p "Would you like to reboot now? [y/n]: " yn
        case $yn in
            [Yy]* ) 
                log_message "${TEXT_YELLOW}Reboot initiated by user.${TEXT_RESET}"
                sleep 1
                reboot
                break;;
            [Nn]* ) 
                log_message "${TEXT_YELLOW}Reboot skipped by user.${TEXT_RESET}"
                exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done
else
    log_message "${TEXT_GREEN}No reboot required. System is up to date.${TEXT_RESET}"
    exit 0
fi

# ==============================================================================
# DOCUMENTATION & DOCSTRINGS
# ==============================================================================

: << 'END_OF_DOCS'

SCRIPT NAME: 
    System Maintenance & Update Utility

DESCRIPTION:
    A robust Bash script designed to automate the updating and cleaning of 
    Debian-based Linux systems (Ubuntu, Debian, Mint, Kali, etc.). 
    It handles package lists, distribution upgrades, cleaning, and autoremoval 
    of unused dependencies.

FEATURES:
    1. Root Check: Ensures script is run with sudo privileges.
    2. Disk Check: Warns if disk space is critically low before updating.
    3. Non-Interactive: Sets environment variables to prevent dpkg config prompts
       from pausing the script indefinitely during automation.
    4. Logging: Writes all outputs to /var/log/system_update_YYYYMMDD.log for auditing.
    5. Snap Support: Automatically detects and updates Snap packages if installed.
    6. Reboot Detection: Checks /var/run/reboot-required and prompts the user
       interactively if a restart is needed.

USAGE:
    sudo ./maintenance.sh

CRONJOB USAGE:
    To run this via cron (automated schedule), you should remove the interactive 
    read prompts at the end or wrap them in a check for terminal interactivity 
    Use `if [ -t 1 ]; then ... fi` to check for an interactive terminal.

EXIT CODES:
    0 - Success
    1 - Permission denied or User cancelled on low disk warning

AUTHOR:
    [Your Name/Organization]

VERSION:
    2.1.0

END_OF_DOCS
