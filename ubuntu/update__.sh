#!/bin/bash

# Define Colors for nicer output
TEXT_RESET='\e[0m'
TEXT_YELLOW='\e[0;33m'
TEXT_RED_B='\e[1;31m'
TEXT_BLUE='\e[1;34m'
TEXT_GREEN='\e[1;32m'

# check for root/sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${TEXT_RED_B}This script must be run as root (use sudo).${TEXT_RESET}"
   exit 1
fi

# Set environment variables for non-interactive updates
# This prevents the script from hanging on config file prompts
export NEEDRESTART_MODE=a
export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical

echo -e $TEXT_BLUE
echo '-----------------------------------'
echo '  Begin System Update Procedure    '
echo '-----------------------------------'
echo -e $TEXT_RESET

# 1. Clean local repository
echo -e "${TEXT_GREEN}[+] Cleaning local repository...${TEXT_RESET}"
apt-get -qy clean

# 2. Update package lists
echo -e "${TEXT_GREEN}[+] Updating package lists...${TEXT_RESET}"
apt-get -qy update

# 3. Perform Distribution Upgrade
# -o Dpkg::Options flags force the system to keep old config files or 
# accept defaults without asking the user, preventing hangs.
echo -e "${TEXT_GREEN}[+] Performing distribution upgrade...${TEXT_RESET}"
apt-get -qy -o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold" dist-upgrade

# 4. Remove unused dependencies
echo -e "${TEXT_GREEN}[+] Removing unused packages...${TEXT_RESET}"
apt-get autoremove -y

# 5. Check for reboot requirements
echo -e $TEXT_BLUE
echo '-----------------------------------'
echo '       Update Complete             '
echo '-----------------------------------'
echo -e $TEXT_RESET

if [ -f /var/run/reboot-required ]; then
    echo -e $TEXT_RED_B
    echo '!!! A SYSTEM REBOOT IS REQUIRED !!!'
    echo -e $TEXT_RESET
    
    # Prompt for reboot
    while true; do
        read -p "Would you like to reboot now? [y/n]: " yn
        case $yn in
            [Yy]* ) 
                echo -e "${TEXT_YELLOW}Rebooting system...${TEXT_RESET}"
                sleep 1
                reboot
                break;;
            [Nn]* ) 
                echo -e "${TEXT_YELLOW}Reboot skipped. Please reboot manually later.${TEXT_RESET}"
                exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done
else
    echo -e "${TEXT_GREEN}No reboot required. Have a nice day!${TEXT_RESET}"
    echo ""
    exit 0
fi
