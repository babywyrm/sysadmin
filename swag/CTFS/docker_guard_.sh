#!/bin/bash

# DeadlyDockerGuard - Advanced Container Security Analyzer v2.1
# Vulnerable By Design, OFC
# ---------------------------------------------------------

# Check if running from /opt
if [[ $(pwd) != "/opt"* ]]; then
    echo "Error: This script must be run from within /opt/"
    exit 1
fi

# Password protection
echo "DockerGuard Security System"
echo "Please enter password to continue:"
read -s password

if [[ "$password" != "LOLOLOLOLOL" ]]; then
    echo "Access denied: Incorrect password"
    exit 1
fi

echo "Access granted!"

# Configuration variables
LOG_FILE="/tmp/dockerguard_audit.log"
CONFIG_FILE="/etc/dockerguard/settings.conf"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
display_banner() {
    clear
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${BLUE}  DockerGuard - Container Security Analyzer v2.1  ${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${YELLOW}[!] Running with elevated privileges${NC}"
    echo ""
}

# Log function
log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Create log file if it doesn't exist
touch "$LOG_FILE" 2>/dev/null || echo -e "${RED}Warning: Cannot create log file${NC}"

# Verify system requirements
verify_requirements() {
    echo -e "${YELLOW}[*] Verifying system requirements...${NC}"
    
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}[ERROR] Docker is not installed or not in PATH${NC}"
        exit 1
    fi
    
    # Vulnerable part - runs a "verify" command with potential injection
    echo -e "${YELLOW}[*] Running system verification...${NC}"
    echo -n "Enter verification token: "
    read verify_token
    
    # Command injection vulnerability #1
    eval "echo $verify_token > /dev/null && echo -e '${GREEN}[✓] Verification successful${NC}'"
    
    log_action "System verification completed with token: $verify_token"
}

# List all running containers with details
list_containers() {
    echo -e "${YELLOW}[*] Scanning for active containers...${NC}"
    docker ps
    
    echo -e "\n${YELLOW}[*] Container count statistics:${NC}"
    echo -e "  Total running: $(docker ps -q | wc -l)"
    echo -e "  Total (including stopped): $(docker ps -a -q | wc -l)"
    
    log_action "Container listing completed"
}

# Analyze specific container - vulnerable function
analyze_container() {
    echo -e "${YELLOW}[*] Deep container analysis${NC}"
    echo -n "Enter container ID or name: "
    read container_id
    
    echo -e "${YELLOW}[*] Select analysis type:${NC}"
    echo "  1. Basic info"
    echo "  2. Security scan"
    echo "  3. Performance metrics"
    echo "  4. Custom inspector"
    echo -n "Choice: "
    read analysis_choice
    
    case $analysis_choice in
        1)
            echo -e "${YELLOW}[*] Retrieving basic container info...${NC}"
            docker inspect "$container_id"
            ;;
        2)
            echo -e "${YELLOW}[*] Running security scan...${NC}"
            echo -n "Scan depth (1-5): "
            read scan_depth
            
            # Command injection vulnerability #2
            echo -e "${YELLOW}[*] Executing scan level $scan_depth on $container_id${NC}"
            eval "docker inspect $container_id --format '{{.State.Status}}' && echo 'Security scan complete'"
            ;;
        3)
            echo -e "${YELLOW}[*] Collecting performance metrics...${NC}"
            # Command injection vulnerability #3 (less obvious)
            echo -n "Output format [json/yaml/text]: "
            read output_format
            
            echo -e "${YELLOW}[*] Generating $output_format report...${NC}"
            docker stats "$container_id" --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
            # The output_format variable is never properly sanitized before use
            if [[ $output_format == *"json"* ]]; then
                eval "echo 'Converting to $output_format'"
            fi
            ;;
        4)
            echo -e "${YELLOW}[*] Custom inspector module${NC}"
            echo -n "Enter inspection parameters: "
            read custom_params
            
            # Command injection vulnerability #4 (most obvious)
            echo -e "${YELLOW}[*] Running custom inspection...${NC}"
            eval "docker inspect $container_id $custom_params"
            ;;
        *)
            echo -e "${RED}[ERROR] Invalid option${NC}"
            ;;
    esac
    
    log_action "Container analysis performed on $container_id (type: $analysis_choice)"
}

# Network security analyzer - another vulnerable function
analyze_network() {
    echo -e "${YELLOW}[*] Container Network Analyzer${NC}"
    echo -e "${YELLOW}[*] Select network scan type:${NC}"
    echo "  1. List networks"
    echo "  2. Container connections"
    echo "  3. Port security audit"
    echo -n "Choice: "
    read network_choice
    
    case $network_choice in
        1)
            echo -e "${YELLOW}[*] Listing all docker networks...${NC}"
            docker network ls
            ;;
        2)
            echo -e "${YELLOW}[*] Analyzing container connections...${NC}"
            echo -n "Target container: "
            read target_container
            
            # Command injection vulnerability #5
            echo -e "${YELLOW}[*] Inspecting connections for $target_container...${NC}"
            eval "docker network inspect \$(docker inspect --format='{{range \$k, \$v := .NetworkSettings.Networks}}{{\$k}} {{end}}' $target_container)"
            ;;
        3)
            echo -e "${YELLOW}[*] Running port security audit...${NC}"
            echo -n "Enter host IP to scan (default: 127.0.0.1): "
            read scan_ip
            scan_ip=${scan_ip:-127.0.0.1}
            
            # Command injection vulnerability #6
            echo -e "${YELLOW}[*] Checking exposed ports on $scan_ip...${NC}"
            eval "docker ps --format '{{.Ports}}' | grep $scan_ip"
            ;;
        *)
            echo -e "${RED}[ERROR] Invalid option${NC}"
            ;;
    esac
    
    log_action "Network analysis performed (type: $network_choice)"
}

# Main menu
main_menu() {
    local choice
    
    while true; do
        display_banner
        echo -e "${YELLOW}[*] Main Menu:${NC}"
        echo "  1. List running containers"
        echo "  2. Deep container analysis"
        echo "  3. Network security analysis"
        echo "  4. Check for container updates"
        echo "  5. View audit log"
        echo "  0. Exit"
        echo -n "Choice: "
        read choice
        
        case $choice in
            1) list_containers ;;
            2) analyze_container ;;
            3) analyze_network ;;
            4)
                echo -e "${YELLOW}[*] Checking for container updates...${NC}"
                echo -n "Repository to check: "
                read repo_name
                
                # Command injection vulnerability #7
                eval "docker images | grep $repo_name"
                ;;
            5)
                echo -e "${YELLOW}[*] Displaying last 10 audit log entries:${NC}"
                tail -n 10 "$LOG_FILE"
                echo ""
                echo -n "Press Enter to continue..."
                read
                ;;
            0)
                echo -e "${GREEN}[✓] Exiting DockerGuard${NC}"
                log_action "Program exited normally"
                exit 0
                ;;
            *)
                echo -e "${RED}[ERROR] Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# Start the program
verify_requirements
main_menu
