#!/bin/bash
# linux_persistence_hunter.sh
# Advanced Linux Persistence & Backdoor Detection/Remediation Tool
# Author: Security Researcher
# License: MIT

set -euo pipefail

# ========================
# CONFIGURATION
# ========================
VERSION="1.0.0"
SCRIPT_NAME="Linux Persistence Hunter"
TIMESTAMP=$(date +%F_%H-%M-%S)
LOGDIR="/var/log/persist_hunter"
LOGFILE="${LOGDIR}/scan_${TIMESTAMP}.log"
JSON_OUTPUT="${LOGDIR}/scan_${TIMESTAMP}.json"

# Create log directory
mkdir -p "$LOGDIR"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Flags
SAFE_MODE=1
EXPORT_JSON=0
VERBOSE=0

# Check selections (all enabled by default)
CHECK_PROCESSES=1
CHECK_CRON=1
CHECK_SHELLS=1
CHECK_SUID=1
CHECK_SSH=1
CHECK_USERS=1
CHECK_SERVICES=1
CHECK_NETWORK=1
CHECK_TEMP=1
CHECK_INTEGRITY=1
CHECK_KERNEL_MODULES=1
CHECK_CAPABILITIES=1
CHECK_PRELOAD=1

# Findings array for JSON export
declare -a FINDINGS=()

# ========================
# HELPER FUNCTIONS
# ========================

log() {
  echo -e "${CYAN}[*]${NC} $1" | tee -a "$LOGFILE"
}

success() {
  echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOGFILE"
}

warning() {
  echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOGFILE"
}

alert() {
  echo -e "${RED}[⚠]${NC} $1" | tee -a "$LOGFILE"
}

section() {
  echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOGFILE"
  echo -e "${BLUE}▶ $1${NC}" | tee -a "$LOGFILE"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOGFILE"
}

add_finding() {
  local category="$1"
  local severity="$2"
  local description="$3"
  local path="${4:-N/A}"
  
  FINDINGS+=("{\"category\":\"$category\",\"severity\":\"$severity\",\"description\":\"$description\",\"path\":\"$path\",\"timestamp\":\"$(date -Iseconds)\"}")
  
  case "$severity" in
    CRITICAL) alert "$description ($path)" ;;
    HIGH) warning "$description ($path)" ;;
    MEDIUM) warning "$description ($path)" ;;
    *) log "$description ($path)" ;;
  esac
}

detect_distro() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "$ID"
  elif [ -f /etc/redhat-release ]; then
    echo "rhel"
  else
    echo "unknown"
  fi
}

require_root() {
  if [ "$EUID" -ne 0 ]; then
    alert "This script must be run as root"
    exit 1
  fi
}

export_json() {
  if [ "$EXPORT_JSON" -eq 1 ]; then
    log "Exporting findings to JSON: $JSON_OUTPUT"
    echo "{\"scan_time\":\"$(date -Iseconds)\",\"hostname\":\"$(hostname)\",\"findings\":[" > "$JSON_OUTPUT"
    printf '%s\n' "${FINDINGS[@]}" | paste -sd ',' >> "$JSON_OUTPUT"
    echo "]}" >> "$JSON_OUTPUT"
    success "JSON export complete"
  fi
}

# ========================
# CHECK MODULES
# ========================

check_processes() {
  section "Suspicious Processes"
  
  # Look for reverse shells and suspicious patterns
  local suspicious_procs=$(ps aux | grep -E "(bash -i|/dev/tcp|nc -|ncat|socat|perl.*socket|python.*socket|ruby.*socket)" | grep -v grep)
  
  if [ -n "$suspicious_procs" ]; then
    alert "Found suspicious processes:"
    echo "$suspicious_procs" | tee -a "$LOGFILE"
    echo "$suspicious_procs" | while read -r line; do
      local pid=$(echo "$line" | awk '{print $2}')
      local cmd=$(echo "$line" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=""; print $0}')
      add_finding "processes" "CRITICAL" "Suspicious process detected" "PID:$pid CMD:$cmd"
    done
  else
    success "No obvious suspicious processes detected"
  fi
  
  # Check for hidden processes (compare ps to /proc)
  log "Checking for hidden processes..."
  local proc_count=$(ls /proc | grep -E '^[0-9]+$' | wc -l)
  local ps_count=$(ps aux | wc -l)
  if [ $((proc_count - ps_count)) -gt 10 ]; then
    warning "Process count mismatch detected (possible rootkit)"
    add_finding "processes" "HIGH" "Process hiding detected" "/proc vs ps"
  fi
}

check_cron() {
  section "Cron Jobs Analysis"
  
  # User crontabs
  log "Checking user crontabs..."
  for user in $(cut -f1 -d: /etc/passwd); do
    local cron_content=$(crontab -u "$user" -l 2>/dev/null)
    if [ -n "$cron_content" ]; then
      echo "$cron_content" | grep -E "(curl|wget|nc|bash -i|/dev/tcp|python.*http)" && {
        warning "Suspicious cron for user: $user"
        add_finding "cron" "HIGH" "Suspicious cron job for user $user" "/var/spool/cron/crontabs/$user"
      }
    fi
  done
  
  # System cron directories
  log "Checking system cron directories..."
  for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
      find "$crondir" -type f -exec grep -l "curl\|wget\|nc\|bash -i\|/dev/tcp" {} \; 2>/dev/null | while read -r file; do
        warning "Suspicious content in: $file"
        add_finding "cron" "HIGH" "Suspicious cron script" "$file"
      done
    fi
  done
  
  success "Cron analysis complete"
}

check_shells() {
  section "Shell Initialization Scripts"
  
  local shell_files=(
    "/etc/profile"
    "/etc/bash.bashrc"
    "/etc/bashrc"
    "/root/.bashrc"
    "/root/.bash_profile"
    "/root/.profile"
  )
  
  # Add user home directories
  for home in /home/*; do
    [ -d "$home" ] && shell_files+=("$home/.bashrc" "$home/.bash_profile" "$home/.profile")
  done
  
  log "Scanning shell initialization scripts..."
  for file in "${shell_files[@]}"; do
    if [ -f "$file" ]; then
      if grep -qE "(bash -i|/dev/tcp|nc -|curl.*sh|wget.*\|.*sh|eval.*base64)" "$file" 2>/dev/null; then
        alert "Suspicious content in: $file"
        grep -n "bash -i\|/dev/tcp\|nc -\|curl.*sh\|wget.*\|.*sh" "$file" | tee -a "$LOGFILE"
        add_finding "shells" "CRITICAL" "Backdoor in shell init script" "$file"
      fi
    fi
  done
  
  success "Shell script analysis complete"
}

check_suid() {
  section "SUID/SGID Binaries"
  
  log "Scanning for SUID binaries..."
  local known_good=(
    "/usr/bin/sudo"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/newgrp"
    "/usr/bin/su"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/pkexec"
    "/bin/su"
    "/bin/mount"
    "/bin/umount"
    "/bin/ping"
  )
  
  find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r suid_file; do
    local is_known=0
    for known in "${known_good[@]}"; do
      if [ "$suid_file" = "$known" ]; then
        is_known=1
        break
      fi
    done
    
    if [ $is_known -eq 0 ]; then
      warning "Unusual SUID/SGID binary: $suid_file"
      ls -lah "$suid_file" | tee -a "$LOGFILE"
      add_finding "suid" "HIGH" "Unusual SUID/SGID binary detected" "$suid_file"
    fi
  done
  
  # Check for bash copies with SUID
  find /bin /sbin /usr/bin /usr/sbin -name "*sh*" -perm -4000 2>/dev/null | while read -r shell; do
    alert "SUID shell found: $shell"
    add_finding "suid" "CRITICAL" "SUID shell binary" "$shell"
  done
  
  success "SUID/SGID scan complete"
}

check_ssh() {
  section "SSH Key Analysis"
  
  log "Checking authorized_keys files..."
  find /root /home -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
    if [ -f "$keyfile" ]; then
      log "Found: $keyfile"
      local key_count=$(grep -c "^ssh-" "$keyfile" 2>/dev/null || echo 0)
      
      if [ "$key_count" -gt 0 ]; then
        warning "$keyfile contains $key_count SSH key(s)"
        grep "^ssh-" "$keyfile" | while read -r key; do
          echo "  → $(echo $key | cut -d' ' -f1-2)" | tee -a "$LOGFILE"
        done
        add_finding "ssh" "MEDIUM" "SSH keys found in $keyfile" "$keyfile"
      fi
    fi
  done
  
  # Check for suspicious SSH config
  if [ -f /etc/ssh/sshd_config ]; then
    log "Checking SSH daemon config..."
    if grep -qE "^PermitRootLogin yes|^PasswordAuthentication yes|^PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
      warning "Insecure SSH configuration detected"
      grep "PermitRootLogin\|PasswordAuthentication\|PermitEmptyPasswords" /etc/ssh/sshd_config | tee -a "$LOGFILE"
      add_finding "ssh" "MEDIUM" "Insecure SSH configuration" "/etc/ssh/sshd_config"
    fi
  fi
  
  success "SSH analysis complete"
}

check_users() {
  section "User Account Analysis"
  
  log "Checking for suspicious users..."
  
  # Check for UID 0 accounts other than root
  awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read -r user; do
    alert "Non-root user with UID 0: $user"
    add_finding "users" "CRITICAL" "UID 0 account detected" "$user"
  done
  
  # Check for users with shell access
  awk -F: '$7 ~ /(bash|sh|zsh|ksh|fish)$/ {print $1":"$3":"$7}' /etc/passwd | tee -a "$LOGFILE"
  
  # Check for users with no password
  awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | while read -r user; do
    warning "User with no password: $user"
    add_finding "users" "HIGH" "No password set" "$user"
  done
  
  # Check for service accounts with shells
  awk -F: '$3 < 1000 && $3 != 0 && $7 ~ /(bash|sh)$/ {print $1":"$7}' /etc/passwd | while read -r line; do
    warning "Service account with shell: $line"
    add_finding "users" "MEDIUM" "Service account has shell access" "$(echo $line | cut -d: -f1)"
  done
  
  success "User account analysis complete"
}

check_services() {
  section "Service Analysis"
  
  if command -v systemctl &>/dev/null; then
    log "Analyzing systemd services..."
    
    # Check for suspicious service files
    find /etc/systemd/system /usr/lib/systemd/system -name "*.service" 2>/dev/null | while read -r service; do
      if grep -qE "(curl|wget|nc |bash -i|/dev/tcp|python.*http\.server)" "$service" 2>/dev/null; then
        alert "Suspicious service: $service"
        grep -n "ExecStart\|ExecStartPre" "$service" | tee -a "$LOGFILE"
        add_finding "services" "CRITICAL" "Suspicious systemd service" "$service"
      fi
    done
    
    # Check for enabled suspicious services
    systemctl list-unit-files --type=service --state=enabled | grep -vE "^(getty|systemd|dbus|network|rsyslog|cron|ssh)" | tee -a "$LOGFILE"
    
  elif [ -d /etc/init.d ]; then
    log "Analyzing init.d services..."
    find /etc/init.d -type f -exec grep -l "curl\|wget\|nc \|bash -i" {} \; 2>/dev/null | while read -r init_script; do
      warning "Suspicious init script: $init_script"
      add_finding "services" "HIGH" "Suspicious init.d script" "$init_script"
    done
  fi
  
  success "Service analysis complete"
}

check_network() {
  section "Network Listeners"
  
  log "Checking for network listeners..."
  
  if command -v ss &>/dev/null; then
    ss -tulpn | tee -a "$LOGFILE"
  elif command -v netstat &>/dev/null; then
    netstat -tulpn | tee -a "$LOGFILE"
  else
    warning "Neither ss nor netstat available"
  fi
  
  # Check for common backdoor ports
  local backdoor_ports=(4444 4445 5555 6666 7777 8888 9999 31337 12345)
  for port in "${backdoor_ports[@]}"; do
    if ss -tulpn 2>/dev/null | grep -q ":$port " || netstat -tulpn 2>/dev/null | grep -q ":$port "; then
      alert "Suspicious port listening: $port"
      add_finding "network" "CRITICAL" "Common backdoor port listening" "Port:$port"
    fi
  done
  
  success "Network analysis complete"
}

check_temp() {
  section "Temporary Directory Analysis"
  
  local temp_dirs=("/tmp" "/var/tmp" "/dev/shm")
  
  for dir in "${temp_dirs[@]}"; do
    log "Scanning $dir..."
    find "$dir" -type f -executable 2>/dev/null | while read -r file; do
      warning "Executable in temp dir: $file"
      ls -lah "$file" | tee -a "$LOGFILE"
      add_finding "temp" "MEDIUM" "Executable file in temp directory" "$file"
    done
  done
  
  success "Temp directory scan complete"
}

check_integrity() {
  section "Binary Integrity Check"
  
  local distro=$(detect_distro)
  
  case "$distro" in
    ubuntu|debian)
      if command -v debsums &>/dev/null; then
        log "Running debsums verification..."
        debsums -c 2>/dev/null | tee -a "$LOGFILE" | while read -r line; do
          add_finding "integrity" "HIGH" "Modified system binary" "$line"
        done
      else
        warning "debsums not installed (apt install debsums)"
      fi
      ;;
    rhel|centos|fedora)
      if command -v rpm &>/dev/null; then
        log "Running RPM verification..."
        rpm -Va 2>/dev/null | grep '^..5' | tee -a "$LOGFILE" | while read -r line; do
          add_finding "integrity" "HIGH" "Modified system binary" "$(echo $line | awk '{print $NF}')"
        done
      fi
      ;;
    *)
      warning "Unable to perform integrity check on distro: $distro"
      ;;
  esac
  
  success "Integrity check complete"
}

check_kernel_modules() {
  section "Kernel Module Analysis"
  
  log "Checking loaded kernel modules..."
  lsmod | tee -a "$LOGFILE"
  
  # Check for suspicious module names
  lsmod | awk '{print $1}' | grep -vE "^Module$" | while read -r module; do
    if [[ "$module" =~ ^(rootkit|backdoor|hide|snake) ]]; then
      alert "Suspicious kernel module: $module"
      add_finding "kernel" "CRITICAL" "Suspicious kernel module loaded" "$module"
    fi
  done
  
  # Check module signing
  if [ -f /sys/module/module/parameters/sig_enforce ]; then
    local sig_enforce=$(cat /sys/module/module/parameters/sig_enforce)
    if [ "$sig_enforce" = "N" ]; then
      warning "Kernel module signature enforcement is disabled"
      add_finding "kernel" "MEDIUM" "Module signature enforcement disabled" "/sys/module/module/parameters/sig_enforce"
    fi
  fi
  
  success "Kernel module analysis complete"
}

check_capabilities() {
  section "File Capabilities Analysis"
  
  log "Checking for files with capabilities..."
  
  if command -v getcap &>/dev/null; then
    getcap -r / 2>/dev/null | tee -a "$LOGFILE" | while read -r line; do
      local file=$(echo "$line" | awk '{print $1}')
      local caps=$(echo "$line" | awk '{print $3}')
      
      # Check for dangerous capabilities
      if echo "$caps" | grep -qE "(cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin)"; then
        warning "Dangerous capability: $line"
        add_finding "capabilities" "HIGH" "Dangerous file capability" "$file ($caps)"
      fi
    done
  else
    warning "getcap not available (install libcap2-bin on Debian/Ubuntu)"
  fi
  
  success "Capabilities analysis complete"
}

check_preload() {
  section "LD_PRELOAD Analysis"
  
  log "Checking for LD_PRELOAD hijacking..."
  
  # Check /etc/ld.so.preload
  if [ -f /etc/ld.so.preload ]; then
    alert "/etc/ld.so.preload exists!"
    cat /etc/ld.so.preload | tee -a "$LOGFILE"
    add_finding "preload" "CRITICAL" "LD_PRELOAD file exists" "/etc/ld.so.preload"
  fi
  
  # Check environment variables
  if [ -n "$LD_PRELOAD" ]; then
    alert "LD_PRELOAD environment variable set: $LD_PRELOAD"
    add_finding "preload" "CRITICAL" "LD_PRELOAD env variable set" "$LD_PRELOAD"
  fi
  
  success "LD_PRELOAD analysis complete"
}

# ========================
# MAIN EXECUTION
# ========================

show_banner() {
  echo -e "${CYAN}"
  cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   █░░ █ █▄░█ █░█ ▀▄▀   █▀█ █▀▀ █▀█ █▀ █ █▀ ▀█▀            ║
║   █▄▄ █ █░▀█ █▄█ █░█   █▀▀ ██▄ █▀▄ ▄█ █ ▄█ ░█░            ║
║                                                           ║
║              █░█ █░█ █▄░█ ▀█▀ █▀▀ █▀█                     ║
║              █▀█ █▄█ █░▀█ ░█░ ██▄ █▀▄                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
  echo -e "${NC}"
  echo -e "${BLUE}Version: $VERSION${NC}"
  echo -e "${BLUE}Scan started: $(date)${NC}\n"
}

show_usage() {
  cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
  -h, --help              Show this help message
  -a, --all               Run all checks (default)
  -p, --processes         Check for suspicious processes
  -c, --cron              Check cron jobs
  -s, --shells            Check shell init scripts
  -u, --suid              Check SUID/SGID binaries
  -k, --ssh               Check SSH keys and config
  -U, --users             Check user accounts
  -S, --services          Check systemd/init services
  -n, --network           Check network listeners
  -t, --temp              Check temp directories
  -i, --integrity         Check binary integrity
  -m, --modules           Check kernel modules
  -C, --capabilities      Check file capabilities
  -P, --preload           Check LD_PRELOAD
  
  -j, --json              Export findings to JSON
  -v, --verbose           Verbose output
  -r, --remediate         Enable remediation mode (NOT YET IMPLEMENTED)
  
EXAMPLES:
  # Run all checks
  sudo $0 -a
  
  # Check only cron and SSH
  sudo $0 -c -k
  
  # Full scan with JSON export
  sudo $0 -a -j

EOF
}

parse_args() {
  if [ $# -eq 0 ]; then
    # No arguments, run all checks by default
    return
  fi
  
  # If specific checks are requested, disable all first
  local specific_checks=0
  for arg in "$@"; do
    case "$arg" in
      -p|--processes|-c|--cron|-s|--shells|-u|--suid|-k|--ssh|-U|--users|-S|--services|-n|--network|-t|--temp|-i|--integrity|-m|--modules|-C|--capabilities|-P|--preload)
        specific_checks=1
        ;;
    esac
  done
  
  if [ $specific_checks -eq 1 ]; then
    CHECK_PROCESSES=0
    CHECK_CRON=0
    CHECK_SHELLS=0
    CHECK_SUID=0
    CHECK_SSH=0
    CHECK_USERS=0
    CHECK_SERVICES=0
    CHECK_NETWORK=0
    CHECK_TEMP=0
    CHECK_INTEGRITY=0
    CHECK_KERNEL_MODULES=0
    CHECK_CAPABILITIES=0
    CHECK_PRELOAD=0
  fi
  
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        show_usage
        exit 0
        ;;
      -a|--all)
        # Already enabled by default
        ;;
      -p|--processes) CHECK_PROCESSES=1 ;;
      -c|--cron) CHECK_CRON=1 ;;
      -s|--shells) CHECK_SHELLS=1 ;;
      -u|--suid) CHECK_SUID=1 ;;
      -k|--ssh) CHECK_SSH=1 ;;
      -U|--users) CHECK_USERS=1 ;;
      -S|--services) CHECK_SERVICES=1 ;;
      -n|--network) CHECK_NETWORK=1 ;;
      -t|--temp) CHECK_TEMP=1 ;;
      -i|--integrity) CHECK_INTEGRITY=1 ;;
      -m|--modules) CHECK_KERNEL_MODULES=1 ;;
      -C|--capabilities) CHECK_CAPABILITIES=1 ;;
      -P|--preload) CHECK_PRELOAD=1 ;;
      -j|--json) EXPORT_JSON=1 ;;
      -v|--verbose) VERBOSE=1 ;;
      -r|--remediate)
        alert "Remediation mode not yet implemented"
        SAFE_MODE=0
        ;;
      *)
        echo "Unknown option: $1"
        show_usage
        exit 1
        ;;
    esac
    shift
  done
}

main() {
  show_banner
  parse_args "$@"
  require_root
  
  log "Starting $SCRIPT_NAME v$VERSION"
  log "Hostname: $(hostname)"
  log "Distribution: $(detect_distro)"
  log "Kernel: $(uname -r)"
  log "Log file: $LOGFILE"
  
  # Run selected checks
  [ $CHECK_PROCESSES -eq 1 ] && check_processes
  [ $CHECK_CRON -eq 1 ] && check_cron
  [ $CHECK_SHELLS -eq 1 ] && check_shells
  [ $CHECK_SUID -eq 1 ] && check_suid
  [ $CHECK_SSH -eq 1 ] && check_ssh
  [ $CHECK_USERS -eq 1 ] && check_users
  [ $CHECK_SERVICES -eq 1 ] && check_services
  [ $CHECK_NETWORK -eq 1 ] && check_network
  [ $CHECK_TEMP -eq 1 ] && check_temp
  [ $CHECK_INTEGRITY -eq 1 ] && check_integrity
  [ $CHECK_KERNEL_MODULES -eq 1 ] && check_kernel_modules
  [ $CHECK_CAPABILITIES -eq 1 ] && check_capabilities
  [ $CHECK_PRELOAD -eq 1 ] && check_preload
  
  # Summary
  section "Scan Summary"
  local finding_count=${#FINDINGS[@]}
  
  if [ $finding_count -eq 0 ]; then
    success "No suspicious findings detected"
  else
    alert "Found $finding_count suspicious items"
  fi
  
  log "Full report: $LOGFILE"
  
  export_json
  
  echo -e "\n${GREEN}Scan complete!${NC}"
}

# Run main
main "$@"
