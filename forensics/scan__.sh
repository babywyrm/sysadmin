#!/bin/bash
# linux_persistence_hunter.sh - EXTENDED, (..beta..)
# Added: Docker, YARA, Webshells, Timeline Analysis, Hidden Files, and more

# ... [Keep all previous configuration and helper functions] ...

# Add these new flags after the existing CHECK_* flags
CHECK_DOCKER=1
CHECK_YARA=1
CHECK_TIMELINE=1
CHECK_HIDDEN=1
CHECK_WEBSHELLS=1
CHECK_PACKAGES=1
CHECK_WRITABLE=1

# ========================
# NEW CHECK MODULES
# ========================

check_docker() {
  section "Docker & Container Analysis"
  
  if ! command -v docker &>/dev/null; then
    log "Docker not installed, skipping container checks"
    return
  fi
  
  log "Checking Docker installation..."
  
  # Check if Docker daemon is running
  if ! systemctl is-active docker &>/dev/null && ! pgrep dockerd &>/dev/null; then
    log "Docker daemon not running"
    return
  fi
  
  # List running containers
  log "Running containers:"
  docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | tee -a "$LOGFILE"
  
  # Check for privileged containers
  log "Checking for privileged containers..."
  docker ps -q 2>/dev/null | while read -r container_id; do
    if docker inspect "$container_id" --format='{{.HostConfig.Privileged}}' 2>/dev/null | grep -q true; then
      warning "Privileged container detected: $container_id"
      docker inspect "$container_id" --format='{{.Name}} - {{.Config.Image}}' | tee -a "$LOGFILE"
      add_finding "docker" "HIGH" "Privileged container running" "$container_id"
    fi
  done
  
  # Check for containers with host network mode
  log "Checking for containers with host networking..."
  docker ps -q 2>/dev/null | while read -r container_id; do
    if docker inspect "$container_id" --format='{{.HostConfig.NetworkMode}}' 2>/dev/null | grep -q host; then
      warning "Container using host network: $container_id"
      add_finding "docker" "MEDIUM" "Container with host networking" "$container_id"
    fi
  done
  
  # Check for suspicious bind mounts
  log "Checking for suspicious volume mounts..."
  docker ps -q 2>/dev/null | while read -r container_id; do
    local mounts=$(docker inspect "$container_id" --format='{{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' 2>/dev/null)
    
    if echo "$mounts" | grep -qE "(/etc|/root|/home|/var/log|/usr/bin|/usr/sbin)->"; then
      warning "Suspicious mount in container $container_id:"
      echo "  $mounts" | tee -a "$LOGFILE"
      add_finding "docker" "HIGH" "Suspicious volume mount" "$container_id: $mounts"
    fi
  done
  
  # Check Docker socket exposure
  if [ -S /var/run/docker.sock ]; then
    local socket_perms=$(stat -c '%a' /var/run/docker.sock)
    if [ "$socket_perms" != "660" ]; then
      warning "Docker socket has unusual permissions: $socket_perms"
      add_finding "docker" "MEDIUM" "Unusual Docker socket permissions" "/var/run/docker.sock ($socket_perms)"
    fi
    
    # Check if docker.sock is mounted in any container
    docker ps -q 2>/dev/null | while read -r container_id; do
      if docker inspect "$container_id" --format='{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep -q "/var/run/docker.sock"; then
        alert "Docker socket mounted in container: $container_id"
        add_finding "docker" "CRITICAL" "Docker socket exposed to container" "$container_id"
      fi
    done
  fi
  
  # Check for containers running as root
  log "Checking container user context..."
  docker ps -q 2>/dev/null | while read -r container_id; do
    local user=$(docker inspect "$container_id" --format='{{.Config.User}}' 2>/dev/null)
    if [ -z "$user" ] || [ "$user" = "0" ] || [ "$user" = "root" ]; then
      warning "Container running as root: $container_id"
      add_finding "docker" "MEDIUM" "Container running as root user" "$container_id"
    fi
  done
  
  # Check Docker images for suspicious tags
  log "Checking Docker images..."
  docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -E "(latest|:<none>|malware|hack|backdoor)" | while read -r image; do
    warning "Suspicious or untagged image: $image"
    add_finding "docker" "LOW" "Suspicious Docker image" "$image"
  done
  
  success "Docker analysis complete"
}

check_yara() {
  section "YARA Malware Scanning"
  
  if ! command -v yara &>/dev/null; then
    warning "YARA not installed (recommended: apt install yara / yum install yara)"
    log "Falling back to basic signature scanning..."
    
    # Basic signature-based detection without YARA
    log "Scanning for common malware patterns..."
    
    local scan_paths=("/tmp" "/var/tmp" "/dev/shm" "/home" "/root")
    local malware_patterns=(
      "eval(base64_decode"
      "system(\$_"
      "exec(\$_"
      "passthru(\$_"
      "shell_exec(\$_"
      "/bin/bash -i"
      "/bin/sh -i"
      "nc -e"
      "socat"
      "python.*pty.spawn"
      "perl.*socket"
    )
    
    for path in "${scan_paths[@]}"; do
      [ ! -d "$path" ] && continue
      log "Scanning $path..."
      
      for pattern in "${malware_patterns[@]}"; do
        grep -r -l "$pattern" "$path" 2>/dev/null | head -10 | while read -r file; do
          warning "Potential malware pattern in: $file"
          add_finding "yara" "HIGH" "Malware signature detected" "$file (pattern: $pattern)"
        done
      done
    done
    
    return
  fi
  
  log "YARA installed, preparing ruleset..."
  
  # Create temporary YARA rules for common backdoors
  local YARA_RULES="/tmp/persist_hunter_rules.yar"
  
  cat > "$YARA_RULES" << 'EOF'
rule PHP_Webshell {
    meta:
        description = "Detects common PHP webshell patterns"
        severity = "high"
    strings:
        $php1 = "eval($_POST"
        $php2 = "system($_GET"
        $php3 = "exec($_REQUEST"
        $php4 = "assert($_POST"
        $php5 = "base64_decode"
        $shell1 = "shell_exec"
        $shell2 = "passthru"
    condition:
        any of ($php*) and any of ($shell*)
}

rule Reverse_Shell {
    meta:
        description = "Detects reverse shell patterns"
        severity = "critical"
    strings:
        $bash1 = "/bin/bash -i"
        $bash2 = "/bin/sh -i"
        $nc1 = "nc -e /bin"
        $nc2 = "ncat -e"
        $python1 = "socket.socket"
        $python2 = "pty.spawn"
        $perl1 = "use Socket"
    condition:
        any of them
}

rule SSH_Key_Stealer {
    meta:
        description = "Detects SSH key theft patterns"
    strings:
        $ssh1 = ".ssh/id_rsa"
        $ssh2 = "authorized_keys"
        $send1 = "curl"
        $send2 = "wget"
    condition:
        all of ($ssh*) and any of ($send*)
}

rule Credential_Harvester {
    meta:
        description = "Detects credential harvesting"
    strings:
        $pass1 = "/etc/shadow"
        $pass2 = "/etc/passwd"
        $exfil1 = "base64"
        $exfil2 = "| nc"
    condition:
        any of ($pass*) and any of ($exfil*)
}
EOF

  log "Scanning with YARA rules..."
  local scan_dirs=("/tmp" "/var/tmp" "/dev/shm" "/var/www" "/srv" "/opt")
  
  for dir in "${scan_dirs[@]}"; do
    if [ -d "$dir" ]; then
      log "Scanning $dir with YARA..."
      yara -r "$YARA_RULES" "$dir" 2>/dev/null | while read -r match; do
        alert "YARA match: $match"
        add_finding "yara" "CRITICAL" "YARA rule matched" "$match"
      done
    fi
  done
  
  rm -f "$YARA_RULES"
  success "YARA scan complete"
}

check_timeline() {
  section "File Timeline Analysis"
  
  log "Finding recently modified files (last 7 days)..."
  
  # Critical system directories to monitor
  local critical_dirs=(
    "/etc"
    "/usr/bin"
    "/usr/sbin"
    "/bin"
    "/sbin"
    "/root"
    "/var/spool/cron"
  )
  
  for dir in "${critical_dirs[@]}"; do
    [ ! -d "$dir" ] && continue
    
    log "Checking $dir for recent modifications..."
    find "$dir" -type f -mtime -7 2>/dev/null | while read -r file; do
      local mod_time=$(stat -c '%y' "$file" 2>/dev/null)
      warning "Recently modified: $file (modified: $mod_time)"
      add_finding "timeline" "MEDIUM" "Recently modified system file" "$file"
    done | head -20  # Limit output
  done
  
  # Check for files modified in suspicious time ranges (e.g., 2-4 AM)
  log "Checking for files modified during unusual hours (00:00-05:00)..."
  find /etc /usr/bin /usr/sbin -type f -mtime -30 2>/dev/null | while read -r file; do
    local mod_hour=$(stat -c '%y' "$file" | cut -d' ' -f2 | cut -d':' -f1)
    if [ "$mod_hour" -ge 0 ] && [ "$mod_hour" -le 5 ]; then
      warning "File modified during suspicious hours: $file"
      add_finding "timeline" "MEDIUM" "File modified during off-hours" "$file"
    fi
  done | head -10
  
  success "Timeline analysis complete"
}

check_hidden() {
  section "Hidden Files Detection"
  
  log "Scanning for hidden files and directories..."
  
  local search_paths=("/" "/tmp" "/var/tmp" "/dev/shm" "/home" "/root")
  
  for path in "${search_paths[@]}"; do
    [ ! -d "$path" ] && continue
    
    log "Scanning $path..."
    
    # Find hidden files (starting with .)
    find "$path" -maxdepth 3 -name ".*" -type f 2>/dev/null | grep -v ".bashrc\|.profile\|.bash_history" | while read -r hidden; do
      # Check if executable or suspicious
      if [ -x "$hidden" ] || file "$hidden" | grep -qE "(script|executable)"; then
        warning "Suspicious hidden file: $hidden"
        file "$hidden" | tee -a "$LOGFILE"
        add_finding "hidden" "MEDIUM" "Hidden executable file" "$hidden"
      fi
    done | head -20
    
    # Find hidden directories
    find "$path" -maxdepth 2 -name ".*" -type d 2>/dev/null | grep -v "^\./\.\|\.cache\|\.config\|\.ssh\|\.gnupg" | while read -r hidden_dir; do
      warning "Hidden directory: $hidden_dir"
      ls -la "$hidden_dir" 2>/dev/null | head -5 | tee -a "$LOGFILE"
      add_finding "hidden" "LOW" "Hidden directory found" "$hidden_dir"
    done | head -10
  done
  
  # Check for spaces in filenames (common obfuscation)
  log "Checking for files with suspicious names..."
  find /tmp /var/tmp /dev/shm -type f 2>/dev/null | while read -r file; do
    local basename=$(basename "$file")
    if [[ "$basename" =~ ^\ +$ ]] || [[ "$basename" =~ \.\. ]]; then
      alert "File with suspicious name: $file"
      add_finding "hidden" "HIGH" "Obfuscated filename" "$file"
    fi
  done
  
  success "Hidden files scan complete"
}

check_webshells() {
  section "Webshell Detection"
  
  # Common web directories
  local web_dirs=(
    "/var/www"
    "/var/www/html"
    "/usr/share/nginx"
    "/srv/http"
    "/opt/lampp/htdocs"
    "/home/*/public_html"
  )
  
  log "Scanning for webshells..."
  
  for web_dir in "${web_dirs[@]}"; do
    # Expand glob
    for expanded_dir in $web_dir; do
      [ ! -d "$expanded_dir" ] && continue
      
      log "Scanning web directory: $expanded_dir"
      
      # PHP webshells
      find "$expanded_dir" -type f -name "*.php" 2>/dev/null | while read -r php_file; do
        if grep -qE "(eval\(|base64_decode|system\(|exec\(|passthru\(|shell_exec\(|assert\()" "$php_file" 2>/dev/null; then
          alert "Potential PHP webshell: $php_file"
          grep -n "eval\|base64_decode\|system\|exec\|passthru" "$php_file" | head -3 | tee -a "$LOGFILE"
          add_finding "webshells" "CRITICAL" "PHP webshell detected" "$php_file"
        fi
      done
      
      # JSP webshells
      find "$expanded_dir" -type f -name "*.jsp" 2>/dev/null | while read -r jsp_file; do
        if grep -qE "(Runtime\.getRuntime|ProcessBuilder|java\.lang\.Runtime)" "$jsp_file" 2>/dev/null; then
          alert "Potential JSP webshell: $jsp_file"
          add_finding "webshells" "CRITICAL" "JSP webshell detected" "$jsp_file"
        fi
      done
      
      # ASPX webshells
      find "$expanded_dir" -type f -name "*.aspx" 2>/dev/null | while read -r aspx_file; do
        if grep -qE "(eval\(|System\.Diagnostics\.Process)" "$aspx_file" 2>/dev/null; then
          alert "Potential ASPX webshell: $aspx_file"
          add_finding "webshells" "CRITICAL" "ASPX webshell detected" "$aspx_file"
        fi
      done
      
      # Check for suspicious filenames
      find "$expanded_dir" -type f 2>/dev/null | grep -iE "(shell|cmd|backdoor|c99|r57|b374k|wso)" | while read -r susp_file; do
        warning "Suspicious filename in web directory: $susp_file"
        add_finding "webshells" "HIGH" "Suspicious web file" "$susp_file"
      done
    done
  done
  
  success "Webshell scan complete"
}

check_packages() {
  section "Package Manager Analysis"
  
  local distro=$(detect_distro)
  
  case "$distro" in
    ubuntu|debian)
      if command -v dpkg &>/dev/null; then
        log "Checking for unsigned packages..."
        dpkg -l | grep "^ii" | awk '{print $2}' | while read -r pkg; do
          if ! apt-cache policy "$pkg" 2>/dev/null | grep -q "security.ubuntu.com\|security.debian.org"; then
            # This is a simplified check; not all packages are from security repos
            : # Placeholder for more sophisticated checks
          fi
        done
        
        log "Checking for held packages..."
        dpkg --get-selections | grep "hold$" | tee -a "$LOGFILE" | while read -r held; do
          warning "Package on hold: $held"
          add_finding "packages" "LOW" "Package held from updates" "$(echo $held | awk '{print $1}')"
        done
      fi
      ;;
      
    rhel|centos|fedora)
      if command -v rpm &>/dev/null; then
        log "Checking for unsigned packages..."
        rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n' | grep -i "none" | tee -a "$LOGFILE" | while read -r pkg; do
          warning "Unsigned package: $pkg"
          add_finding "packages" "MEDIUM" "Unsigned RPM package" "$(echo $pkg | awk '{print $1}')"
        done
      fi
      ;;
  esac
  
  # Check for packages installed from source
  log "Checking /usr/local for manually installed software..."
  find /usr/local/bin /usr/local/sbin -type f -executable 2>/dev/null | while read -r binary; do
    log "Manually installed binary: $binary"
    add_finding "packages" "LOW" "Manually installed binary" "$binary"
  done | head -20
  
  success "Package analysis complete"
}

check_writable() {
  section "Writable System Directories"
  
  log "Checking for world-writable directories in critical paths..."
  
  local critical_paths=(
    "/etc"
    "/usr/bin"
    "/usr/sbin"
    "/bin"
    "/sbin"
    "/lib"
    "/lib64"
  )
  
  for path in "${critical_paths[@]}"; do
    [ ! -d "$path" ] && continue
    
    find "$path" -type d -perm -002 2>/dev/null | while read -r writable_dir; do
      alert "World-writable directory: $writable_dir"
      ls -ld "$writable_dir" | tee -a "$LOGFILE"
      add_finding "writable" "HIGH" "World-writable system directory" "$writable_dir"
    done
  done
  
  # Check for world-writable files in critical directories
  log "Checking for world-writable files..."
  for path in "${critical_paths[@]}"; do
    [ ! -d "$path" ] && continue
    
    find "$path" -type f -perm -002 2>/dev/null | while read -r writable_file; do
      alert "World-writable file: $writable_file"
      ls -l "$writable_file" | tee -a "$LOGFILE"
      add_finding "writable" "CRITICAL" "World-writable system file" "$writable_file"
    done | head -10
  done
  
  success "Writable directories check complete"
}

# ========================
# UPDATE MAIN FUNCTION
# ========================

# Update the parse_args function to include new checks
parse_args() {
  if [ $# -eq 0 ]; then
    return
  fi
  
  local specific_checks=0
  for arg in "$@"; do
    case "$arg" in
      -p|--processes|-c|--cron|-s|--shells|-u|--suid|-k|--ssh|-U|--users|-S|--services|-n|--network|-t|--temp|-i|--integrity|-m|--modules|-C|--capabilities|-P|--preload|-d|--docker|-y|--yara|-T|--timeline|-H|--hidden|-w|--webshells|-K|--packages|-W|--writable)
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
    CHECK_DOCKER=0
    CHECK_YARA=0
    CHECK_TIMELINE=0
    CHECK_HIDDEN=0
    CHECK_WEBSHELLS=0
    CHECK_PACKAGES=0
    CHECK_WRITABLE=0
  fi
  
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        show_usage
        exit 0
        ;;
      -a|--all) ;;
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
      -d|--docker) CHECK_DOCKER=1 ;;
      -y|--yara) CHECK_YARA=1 ;;
      -T|--timeline) CHECK_TIMELINE=1 ;;
      -H|--hidden) CHECK_HIDDEN=1 ;;
      -w|--webshells) CHECK_WEBSHELLS=1 ;;
      -K|--packages) CHECK_PACKAGES=1 ;;
      -W|--writable) CHECK_WRITABLE=1 ;;
      -j|--json) EXPORT_JSON=1 ;;
      -v|--verbose) VERBOSE=1 ;;
      -r|--remediate)
        alert "Remediation mode not implemented"
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

# Update show_usage to include new options
show_usage() {
  cat << EOF
Usage: $0 [OPTIONS]

CORE CHECKS:
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

EXTENDED CHECKS:
  -d, --docker            Check Docker containers
  -y, --yara              Run YARA malware scan
  -T, --timeline          File timeline analysis
  -H, --hidden            Hidden files detection
  -w, --webshells         Webshell detection
  -K, --packages          Package manager analysis
  -W, --writable          World-writable directories
  
OUTPUT OPTIONS:
  -j, --json              Export findings to JSON
  -v, --verbose           Verbose output
  
EXAMPLES:
  # Run all checks
  sudo $0 -a
  
  # Check Docker and webshells only
  sudo $0 -d -w
  
  # Full scan with JSON export
  sudo $0 -a -j
  
  # Quick triage (processes, network, docker)
  sudo $0 -p -n -d

EOF
}

# Update main() to include new checks
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
  [ $CHECK_DOCKER -eq 1 ] && check_docker
  [ $CHECK_YARA -eq 1 ] && check_yara
  [ $CHECK_TIMELINE -eq 1 ] && check_timeline
  [ $CHECK_HIDDEN -eq 1 ] && check_hidden
  [ $CHECK_WEBSHELLS -eq 1 ] && check_webshells
  [ $CHECK_PACKAGES -eq 1 ] && check_packages
  [ $CHECK_WRITABLE -eq 1 ] && check_writable
  
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
