#!/usr/bin/env bash
#
# ConfigServer Security & Firewall (CSF) Installation Script
# Modernized for current Linux distributions
#
# Supports: Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+, Fedora 35+
# Version: 2024.1
# License: MIT

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# Configuration
# ============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly CSF_VERSION="${CSF_VERSION:-latest}"
readonly CSF_URL="https://download.configserver.com/csf.tgz"
readonly TMP_DIR="$(mktemp -d -t csf-install-XXXXXX)"
readonly LOG_DIR="/var/log/csf-install"
readonly INSTALL_LOG="${LOG_DIR}/install-$(date +%Y%m%d-%H%M%S).log"
readonly ERROR_LOG="${LOG_DIR}/error-$(date +%Y%m%d-%H%M%S).log"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ============================================================================
# Utility Functions
# ============================================================================

# Initialize logging
init_logging() {
    mkdir -p "$LOG_DIR"
    touch "$INSTALL_LOG" "$ERROR_LOG"
    chmod 600 "$INSTALL_LOG" "$ERROR_LOG"
}

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$INSTALL_LOG"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    log "INFO" "$*"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
    log "SUCCESS" "$*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
    log "WARN" "$*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    log "ERROR" "$*"
    echo "[$timestamp] [ERROR] $*" >> "$ERROR_LOG"
}

fatal() {
    error "$*"
    error "Installation failed. Check logs at: $LOG_DIR"
    cleanup
    exit 1
}

# Cleanup function
cleanup() {
    if [[ -d "$TMP_DIR" ]]; then
        info "Cleaning up temporary files..."
        rm -rf "$TMP_DIR"
    fi
}

# Trap for cleanup
trap cleanup EXIT
trap 'fatal "Installation interrupted by user"' INT TERM

# ============================================================================
# System Detection
# ============================================================================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    else
        fatal "Cannot detect operating system"
    fi
    
    info "Detected OS: $OS_NAME"
}

detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
        PKG_CHECK="dpkg -s"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf check-update || true"
        PKG_CHECK="rpm -q"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum check-update || true"
        PKG_CHECK="rpm -q"
    else
        fatal "No supported package manager found (apt, dnf, or yum required)"
    fi
    
    info "Package manager: $PKG_MANAGER"
}

detect_init_system() {
    if command -v systemctl &> /dev/null && systemctl --version &> /dev/null; then
        INIT_SYSTEM="systemd"
    elif [[ -f /etc/init.d/cron ]] || [[ -f /etc/init.d/crond ]]; then
        INIT_SYSTEM="sysvinit"
    else
        fatal "Cannot detect init system"
    fi
    
    info "Init system: $INIT_SYSTEM"
}

# ============================================================================
# Validation
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "This script must be run as root"
    fi
}

check_internet() {
    info "Checking internet connectivity..."
    
    if command -v curl &> /dev/null; then
        if ! curl -s --head --connect-timeout 5 https://configserver.com > /dev/null; then
            fatal "Cannot reach configserver.com. Check your internet connection."
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q --spider --timeout=5 https://configserver.com; then
            fatal "Cannot reach configserver.com. Check your internet connection."
        fi
    else
        warn "Cannot verify internet connectivity (curl/wget not found)"
    fi
}

check_conflicts() {
    info "Checking for conflicting firewalls..."
    
    local conflicts=("ufw" "firewalld")
    local found_conflicts=()
    
    for fw in "${conflicts[@]}"; do
        if command -v "$fw" &> /dev/null; then
            if systemctl is-active --quiet "$fw" 2>/dev/null; then
                found_conflicts+=("$fw")
            fi
        fi
    done
    
    if [[ ${#found_conflicts[@]} -gt 0 ]]; then
        warn "Found active firewall(s): ${found_conflicts[*]}"
        read -rp "Disable conflicting firewalls? [y/N]: " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            for fw in "${found_conflicts[@]}"; do
                info "Disabling $fw..."
                systemctl stop "$fw" || true
                systemctl disable "$fw" || true
            done
        else
            fatal "Please disable conflicting firewalls manually before installing CSF"
        fi
    fi
}

# ============================================================================
# Package Management
# ============================================================================

update_package_cache() {
    info "Updating package cache..."
    $PKG_UPDATE >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || warn "Package cache update failed"
}

install_package() {
    local package="$1"
    
    if $PKG_CHECK "$package" &> /dev/null; then
        info "Package already installed: $package"
        return 0
    fi
    
    info "Installing package: $package"
    if ! $PKG_INSTALL "$package" >> "$INSTALL_LOG" 2>> "$ERROR_LOG"; then
        error "Failed to install: $package"
        return 1
    fi
    
    success "Installed: $package"
}

get_dependencies() {
    local deps=("perl" "tar" "wget" "net-tools")
    
    case "$PKG_MANAGER" in
        apt)
            deps+=("libwww-perl" "liblwp-protocol-https-perl" "libgd-graph-perl")
            ;;
        dnf|yum)
            deps+=("perl-libwww-perl" "perl-LWP-Protocol-https" "perl-GD-Graph")
            ;;
    esac
    
    echo "${deps[@]}"
}

install_dependencies() {
    info "Installing dependencies..."
    
    local deps
    read -ra deps <<< "$(get_dependencies)"
    
    local failed=()
    for dep in "${deps[@]}"; do
        install_package "$dep" || failed+=("$dep")
    done
    
    if [[ ${#failed[@]} -gt 0 ]]; then
        error "Failed to install: ${failed[*]}"
        error "CSF may not function correctly"
        read -rp "Continue anyway? [y/N]: " response
        [[ "$response" =~ ^[Yy]$ ]] || fatal "Installation aborted"
    fi
}

# ============================================================================
# CSF Installation
# ============================================================================

download_csf() {
    info "Downloading CSF..."
    
    cd "$TMP_DIR" || fatal "Cannot access temporary directory"
    
    if command -v wget &> /dev/null; then
        wget -q --show-progress "$CSF_URL" -O csf.tgz 2>> "$ERROR_LOG" || \
            fatal "Failed to download CSF"
    elif command -v curl &> /dev/null; then
        curl -L -# "$CSF_URL" -o csf.tgz 2>> "$ERROR_LOG" || \
            fatal "Failed to download CSF"
    else
        fatal "Neither wget nor curl is available"
    fi
    
    success "CSF downloaded successfully"
}

verify_download() {
    info "Verifying download..."
    
    if [[ ! -f "$TMP_DIR/csf.tgz" ]]; then
        fatal "Downloaded file not found"
    fi
    
    local filesize
    filesize=$(stat -f%z "$TMP_DIR/csf.tgz" 2>/dev/null || stat -c%s "$TMP_DIR/csf.tgz" 2>/dev/null)
    
    if [[ $filesize -lt 100000 ]]; then
        fatal "Downloaded file appears to be corrupted (too small)"
    fi
    
    success "Download verified"
}

extract_csf() {
    info "Extracting CSF..."
    
    cd "$TMP_DIR" || fatal "Cannot access temporary directory"
    
    tar -xzf csf.tgz >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
        fatal "Failed to extract CSF archive"
    
    if [[ ! -d "$TMP_DIR/csf" ]]; then
        fatal "CSF directory not found after extraction"
    fi
    
    success "CSF extracted successfully"
}

install_csf() {
    info "Installing CSF..."
    
    cd "$TMP_DIR/csf" || fatal "Cannot access CSF directory"
    
    if [[ ! -f install.sh ]]; then
        fatal "Installation script not found"
    fi
    
    bash install.sh >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
        fatal "CSF installation failed"
    
    success "CSF installed successfully"
}

remove_conflicting_software() {
    info "Checking for conflicting software (APF/BFD)..."
    
    if [[ -f /etc/csf/remove_apf_bfd.sh ]]; then
        bash /etc/csf/remove_apf_bfd.sh >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
            warn "Failed to remove APF/BFD"
    fi
}

test_csf() {
    info "Testing CSF installation..."
    
    if [[ -f /etc/csf/csftest.pl ]]; then
        if ! perl /etc/csf/csftest.pl >> "$INSTALL_LOG" 2>> "$ERROR_LOG"; then
            error "CSF test failed"
            error "CSF may not function correctly on this system"
            cat "$ERROR_LOG"
            return 1
        fi
        success "CSF test passed"
    else
        warn "CSF test script not found"
    fi
}

configure_csf() {
    info "Configuring CSF..."
    
    # Backup original config
    if [[ -f /etc/csf/csf.conf ]]; then
        cp /etc/csf/csf.conf /etc/csf/csf.conf.original
    fi
    
    # Disable testing mode
    if [[ -f /etc/csf/csf.conf ]]; then
        sed -i 's/TESTING = "1"/TESTING = "0"/' /etc/csf/csf.conf
        info "Testing mode disabled"
    fi
}

start_csf() {
    info "Starting CSF..."
    
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl enable csf lfd >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
            warn "Failed to enable CSF services"
        systemctl start csf lfd >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
            fatal "Failed to start CSF services"
    else
        service csf start >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
            fatal "Failed to start CSF"
        service lfd start >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
            fatal "Failed to start LFD"
    fi
    
    success "CSF started successfully"
}

# ============================================================================
# Post-Installation
# ============================================================================

display_summary() {
    echo
    echo "========================================================================"
    echo "  ConfigServer Security & Firewall - Installation Complete"
    echo "========================================================================"
    echo
    echo "Configuration file: /etc/csf/csf.conf"
    echo "Log directory:      $LOG_DIR"
    echo
    echo "Useful commands:"
    echo "  csf -h              Show help"
    echo "  csf -l              List firewall rules"
    echo "  csf -a <ip>         Add IP to allow list"
    echo "  csf -d <ip>         Add IP to deny list"
    echo "  csf -r              Restart CSF"
    echo "  csf -x              Disable CSF"
    echo
    echo "Web UI (if installed):"
    echo "  https://your-server-ip:6666"
    echo
    echo "Documentation: https://docs.cpanel.net/csf/"
    echo "========================================================================"
    echo
}

prompt_ui_install() {
    if command -v webmin &> /dev/null; then
        info "Webmin detected"
        read -rp "Install CSF Web UI for Webmin? [y/N]: " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            info "Installing CSF UI for Webmin..."
            cd "$TMP_DIR/csf" || return
            bash webmin/install.sh >> "$INSTALL_LOG" 2>> "$ERROR_LOG" || \
                error "Failed to install CSF Webmin module"
        fi
    fi
}

# ============================================================================
# Main Installation Flow
# ============================================================================

main() {
    echo "========================================================================"
    echo "  ConfigServer Security & Firewall - Installation Script"
    echo "========================================================================"
    echo
    
    # Initialize
    init_logging
    
    # Pre-flight checks
    check_root
    detect_os
    detect_package_manager
    detect_init_system
    check_internet
    check_conflicts
    
    # Update system
    update_package_cache
    
    # Install dependencies
    install_dependencies
    
    # Download and install CSF
    download_csf
    verify_download
    extract_csf
    install_csf
    
    # Post-installation
    remove_conflicting_software
    test_csf
    configure_csf
    start_csf
    
    # Optional components
    prompt_ui_install
    
    # Finish
    display_summary
    
    success "Installation completed successfully!"
    exit 0
}

# ============================================================================
# Script Entry Point
# ============================================================================

main "$@"
