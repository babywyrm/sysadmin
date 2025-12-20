#!/usr/bin/env bash
# install-ptk.sh - Perl Toolkit Cross-Platform Installer
# Version: 1.0.0
# Compatible with: macOS (10.13+), Linux (Ubuntu, Debian, Fedora, CentOS, Arch) ..probably..
# License: MIT

set -e

#############################################################################
# CONFIGURATION
#############################################################################

VERSION="1.0.0"
SCRIPT_NAME="ptk"
REQUIRED_PERL_VERSION="5.32.0"
DEFAULT_INSTALL_DIR="${HOME}/.local/bin"
REQUIRED_MODULES=(
    "List::Util"
    "Time::Piece"
    "JSON::PP"
    "Getopt::Long"
    "Pod::Usage"
)

# Global variables
OS_TYPE=""
DISTRO=""
PACKAGE_MANAGER=""
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
DRY_RUN=false
FORCE=false
UNINSTALL=false
QUIET=false
YES=false
SKIP_MODULES=false
SKIP_PATH_CHECK=false

#############################################################################
# COLORS AND FORMATTING
#############################################################################

setup_colors() {
    if [[ -t 1 ]] && command -v tput &>/dev/null; then
        RED=$(tput setaf 1 2>/dev/null || echo '')
        GREEN=$(tput setaf 2 2>/dev/null || echo '')
        YELLOW=$(tput setaf 3 2>/dev/null || echo '')
        BLUE=$(tput setaf 4 2>/dev/null || echo '')
        MAGENTA=$(tput setaf 5 2>/dev/null || echo '')
        CYAN=$(tput setaf 6 2>/dev/null || echo '')
        BOLD=$(tput bold 2>/dev/null || echo '')
        RESET=$(tput sgr0 2>/dev/null || echo '')
    else
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        MAGENTA=''
        CYAN=''
        BOLD=''
        RESET=''
    fi
}

#############################################################################
# OUTPUT FUNCTIONS
#############################################################################

print_header() {
    echo -e "${BOLD}${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         Perl Toolkit (ptk) Installer v${VERSION}          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

print_success() {
    [[ "$QUIET" == "true" ]] && return
    echo -e "${GREEN}✓${RESET} $1"
}

print_error() {
    echo -e "${RED}✗${RESET} $1" >&2
}

print_warning() {
    [[ "$QUIET" == "true" ]] && return
    echo -e "${YELLOW}⚠${RESET} $1"
}

print_info() {
    [[ "$QUIET" == "true" ]] && return
    echo -e "${CYAN}ℹ${RESET} $1"
}

print_step() {
    [[ "$QUIET" == "true" ]] && return
    echo -e "${BOLD}${MAGENTA}➜${RESET} $1"
}

#############################################################################
# HELP AND VERSION
#############################################################################

show_help() {
    cat << EOF
${BOLD}USAGE${RESET}
    $0 [OPTIONS]

${BOLD}DESCRIPTION${RESET}
    Install Perl Toolkit (ptk) - A comprehensive CLI toolkit for text
    processing and data manipulation.
    
    Supports: macOS (10.13+), Linux (Ubuntu, Debian, Fedora, CentOS, Arch)

${BOLD}OPTIONS${RESET}
    -h, --help              Show this help message
    -v, --version           Show version information
    -d, --dir DIR           Installation directory (default: ~/.local/bin)
    -n, --dry-run           Show what would be done without doing it
    -f, --force             Force installation even if already exists
    -u, --uninstall         Uninstall ptk
    -q, --quiet             Quiet mode (minimal output)
    -y, --yes               Skip confirmation prompts
    --no-modules            Skip Perl module installation
    --no-path-check         Skip PATH verification
    --system                Install system-wide (requires sudo)

${BOLD}EXAMPLES${RESET}
    # Standard installation
    $0

    # Install to custom directory
    $0 --dir ~/bin

    # System-wide installation (Linux/macOS)
    sudo $0 --system --dir /usr/local/bin

    # Dry run to see what would happen
    $0 --dry-run

    # Uninstall ptk
    $0 --uninstall

    # Force reinstall with auto-yes
    $0 --force --yes

${BOLD}REQUIREMENTS${RESET}
    - Perl v${REQUIRED_PERL_VERSION} or higher
    - Write access to installation directory
    - Internet connection (for module installation)

${BOLD}PLATFORM NOTES${RESET}
    macOS:
      - Xcode Command Line Tools recommended
      - Homebrew optional but helpful
      - Works with system Perl or Homebrew Perl
    
    Linux:
      - Standard build tools (gcc, make)
      - Root access for system-wide install
      - Package manager access for dependencies

${BOLD}TROUBLESHOOTING${RESET}
    If installation fails:
      1. Check Perl version: perl -v
      2. Try manual module install: cpan List::Util
      3. Check permissions: ls -la ~/.local/bin
      4. View logs with: $0 --dry-run

${BOLD}MORE INFO${RESET}
    GitHub:  https://github.com/yourusername/perl-toolkit
    Issues:  https://github.com/yourusername/perl-toolkit/issues
    Docs:    https://github.com/yourusername/perl-toolkit/wiki
EOF
}

show_version() {
    echo "Perl Toolkit Installer v${VERSION}"
    echo "Platform: $(detect_os)"
}

#############################################################################
# PLATFORM DETECTION
#############################################################################

detect_os() {
    case "$(uname -s)" in
        Darwin*)
            echo "macOS"
            OS_TYPE="macos"
            detect_macos_version
            ;;
        Linux*)
            echo "Linux"
            OS_TYPE="linux"
            detect_linux_distro
            ;;
        CYGWIN*|MINGW*|MSYS*)
            echo "Windows"
            OS_TYPE="windows"
            print_error "Windows is not fully supported. Use WSL instead."
            exit 1
            ;;
        *)
            echo "Unknown"
            OS_TYPE="unknown"
            print_error "Unsupported operating system"
            exit 1
            ;;
    esac
}

detect_macos_version() {
    if command -v sw_vers &>/dev/null; then
        local version=$(sw_vers -productVersion)
        DISTRO="macOS ${version}"
        print_info "Detected: macOS ${version}"
        
        # Check for Xcode Command Line Tools
        if ! xcode-select -p &>/dev/null; then
            print_warning "Xcode Command Line Tools not found"
            print_info "Install with: xcode-select --install"
        fi
        
        # Check for Homebrew
        if command -v brew &>/dev/null; then
            print_info "Homebrew detected"
            PACKAGE_MANAGER="brew"
        else
            print_info "Homebrew not found (optional)"
        fi
    fi
}

detect_linux_distro() {
    # Try various methods to detect distro
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="$NAME"
        print_info "Detected: $DISTRO"
        
        case "$ID" in
            ubuntu|debian)
                PACKAGE_MANAGER="apt"
                ;;
            fedora|rhel|centos)
                PACKAGE_MANAGER="dnf"
                [[ ! -x "$(command -v dnf)" ]] && PACKAGE_MANAGER="yum"
                ;;
            arch|manjaro)
                PACKAGE_MANAGER="pacman"
                ;;
            *)
                PACKAGE_MANAGER="unknown"
                ;;
        esac
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO=$(cat /etc/redhat-release)
        PACKAGE_MANAGER="yum"
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="Debian $(cat /etc/debian_version)"
        PACKAGE_MANAGER="apt"
    else
        DISTRO="Unknown Linux"
        PACKAGE_MANAGER="unknown"
    fi
    
    print_info "Package manager: $PACKAGE_MANAGER"
}

#############################################################################
# UTILITY FUNCTIONS
#############################################################################

check_command() {
    command -v "$1" &>/dev/null
}

version_compare() {
    # Compare two version strings
    # Returns: 0 if equal, 1 if $1 > $2, 2 if $1 < $2
    local ver1="$1"
    local ver2="$2"
    
    # Remove 'v' prefix if present
    ver1="${ver1#v}"
    ver2="${ver2#v}"
    
    if [[ "$ver1" == "$ver2" ]]; then
        return 0
    fi
    
    # Use sort -V if available (GNU), otherwise use custom comparison
    if sort --version-sort /dev/null &>/dev/null 2>&1; then
        local sorted=$(printf '%s\n%s' "$ver1" "$ver2" | sort -V | head -n1)
        if [[ "$sorted" == "$ver2" ]]; then
            return 1
        else
            return 2
        fi
    else
        # macOS/BSD fallback - manual comparison
        local IFS=.
        local i ver1_arr=($ver1) ver2_arr=($ver2)
        
        for ((i=0; i<${#ver1_arr[@]} || i<${#ver2_arr[@]}; i++)); do
            local v1=${ver1_arr[i]:-0}
            local v2=${ver2_arr[i]:-0}
            
            if ((v1 > v2)); then
                return 1
            elif ((v1 < v2)); then
                return 2
            fi
        done
        
        return 0
    fi
}

#############################################################################
# PERL CHECKS
#############################################################################

check_perl() {
    print_step "Checking Perl installation..."
    
    if ! check_command perl; then
        print_error "Perl not found. Please install Perl first."
        echo ""
        show_perl_install_instructions
        return 1
    fi
    
    local perl_version
    perl_version=$(perl -e 'print $^V' | sed 's/v//' 2>/dev/null || perl -e 'print $]')
    
    version_compare "$perl_version" "$REQUIRED_PERL_VERSION"
    local result=$?
    
    if [[ $result -eq 2 ]]; then
        print_error "Perl version ${REQUIRED_PERL_VERSION} or higher required"
        print_info "Found: v${perl_version}"
        echo ""
        show_perl_install_instructions
        return 1
    fi
    
    print_success "Perl v${perl_version} found"
    
    # Check which perl is being used
    local perl_path=$(which perl)
    print_info "Using: $perl_path"
    
    return 0
}

show_perl_install_instructions() {
    case "$OS_TYPE" in
        macos)
            echo "  ${BOLD}macOS Installation Options:${RESET}"
            echo ""
            echo "  1. System Perl (already installed, but may be outdated):"
            echo "     /usr/bin/perl"
            echo ""
            echo "  2. Homebrew (recommended):"
            echo "     brew install perl"
            echo ""
            echo "  3. Perlbrew (for multiple versions):"
            echo "     curl -L https://install.perlbrew.pl | bash"
            echo "     perlbrew install perl-5.38.0"
            ;;
        linux)
            echo "  ${BOLD}Linux Installation Options:${RESET}"
            echo ""
            case "$PACKAGE_MANAGER" in
                apt)
                    echo "  Ubuntu/Debian:"
                    echo "     sudo apt-get update"
                    echo "     sudo apt-get install perl"
                    ;;
                dnf|yum)
                    echo "  Fedora/RHEL/CentOS:"
                    echo "     sudo ${PACKAGE_MANAGER} install perl"
                    ;;
                pacman)
                    echo "  Arch Linux:"
                    echo "     sudo pacman -S perl"
                    ;;
                *)
                    echo "  Use your distribution's package manager to install perl"
                    ;;
            esac
            echo ""
            echo "  Or use Perlbrew:"
            echo "     curl -L https://install.perlbrew.pl | bash"
            ;;
    esac
}

#############################################################################
# MODULE CHECKS
#############################################################################

check_module() {
    local module="$1"
    perl -M"${module}" -e 'exit 0' 2>/dev/null
}

check_modules() {
    [[ "$SKIP_MODULES" == "true" ]] && return 0
    
    print_step "Checking Perl modules..."
    
    local missing_modules=()
    
    for module in "${REQUIRED_MODULES[@]}"; do
        if check_module "$module"; then
            [[ "$QUIET" != "true" ]] && print_success "$module installed"
        else
            missing_modules+=("$module")
            [[ "$QUIET" != "true" ]] && print_warning "$module not found"
        fi
    done
    
    if [[ ${#missing_modules[@]} -gt 0 ]]; then
        echo ""
        print_info "Missing modules: ${missing_modules[*]}"
        return 1
    fi
    
    print_success "All required modules installed"
    return 0
}

install_modules() {
    [[ "$SKIP_MODULES" == "true" ]] && return 0
    
    print_step "Installing Perl modules..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "Would install: ${REQUIRED_MODULES[*]}"
        return 0
    fi
    
    # Determine which CPAN client to use
    local cpan_cmd=""
    local cpan_args=""
    
    if check_command cpanm; then
        cpan_cmd="cpanm"
        cpan_args="--quiet --notest"
        print_info "Using cpanminus"
    elif check_command cpan; then
        cpan_cmd="cpan"
        cpan_args=""
        print_info "Using cpan"
    else
        print_warning "No CPAN client found. Installing cpanminus..."
        install_cpanminus || return 1
        cpan_cmd="cpanm"
        cpan_args="--quiet --notest"
    fi
    
    # Install missing modules
    local failed_modules=()
    
    for module in "${REQUIRED_MODULES[@]}"; do
        if ! check_module "$module"; then
            print_info "Installing $module..."
            
            if $cpan_cmd $cpan_args "$module" &>/dev/null; then
                print_success "$module installed"
            else
                print_error "Failed to install $module"
                failed_modules+=("$module")
            fi
        fi
    done
    
    if [[ ${#failed_modules[@]} -gt 0 ]]; then
        print_error "Failed to install: ${failed_modules[*]}"
        echo ""
        print_info "Try manual installation:"
        for module in "${failed_modules[@]}"; do
            echo "  cpan $module"
        done
        return 1
    fi
    
    print_success "All modules installed"
    return 0
}

install_cpanminus() {
    print_info "Installing cpanminus..."
    
    if curl -L https://cpanmin.us 2>/dev/null | perl - --sudo App::cpanminus 2>/dev/null; then
        print_success "cpanminus installed"
        return 0
    elif wget -qO- https://cpanmin.us 2>/dev/null | perl - --sudo App::cpanminus 2>/dev/null; then
        print_success "cpanminus installed"
        return 0
    else
        print_error "Failed to install cpanminus"
        print_info "Install manually from: https://cpanmin.us"
        return 1
    fi
}

#############################################################################
# INSTALLATION FUNCTIONS
#############################################################################

check_ptk_script() {
    if [[ ! -f "$SCRIPT_NAME" ]]; then
        print_error "ptk script not found in current directory"
        print_info "Download from: https://github.com/yourusername/perl-toolkit"
        return 1
    fi
    
    if ! perl -c "$SCRIPT_NAME" &>/dev/null; then
        print_error "ptk script has syntax errors"
        perl -c "$SCRIPT_NAME"
        return 1
    fi
    
    print_success "ptk script validated"
    return 0
}

create_install_dir() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            print_info "Would create directory: $INSTALL_DIR"
            return 0
        fi
        
        print_info "Creating installation directory: $INSTALL_DIR"
        if mkdir -p "$INSTALL_DIR" 2>/dev/null; then
            print_success "Directory created"
        else
            print_error "Failed to create directory: $INSTALL_DIR"
            print_info "Try with sudo or choose a different directory"
            return 1
        fi
    else
        print_success "Installation directory exists: $INSTALL_DIR"
    fi
    return 0
}

install_ptk() {
    local dest="${INSTALL_DIR}/${SCRIPT_NAME}"
    
    if [[ -f "$dest" ]] && [[ "$FORCE" != "true" ]]; then
        print_warning "ptk already installed at: $dest"
        
        if [[ "$YES" != "true" ]]; then
            read -p "Overwrite? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_info "Installation cancelled"
                return 1
            fi
        fi
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "Would copy ptk to: $dest"
        print_info "Would set permissions: chmod +x"
        return 0
    fi
    
    print_step "Installing ptk..."
    
    if cp "$SCRIPT_NAME" "$dest" 2>/dev/null; then
        print_success "Copied to $dest"
    else
        print_error "Failed to copy ptk"
        print_info "Check write permissions for: $INSTALL_DIR"
        return 1
    fi
    
    if chmod +x "$dest" 2>/dev/null; then
        print_success "Set executable permissions"
    else
        print_error "Failed to set permissions"
        return 1
    fi
    
    return 0
}

check_path() {
    [[ "$SKIP_PATH_CHECK" == "true" ]] && return 0
    
    print_step "Checking PATH configuration..."
    
    if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
        print_success "$INSTALL_DIR is in PATH"
        return 0
    fi
    
    print_warning "$INSTALL_DIR is not in your PATH"
    echo ""
    print_info "To use ptk from anywhere, add it to your PATH:"
    echo ""
    
    # Detect shell and provide specific instructions
    local shell_config=""
    local current_shell=$(basename "$SHELL")
    
    case "$current_shell" in
        bash)
            if [[ "$OS_TYPE" == "macos" ]]; then
                shell_config="~/.bash_profile"
            else
                shell_config="~/.bashrc"
            fi
            ;;
        zsh)
            shell_config="~/.zshrc"
            ;;
        fish)
            shell_config="~/.config/fish/config.fish"
            echo "  ${BOLD}set -gx PATH ${INSTALL_DIR} \$PATH${RESET}"
            echo ""
            echo "  Add to: ${BOLD}$shell_config${RESET}"
            echo ""
            return 1
            ;;
        *)
            shell_config="your shell's config file"
            ;;
    esac
    
    echo "  ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${RESET}"
    echo ""
    echo "  Add to: ${BOLD}$shell_config${RESET}"
    echo ""
    echo "  Then run: ${BOLD}source $shell_config${RESET}"
    echo ""
    
    return 1
}

verify_installation() {
    print_step "Verifying installation..."
    
    local ptk_path="${INSTALL_DIR}/${SCRIPT_NAME}"
    
    if [[ ! -f "$ptk_path" ]]; then
        print_error "ptk not found at: $ptk_path"
        return 1
    fi
    
    if [[ ! -x "$ptk_path" ]]; then
        print_error "ptk is not executable"
        return 1
    fi
    
    # Try to run ptk version
    if "$ptk_path" version &>/dev/null; then
        print_success "Installation verified"
        local version_output=$("$ptk_path" version 2>/dev/null)
        print_info "$version_output"
        return 0
    else
        print_warning "ptk installed but may have issues"
        print_info "Try running: $ptk_path help"
        return 1
    fi
}

#############################################################################
# UNINSTALL FUNCTION
#############################################################################

uninstall_ptk() {
    print_step "Uninstalling ptk..."
    
    local ptk_path="${INSTALL_DIR}/${SCRIPT_NAME}"
    
    if [[ ! -f "$ptk_path" ]]; then
        print_error "ptk not found at: $ptk_path"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "Would remove: $ptk_path"
        return 0
    fi
    
    if [[ "$YES" != "true" ]]; then
        read -p "Remove $ptk_path? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Uninstall cancelled"
            return 1
        fi
    fi
    
    if rm "$ptk_path" 2>/dev/null; then
        print_success "Removed: $ptk_path"
        echo ""
        print_info "ptk has been uninstalled"
        print_info "Perl modules were not removed (they may be used by other scripts)"
        return 0
    else
        print_error "Failed to remove: $ptk_path"
        return 1
    fi
}

#############################################################################
# ARGUMENT PARSING
#############################################################################

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -n|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -u|--uninstall)
                UNINSTALL=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -y|--yes)
                YES=true
                shift
                ;;
            --no-modules)
                SKIP_MODULES=true
                shift
                ;;
            --no-path-check)
                SKIP_PATH_CHECK=true
                shift
                ;;
            --system)
                INSTALL_DIR="/usr/local/bin"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Run '$0 --help' for usage information"
                exit 1
                ;;
        esac
    done
}

#############################################################################
# MAIN INSTALLATION FLOW
#############################################################################

main() {
    # Setup
    setup_colors
    parse_arguments "$@"
    
    # Show header
    [[ "$QUIET" != "true" ]] && print_header
    
    # Detect platform
    detect_os
    echo ""
    
    # Handle uninstall
    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall_ptk
        exit $?
    fi
    
    # Pre-flight checks
    check_perl || exit 1
    echo ""
    
    if ! check_modules; then
        echo ""
        if [[ "$YES" == "true" ]] || [[ "$SKIP_MODULES" == "true" ]]; then
            install_modules || exit 1
        else
            read -p "Install missing modules? (Y/n) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
                install_modules || exit 1
            else
                print_error "Required modules not installed. Exiting."
                exit 1
            fi
        fi
        echo ""
    else
        echo ""
    fi
    
    # Check for ptk script
    check_ptk_script || exit 1
    echo ""
    
    # Create installation directory
    create_install_dir || exit 1
    echo ""
    
    # Install ptk
    install_ptk || exit 1
    echo ""
    
    # Verify installation
    verify_installation
    echo ""
    
    # Check PATH
    check_path
    path_in_path=$?
    echo ""
    
    # Final message
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "Dry run complete. No changes were made."
    else
        echo -e "${BOLD}${GREEN}Installation complete!${RESET}"
        echo ""
        if [[ $path_in_path -ne 0 ]]; then
            print_info "Remember to add $INSTALL_DIR to your PATH"
            echo ""
        fi
        print_info "Run '${BOLD}ptk help${RESET}' to get started"
        echo ""
        print_info "Documentation: https://github.com/yourusername/perl-toolkit"
    fi
}

# Run main function
main "$@"
