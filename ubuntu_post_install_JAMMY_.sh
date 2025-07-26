#!/bin/bash

# ==============================================================================
#
#          Modern Ubuntu 22.04+ Server Setup Script (2025 Edition)
#
# - Updates and upgrades the system.
# - Installs and configures UFW firewall.
# - Hardens SSH for better security.
# - Sets up unattended security upgrades.
# - Installs and configures Fail2Ban.
# - Configures a secure SFTP-only group.
# - Optionally installs Docker, Portainer, and WireGuard.
#
# ==============================================================================

# --- Script Setup ---
# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u

# --- Helper Functions for Logging ---
log_info() {
    echo -e "\n\e[1;34m[INFO]\e[0m $1"
}

log_success() {
    echo -e "\e[1;32m[SUCCESS]\e[0m $1"
}

log_warn() {
    echo -e "\e[1;33m[WARNING]\e[0m $1"
}

log_error() {
    echo -e "\e[1;31m[ERROR]\e[0m $1" >&2
    exit 1
}

# --- Main Functions ---

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This script must be run with sudo or as root."
    fi
}

initial_setup() {
    log_info "Updating package lists and upgrading the system..."
    apt-get update -y
    # Perform a non-interactive upgrade to avoid prompts
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    log_success "System is up to date."

    log_info "Installing essential packages: openssh-server, unattended-upgrades, speedtest-cli..."
    apt-get install -y openssh-server unattended-upgrades speedtest-cli
    log_success "Essential packages installed."
}

configure_firewall() {
    log_info "Configuring UFW (Uncomplicated Firewall)..."
    ufw allow OpenSSH
    # Use 'ufw --force enable' to enable without a y/n prompt
    ufw --force enable
    log_success "Firewall is active and allows SSH."
}

harden_ssh() {
    log_info "Hardening SSH configuration..."
    SSH_CONFIG="/etc/ssh/sshd_config"

    # Disable root login
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    # Disable empty passwords
    sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    # Ensure PasswordAuthentication is enabled for initial setup, can be changed later
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' "$SSH_CONFIG"

    log_info "Configuring secure SFTP group..."
    # Add the sftp group if it doesn't exist
    if ! getent group sftp >/dev/null; then
        addgroup sftp
    fi

    # Use a heredoc to append the SFTP configuration block if it doesn't exist
    if ! grep -q "Match group sftp" "$SSH_CONFIG"; then
        cat <<'EOF' >> "$SSH_CONFIG"

# --- SFTP Secure Chroot Configuration ---
Match group sftp
    ChrootDirectory %h
    X11Forwarding no
    AllowTcpForwarding no
    ForceCommand internal-sftp
EOF
    fi

    log_info "Restarting SSH service to apply changes..."
    systemctl restart sshd
    log_success "SSH has been hardened."
}

setup_motd() {
    log_info "Setting up custom Message of the Day (MOTD)..."
    wget -q https://raw.githubusercontent.com/jwandrews99/Linux-Automation/master/misc/motd.sh -O /etc/update-motd.d/05-info
    chmod +x /etc/update-motd.d/05-info
    log_success "Custom MOTD installed."
}

setup_unattended_upgrades() {
    log_info "Configuring automatic security updates..."
    # Create a clean, correct configuration file for unattended upgrades
    cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    cat <<'EOF' > /etc/apt/apt.conf.d/50unattended-upgrades
// Automatically upgrade packages from these origin patterns
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    //"${distro_id}:${distro_codename}-updates";
    //"${distro_id}:${distro_codename}-proposed";
    //"${distro_id}:${distro_codename}-backports";
};

// Automatically reboot if required
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    log_success "Unattended security upgrades are configured."
}

install_fail2ban() {
    log_info "Installing and configuring Fail2Ban..."
    apt-get install -y fail2ban

    # Create a local jail configuration for SSH
    cat <<'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
# Ban hosts for 1 hour
bantime = 1h
# An IP is banned if it has generated "maxretry" during the last "findtime"
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    log_success "Fail2Ban is installed and protecting SSH."
}

prompt_yes_no() {
    while true; do
        read -p "$1 [y/N]: " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]*|"" ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

install_docker() {
    log_info "Starting Docker installation..."
    # Add Docker's official GPG key
    apt-get install -y ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    # Add the repository to Apt sources
    # Use $(lsb_release -cs) to get the codename (e.g., "jammy")
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y

    log_info "Installing Docker Engine, CLI, and Compose plugin..."
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Add the current user to the docker group
    if [ -n "${SUDO_USER-}" ]; then
        usermod -aG docker "$SUDO_USER"
        log_warn "User '$SUDO_USER' has been added to the 'docker' group."
        log_warn "You must log out and log back in for this change to take effect!"
    fi

    log_info "Installing Portainer management UI on port 9000..."
    docker volume create portainer_data
    docker run -d -p 9000:9000 --name=portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:latest

    log_success "Docker and Portainer have been installed."
    docker -v
}

install_wireguard() {
    log_info "Downloading WireGuard installation script..."
    log_warn "This will run a well-known third-party script from GitHub."
    wget https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh -O wireguard-install.sh
    chmod +x wireguard-install.sh
    
    log_info "Starting WireGuard setup process. Please follow the prompts."
    # The script will prompt the user for configuration details
    ./wireguard-install.sh
    log_success "WireGuard installation process finished."
}

final_cleanup() {
    log_info "Cleaning up unused packages..."
    apt-get autoremove -y
    apt-get clean
    log_success "System cleanup complete."
}

# --- Main Execution ---
main() {
    check_root
    initial_setup
    configure_firewall
    harden_ssh
    setup_motd
    setup_unattended_upgrades
    install_fail2ban

    echo
    if prompt_yes_no "Do you want to install Docker and Portainer?"; then
        install_docker
    else
        log_info "Skipping Docker installation."
    fi

    echo
    if prompt_yes_no "Do you want to install a WireGuard VPN server?"; then
        install_wireguard
    else
        log_info "Skipping WireGuard installation."
    fi

    final_cleanup

    echo -e "\n\e[1;32m####################################################################"
    echo -e "#                                                                  #"
    echo -e "#              🚀 Ubuntu Server Setup is Complete! 🚀              #"
    echo -e "#                                                                  #"
    echo -e "####################################################################\e[0m"
    echo
    echo "A few final notes:"
    echo "  - To test your network speed, just run: \e[1;33mspeedtest\e[0m"
    echo "  - If you installed Docker, Portainer is running at: \e[1;33mhttp://<your_server_ip>:9000\e[0m"
    echo "  - To manage WireGuard, re-run the installer: \e[1;33m./wireguard-install.sh\e[0m"
    echo "  - A system reboot is recommended to ensure all services are running correctly."
    echo
}

main
exit 0
