#!/usr/bin/env bash
set -euo pipefail

#
# Firecracker Development Environment Setup for Ubuntu
# -----------------------------------------------------
# Supports Ubuntu 18.04, 20.04, 22.04, and 24.04
#

echo "==============================================================="
echo "Setting up Firecracker development environment on Ubuntu"
echo "==============================================================="

#--- Detect OS --------------------------------------------------------------
if ! grep -qi ubuntu /etc/os-release; then
    echo "This script is intended for Ubuntu systems only."
    exit 1
fi

UBUNTU_VERSION=$(lsb_release -rs)
echo "Detected Ubuntu $UBUNTU_VERSION"

#--- Check for CPU virtualization support -----------------------------------
echo "Checking for CPU virtualization support..."
if ! grep -E -c '(vmx|svm)' /proc/cpuinfo >/dev/null; then
    echo "Your CPU or VM does not support hardware virtualization (KVM)."
    echo "If you're inside a VM, enable nested virtualization."
    exit 1
else
    echo "Virtualization extensions detected."
fi

#--- Install dependencies ---------------------------------------------------
echo "Installing dependencies..."
sudo apt-get update -y
sudo apt-get install -y \
    build-essential cmake curl git jq wget unzip \
    libssl-dev pkg-config python3 python3-pip python3-venv \
    linux-headers-$(uname -r) qemu-kvm virt-manager libvirt-daemon-system \
    bridge-utils cpu-checker net-tools acl iptables iproute2 dnsmasq-base

#--- Verify KVM -------------------------------------------------------------
echo "Checking /dev/kvm..."
if [ ! -e /dev/kvm ]; then
    echo "/dev/kvm not found. Ensure virtualization is enabled in BIOS."
    exit 1
else
    echo "/dev/kvm present."
fi

#--- Permissions ------------------------------------------------------------
echo "Setting permissions for current user..."
sudo setfacl -m u:${USER}:rw /dev/kvm || true

if groups $USER | grep -qw kvm; then
    echo "User already in 'kvm' group."
else
    sudo usermod -aG kvm $USER
    echo "Added user to 'kvm' group (log out and back in to apply)."
fi

#--- Install Rust toolchain -------------------------------------------------
read -p "Install Rust (required for building Firecracker)? [Y/n] " RESP
if [[ "$RESP" =~ ^[Yy]?$ ]]; then
    echo "Installing Rust toolchain..."
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
    rustup default stable
    rustup component add rustfmt clippy
    echo "Rust $(rustc --version) installed."
fi

#--- Clone Firecracker repo -------------------------------------------------
read -p "Clone Firecracker repository to ~/firecracker? [Y/n] " RESP2
if [[ "$RESP2" =~ ^[Yy]?$ ]]; then
    cd ~
    if [ ! -d firecracker ]; then
        git clone https://github.com/firecracker-microvm/firecracker.git
    fi
    cd firecracker
    echo "Firecracker repository ready at $(pwd)"
fi

#--- Final summary ----------------------------------------------------------
echo
echo "==============================================================="
echo "Firecracker setup complete."
echo "---------------------------------------------------------------"
echo "Next steps:"
echo "  kvm-ok                     # Verify KVM acceleration"
echo "  cd ~/firecracker           # Navigate to repo"
echo "  tools/devtool build        # Build Firecracker binaries"
echo "---------------------------------------------------------------"
echo "Full documentation:"
echo "  https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md"
echo "==============================================================="
