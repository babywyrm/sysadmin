#!/usr/bin/env bash
## (BETA) ##
# install-docker-ce.sh — Install Docker CE with automatic updates on Debian/Ubuntu or RHEL/CentOS
# Usage: sudo ./install-docker-ce.sh [--image IMAGE] [--help]
set -euo pipefail

IMAGE=""

print_usage() {
  cat <<EOF
Usage: $0 [--image IMAGE] [--help]

  --image IMAGE   After install, pull IMAGE (e.g. nginx:latest)
  --help          Show this message
EOF
  exit 1
}

# Parse args
while [ $# -gt 0 ]; do
  case "$1" in
    --image)
      shift
      [ $# -gt 0 ] || print_usage
      IMAGE=$1
      ;;
    --help)
      print_usage
      ;;
    *)
      echo "Unknown argument: $1"
      print_usage
      ;;
  esac
  shift
done

detect_os() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID,,}"
    OS_LIKE="${ID_LIKE,,}"
    # On Debian/Ubuntu, we need the codename
    VERSION_CODENAME="${VERSION_CODENAME:-${OS_ID}}"
  else
    echo "Cannot detect OS (no /etc/os-release)" >&2
    exit 1
  fi
}

install_on_debian() {
  echo "Installing on Debian/Ubuntu..."
  apt-get update -qq
  apt-get install -y ca-certificates curl gnupg lsb-release

  # Install Docker’s key and repo
  install -m0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/${OS_ID} \
    $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  # Install and configure unattended-upgrades
  apt-get install -y unattended-upgrades apt-listchanges
  # Enable periodic updates
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  # Allow Docker repo in unattended-upgrades
  if ! grep -q "Docker:${VERSION_CODENAME}" /etc/apt/apt.conf.d/50unattended-upgrades; then
    sed -i "/^Unattended-Upgrade::Allowed-Origins {/a\        \"Docker:${VERSION_CODENAME}\";" \
      /etc/apt/apt.conf.d/50unattended-upgrades
  fi
  echo "Configured unattended-upgrades (including Docker) on Debian/Ubuntu." 
}

install_on_redhat() {
  echo "Installing on RHEL/CentOS..."
  yum install -y yum-utils device-mapper-persistent-data lvm2

  yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo

  yum install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  echo "Configuring automatic updates on RHEL/CentOS..."
  if command -v dnf >/dev/null; then
    # RHEL 8+ / Fedora
    yum install -y dnf-automatic
    # Ensure it applies updates automatically
    sed -i 's/^#\?apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
    sed -i 's/^#\?download_updates.*/download_updates = yes/' /etc/dnf/automatic.conf
    systemctl enable --now dnf-automatic.timer
    echo "Enabled dnf-automatic.timer"
  else
    # RHEL 7
    yum install -y yum-cron
    sed -i 's/^update_cmd =.*/update_cmd = default/' /etc/yum/yum-cron.conf
    sed -i 's/^apply_updates =.*/apply_updates = yes/' /etc/yum/yum-cron.conf
    systemctl enable --now yum-cron
    echo "Enabled yum-cron service"
  fi
}

start_and_enable() {
  echo "Starting and enabling Docker service..."
  systemctl daemon-reload
  systemctl enable --now docker
  docker version >/dev/null 2>&1
}

main() {
  detect_os

  case "$OS_ID" in
    debian|ubuntu)
      install_on_debian
      ;;
    centos|rhel|fedora)
      install_on_redhat
      ;;
    *)
      case "$OS_LIKE" in
        *debian*)
          install_on_debian
          ;;
        *rhel*|*fedora*)
          install_on_redhat
          ;;
        *)
          echo "Unsupported distribution: $OS_ID" >&2
          exit 1
          ;;
      esac
      ;;
  esac

  start_and_enable

  if [ -n "$IMAGE" ]; then
    echo "Pulling image: $IMAGE"
    docker pull "$IMAGE"
  fi

  echo "Docker CE installation complete."
}

main
