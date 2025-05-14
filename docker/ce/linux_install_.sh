#!/usr/bin/env bash
# install-docker-ce.sh — Install Docker CE on Debian/Ubuntu or RHEL/CentOS
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
      echo "Unknown arg: $1"
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
  else
    echo "Cannot detect OS (no /etc/os-release)" >&2
    exit 1
  fi
}

install_on_debian() {
  echo "==> Installing on Debian/Ubuntu..."
  apt-get update -qq
  DEPS=(ca-certificates curl gnupg lsb-release)
  apt-get install -y "${DEPS[@]}"

  # Add Docker’s official GPG key
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/${OS_ID}/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  # Add the repo
  echo \
    "deb [arch=$(dpkg --print-architecture) \
      signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/${OS_ID} \
      $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_on_redhat() {
  echo "==> Installing on RHEL/CentOS..."
  # Install prerequisites
  yum install -y yum-utils device-mapper-persistent-data lvm2

  # Add Docker’s official repo
  yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo

  # Install
  yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

start_and_enable() {
  echo "==> Starting and enabling Docker service..."
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
      # Sometimes ID_LIKE contains “debian” or “rhel”
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
    echo "==> Pulling image: $IMAGE"
    docker pull "$IMAGE"
  fi

  echo "✅ Docker CE installation complete!"
}

main
