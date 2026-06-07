#!/usr/bin/env bash
## install-docker-ce.sh — Docker CE install & auto-update with rich logging
set -euo pipefail

### Defaults ###
IMAGE=""
DRY_RUN=false
VERBOSE=false
DEBUG=false
LOG_FILE="/var/log/install-docker-ce.log"
NETWORK_TYPE="none"       # none | nat | transparent
NAT_SUBNET=""

### Usage ###
print_usage() {
  cat <<EOF
Usage: sudo $0 [options]

Options:
  --image IMAGE           Pull IMAGE after install (e.g. nginx:latest)
  --network-type TYPE     none (default), nat, or transparent
  --nat-subnet SUBNET     Required if --network-type=nat
  --log-file PATH         Log to PATH (default: $LOG_FILE)
  --dry-run               Show what would be done, but don’t execute
  --verbose               Print INFO and above (default)
  --debug                 Print DEBUG and above
  --help                  Show this help
EOF
  exit 1
}

### Arg parsing ###
while [ $# -gt 0 ]; do
  case "$1" in
    --image)        IMAGE="$2"; shift 2;;
    --network-type) NETWORK_TYPE="$2"; shift 2;;
    --nat-subnet)   NAT_SUBNET="$2"; shift 2;;
    --log-file)     LOG_FILE="$2"; shift 2;;
    --dry-run)      DRY_RUN=true; shift;;
    --verbose)      VERBOSE=true; shift;;
    --debug)        DEBUG=true; shift;;
    --help)         print_usage;;
    *)
      echo "Unknown argument: $1" >&2
      print_usage
      ;;
  esac
done

### Log setup ###
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  local level="$1"; shift
  local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
  case "$level" in
    ERROR) echo "$ts [ERROR] $*" >&2;;
    WARN)  echo "$ts [WARN]  $*";;
    INFO)  echo "$ts [INFO]  $*";;
    DEBUG) echo "$ts [DEBUG] $*";;
  esac
}

# Control which levels are printed
log_allowed() {
  case "$1" in
    DEBUG) [ "$DEBUG" = true ];;
    INFO)  [ "$DEBUG" = true ] || [ "$VERBOSE" = true ] || true;;
    WARN)  true;;
    ERROR) true;;
  esac
}

run_cmd() {
  local cmd="$*"
  if [ "$DRY_RUN" = true ]; then
    log_allowed INFO && log INFO "[DRY RUN] $cmd"
  else
    log_allowed INFO && log INFO "Running: $cmd"
    eval "$cmd"
  fi
}

### OS detection ###
detect_os() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID,,}"
    OS_LIKE="${ID_LIKE,,}"
    VERSION_CODENAME="${VERSION_CODENAME:-${OS_ID}}"
    log_allowed DEBUG && log DEBUG "Detected OS_ID=$OS_ID OS_LIKE=$OS_LIKE"
  else
    log_allowed ERROR && log ERROR "Cannot detect OS (no /etc/os-release)"
    exit 1
  fi
}

### Debian/Ubuntu installer ###
install_on_debian() {
  log_allowed INFO && log INFO "Installing on Debian/Ubuntu..."
  run_cmd apt-get update -qq
  run_cmd apt-get install -y ca-certificates curl gnupg lsb-release

  run_cmd install -m0755 -d /etc/apt/keyrings
  run_cmd curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
    \| gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${OS_ID} \
$(lsb_release -cs) stable
EOF

  run_cmd apt-get update -qq
  run_cmd apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  # Auto-updates
  run_cmd apt-get install -y unattended-upgrades apt-listchanges
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  if ! grep -q "Docker:${VERSION_CODENAME}" /etc/apt/apt.conf.d/50unattended-upgrades; then
    sed -i "/^Unattended-Upgrade::Allowed-Origins {/a\        \"Docker:${VERSION_CODENAME}\";" \
      /etc/apt/apt.conf.d/50unattended-upgrades
  fi

  log_allowed INFO && log INFO "Debian unattended-upgrades configured."
}

### RHEL/CentOS installer ###
install_on_redhat() {
  log_allowed INFO && log INFO "Installing on RHEL/CentOS..."
  run_cmd yum install -y yum-utils device-mapper-persistent-data lvm2
  run_cmd yum-config-manager --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
  run_cmd yum install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  log_allowed INFO && log INFO "Configuring automatic updates..."
  if command -v dnf &>/dev/null; then
    run_cmd yum install -y dnf-automatic
    sed -i 's/^#\?apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
    sed -i 's/^#\?download_updates.*/download_updates = yes/' /etc/dnf/automatic.conf
    run_cmd systemctl enable --now dnf-automatic.timer
  else
    run_cmd yum install -y yum-cron
    sed -i 's/^update_cmd =.*/update_cmd = default/' /etc/yum/yum-cron.conf
    sed -i 's/^apply_updates =.*/apply_updates = yes/' /etc/yum/yum-cron.conf
    run_cmd systemctl enable --now yum-cron
  fi
}

### Docker service startup ###
start_and_enable() {
  log_allowed INFO && log INFO "Starting & enabling Docker service..."
  run_cmd systemctl daemon-reload
  run_cmd systemctl enable --now docker
}

### Networking ###
setup_networking() {
  case "$NETWORK_TYPE" in
    transparent)
      log_allowed INFO && log INFO "Creating transparent network..."
      if ! docker network ls --format '{{.Name}}' | grep -qx Transparent; then
        run_cmd docker network create -d transparent Transparent
      else
        log_allowed INFO && log INFO "Transparent network exists."
      fi
      ;;
    nat)
      if [ -z "$NAT_SUBNET" ]; then
        log_allowed ERROR && log ERROR "--nat-subnet is required for nat mode"
        exit 1
      fi
      # NAT subnet handled via daemon.json on Debian; on RHEL you'd need custom CNI or dockerd flags.
      log_allowed INFO && log INFO "NAT subnet set to $NAT_SUBNET (ensure daemon.json manually)"
      ;;
    none) 
      log_allowed INFO && log INFO "No custom networking requested."
      ;;
    *)
      log_allowed ERROR && log ERROR "Invalid network type: $NETWORK_TYPE"
      exit 1
      ;;
  esac
}

### Main ###
main() {
  detect_os

  case "$OS_ID" in
    debian|ubuntu) install_on_debian ;;
    centos|rhel|fedora) install_on_redhat ;;
    *)
      case "$OS_LIKE" in
        *debian*) install_on_debian ;;
        *rhel*|*fedora*) install_on_redhat ;;
        *)
          log_allowed ERROR && log ERROR "Unsupported distribution: $OS_ID"
          exit 1
          ;;
      esac
      ;;
  esac

  start_and_enable
  setup_networking

  if [ -n "$IMAGE" ]; then
    log_allowed INFO && log INFO "Pulling image: $IMAGE"
    run_cmd docker pull "$IMAGE"
  fi

  log_allowed INFO && log INFO "Docker CE installation complete."
}

main
