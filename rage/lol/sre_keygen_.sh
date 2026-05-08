#!/usr/bin/env bash
set -Eeuo pipefail

###############################################
# rotate-and-seal-ssh-keys.sh    ..better..
#
# Generates fresh Ed25519 SSH keys for:
#   1. serviceuser
#   2. root/admin failsafe
#
# Encrypts/seals private keys with age/rage.
# Stores the admin sealed key in a Kubernetes Secret.
#
# Requirements:
#   - bash
#   - ssh-keygen
#   - rage
#   - kubectl
#   - install
#   - stat
#
# Notes:
#   - The recipient must be an age public recipient, for example:
#       age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#   - Do not pass a private identity key to rage encryption with -i.
###############################################

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

ORIGINAL_KEY="${ORIGINAL_KEY:-/srv/secure/identity/id_ed25519}"
ORIGINAL_KEY_PUB="${ORIGINAL_KEY_PUB:-${ORIGINAL_KEY}.pub}"
AGE_RECIPIENT_FILE="${AGE_RECIPIENT_FILE:-/srv/secure/identity/age-recipient.txt}"

SERVICE_USER="${SERVICE_USER:-serviceuser}"
ADMIN_USER="${ADMIN_USER:-root}"

SERVICE_HOME="${SERVICE_HOME:-/home/$SERVICE_USER}"
SERVICE_SSH_DIR="$SERVICE_HOME/.ssh"
SERVICE_NEW_PRIV="$SERVICE_SSH_DIR/id_ed25519"
SERVICE_NEW_PUB="$SERVICE_SSH_DIR/id_ed25519.pub"
SERVICE_OBFUSCATED="/srv/secure/obfuscated/id_ed25519_${SERVICE_USER}.age"

ADMIN_HOME="${ADMIN_HOME:-/root}"
ADMIN_SSH_DIR="$ADMIN_HOME/.ssh"
ADMIN_NEW_PRIV="$ADMIN_SSH_DIR/id_ed25519"
ADMIN_NEW_PUB="$ADMIN_SSH_DIR/id_ed25519.pub"
ADMIN_OBFUSCATED="/srv/secure/obfuscated/id_ed25519_${ADMIN_USER}.age"

OBFUSCATED_DIR="${OBFUSCATED_DIR:-/srv/secure/obfuscated}"

SECRET_NAME="${SECRET_NAME:-admin-failsafe}"
SECRET_NAMESPACE="${SECRET_NAMESPACE:-infra}"
SECRET_KEY_NAME="${SECRET_KEY_NAME:-id_ed25519_root.age}"

DRY_RUN=false
VERBOSE=false
BACKUP=false
ROLLBACK=false
FORCE=false
NO_K8S=false

BACKUP_DIR=""

usage() {
  cat <<EOF
Usage:
  $0 [options]

Options:
  --dry-run       Print actions without changing files or Kubernetes resources
  --verbose       Print commands before executing them
  --backup        Back up existing key files before replacing them
  --rollback      Roll back changed files on error, if backups exist
  --force         Do not prompt before replacing existing key material
  --no-k8s        Generate and seal keys, but do not update Kubernetes Secret
  -h, --help      Show this help

Environment overrides:
  KUBECONFIG
  ORIGINAL_KEY
  ORIGINAL_KEY_PUB
  AGE_RECIPIENT_FILE
  SERVICE_USER
  SERVICE_HOME
  ADMIN_USER
  ADMIN_HOME
  SECRET_NAME
  SECRET_NAMESPACE
  SECRET_KEY_NAME

Expected recipient file:
  \$AGE_RECIPIENT_FILE should contain one age recipient, for example:
    age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      ;;
    --verbose)
      VERBOSE=true
      ;;
    --backup)
      BACKUP=true
      ;;
    --rollback)
      ROLLBACK=true
      ;;
    --force)
      FORCE=true
      ;;
    --no-k8s)
      NO_K8S=true
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

log() {
  printf '[*] %s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

die() {
  printf '[x] %s\n' "$*" >&2
  exit 1
}

run() {
  if "$VERBOSE" || "$DRY_RUN"; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  fi

  if ! "$DRY_RUN"; then
    "$@"
  fi
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "This script must be run as root."
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

confirm_or_die() {
  if "$FORCE" || "$DRY_RUN"; then
    return 0
  fi

  cat <<EOF
This will replace SSH key material for:

  $SERVICE_USER:
    $SERVICE_NEW_PRIV
    $SERVICE_NEW_PUB
    $SERVICE_SSH_DIR/authorized_keys

  $ADMIN_USER:
    $ADMIN_NEW_PRIV
    $ADMIN_NEW_PUB
    $ADMIN_SSH_DIR/authorized_keys

And update Kubernetes Secret:

  namespace: $SECRET_NAMESPACE
  secret:    $SECRET_NAME

EOF

  read -r -p "Continue? Type 'rotate' to proceed: " answer
  [[ "$answer" == "rotate" ]] || die "Aborted."
}

init_backup_dir() {
  if "$BACKUP" || "$ROLLBACK"; then
    BACKUP_DIR="/srv/secure/backups/key-rotation-$(date -u +%Y%m%dT%H%M%SZ)"
    run install -d -m 0700 "$BACKUP_DIR"
    log "Backup directory: $BACKUP_DIR"
  fi
}

backup_file() {
  local file="$1"

  if [[ -f "$file" ]]; then
    local safe_name
    safe_name="$(printf '%s' "$file" | sed 's#^/##; s#/#__#g')"

    log "Backing up $file"
    run cp -a "$file" "$BACKUP_DIR/$safe_name"
  fi
}

restore_file() {
  local file="$1"
  local safe_name
  safe_name="$(printf '%s' "$file" | sed 's#^/##; s#/#__#g')"

  if [[ -f "$BACKUP_DIR/$safe_name" ]]; then
    log "Restoring $file"
    run cp -a "$BACKUP_DIR/$safe_name" "$file"
  fi
}

rollback_keys() {
  warn "Error encountered."

  if ! "$ROLLBACK"; then
    warn "Rollback disabled. Existing backups, if any, are in: ${BACKUP_DIR:-none}"
    return
  fi

  if [[ -z "$BACKUP_DIR" || ! -d "$BACKUP_DIR" ]]; then
    warn "Rollback requested, but no backup directory exists."
    return
  fi

  warn "Rolling back key files from $BACKUP_DIR"

  restore_file "$SERVICE_NEW_PRIV"
  restore_file "$SERVICE_NEW_PUB"
  restore_file "$SERVICE_SSH_DIR/authorized_keys"
  restore_file "$SERVICE_OBFUSCATED"

  restore_file "$ADMIN_NEW_PRIV"
  restore_file "$ADMIN_NEW_PUB"
  restore_file "$ADMIN_SSH_DIR/authorized_keys"
  restore_file "$ADMIN_OBFUSCATED"
}

trap rollback_keys ERR

validate_inputs() {
  require_root

  require_cmd ssh-keygen
  require_cmd rage
  require_cmd kubectl
  require_cmd install
  require_cmd sed
  require_cmd awk

  id "$SERVICE_USER" >/dev/null 2>&1 ||
    die "Service user does not exist: $SERVICE_USER"

  [[ -d "$SERVICE_HOME" ]] ||
    die "Service home does not exist: $SERVICE_HOME"

  [[ -f "$ORIGINAL_KEY" ]] ||
    warn "ORIGINAL_KEY exists check failed. Not used directly for encryption: $ORIGINAL_KEY"

  [[ -f "$AGE_RECIPIENT_FILE" ]] ||
    die "Missing age recipient file: $AGE_RECIPIENT_FILE"

  local recipient
  recipient="$(awk 'NF && $1 !~ /^#/ { print $1; exit }' "$AGE_RECIPIENT_FILE")"

  [[ "$recipient" == age1* ]] ||
    die "Recipient file does not appear to contain an age recipient: $AGE_RECIPIENT_FILE"

  if ! "$NO_K8S"; then
    [[ -f "$KUBECONFIG" ]] || die "KUBECONFIG not found: $KUBECONFIG"

    kubectl get namespace "$SECRET_NAMESPACE" >/dev/null 2>&1 ||
      die "Kubernetes namespace does not exist: $SECRET_NAMESPACE"
  fi
}

prepare_dirs() {
  log "Preparing directories"

  run install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$SERVICE_SSH_DIR"
  run install -d -m 0700 -o root -g root "$ADMIN_SSH_DIR"
  run install -d -m 0700 -o root -g root "$OBFUSCATED_DIR"
}

backup_existing_files() {
  if ! "$BACKUP" && ! "$ROLLBACK"; then
    return 0
  fi

  backup_file "$SERVICE_NEW_PRIV"
  backup_file "$SERVICE_NEW_PUB"
  backup_file "$SERVICE_SSH_DIR/authorized_keys"
  backup_file "$SERVICE_OBFUSCATED"

  backup_file "$ADMIN_NEW_PRIV"
  backup_file "$ADMIN_NEW_PUB"
  backup_file "$ADMIN_SSH_DIR/authorized_keys"
  backup_file "$ADMIN_OBFUSCATED"
}

generate_keypair() {
  local owner_user="$1"
  local owner_group="$2"
  local priv_path="$3"
  local pub_path="$4"
  local ssh_dir="$5"

  log "Generating SSH keypair: $priv_path"

  run rm -f "$priv_path" "$pub_path"
  run ssh-keygen -t ed25519 -f "$priv_path" -N "" -q \
    -C "$owner_user@$(hostname -f 2>/dev/null || hostname)-$(date -u +%Y%m%dT%H%M%SZ)"

  if ! "$DRY_RUN"; then
    [[ -f "$priv_path" ]] || die "Failed to generate private key: $priv_path"
    [[ -f "$pub_path" ]] || die "Failed to generate public key: $pub_path"
  fi

  run chmod 0600 "$priv_path"
  run chmod 0644 "$pub_path"
  run chown "$owner_user:$owner_group" "$priv_path" "$pub_path"

  install_authorized_key "$owner_user" "$owner_group" "$pub_path" "$ssh_dir"
}

install_authorized_key() {
  local owner_user="$1"
  local owner_group="$2"
  local pub_path="$3"
  local ssh_dir="$4"
  local authorized_keys="$ssh_dir/authorized_keys"

  log "Installing authorized_keys: $authorized_keys"

  run cp "$pub_path" "$authorized_keys"
  run chmod 0600 "$authorized_keys"
  run chown "$owner_user:$owner_group" "$authorized_keys"
}

seal_private_key() {
  local priv_path="$1"
  local output_path="$2"

  log "Encrypting private key with age recipient file: $output_path"

  run rm -f "$output_path"
  run rage --encrypt -R "$AGE_RECIPIENT_FILE" -o "$output_path" "$priv_path"

  if ! "$DRY_RUN"; then
    [[ -f "$output_path" ]] || die "Failed to create encrypted key: $output_path"
  fi

  run chmod 0600 "$output_path"
  run chown root:root "$output_path"
}

update_kubernetes_secret() {
  if "$NO_K8S"; then
    log "Skipping Kubernetes Secret update because --no-k8s was set."
    return 0
  fi

  log "Updating Kubernetes Secret: $SECRET_NAMESPACE/$SECRET_NAME"

  if "$DRY_RUN"; then
    run kubectl -n "$SECRET_NAMESPACE" create secret generic "$SECRET_NAME" \
      "--from-file=$SECRET_KEY_NAME=$ADMIN_OBFUSCATED" \
      --dry-run=client \
      -o yaml
    return 0
  fi

  kubectl -n "$SECRET_NAMESPACE" create secret generic "$SECRET_NAME" \
    "--from-file=$SECRET_KEY_NAME=$ADMIN_OBFUSCATED" \
    --dry-run=client \
    -o yaml |
    kubectl apply -f -

  kubectl -n "$SECRET_NAMESPACE" label secret "$SECRET_NAME" \
    "app.kubernetes.io/managed-by=key-rotation-script" \
    "security.tier=failsafe" \
    --overwrite

  kubectl -n "$SECRET_NAMESPACE" annotate secret "$SECRET_NAME" \
    "rotation.security.example.com/rotated-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "rotation.security.example.com/admin-user=$ADMIN_USER" \
    --overwrite
}

print_summary() {
  cat <<EOF

[+] All keys successfully created and deployed.

    Service user:
      user:              $SERVICE_USER
      private key:       $SERVICE_NEW_PRIV
      public key:        $SERVICE_NEW_PUB
      sealed private:    $SERVICE_OBFUSCATED

    Admin user:
      user:              $ADMIN_USER
      private key:       $ADMIN_NEW_PRIV
      public key:        $ADMIN_NEW_PUB
      sealed private:    $ADMIN_OBFUSCATED

    Kubernetes:
      namespace:         $SECRET_NAMESPACE
      secret:            $SECRET_NAME
      key:               $SECRET_KEY_NAME

EOF

  if [[ -n "$BACKUP_DIR" ]]; then
    echo "    Backups:"
    echo "      $BACKUP_DIR"
    echo
  fi
}

main() {
  validate_inputs
  confirm_or_die
  init_backup_dir
  prepare_dirs
  backup_existing_files

  log "Processing SSH keys for $SERVICE_USER"
  generate_keypair \
    "$SERVICE_USER" \
    "$SERVICE_USER" \
    "$SERVICE_NEW_PRIV" \
    "$SERVICE_NEW_PUB" \
    "$SERVICE_SSH_DIR"
  seal_private_key "$SERVICE_NEW_PRIV" "$SERVICE_OBFUSCATED"

  log "Processing SSH keys for $ADMIN_USER"
  generate_keypair \
    root \
    root \
    "$ADMIN_NEW_PRIV" \
    "$ADMIN_NEW_PUB" \
    "$ADMIN_SSH_DIR"
  seal_private_key "$ADMIN_NEW_PRIV" "$ADMIN_OBFUSCATED"

  update_kubernetes_secret
  print_summary
}

main "$@"
