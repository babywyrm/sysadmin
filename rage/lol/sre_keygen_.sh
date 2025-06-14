#!/bin/bash
set -euo pipefail

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

ORIGINAL_KEY="/srv/secure/identity/id_ed25519"
SERVICE_USER="serviceuser"
ADMIN_USER="adminuser"

SERVICE_HOME="/home/$SERVICE_USER"
SERVICE_SSH_DIR="$SERVICE_HOME/.ssh"
SERVICE_NEW_PRIV="$SERVICE_SSH_DIR/id_ed25519"
SERVICE_NEW_PUB="$SERVICE_SSH_DIR/id_ed25519.pub"
SERVICE_OBFUSCATED="/srv/secure/obfuscated/id_ed25519_${SERVICE_USER}.rage"

ADMIN_SSH_DIR="/root/.ssh"
ADMIN_NEW_PRIV="$ADMIN_SSH_DIR/id_ed25519"
ADMIN_NEW_PUB="$ADMIN_SSH_DIR/id_ed25519.pub"
ADMIN_OBFUSCATED="/srv/secure/obfuscated/id_ed25519_${ADMIN_USER}.rage"

SECRET_NAME="admin-failsafe"
SECRET_NAMESPACE="infra"

#############################
# Optional flags
#############################
DRY_RUN=false
VERBOSE=false
BACKUP=false
ROLLBACK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true ;;
        --verbose) VERBOSE=true ;;
        --backup) BACKUP=true ;;
        --rollback) ROLLBACK=true ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

log() { echo -e "[*] $*"; }
vrun() {
    $VERBOSE && echo "+ $*"
    $DRY_RUN || eval "$@"
}
safe_cp() {
    if [ -f "$1" ]; then
        local backup="$1.bak.$(date +%s)"
        log "Backing up $1 to $backup"
        vrun cp "$1" "$backup"
    fi
}

rollback_keys() {
    for file in "$SERVICE_NEW_PRIV" "$SERVICE_NEW_PUB" "$ADMIN_NEW_PRIV" "$ADMIN_NEW_PUB"; do
        bak=$(ls "${file}.bak."* 2>/dev/null | tail -n1 || true)
        [ -n "$bak" ] && vrun cp "$bak" "$file" && log "Rolled back $file from $bak"
    done
    exit 1
}

trap '[[ $ROLLBACK == true ]] && log "Rolling back..." && rollback_keys' ERR

###############################################
# Section 1: serviceuser key generation
###############################################
log "Processing SSH keys for $SERVICE_USER..."

$BACKUP && for f in "$SERVICE_NEW_PRIV" "$SERVICE_NEW_PUB"; do safe_cp "$f"; done

vrun rm -f "$SERVICE_NEW_PRIV" "$SERVICE_NEW_PUB"
vrun mkdir -p "$SERVICE_SSH_DIR"
vrun chmod 700 "$SERVICE_SSH_DIR"
vrun ssh-keygen -t ed25519 -f "$SERVICE_NEW_PRIV" -N "" -q
[[ -f "$SERVICE_NEW_PRIV" ]] || { echo "Error: Failed to generate $SERVICE_USER key"; exit 1; }

vrun rage --encrypt -i "$ORIGINAL_KEY" -o "$SERVICE_OBFUSCATED" "$SERVICE_NEW_PRIV"
[[ -f "$SERVICE_OBFUSCATED" ]] || { echo "Error: Failed to obfuscate $SERVICE_USER key"; exit 1; }

vrun cp "$SERVICE_NEW_PUB" "$SERVICE_SSH_DIR/authorized_keys"
vrun chmod 600 "$SERVICE_NEW_PRIV" "$SERVICE_SSH_DIR/authorized_keys"
vrun chown "$SERVICE_USER:$SERVICE_USER" "$SERVICE_NEW_PRIV" "$SERVICE_NEW_PUB" "$SERVICE_SSH_DIR/authorized_keys"

log "$SERVICE_USER's new key generated and obfuscated."

###############################################
# Section 2: adminuser key generation
###############################################
log "Processing SSH keys for $ADMIN_USER..."

$BACKUP && for f in "$ADMIN_NEW_PRIV" "$ADMIN_NEW_PUB"; do safe_cp "$f"; done

vrun rm -f "$ADMIN_NEW_PRIV" "$ADMIN_NEW_PUB"
vrun mkdir -p "$ADMIN_SSH_DIR"
vrun chmod 700 "$ADMIN_SSH_DIR"
vrun ssh-keygen -t ed25519 -f "$ADMIN_NEW_PRIV" -N "" -q
[[ -f "$ADMIN_NEW_PRIV" ]] || { echo "Error: Failed to generate $ADMIN_USER key"; exit 1; }

vrun rage --encrypt -i "$ORIGINAL_KEY" -o "$ADMIN_OBFUSCATED" "$ADMIN_NEW_PRIV"
[[ -f "$ADMIN_OBFUSCATED" ]] || { echo "Error: Failed to obfuscate $ADMIN_USER key"; exit 1; }

vrun cp "$ADMIN_NEW_PUB" "$ADMIN_SSH_DIR/authorized_keys"
vrun chmod 600 "$ADMIN_NEW_PRIV" "$ADMIN_SSH_DIR/authorized_keys"
vrun chown root:root "$ADMIN_NEW_PRIV" "$ADMIN_NEW_PUB" "$ADMIN_SSH_DIR/authorized_keys"

log "$ADMIN_USER's new key generated and obfuscated."

###############################################
# Section 3: Update Kubernetes Secret
###############################################
B64_OBFUSCATED=$(base64 -w0 "$ADMIN_OBFUSCATED")

log "Updating Kubernetes secret '$SECRET_NAME' in namespace '$SECRET_NAMESPACE'..."

vrun kubectl -n "$SECRET_NAMESPACE" delete secret "$SECRET_NAME" --ignore-not-found
vrun kubectl -n "$SECRET_NAMESPACE" create secret generic "$SECRET_NAME" --from-literal=key="$B64_OBFUSCATED"

log "Kubernetes secret updated."

###############################################
# Final Output
###############################################
echo "[+] All keys successfully created and deployed."
echo "    $SERVICE_USER obfuscated key -> $SERVICE_OBFUSCATED"
echo "    $ADMIN_USER obfuscated key -> $ADMIN_OBFUSCATED"
echo "    $ADMIN_USER's obfuscated key also stored in Kubernetes Secret '$SECRET_NAME' (namespace: $SECRET_NAMESPACE)."

