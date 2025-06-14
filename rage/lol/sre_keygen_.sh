#!/bin/bash
set -euo pipefail

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

ORIGINAL_KEY="/opt/rage/secret/save/id_ed25519"
BABY_WYRM_HOME="/home/babywyrm"
BABY_WYRM_SSH_DIR="$BABY_WYRM_HOME/.ssh"
BABY_WYRM_NEW_PRIV="$BABY_WYRM_SSH_DIR/id_ed25519"
BABY_WYRM_NEW_PUB="$BABY_WYRM_SSH_DIR/id_ed25519.pub"
BABY_WYRM_OBFUSCATED="/opt/rage/secret/id_ed25519.obfuscated"

ROOT_SSH_DIR="/root/.ssh"
ROOT_NEW_PRIV="$ROOT_SSH_DIR/id_ed25519"
ROOT_NEW_PUB="$ROOT_SSH_DIR/id_ed25519.pub"
ROOT_OBFUSCATED="$ROOT_SSH_DIR/id_ed25519.obfuscated"

SECRET_NAME="root-failsafe"
SECRET_NAMESPACE="orthanc"

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
    for file in "$BABY_WYRM_NEW_PRIV" "$BABY_WYRM_NEW_PUB" "$ROOT_NEW_PRIV" "$ROOT_NEW_PUB"; do
        bak=$(ls "${file}.bak."* 2>/dev/null | tail -n1 || true)
        [ -n "$bak" ] && vrun cp "$bak" "$file" && log "Rolled back $file from $bak"
    done
    exit 1
}

trap '[[ $ROLLBACK == true ]] && log "Rolling back..." && rollback_keys' ERR

###############################################
# Section 1: babywyrm key generation
###############################################
log "Processing SSH keys for babywyrm..."

$BACKUP && for f in "$BABY_WYRM_NEW_PRIV" "$BABY_WYRM_NEW_PUB"; do safe_cp "$f"; done

vrun rm -f "$BABY_WYRM_NEW_PRIV" "$BABY_WYRM_NEW_PUB"
vrun mkdir -p "$BABY_WYRM_SSH_DIR"
vrun chmod 700 "$BABY_WYRM_SSH_DIR"
vrun ssh-keygen -t ed25519 -f "$BABY_WYRM_NEW_PRIV" -N "" -q
[[ -f "$BABY_WYRM_NEW_PRIV" ]] || { echo "Error: Failed to generate babywyrm key"; exit 1; }

vrun rage --encrypt -i "$ORIGINAL_KEY" -o "$BABY_WYRM_OBFUSCATED" "$BABY_WYRM_NEW_PRIV"
[[ -f "$BABY_WYRM_OBFUSCATED" ]] || { echo "Error: Failed to obfuscate babywyrm key"; exit 1; }

vrun cp "$BABY_WYRM_NEW_PUB" "$BABY_WYRM_SSH_DIR/authorized_keys"
vrun chmod 600 "$BABY_WYRM_NEW_PRIV" "$BABY_WYRM_SSH_DIR/authorized_keys"
vrun chown babywyrm:babywyrm "$BABY_WYRM_NEW_PRIV" "$BABY_WYRM_NEW_PUB" "$BABY_WYRM_SSH_DIR/authorized_keys"

log "babywyrm's new key generated and obfuscated."

###############################################
# Section 2: root key generation
###############################################
log "Processing SSH keys for root..."

$BACKUP && for f in "$ROOT_NEW_PRIV" "$ROOT_NEW_PUB"; do safe_cp "$f"; done

vrun rm -f "$ROOT_NEW_PRIV" "$ROOT_NEW_PUB"
vrun mkdir -p "$ROOT_SSH_DIR"
vrun chmod 700 "$ROOT_SSH_DIR"
vrun ssh-keygen -t ed25519 -f "$ROOT_NEW_PRIV" -N "" -q
[[ -f "$ROOT_NEW_PRIV" ]] || { echo "Error: Failed to generate root key"; exit 1; }

vrun rage --encrypt -i "$ORIGINAL_KEY" -o "$ROOT_OBFUSCATED" "$ROOT_NEW_PRIV"
[[ -f "$ROOT_OBFUSCATED" ]] || { echo "Error: Failed to obfuscate root key"; exit 1; }

vrun cp "$ROOT_NEW_PUB" "$ROOT_SSH_DIR/authorized_keys"
vrun chmod 600 "$ROOT_NEW_PRIV" "$ROOT_SSH_DIR/authorized_keys"
vrun chown root:root "$ROOT_NEW_PRIV" "$ROOT_NEW_PUB" "$ROOT_SSH_DIR/authorized_keys"

log "root's new key generated and obfuscated."

###############################################
# Section 3: Update Kubernetes Secret
###############################################
B64_OBFUSCATED=$(base64 -w0 "$ROOT_OBFUSCATED")

log "Updating Kubernetes secret '$SECRET_NAME' in namespace '$SECRET_NAMESPACE'..."

vrun kubectl -n "$SECRET_NAMESPACE" delete secret "$SECRET_NAME" --ignore-not-found
vrun kubectl -n "$SECRET_NAMESPACE" create secret generic "$SECRET_NAME" --from-literal=key="$B64_OBFUSCATED"

log "Kubernetes secret updated."

###############################################
# Final Output
###############################################
echo "[+] All keys successfully created and deployed."
echo "    babywyrm obfuscated key -> $BABY_WYRM_OBFUSCATED"
echo "    root obfuscated key -> $ROOT_OBFUSCATED"
echo "    root obfuscated key also stored in Kubernetes Secret '$SECRET_NAME' (namespace: $SECRET_NAMESPACE)."

