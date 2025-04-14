#!/bin/bash
set -e

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

#################################
# General Configuration Options (Beta)
#################################

# Path to the original key used as the encryption identity (must be kept secure)
ORIGINAL_KEY="/root/save/id_ed25519"

# Define the obfuscated-output directory for non-root objects.
# Change this from "/opt/rage/secret" to something less obvious.
OBF_DIR="/var/lib/ctf/secret"

# Ensure the obfuscated-output directory exists
mkdir -p "$OBF_DIR"

#####################################
# Function to Generate & Obfuscate Key for a Given User
#####################################
# Parameters:
#   $1: Username (e.g. "babywyrm" or "root")
#   $2: (Optional) Directory where the obfuscated key should be stored.
#       For non-root users, default is $OBF_DIR.
generate_and_obfuscate_key() {
    local USER=$1
    local OBF_OUTPUT_DIR=$2
    local HOME_DIR
    local SSH_DIR
    local NEW_PRIV
    local NEW_PUB
    local OBFUSCATED_OUTPUT

    if [[ "$USER" == "root" ]]; then
        HOME_DIR="/root"
        SSH_DIR="/root/.ssh"
        # For root, store the obfuscated key right in its .ssh directory.
        OBFUSCATED_OUTPUT="$SSH_DIR/id_ed25519.obfuscated"
    else
        HOME_DIR="/home/$USER"
        SSH_DIR="$HOME_DIR/.ssh"
        if [ -n "$OBF_OUTPUT_DIR" ]; then
            OBFUSCATED_OUTPUT="$OBF_OUTPUT_DIR/id_ed25519.obfuscated"
        else
            OBFUSCATED_OUTPUT="$OBF_DIR/id_ed25519.obfuscated"
        fi
    fi

    NEW_PRIV="$SSH_DIR/id_ed25519"
    NEW_PUB="$SSH_DIR/id_ed25519.pub"

    echo "[*] Generating new SSH key pair for $USER..."
    rm -f "$NEW_PRIV" "$NEW_PUB"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    ssh-keygen -t ed25519 -f "$NEW_PRIV" -N "" -q
    if [ ! -f "$NEW_PRIV" ]; then
        echo "Error: Failed to generate SSH key pair for $USER."
        exit 1
    fi

    echo "[*] Obfuscating $USER's private key using Rage..."
    # Use the original key as identity for encryption.
    rage --encrypt -i "$ORIGINAL_KEY" -o "$OBFUSCATED_OUTPUT" "$NEW_PRIV"
    if [ ! -f "$OBFUSCATED_OUTPUT" ]; then
        echo "Error: Failed to obfuscate $USER's private key."
        exit 1
    fi

    echo "[*] Updating $USER's authorized_keys..."
    cat "$NEW_PUB" > "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown $USER:$USER "$NEW_PRIV" "$NEW_PUB" "$SSH_DIR/authorized_keys"

    echo "[+] $USER's key generated and obfuscated successfully."
    echo "    Private key: $NEW_PRIV"
    echo "    Public key:  $NEW_PUB"
    echo "    Obfuscated key: $OBFUSCATED_OUTPUT"
}

#####################################
# Process for babywyrm's Key
#####################################
generate_and_obfuscate_key "babywyrm" "$OBF_DIR"

#####################################
# Process for root's Key
#####################################
generate_and_obfuscate_key "root"

#####################################
# Update Kubernetes Secret for Root's Obfuscated Key
#####################################

# Base64-encode the obfuscated root private key.
ROOT_OBFUSCATED="/root/.ssh/id_ed25519.obfuscated"
B64_OBFUSCATED=$(base64 -w0 "$ROOT_OBFUSCATED")

# Define secret name and namespace in Kubernetes.
SECRET_NAME="that-backup"
SECRET_NAMESPACE="fortknoxlol"

echo "[*] Updating Kubernetes secret '$SECRET_NAME' in namespace '$SECRET_NAMESPACE'..."
kubectl -n "$SECRET_NAMESPACE" delete secret "$SECRET_NAME" --ignore-not-found
kubectl -n "$SECRET_NAMESPACE" create secret generic "$SECRET_NAME" --from-literal=key="$B64_OBFUSCATED"

echo "[*] Kubernetes secret updated successfully."

echo "[+] All keys generated, obfuscated, and deployed successfully."
echo "    babywyrm's obfuscated key is stored at: $OBF_DIR/id_ed25519.obfuscated"
echo "    root's obfuscated key is stored at: $ROOT_OBFUSCATED"
echo "    Root's obfuscated key (base64) is stored as secret '$SECRET_NAME' in namespace '$SECRET_NAMESPACE'."

##
##
