#!/bin/bash
set -e

# Usage function
usage() {
    echo "Usage: $0 [-u username] [-o obf_dir]"
    echo "  -u username   The target user for key generation (default: babywyrm)"
    echo "  -o obf_dir    Directory for storing obfuscated keys for non-root users (default: /var/lib/ctf/secret)"
    exit 1
}

# Default values
TARGET_USER="babywyrm"
OBF_DIR="/var/lib/ctf/secret"

# Parse options
while getopts "u:o:h" opt; do
    case "$opt" in
        u) TARGET_USER="$OPTARG" ;;
        o) OBF_DIR="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# Ensure OBF_DIR exists for non-root keys
mkdir -p "$OBF_DIR"

# Path to the original key used as the encryption identity (keep this secure!)
ORIGINAL_KEY="/thing/somewhere/secret/save/id_ed25519"

if [ ! -f "$ORIGINAL_KEY" ]; then
    echo "Error: ORIGINAL_KEY ($ORIGINAL_KEY) does not exist."
    exit 1
fi

# Set target account details
if [ "$TARGET_USER" == "root" ]; then
    HOME_DIR="/root"
    SSH_DIR="/root/.ssh"
    # For root, store the obfuscated key in its .ssh directory.
    OBFUSCATED_OUTPUT="$SSH_DIR/id_ed25519.obfuscated"
else
    HOME_DIR="/home/$TARGET_USER"
    SSH_DIR="$HOME_DIR/.ssh"
    OBFUSCATED_OUTPUT="$OBF_DIR/id_ed25519.obfuscated"
fi

NEW_PRIV="$SSH_DIR/id_ed25519"
NEW_PUB="$SSH_DIR/id_ed25519.pub"

echo "[*] Generating new SSH key pair for user: $TARGET_USER"
rm -f "$NEW_PRIV" "$NEW_PUB"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
ssh-keygen -t ed25519 -f "$NEW_PRIV" -N "" -q

if [ ! -f "$NEW_PRIV" ]; then
    echo "Error: Failed to generate SSH key pair for $TARGET_USER."
    exit 1
fi

echo "[*] Obfuscating $TARGET_USER's private key using Rage..."
# Use the ORIGINAL_KEY as identity for encryption.
rage --encrypt -i "$ORIGINAL_KEY" -o "$OBFUSCATED_OUTPUT" "$NEW_PRIV"
if [ ! -f "$OBFUSCATED_OUTPUT" ]; then
    echo "Error: Failed to obfuscate $TARGET_USER's private key."
    exit 1
fi

echo "[*] Updating $TARGET_USER's authorized_keys..."
cat "$NEW_PUB" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown $TARGET_USER:$TARGET_USER "$NEW_PRIV" "$NEW_PUB" "$SSH_DIR/authorized_keys"

echo "[+] $TARGET_USER's key generated and obfuscated successfully."
echo "    Private key: $NEW_PRIV"
echo "    Public key:  $NEW_PUB"
echo "    Obfuscated key: $OBFUSCATED_OUTPUT"

# If the target user is "root", update the Kubernetes secret (if kubectl is available)
if [ "$TARGET_USER" == "root" ]; then
    if command -v kubectl >/dev/null 2>&1 && [ -n "$KUBECONFIG" ]; then
        SECRET_NAME="root-access"
        SECRET_NAMESPACE="orthanc"
        echo "[*] Base64 encoding obfuscated root key and updating Kubernetes secret..."
        B64_OBFUSCATED=$(base64 -w0 "$OBFUSCATED_OUTPUT")
        kubectl -n "$SECRET_NAMESPACE" delete secret "$SECRET_NAME" --ignore-not-found
        kubectl -n "$SECRET_NAMESPACE" create secret generic "$SECRET_NAME" --from-literal=key="$B64_OBFUSCATED"
        echo "[*] Kubernetes secret '$SECRET_NAME' updated in namespace '$SECRET_NAMESPACE'."
    else
        echo "[!] kubectl not found or KUBECONFIG not set. Skipping Kubernetes secret update."
    fi
fi

echo "[+] All operations completed successfully."
