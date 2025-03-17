#!/bin/bash
set -e

# Define installation directory for binaries
INSTALL_DIR="/usr/local/bin"

# Create a temporary working directory
TMP_DIR=$(mktemp -d)

##############################
# Install kubectx and kubens #
##############################
echo "Installing kubectx and kubens..."
if [ ! -d "/opt/kubectx" ]; then
  sudo git clone --depth 1 https://github.com/ahmetb/kubectx /opt/kubectx
else
  sudo git -C /opt/kubectx pull
fi
sudo ln -sf /opt/kubectx/kubectx "${INSTALL_DIR}/kubectx"
sudo ln -sf /opt/kubectx/kubens "${INSTALL_DIR}/kubens"
echo "kubectx and kubens installed to ${INSTALL_DIR}"

#################
# Install stern #
#################
echo "Installing stern v1.32.0..."
cd "$TMP_DIR"
# Detect OS and architecture to build the correct URL
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [[ "$OS" == "linux" ]]; then
  case "$ARCH" in
    x86_64)
      STERN_ARCH="amd64"
      ;;
    aarch64|arm64)
      STERN_ARCH="arm64"
      ;;
    armv7l)
      STERN_ARCH="arm"
      ;;
    *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac
else
  echo "Unsupported OS: $OS"
  exit 1
fi

# Set version details for stern
STERN_VERSION="v1.32.0"
# Remove the 'v' prefix for the file name
STERN_VERSION_NO_V="${STERN_VERSION#v}"
STERN_URL="https://github.com/stern/stern/releases/download/${STERN_VERSION}/stern_${STERN_VERSION_NO_V}_${OS}_${STERN_ARCH}.tar.gz"
echo "Downloading stern from: $STERN_URL"
curl -sL -o stern.tar.gz "$STERN_URL"
tar -xzf stern.tar.gz
sudo mv stern "${INSTALL_DIR}/stern"
sudo chmod +x "${INSTALL_DIR}/stern"
echo "stern installed to ${INSTALL_DIR}"

#####################
# Install kube-ps1  #
#####################
echo "Installing kube-ps1..."
if [ ! -d "/opt/kube-ps1" ]; then
  sudo git clone --depth 1 https://github.com/jonmosco/kube-ps1.git /opt/kube-ps1
else
  sudo git -C /opt/kube-ps1 pull
fi
echo "kube-ps1 has been cloned to /opt/kube-ps1."
echo "To enable it, add these lines to your shell rc file (e.g., ~/.bashrc or ~/.zshrc):"
echo "    source /opt/kube-ps1/kube-ps1.sh"
echo "    PS1=\"[\$(kube_ps1)] \$PS1\""

###############
# Install Helm#
###############
echo "Installing Helm..."
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
rm get_helm.sh

##################
# Install kubetail#
##################
echo "Installing kubetail..."
if [ ! -d "/opt/kubetail" ]; then
  sudo git clone --depth 1 https://github.com/johanhaleby/kubetail.git /opt/kubetail
else
  sudo git -C /opt/kubetail pull
fi
sudo ln -sf /opt/kubetail/kubetail "${INSTALL_DIR}/kubetail"
sudo chmod +x "${INSTALL_DIR}/kubetail"
echo "kubetail installed to ${INSTALL_DIR}"

######################
# Install kube-shell #
######################
echo "Installing kube-shell via pip3..."
if command -v pip3 &>/dev/null; then
  sudo pip3 install kube-shell
else
  echo "pip3 not found. Please install pip3 and re-run the script for kube-shell."
fi

######################
# Install kubecolor  #
######################
echo "Installing kubecolor v0.5.0..."
cd "$TMP_DIR"
KUBECOLOR_VERSION="0.5.0"
KUBECOLOR_URL="https://github.com/kubecolor/kubecolor/releases/download/v${KUBECOLOR_VERSION}/kubecolor_${KUBECOLOR_VERSION}_linux_amd64.tar.gz"
echo "Downloading kubecolor from: $KUBECOLOR_URL"
curl -sL -o kubecolor.tar.gz "$KUBECOLOR_URL"
tar -xzf kubecolor.tar.gz
sudo mv kubecolor "${INSTALL_DIR}/kubecolor"
sudo chmod +x "${INSTALL_DIR}/kubecolor"
echo "kubecolor installed to ${INSTALL_DIR}"

# Clean up temporary directory
rm -rf "$TMP_DIR"

#########################
# Final status message  #
#########################
echo ""
echo "Installation complete! Tools installed:"
echo " - kubectx: $(which kubectx)"
echo " - kubens: $(which kubens)"
echo " - stern: $(which stern)  (version ${STERN_VERSION})"
echo " - kube-ps1: to be enabled by sourcing /opt/kube-ps1/kube-ps1.sh in your shell rc file"
echo " - helm: $(which helm)"
echo " - kubetail: $(which kubetail)"
echo " - kube-shell: $(which kube-shell)   (run 'kube-shell' to start the interactive shell)"
echo " - kubecolor: $(which kubecolor)"
echo ""
echo "Additional suggestions:"
echo " - Consider installing kube-capacity for resource usage monitoring: https://github.com/kube-capacity/kube-capacity"
echo " - Explore additional tools like kubecolor (installed above) to improve your kubectl output."
