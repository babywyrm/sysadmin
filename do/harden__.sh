#!/bin/bash
set -euo pipefail
##

SERVICE_FILE="/etc/systemd/system/block-metadata.service"

usage() {
  echo "Usage: $0 [--install-service]"
  echo
  echo "  --install-service   Install and enable systemd unit to block metadata on every boot"
  exit 1
}

# --- Parse flags ---
INSTALL_SERVICE=false
if [[ "${1:-}" == "--install-service" ]]; then
  INSTALL_SERVICE=true
elif [[ $# -gt 0 ]]; then
  usage
fi

echo "[*] Hardening DigitalOcean Droplet Metadata Access..."

# 1. Disable cloud-init permanently
echo "[*] Disabling cloud-init..."
sudo touch /etc/cloud/cloud-init.disabled || true
sudo systemctl disable --now cloud-init 2>/dev/null || true
sudo rm -rf /var/lib/cloud /run/cloud-init /var/log/cloud-init*.log || true

# 2. Optional systemd unit to block metadata IP
if $INSTALL_SERVICE; then
  echo "[*] Installing systemd service to block metadata service..."
  sudo tee "$SERVICE_FILE" > /dev/null <<'EOF'
[Unit]
Description=Block DigitalOcean Metadata Service
DefaultDependencies=no
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables -I OUTPUT -d 169.254.169.254 -j REJECT
ExecStart=/sbin/ip6tables -I OUTPUT -d fe80::a9fe:a9fe/128 -j REJECT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable block-metadata.service
  sudo systemctl start block-metadata.service
  echo "[✓] Systemd metadata-block service installed and enabled."
else
  echo "[*] Skipping persistent metadata-block systemd service (run with --install-service to add)."
fi

# 3. Regenerate machine-id (avoid snapshot reuse issues)
echo "[*] Refreshing /etc/machine-id..."
sudo truncate -s 0 /etc/machine-id
sudo systemd-machine-id-setup

# 4. Harden SSH settings (disable cloud-injected keys)
echo "[*] Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
sudo sed -i 's|^#\?AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys|' "$SSHD_CONFIG"
sudo systemctl restart sshd

# 5. Apply sysctl metadata routing protection
echo "[*] Applying sysctl metadata protection..."
SYSCTL_FILE="/etc/sysctl.d/99-metadata.conf"
sudo tee "$SYSCTL_FILE" > /dev/null <<'EOF'
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.default.route_localnet=0
EOF
sudo sysctl -p "$SYSCTL_FILE"

echo
echo "[✓] Metadata hardening complete!"
echo "    - Cloud-init disabled"
if $INSTALL_SERVICE; then
  echo "    - Metadata IP blocked via systemd firewall unit"
else
  echo "    - Metadata IP *not* persisted (use --install-service to enable at boot)"
fi
echo "    - Machine ID refreshed"
echo "    - SSH hardened"
echo "    - Sysctl protections applied"
