#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Harden cloud metadata access (DigitalOcean / EC2-style)
# Safe for CentOS / Ubuntu / Debian cloud images
###############################################################################

SERVICE_FILE="/etc/systemd/system/block-metadata.service"
SYSCTL_FILE="/etc/sysctl.d/99-metadata.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"

log()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }

[[ $EUID -eq 0 ]] || { echo "Must be run as root"; exit 1; }

INSTALL_SERVICE=false
[[ "${1:-}" == "--install-service" ]] && INSTALL_SERVICE=true

log "Hardening cloud metadata access"

###############################################################################
# 1. Disable and mask cloud-init
###############################################################################
log "Disabling cloud-init"
touch /etc/cloud/cloud-init.disabled || true
systemctl disable --now cloud-init 2>/dev/null || true
systemctl mask cloud-init 2>/dev/null || true
rm -rf /var/lib/cloud /run/cloud-init /var/log/cloud-init*.log || true

###############################################################################
# 2. Firewall metadata IP (iptables OR nftables)
###############################################################################
block_metadata() {
  if command -v nft >/dev/null; then
    log "Using nftables to block metadata IP"
    nft list table inet filter >/dev/null 2>&1 || nft add table inet filter
    nft list chain inet filter output >/dev/null 2>&1 || \
      nft add chain inet filter output '{ type filter hook output priority 0 ; }'
    nft add rule inet filter output ip daddr 169.254.169.254 reject || true
  else
    log "Using iptables to block metadata IP"
    iptables -C OUTPUT -d 169.254.169.254 -j REJECT 2>/dev/null || \
      iptables -I OUTPUT -d 169.254.169.254 -j REJECT
  fi
}

if $INSTALL_SERVICE; then
  log "Installing persistent metadata block service"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Block Cloud Metadata Service
DefaultDependencies=no
Before=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '$(declare -f block_metadata); block_metadata'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now block-metadata.service
else
  block_metadata
fi

###############################################################################
# 3. Regenerate machine-id
###############################################################################
log "Refreshing machine-id"
truncate -s 0 /etc/machine-id
systemd-machine-id-setup

###############################################################################
# 4. Harden SSH configuration (safe edits)
###############################################################################
log "Hardening SSH configuration"

apply_sshd_setting() {
  local key="$1" value="$2"
  grep -q "^$key" "$SSHD_CONFIG" \
    && sed -i "s/^$key.*/$key $value/" "$SSHD_CONFIG" \
    || echo "$key $value" >> "$SSHD_CONFIG"
}

apply_sshd_setting PermitRootLogin prohibit-password
apply_sshd_setting PasswordAuthentication no
apply_sshd_setting PubkeyAuthentication yes
apply_sshd_setting PermitEmptyPasswords no
apply_sshd_setting AuthorizedKeysFile ".ssh/authorized_keys"

sshd -t && systemctl restart sshd

###############################################################################
# 5. Sysctl protections
###############################################################################
log "Applying sysctl hardening"

cat > "$SYSCTL_FILE" <<EOF
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.default.route_localnet=0
net.ipv4.ip_forward=0
EOF

sysctl -p "$SYSCTL_FILE"

###############################################################################
# 6. Verification
###############################################################################
log "Verification"

if curl -m 2 http://169.254.169.254 2>/dev/null; then
  warn "Metadata IP still reachable!"
else
  log "Metadata IP blocked successfully"
fi

log "Hardening complete"
