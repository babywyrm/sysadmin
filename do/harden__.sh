#!/usr/bin/env bash
set -euo pipefail
###############################################################################
# Cloud Metadata Hardening Script (CentOS / legacy cloud images)
# Supports optional stretch hardening goals via flags
###############################################################################

SERVICE_FILE="/etc/systemd/system/block-metadata.service"
SYSCTL_FILE="/etc/sysctl.d/99-metadata.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"
AUDIT_RULES_FILE="/etc/audit/rules.d/metadata.rules"

log()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must be run as root"

###############################################################################
# Flag parsing
###############################################################################
INSTALL_SERVICE=false
HARDEN_RAW=false
DISABLE_USERNS=false
AUDIT_METADATA=false
STRICT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-service) INSTALL_SERVICE=true ;;
    --harden-raw-sockets) HARDEN_RAW=true ;;
    --disable-userns) DISABLE_USERNS=true ;;
    --audit-metadata) AUDIT_METADATA=true ;;
    --strict) STRICT=true ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

if $STRICT; then
  HARDEN_RAW=true
  DISABLE_USERNS=true
  AUDIT_METADATA=true
fi

###############################################################################
# 1. Disable and mask cloud-init
###############################################################################
log "Disabling cloud-init"
touch /etc/cloud/cloud-init.disabled || true
systemctl disable --now cloud-init 2>/dev/null || true
systemctl mask cloud-init 2>/dev/null || true
rm -rf /var/lib/cloud /run/cloud-init /var/log/cloud-init*.log || true

###############################################################################
# 2. Firewall metadata IP (iptables or nftables)
###############################################################################
block_metadata() {
  if command -v nft >/dev/null; then
    nft list table inet filter >/dev/null 2>&1 || nft add table inet filter
    nft list chain inet filter output >/dev/null 2>&1 || \
      nft add chain inet filter output '{ type filter hook output priority 0 ; }'
    nft add rule inet filter output ip daddr 169.254.169.254 reject || true
  else
    iptables -C OUTPUT -d 169.254.169.254 -j REJECT 2>/dev/null || \
      iptables -I OUTPUT -d 169.254.169.254 -j REJECT
  fi
}

if $INSTALL_SERVICE; then
  log "Installing persistent metadata-block service"
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
# 4. Harden SSH configuration
###############################################################################
log "Hardening SSH configuration"

apply_sshd() {
  local key="$1" value="$2"
  grep -q "^$key" "$SSHD_CONFIG" \
    && sed -i "s/^$key.*/$key $value/" "$SSHD_CONFIG" \
    || echo "$key $value" >> "$SSHD_CONFIG"
}

apply_sshd PermitRootLogin prohibit-password
apply_sshd PasswordAuthentication no
apply_sshd PubkeyAuthentication yes
apply_sshd PermitEmptyPasswords no
apply_sshd AuthorizedKeysFile ".ssh/authorized_keys"

sshd -t && systemctl restart sshd

###############################################################################
# 5. Base sysctl protections
###############################################################################
log "Applying sysctl protections"

cat > "$SYSCTL_FILE" <<EOF
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.default.route_localnet=0
net.ipv4.ip_forward=0
EOF

###############################################################################
# 6. Stretch: raw socket hardening
###############################################################################
if $HARDEN_RAW; then
  log "Enabling raw socket hardening"
  cat >> "$SYSCTL_FILE" <<EOF
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
EOF
fi

###############################################################################
# 7. Stretch: disable unprivileged user namespaces
###############################################################################
if $DISABLE_USERNS; then
  log "Disabling unprivileged user namespaces"
  sysctl -w kernel.unprivileged_userns_clone=0
fi

sysctl -p "$SYSCTL_FILE"

###############################################################################
# 8. Stretch: audit metadata access attempts
###############################################################################
if $AUDIT_METADATA; then
  log "Installing auditd rules for metadata probing"
  cat > "$AUDIT_RULES_FILE" <<EOF
-a always,exit -F arch=b64 -S connect -F a2=169.254.169.254 -k metadata_access
EOF
  command -v augenrules >/dev/null && augenrules --load
  systemctl restart auditd || true
fi

###############################################################################
# 9. Verification
###############################################################################
log "Verifying metadata access"
if curl -m 2 http://169.254.169.254 >/dev/null 2>&1; then
  warn "Metadata IP is still reachable!"
else
  log "Metadata access successfully blocked"
fi

log "Hardening complete"
