#!/usr/bin/env bash
set -euo pipefail
###############################################################################
# Cloud Metadata Hardening Script (AlmaLinux / EL8+ / legacy cloud images)
#
# Goals:
#  - Block cloud metadata access (SSRF defense)
#  - Harden SSH, sysctl, namespaces
#  - Preserve idempotence
#  - Support strict + dry-run modes
#  - Be safe for GH publication & research reuse
###############################################################################

###############################################################################
# Globals
###############################################################################
SERVICE_FILE="/etc/systemd/system/block-metadata.service"
SYSCTL_FILE="/etc/sysctl.d/99-metadata.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"
AUDIT_RULES_FILE="/etc/audit/rules.d/metadata.rules"

INSTALL_SERVICE=false
HARDEN_RAW=false
DISABLE_USERNS=false
AUDIT_METADATA=false
STRICT=false
DRY_RUN=false

###############################################################################
# Logging helpers
###############################################################################
log()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

run() {
  if $DRY_RUN; then
    echo "[DRY] $*"
  else
    eval "$@"
  fi
}

[[ $EUID -eq 0 ]] || die "Must be run as root"

###############################################################################
# OS Detection
###############################################################################
source /etc/os-release || die "Unable to detect OS"
OS_ID="${ID:-unknown}"
OS_VER="${VERSION_ID:-unknown}"

log "Detected OS: $OS_ID $OS_VER"

###############################################################################
# Flag parsing
###############################################################################
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-service) INSTALL_SERVICE=true ;;
    --harden-raw-sockets) HARDEN_RAW=true ;;
    --disable-userns) DISABLE_USERNS=true ;;
    --audit-metadata) AUDIT_METADATA=true ;;
    --strict) STRICT=true ;;
    --dry-run) DRY_RUN=true ;;
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
# 1. cloud-init handling (safe default, strict wipes)
###############################################################################
log "Handling cloud-init"

if systemctl list-unit-files | grep -q '^cloud-init'; then
  if $STRICT; then
    warn "Strict mode: fully disabling cloud-init"
    run "touch /etc/cloud/cloud-init.disabled"
    run "systemctl mask cloud-init cloud-config cloud-final cloud-init-local || true"
    run "rm -rf /var/lib/cloud /run/cloud-init /var/log/cloud-init*.log || true"
  else
    warn "Disabling future cloud-init runs (preserving state)"
    run "touch /etc/cloud/cloud-init.disabled"
    run "systemctl mask cloud-init cloud-config cloud-final cloud-init-local || true"
  fi
else
  log "cloud-init not present"
fi

###############################################################################
# 2. Metadata IP blocking (nftables-first)
###############################################################################
block_metadata() {
  if command -v nft >/dev/null; then
    nft list table inet metadata_block >/dev/null 2>&1 || \
      nft add table inet metadata_block
    nft list chain inet metadata_block output >/dev/null 2>&1 || \
      nft add chain inet metadata_block output \
        '{ type filter hook output priority 0; policy accept; }'
    nft add rule inet metadata_block output ip daddr 169.254.169.254 reject \
      2>/dev/null || true
  else
    iptables -C OUTPUT -d 169.254.169.254 -j REJECT 2>/dev/null || \
      iptables -I OUTPUT -d 169.254.169.254 -j REJECT
  fi
}

if systemctl is-active firewalld >/dev/null 2>&1; then
  warn "firewalld detected — ensure metadata rules persist across reloads"
fi

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
  run "systemctl daemon-reload"
  run "systemctl enable --now block-metadata.service"
else
  log "Applying metadata block immediately"
  run "block_metadata"
fi

###############################################################################
# 3. Safe machine-id regeneration (EL8+ compliant)
###############################################################################
log "Refreshing machine-id safely"
run "rm -f /etc/machine-id"
run "systemd-machine-id-setup --commit"

###############################################################################
# 4. SSH hardening
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
apply_sshd ChallengeResponseAuthentication no
apply_sshd X11Forwarding no
apply_sshd MaxAuthTries 3
apply_sshd LoginGraceTime 30s
apply_sshd UsePAM yes

if $STRICT; then
  apply_sshd AllowTcpForwarding no
fi

run "sshd -t"
run "systemctl restart sshd"

###############################################################################
# 5. Sysctl protections
###############################################################################
log "Applying sysctl protections"

cat > "$SYSCTL_FILE" <<EOF
# Network hardening
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.default.route_localnet=0
net.ipv4.ip_forward=0
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Kernel hardening
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
EOF

###############################################################################
# 6. Raw socket hardening (optional)
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
# 7. Disable unprivileged user namespaces (optional)
###############################################################################
if $DISABLE_USERNS; then
  if sysctl kernel.unprivileged_userns_clone | grep -q '= 0'; then
    log "Unprivileged user namespaces already disabled"
  else
    log "Disabling unprivileged user namespaces"
    run "sysctl -w kernel.unprivileged_userns_clone=0"
  fi
fi

run "sysctl -p $SYSCTL_FILE"

###############################################################################
# 8. Audit metadata tooling (realistic + safe)
###############################################################################
if $AUDIT_METADATA; then
  log "Installing auditd rules for metadata probing tools"
  cat > "$AUDIT_RULES_FILE" <<EOF
-w /usr/bin/curl -p x -k metadata_access
-w /usr/bin/wget -p x -k metadata_access
-w /usr/bin/nc -p x -k metadata_access
-w /usr/bin/python3 -p x -k metadata_access
EOF
  command -v augenrules >/dev/null && run "augenrules --load"
  run "systemctl restart auditd || true"
fi

###############################################################################
# 9. Verification
###############################################################################
log "Verifying metadata routing"
if ip route get 169.254.169.254 >/dev/null 2>&1; then
  warn "Route to metadata IP exists"
else
  log "No route to metadata IP"
fi

log "Testing HTTP metadata access"
if curl -m 2 http://169.254.169.254 >/dev/null 2>&1; then
  warn "Metadata IP is still reachable!"
else
  log "Metadata access successfully blocked"
fi

log "Hardening complete"

##
##
