#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Cloud Metadata Hardening Script
# Supports: CentOS 7, RHEL 7/8, and legacy cloud images
#
# Usage:
#   sudo bash harden.sh [OPTIONS]
#
# Options:
#   --install-service       Persist firewall rules via systemd unit
#   --harden-raw-sockets    Block ICMP redirects and raw socket abuse
#   --disable-userns        Disable unprivileged user namespaces
#   --audit-metadata        Install auditd rules for metadata probe detection
#   --strict                Enable all hardening options above
#   --dry-run               Preview changes without applying them
#   --rollback              Undo changes made by this script
#   --report                Print a post-run hardening report
#   --skip-ssh              Skip SSH hardening (e.g. remote sessions)
#   --skip-cloud-init       Skip cloud-init disabling
#
# Examples:
#   sudo bash harden.sh --strict --report
#   sudo bash harden.sh --audit-metadata --dry-run
#   sudo bash harden.sh --rollback
###############################################################################

###############################################################################
# Paths
###############################################################################
SERVICE_FILE="/etc/systemd/system/block-metadata.service"
SYSCTL_FILE="/etc/sysctl.d/99-cloud-hardening.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="/etc/ssh/sshd_config.pre-hardening.bak"
AUDIT_RULES_FILE="/etc/audit/rules.d/99-metadata.rules"
LOG_FILE="/var/log/cloud-hardening.log"
ROLLBACK_MANIFEST="/var/lib/cloud-hardening/rollback.manifest"

###############################################################################
# Logging
###############################################################################
SCRIPT_NAME="$(basename "$0")"
_ts() { date '+%Y-%m-%d %H:%M:%S'; }

log()     { _emit INFO  "1;32" "$@"; }
warn()    { _emit WARN  "1;33" "$@"; }
error()   { _emit ERROR "1;31" "$@"; }
step()    { _emit STEP  "1;36" "$@"; }
dry_log() { _emit "DRY " "0;35" "$@"; }

_emit() {
  local level="$1" color="$2"; shift 2
  local line="[$(_ts)] [${SCRIPT_NAME}] $(
    printf '\033[%sm%-5s\033[0m' "$color" "$level"
  ) $*"
  echo -e "$line"
  echo -e "$line" >> "$LOG_FILE" 2>/dev/null || true
}

die() { error "$@"; exit 1; }

###############################################################################
# Require root
###############################################################################
[[ $EUID -eq 0 ]] || die "Must be run as root"

###############################################################################
# Flag defaults
###############################################################################
INSTALL_SERVICE=false
HARDEN_RAW=false
DISABLE_USERNS=false
AUDIT_METADATA=false
STRICT=false
DRY_RUN=false
ROLLBACK=false
REPORT=false
SKIP_SSH=false
SKIP_CLOUD_INIT=false

_WARNINGS=()
_APPLIED=()

###############################################################################
# Flag parsing
###############################################################################
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-service)    INSTALL_SERVICE=true ;;
    --harden-raw-sockets) HARDEN_RAW=true ;;
    --disable-userns)     DISABLE_USERNS=true ;;
    --audit-metadata)     AUDIT_METADATA=true ;;
    --strict)             STRICT=true ;;
    --dry-run)            DRY_RUN=true ;;
    --rollback)           ROLLBACK=true ;;
    --report)             REPORT=true ;;
    --skip-ssh)           SKIP_SSH=true ;;
    --skip-cloud-init)    SKIP_CLOUD_INIT=true ;;
    --help|-h)
      grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
      exit 0
      ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
  shift
done

if $STRICT; then
  HARDEN_RAW=true
  DISABLE_USERNS=true
  AUDIT_METADATA=true
  INSTALL_SERVICE=true
fi

###############################################################################
# Dry-run wrapper
###############################################################################
run() {
  if $DRY_RUN; then
    dry_log "Would run: $*"
  else
    "$@"
  fi
}

run_shell() {
  # For piped/compound commands — wraps in bash -c under dry-run
  if $DRY_RUN; then
    dry_log "Would run: $*"
  else
    bash -c "$*"
  fi
}

###############################################################################
# Rollback manifest helpers
###############################################################################
_manifest_init() {
  $DRY_RUN && return
  mkdir -p "$(dirname "$ROLLBACK_MANIFEST")"
  touch "$ROLLBACK_MANIFEST"
}

_manifest_record() {
  $DRY_RUN && return
  echo "$*" >> "$ROLLBACK_MANIFEST"
}

###############################################################################
# Rollback
###############################################################################
do_rollback() {
  step "Rolling back cloud hardening changes"

  if [[ ! -f "$ROLLBACK_MANIFEST" ]]; then
    die "No rollback manifest found at ${ROLLBACK_MANIFEST}"
  fi

  while IFS= read -r entry; do
    local action artifact
    action="${entry%%:*}"
    artifact="${entry#*:}"

    case "$action" in
      sysctl_file)
        [[ -f "$artifact" ]] && run rm -f "$artifact" && \
          log "Removed sysctl file: ${artifact}"
        run sysctl --system
        ;;
      service)
        if systemctl is-active --quiet "$artifact" 2>/dev/null; then
          run systemctl disable --now "$artifact" || true
        fi
        [[ -f "/etc/systemd/system/${artifact}" ]] && \
          run rm -f "/etc/systemd/system/${artifact}"
        run systemctl daemon-reload
        log "Removed service: ${artifact}"
        ;;
      audit_rules)
        [[ -f "$artifact" ]] && run rm -f "$artifact"
        command -v augenrules &>/dev/null && run augenrules --load
        log "Removed audit rules: ${artifact}"
        ;;
      sshd_backup)
        if [[ -f "$artifact" ]]; then
          run cp "$artifact" "$SSHD_CONFIG"
          run sshd -t && run systemctl restart sshd
          log "Restored sshd_config from: ${artifact}"
        fi
        ;;
      cloud_init_disabled)
        run rm -f /etc/cloud/cloud-init.disabled
        run systemctl unmask cloud-init 2>/dev/null || true
        run systemctl enable cloud-init 2>/dev/null || true
        log "Re-enabled cloud-init"
        ;;
      iptables_rule)
        run iptables -D OUTPUT -d 169.254.169.254 -j REJECT 2>/dev/null || true
        log "Removed iptables rule for metadata IP"
        ;;
      nft_rule)
        run nft delete rule inet filter output handle "$artifact" 2>/dev/null || true
        log "Removed nft rule (handle: ${artifact})"
        ;;
    esac
  done < "$ROLLBACK_MANIFEST"

  run rm -f "$ROLLBACK_MANIFEST"
  log "Rollback complete"
  exit 0
}

$ROLLBACK && do_rollback

###############################################################################
# Trap / cleanup on unexpected exit
###############################################################################
_on_exit() {
  local code=$?
  [[ $code -eq 0 ]] && return
  error "Script failed with exit code ${code} — check ${LOG_FILE}"
  if [[ ${#_WARNINGS[@]} -gt 0 ]]; then
    warn "Warnings accumulated before failure:"
    for w in "${_WARNINGS[@]}"; do warn "  • $w"; done
  fi
}
trap _on_exit EXIT

###############################################################################
# Preflight checks
###############################################################################
step "Pre-flight checks"

_manifest_init

if grep -q "CentOS Linux release 7" /etc/centos-release 2>/dev/null; then
  log "Detected CentOS 7"
elif grep -qE "release [78]" /etc/redhat-release 2>/dev/null; then
  log "Detected RHEL-compatible system"
else
  warn "Unrecognized OS — proceeding cautiously"
  _WARNINGS+=("Unrecognized OS")
fi

if $DRY_RUN; then
  warn "DRY_RUN enabled — no changes will be applied"
fi

###############################################################################
# 1. Disable and mask cloud-init
###############################################################################
if ! $SKIP_CLOUD_INIT; then
  step "Disabling and masking cloud-init"

  # Check if already disabled
  if [[ -f /etc/cloud/cloud-init.disabled ]]; then
    log "cloud-init already disabled — skipping"
  else
    run touch /etc/cloud/cloud-init.disabled
    _manifest_record "cloud_init_disabled:/etc/cloud/cloud-init.disabled"
    _APPLIED+=("cloud-init disabled")
  fi

  run systemctl disable --now cloud-init 2>/dev/null || true
  run systemctl mask cloud-init 2>/dev/null || true
  run rm -rf /var/lib/cloud /run/cloud-init /var/log/cloud-init*.log || true
else
  warn "--skip-cloud-init set — skipping cloud-init hardening"
  _WARNINGS+=("cloud-init hardening skipped")
fi

###############################################################################
# 2. Firewall metadata IP
###############################################################################
step "Blocking metadata IP (169.254.169.254)"

_block_via_nft() {
  nft list table inet filter &>/dev/null || run nft add table inet filter
  nft list chain inet filter output &>/dev/null || \
    run nft add chain inet filter output \
      '{ type filter hook output priority 0 ; policy accept ; }'

  # Avoid duplicate rules
  if nft list ruleset 2>/dev/null | grep -q "169.254.169.254"; then
    log "nft: metadata block rule already present"
  else
    run nft add rule inet filter output \
      ip daddr 169.254.169.254 counter reject
    local handle
    handle=$(nft -a list chain inet filter output 2>/dev/null \
      | grep "169.254.169.254" \
      | grep -oP '# handle \K\d+' || echo "unknown")
    _manifest_record "nft_rule:${handle}"
    _APPLIED+=("nftables: metadata IP blocked")
  fi
}

_block_via_iptables() {
  if iptables -C OUTPUT -d 169.254.169.254 -j REJECT 2>/dev/null; then
    log "iptables: metadata block rule already present"
  else
    run iptables -I OUTPUT -d 169.254.169.254 -j REJECT
    _manifest_record "iptables_rule:OUTPUT"
    _APPLIED+=("iptables: metadata IP blocked")
  fi
}

_write_service() {
  log "Installing persistent block-metadata.service"
  run tee "$SERVICE_FILE" > /dev/null <<'UNIT'
[Unit]
Description=Block Cloud Metadata IP (169.254.169.254)
Documentation=https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
DefaultDependencies=no
Before=network-online.target
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Re-applies on each boot — handles iptables/nft rule flush
ExecStart=/usr/sbin/iptables -I OUTPUT -d 169.254.169.254 -j REJECT
ExecStop=/usr/sbin/iptables -D OUTPUT -d 169.254.169.254 -j REJECT

[Install]
WantedBy=multi-user.target
UNIT
  run systemctl daemon-reload
  run systemctl enable --now block-metadata.service
  _manifest_record "service:block-metadata.service"
  _APPLIED+=("block-metadata.service installed and enabled")
}

if $INSTALL_SERVICE; then
  _write_service
fi

if command -v nft &>/dev/null; then
  _block_via_nft
else
  _block_via_iptables
fi

###############################################################################
# 3. Regenerate machine-id
###############################################################################
step "Regenerating machine-id"

OLD_ID=$(cat /etc/machine-id 2>/dev/null || echo "none")
run truncate -s 0 /etc/machine-id
run systemd-machine-id-setup
NEW_ID=$(cat /etc/machine-id 2>/dev/null || echo "unknown")
log "machine-id: ${OLD_ID} → ${NEW_ID}"
_APPLIED+=("machine-id regenerated")

###############################################################################
# 4. SSH hardening
###############################################################################
if ! $SKIP_SSH; then
  step "Hardening SSH configuration"

  # Backup only if we haven't already
  if [[ ! -f "$SSHD_BACKUP" ]]; then
    run cp "$SSHD_CONFIG" "$SSHD_BACKUP"
    _manifest_record "sshd_backup:${SSHD_BACKUP}"
    log "sshd_config backed up to ${SSHD_BACKUP}"
  else
    log "sshd_config backup already exists — skipping backup"
  fi

  _apply_sshd() {
    local key="$1" value="$2"
    if $DRY_RUN; then
      dry_log "Would set ${key} ${value} in ${SSHD_CONFIG}"
      return
    fi
    # Remove existing (commented or not), then append cleanly
    sed -i "/^#\?[[:space:]]*${key}[[:space:]]/d" "$SSHD_CONFIG"
    echo "${key} ${value}" >> "$SSHD_CONFIG"
  }

  declare -A SSH_SETTINGS=(
    [PermitRootLogin]="prohibit-password"
    [PasswordAuthentication]="no"
    [PubkeyAuthentication]="yes"
    [PermitEmptyPasswords]="no"
    [AuthorizedKeysFile]=".ssh/authorized_keys"
    [X11Forwarding]="no"
    [AllowAgentForwarding]="no"
    [MaxAuthTries]="3"
    [LoginGraceTime]="30"
    [ClientAliveInterval]="300"
    [ClientAliveCountMax]="2"
    [UsePAM]="yes"
  )

  for key in "${!SSH_SETTINGS[@]}"; do
    _apply_sshd "$key" "${SSH_SETTINGS[$key]}"
  done

  if $DRY_RUN; then
    dry_log "Would validate and restart sshd"
  else
    if ! sshd -t; then
      error "sshd config validation failed — restoring backup"
      cp "$SSHD_BACKUP" "$SSHD_CONFIG"
      die "SSH hardening aborted — original config restored"
    fi
    systemctl restart sshd
    log "sshd restarted with hardened config"
    _APPLIED+=("SSH hardened (${#SSH_SETTINGS[@]} settings applied)")
  fi
else
  warn "--skip-ssh set — skipping SSH hardening"
  _WARNINGS+=("SSH hardening skipped")
fi

###############################################################################
# 5. Base sysctl protections
###############################################################################
step "Writing sysctl hardening rules"

_write_sysctl() {
  if $DRY_RUN; then
    dry_log "Would write sysctl config to ${SYSCTL_FILE}"
    return
  fi

  cat > "$SYSCTL_FILE" <<'SYSCTL'
# Cloud metadata hardening — managed by harden.sh
# Do not edit manually

# Disable local routing tricks that expose metadata
net.ipv4.conf.all.route_localnet = 0
net.ipv4.conf.default.route_localnet = 0

# Disable IP forwarding (workloads, not routers)
net.ipv4.ip_forward = 0

# Harden /proc filesystem access
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# Protect against symlink/hardlink attacks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
SYSCTL

  _manifest_record "sysctl_file:${SYSCTL_FILE}"
  _APPLIED+=("base sysctl protections written")
}

_write_sysctl

###############################################################################
# 6. Raw socket hardening
###############################################################################
if $HARDEN_RAW; then
  step "Applying raw socket / ICMP redirect hardening"

  if $DRY_RUN; then
    dry_log "Would append redirect/accept hardening to ${SYSCTL_FILE}"
  else
    cat >> "$SYSCTL_FILE" <<'SYSCTL_RAW'

# Raw socket / ICMP redirect hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
SYSCTL_RAW
    _APPLIED+=("raw socket / ICMP hardening applied")
  fi
fi

###############################################################################
# 7. Disable unprivileged user namespaces
###############################################################################
if $DISABLE_USERNS; then
  step "Disabling unprivileged user namespaces"

  CURRENT=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "N/A")
  if [[ "$CURRENT" == "0" ]]; then
    log "kernel.unprivileged_userns_clone already 0 — skipping"
  else
    run sysctl -w kernel.unprivileged_userns_clone=0
    if ! $DRY_RUN; then
      echo "kernel.unprivileged_userns_clone = 0" >> "$SYSCTL_FILE"
    fi
    _APPLIED+=("unprivileged user namespaces disabled")
  fi
fi

###############################################################################
# Apply sysctl
###############################################################################
if $DRY_RUN; then
  dry_log "Would apply: sysctl -p ${SYSCTL_FILE}"
else
  sysctl -p "$SYSCTL_FILE" | sed "s/^/  [sysctl] /"
fi

###############################################################################
# 8. Auditd rules
###############################################################################
if $AUDIT_METADATA; then
  step "Installing auditd rules for metadata access detection"

  if ! command -v auditctl &>/dev/null; then
    warn "auditd not found — installing"
    run yum install -y audit
  fi

  if $DRY_RUN; then
    dry_log "Would write audit rules to ${AUDIT_RULES_FILE}"
  else
    mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
    cat > "$AUDIT_RULES_FILE" <<'AUDIT'
## Cloud metadata probe detection — managed by harden.sh
## Logs any process attempting to connect to 169.254.169.254

# syscall-level connect attempts (IPv4, b64)
-a always,exit -F arch=b64 -S connect -k metadata_access
-a always,exit -F arch=b32 -S connect -k metadata_access

# Track curl/wget/python attempting metadata fetches
-w /usr/bin/curl -p x -k metadata_tool
-w /usr/bin/wget -p x -k metadata_tool
-w /usr/bin/python3 -p x -k metadata_tool
AUDIT

    _manifest_record "audit_rules:${AUDIT_RULES_FILE}"

    if command -v augenrules &>/dev/null; then
      augenrules --load
    else
      auditctl -R "$AUDIT_RULES_FILE" || true
    fi

    systemctl enable --now auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    _APPLIED+=("auditd rules installed")
  fi
fi

###############################################################################
# 9. Verification
###############################################################################
step "Verifying metadata access is blocked"

VERIFY_PASS=true

if $DRY_RUN; then
  dry_log "Would test: curl -m 2 http://169.254.169.254"
else
  if curl -s -m 2 http://169.254.169.254 &>/dev/null; then
    warn "⚠ Metadata IP is still reachable!"
    _WARNINGS+=("Metadata IP 169.254.169.254 is still reachable after hardening")
    VERIFY_PASS=false
  else
    log "✓ Metadata IP is blocked"
  fi

  # Verify sysctl applied
  for key in \
    net.ipv4.conf.all.route_localnet \
    net.ipv4.ip_forward \
    kernel.kptr_restrict; do
    val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    log "  sysctl ${key} = ${val}"
  done

  # Verify SSH
  if ! $SKIP_SSH; then
    if sshd -t 2>/dev/null; then
      log "✓ sshd config is valid"
    else
      warn "sshd config failed validation"
      _WARNINGS+=("sshd config validation failed post-hardening")
    fi
  fi
fi

###############################################################################
# 10. Report
###############################################################################
if $REPORT; then
  echo
  echo "════════════════════════════════════════════════════"
  echo "  Cloud Hardening Report"
  echo "  $(hostname) — $(_ts)"
  echo "════════════════════════════════════════════════════"

  echo
  echo "  Applied:"
  if [[ ${#_APPLIED[@]} -eq 0 ]]; then
    echo "    (none)"
  else
    for item in "${_APPLIED[@]}"; do
      echo "    ✓ ${item}"
    done
  fi

  echo
  echo "  Warnings:"
  if [[ ${#_WARNINGS[@]} -eq 0 ]]; then
    echo "    (none)"
  else
    for w in "${_WARNINGS[@]}"; do
      echo "    ⚠ ${w}"
    done
  fi

  echo
  $VERIFY_PASS \
    && echo "  Status: ✓ PASS" \
    || echo "  Status: ⚠ REVIEW REQUIRED"

  echo "════════════════════════════════════════════════════"
  echo "  Log: ${LOG_FILE}"
  echo "  Rollback: sudo bash $0 --rollback"
  echo "════════════════════════════════════════════════════"
  echo
fi

###############################################################################
# Done
###############################################################################
log "Hardening complete"
