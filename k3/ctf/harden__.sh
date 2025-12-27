#!/usr/bin/env bash
#
# ctf_assure.sh
#
# Purpose:
#   Hardening + audit script for Linux hosts.
#   Designed to ensure ONLY the intended exploit chain exists.
#
# Philosophy:
#   - Audit first, enforce second
#   - Dry-run safe
#   - Reviewer-readable output
#   - No magic, no guessing
#
# Tested on:
#   Ubuntu 20.04 / 22.04
#   K3s / container-aware hosts
#

set -euo pipefail

### =============================
### Configuration
### =============================

INTENDED_USER="person_thing_probably_"
DRY_RUN="${DRY_RUN:-true}"   # default safe mode

DANGEROUS_PKGS=(
  policykit-1
  pkexec
  sudo
)

HIGH_RISK_GROUPS=(
  sudo admin wheel
  docker lxd
  disk adm
  systemd-journal
  kvm libvirt
  netdev
  k3s microk8s
)

LOG_PREFIX="[CTF-ASSURE]"

### =============================
### Output helpers
### =============================

ok()   { echo -e "${LOG_PREFIX} \033[32m[OK]\033[0m $*"; }
warn() { echo -e "${LOG_PREFIX} \033[33m[WARN]\033[0m $*"; }
fail() { echo -e "${LOG_PREFIX} \033[31m[FAIL]\033[0m $*"; }

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${LOG_PREFIX} \033[36m[DRY-RUN]\033[0m $*"
  else
    eval "$@"
  fi
}

### =============================
### 1. Package-level privilege checks
### =============================

ok "Auditing dangerous privilege-escalation packages"

for pkg in "${DANGEROUS_PKGS[@]}"; do
  if dpkg -l 2>/dev/null | grep -q "^ii\s\+$pkg"; then
    warn "Dangerous package installed: $pkg"
    run "apt purge -y $pkg"
  else
    ok "$pkg not installed"
  fi
done

### =============================
### 2. Runtime process validation
### =============================

ok "Checking for polkit / pkexec processes"

if ps aux | grep -E 'polkit|pkexec' | grep -v grep >/dev/null; then
  fail "polkit-related process still running"
else
  ok "No polkit-related processes running"
fi

### =============================
### 3. SUID binary audit
### =============================

ok "Enumerating SUID binaries"

SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null || true)

echo "$SUID_BINS"

echo "$SUID_BINS" | grep -vE '^/usr/(bin|sbin)/(su|passwd|chsh|chfn|gpasswd|newgrp)$' \
  && warn "Unexpected SUID binaries detected" \
  || ok "SUID binaries restricted to expected baseline"

### =============================
### 4. Linux capabilities audit
### =============================

ok "Auditing file capabilities"

if command -v getcap >/dev/null; then
  CAPS=$(getcap -r / 2>/dev/null || true)
  echo "$CAPS"

  echo "$CAPS" | grep -vE '(ping|mtr-packet)' \
    && warn "Unexpected file capabilities found" \
    || ok "Capabilities restricted to expected binaries"
else
  warn "getcap not installed"
fi

### =============================
### 5. User group membership audit
### =============================

check_user_groups() {
  local user="$1"
  local groups

  if ! id "$user" &>/dev/null; then
    warn "User $user does not exist"
    return
  fi

  groups=$(id -nG "$user")
  ok "User $user groups: $groups"

  for g in "${HIGH_RISK_GROUPS[@]}"; do
    if echo "$groups" | tr ' ' '\n' | grep -qx "$g"; then
      warn "User $user belongs to HIGH-RISK group: $g"
    fi
  done
}

ok "Auditing group memberships"

check_user_groups root
check_user_groups "$INTENDED_USER"

### =============================
### 6. Writable path & PATH injection audit
### =============================

ok "Checking world-writable directories in PATH"

echo "$PATH" | tr ':' '\n' | while read -r p; do
  [[ -d "$p" ]] || continue
  if find "$p" -maxdepth 1 -type d -perm -002 2>/dev/null | grep -q .; then
    warn "World-writable directory in PATH: $p"
  fi
done

### =============================
### 7. Systemd timers audit
### =============================

ok "Auditing systemd timers"

systemctl list-timers --all

if systemctl list-timers --all | grep -q wp_loop.timer; then
  ok "Custom wp_loop.timer detected (expected)"
  systemctl cat wp_loop.timer
  systemctl cat wp_loop.service
else
  warn "wp_loop.timer not found"
fi

### =============================
### 8. Listening services audit
### =============================

ok "Checking listening TCP/UDP sockets"

ss -tulpen

### =============================
### 9. Kernel & namespace sanity
### =============================

ok "Kernel and namespace configuration"

uname -a
sysctl kernel.unprivileged_userns_clone 2>/dev/null || true

### =============================
### 10. WordPress hardening confirmation
### =============================

ok "Verifying WordPress file modification locks"

WP_CONFIG=$(find /var/lib/rancher/k3s/storage -name wp-config.php 2>/dev/null | head -1)

if [[ -n "$WP_CONFIG" ]]; then
  grep -E "DISALLOW_FILE_MODS|DISALLOW_FILE_EDIT" "$WP_CONFIG" \
    && ok "WordPress plugin/theme edits disabled" \
    || warn "WordPress file edits NOT locked down"
else
  warn "wp-config.php not found"
fi

### =============================
### Summary
### =============================

ok "CTF assurance audit complete"

if [[ "$DRY_RUN" == "true" ]]; then
  echo
  warn "Script ran in DRY-RUN mode — no changes applied"
  echo "Set DRY_RUN=false to enforce removals"
fi
