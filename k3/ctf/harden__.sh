#!/usr/bin/env bash
set -euo pipefail

echo "[*] Starting CTF hardening checks..."

### --- CONFIG ---
INTENDED_USER="some_person_probably_"
INTENDED_SUID_ALLOWLIST=(
  /usr/bin/su
  /usr/bin/passwd
  /usr/bin/chsh
  /usr/bin/chfn
  /usr/bin/gpasswd
  /usr/lib/openssh/ssh-keysign
)
DANGEROUS_PKGS=(
  policykit-1
  pkexec
  sudo
)

### --- HELPERS ---
log() { echo "[+] $1"; }
warn() { echo "[!] $1"; }
die() { echo "[X] $1"; exit 1; }

### --- 1. Remove dangerous packages if present ---
for pkg in "${DANGEROUS_PKGS[@]}"; do
  if dpkg -l | grep -q "^ii\s\+$pkg"; then
    warn "Removing dangerous package: $pkg"
    apt purge -y "$pkg"
  fi
done

### --- 2. Verify sudo truly unusable ---
if command -v sudo &>/dev/null; then
  die "sudo still present!"
else
  log "sudo not present"
fi

### --- 3. Audit setuid binaries ---
log "Auditing setuid binaries..."
FOUND_SUID=$(find / -perm -4000 -type f 2>/dev/null || true)

for bin in $FOUND_SUID; do
  if [[ ! " ${INTENDED_SUID_ALLOWLIST[*]} " =~ " $bin " ]]; then
    warn "Unexpected SUID binary: $bin"
  fi
done

### --- 4. Capabilities audit ---
log "Auditing file capabilities..."
getcap -r / 2>/dev/null || log "No capabilities found"

### --- 5. Lock down bash history ---
for user in root "$INTENDED_USER"; do
  HIST="/home/$user/.bash_history"
  [[ "$user" == "root" ]] && HIST="/root/.bash_history"

  if [[ -f "$HIST" ]]; then
    warn "Removing bash history for $user"
    rm -f "$HIST"
    ln -sf /dev/null "$HIST"
  fi
done

### --- 6. Verify PATH safety ---
log "Checking PATH for world-writable directories..."
echo "$PATH" | tr ':' '\n' | while read -r d; do
  [[ -d "$d" ]] || continue
  if stat -c '%a' "$d" | grep -q '[2367]$'; then
    warn "World-writable PATH dir: $d"
  fi
done

### --- 7. WordPress safety checks ---
WP_CFG=$(find /var/lib/rancher/k3s/storage -name wp-config.php 2>/dev/null | head -n1 || true)
if [[ -n "$WP_CFG" ]]; then
  grep -q "DISALLOW_FILE_MODS.*true" "$WP_CFG" \
    && log "WordPress plugin installs disabled" \
    || warn "WordPress plugin installs NOT disabled"
fi

### --- 8. systemd timer sanity ---
log "Checking custom systemd services..."
systemctl list-timers --all | grep -vE 'apt|logrotate|man-db|plocate|motd' || true

### --- DONE ---
log "CTF hardening checks complete"
