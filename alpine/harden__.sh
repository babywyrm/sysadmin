#!/bin/sh
# ==============================================================================
# alpine-harden.sh — Alpine Linux container hardening script
# ==============================================================================
#
# USAGE:
#   COPY alpine-harden.sh /tmp/alpine-harden.sh
#   RUN sh /tmp/alpine-harden.sh && rm -f /tmp/alpine-harden.sh
#
# ENVIRONMENT:
#   APP_USER      Username to create/retain  (default: appuser)
#   APP_UID       UID to assign to APP_USER  (default: 1000)
#   KEEP_SSH      Set to 1 to retain sshd    (default: 0)
#   MIN_DH_BITS   Minimum DH moduli bit size (default: 3072)
#
# NOTES:
#   - Designed for hardened Docker/OCI containers, not general-purpose VMs.
#   - Removes many standard utilities intentionally. Do not run on bare metal.
#   - Review all sections before use. Behaviour is destructive by design.
#
# ==============================================================================

set -eu
# pipefail is not POSIX sh — use explicit checks where needed
IFS="$(printf ' \t\n')"

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
APP_USER="${APP_USER:-appuser}"
APP_UID="${APP_UID:-1000}"
KEEP_SSH="${KEEP_SSH:-0}"
MIN_DH_BITS="${MIN_DH_BITS:-3072}"

SYSDIRS="/bin /etc /lib /sbin /usr"
SENSITIVE_DIRS="/tmp /dev /run /proc /sys"

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
log()  { printf '[INFO]  %s\n' "$*"; }
warn() { printf '[WARN]  %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

step() {
    printf '\n-- %s\n' "$*"
    printf '   %.0s-' $(seq 1 60)
    printf '\n'
}

# ------------------------------------------------------------------------------
# Preflight checks
# ------------------------------------------------------------------------------
step "Preflight checks"

if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root."
fi

if [ ! -f /etc/alpine-release ]; then
    die "This script is intended for Alpine Linux only."
fi

ALPINE_VERSION="$(cat /etc/alpine-release)"
log "Alpine version: $ALPINE_VERSION"
log "Hardening started at: $TIMESTAMP"
log "APP_USER=$APP_USER  APP_UID=$APP_UID  KEEP_SSH=$KEEP_SSH  MIN_DH_BITS=$MIN_DH_BITS"

# Validate APP_USER — alphanumeric + dash/underscore only
case "$APP_USER" in
    *[!a-zA-Z0-9_-]*) die "APP_USER contains invalid characters: $APP_USER" ;;
esac

# Validate APP_UID is a positive integer
case "$APP_UID" in
    *[!0-9]*|'') die "APP_UID must be a positive integer: $APP_UID" ;;
esac

if [ "$APP_UID" -lt 100 ]; then
    die "APP_UID $APP_UID is dangerously low. Use >= 100."
fi

# ------------------------------------------------------------------------------
# 1. Create non-root application user
# ------------------------------------------------------------------------------
step "Creating application user"

if id "$APP_USER" >/dev/null 2>&1; then
    log "User '$APP_USER' already exists — skipping creation."
else
    adduser -D -s /bin/sh -u "$APP_UID" "$APP_USER"
    # Replace locked '!' with 'x' so PAM-less tools don't trip over it
    sed -i -r "s|^${APP_USER}:!|${APP_USER}:x|" /etc/shadow
    log "Created user '$APP_USER' with UID $APP_UID."
fi

# ------------------------------------------------------------------------------
# 2. Remove cron and periodic task infrastructure
# ------------------------------------------------------------------------------
step "Removing cron and periodic tasks"

rm -rf \
    /var/spool/cron \
    /etc/crontabs \
    /etc/periodic

log "Cron infrastructure removed."

# ------------------------------------------------------------------------------
# 3. Strip unnecessary sbin utilities
# ------------------------------------------------------------------------------
step "Stripping sbin utilities"

# Build the exclusion list dynamically
SBIN_KEEP="-name nologin"
if [ "$KEEP_SSH" = "1" ]; then
    SBIN_KEEP="$SBIN_KEEP -o -name sshd"
    log "KEEP_SSH=1 — retaining sshd."
fi

find /sbin /usr/sbin ! -type d \
    ! \( $SBIN_KEEP \) \
    -delete 2>/dev/null || true

log "sbin utilities stripped."

# ------------------------------------------------------------------------------
# 4. Remove world-writable permissions
# ------------------------------------------------------------------------------
step "Removing world-writable permissions"

# Directories — skip known-safe paths
find / -xdev -type d -perm -0002 \
    ! -path /tmp \
    ! -path /dev \
    ! -path /run \
    ! -path /proc \
    ! -path /sys \
    -exec chmod o-w {} + 2>/dev/null || true

# Files — no exceptions
find / -xdev -type f -perm -0002 \
    -exec chmod o-w {} + 2>/dev/null || true

# Restore /tmp sticky bit
chmod 1777 /tmp
log "World-writable permissions removed. /tmp sticky bit set."

# ------------------------------------------------------------------------------
# 5. Restrict /etc/passwd, /etc/group, /etc/shadow
# ------------------------------------------------------------------------------
step "Restricting user accounts"

if [ "$KEEP_SSH" = "1" ]; then
    KEEP_USERS="${APP_USER}|root|sshd|nobody"
else
    KEEP_USERS="${APP_USER}|root|nobody"
fi

# Retain only required users in passwd and group
sed -i -r "/^(${KEEP_USERS})/!d" /etc/passwd
sed -i -r "/^(${KEEP_USERS})/!d" /etc/group
sed -i -r "/^(${KEEP_USERS})/!d" /etc/shadow

# Set shell to /sbin/nologin for all users except APP_USER and root
sed -i -r \
    "/^(${APP_USER}:|root:)/! s|^([^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*):[^:]*$|\1:/sbin/nologin|" \
    /etc/passwd

# Lock all passwords
awk -F: '{print $1}' /etc/passwd | while read -r u; do
    passwd -l "$u" 2>/dev/null || true
done

log "User accounts restricted."

# ------------------------------------------------------------------------------
# 6. Harden SSH configuration and DH moduli
# ------------------------------------------------------------------------------
step "Hardening SSH"

if [ "$KEEP_SSH" = "1" ]; then
    # Filter weak DH groups
    if [ -f /etc/ssh/moduli ]; then
        awk -v bits="$MIN_DH_BITS" '$5 >= bits' \
            /etc/ssh/moduli > /etc/ssh/moduli.safe

        if [ -s /etc/ssh/moduli.safe ]; then
            mv /etc/ssh/moduli.safe /etc/ssh/moduli
            log "SSH moduli filtered to >= $MIN_DH_BITS bits."
        else
            rm -f /etc/ssh/moduli.safe
            warn "No moduli >= $MIN_DH_BITS bits found — original file retained."
        fi
    fi

    # Harden sshd_config if present
    if [ -f /etc/ssh/sshd_config ]; then
        cat >> /etc/ssh/sshd_config <<'SSHEOF'

# --- Appended by alpine-harden.sh ---
Protocol 2
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
PrintMotd yes
# ------------------------------------
SSHEOF
        log "sshd_config hardened."
    fi
else
    log "KEEP_SSH=0 — SSH hardening skipped."
fi

# ------------------------------------------------------------------------------
# 7. Lock down system directory ownership and permissions
# ------------------------------------------------------------------------------
step "Locking down system directories"

for d in $SYSDIRS; do
    if [ -d "$d" ]; then
        chown root:root "$d"
        chmod 0755 "$d"
    fi
done

# Remove apk metadata and editor backup files
find $SYSDIRS -xdev -type f -name '*~'    -delete 2>/dev/null || true
find $SYSDIRS -xdev -type f -name '*.bak' -delete 2>/dev/null || true
find $SYSDIRS -xdev -type f -name '*.orig' -delete 2>/dev/null || true
find $SYSDIRS -xdev -regex '.*apk.*'      -delete 2>/dev/null || true

log "System directory permissions set."

# ------------------------------------------------------------------------------
# 8. Remove dangerous utilities and all SUID/SGID binaries
# ------------------------------------------------------------------------------
step "Removing dangerous utilities and SUID/SGID binaries"

DANGEROUS_TOOLS="
    hexdump chgrp chmod chown ln od strings su
    curl wget nc netcat nmap tcpdump strace ltrace
    gcc cc g++ make gdb python python2 python3
    perl ruby lua php
"

for tool in $DANGEROUS_TOOLS; do
    find $SYSDIRS -xdev -name "$tool" -type f -delete 2>/dev/null || true
done

# Remove all SUID and SGID binaries
find $SYSDIRS -xdev -type f \( -perm -4000 -o -perm -2000 \) -delete 2>/dev/null || true

log "Dangerous utilities and SUID/SGID binaries removed."

# ------------------------------------------------------------------------------
# 9. Remove init, rc, and system management infrastructure
# ------------------------------------------------------------------------------
step "Removing init and rc infrastructure"

rm -rf \
    /etc/init.d \
    /lib/rc \
    /etc/conf.d \
    /etc/inittab \
    /etc/runlevels \
    /etc/rc.conf \
    /etc/sysctl* \
    /etc/modprobe.d \
    /etc/modules \
    /etc/mdev.conf \
    /etc/acpi \
    /etc/fstab

log "Init and rc infrastructure removed."

# ------------------------------------------------------------------------------
# 10. Final cleanup
# ------------------------------------------------------------------------------
step "Final cleanup"

rm -rf \
    /root \
    /tmp/apk* \
    /var/cache/apk/* \
    /var/log/* \
    /usr/share/man \
    /usr/share/doc \
    /usr/share/info \
    /usr/share/locale

# Remove dangling symlinks in system dirs
find $SYSDIRS -xdev -type l ! -exec test -e {} \; -delete 2>/dev/null || true

log "Cleanup complete."

# ------------------------------------------------------------------------------
# 11. Write MOTD
# ------------------------------------------------------------------------------
step "Writing MOTD"

cat > /etc/motd <<EOF
=====================================================
  Hardened Alpine Image
  Alpine: $ALPINE_VERSION
  Built:  $TIMESTAMP
  User:   $APP_USER (UID $APP_UID)
  SSH:    $([ "$KEEP_SSH" = "1" ] && echo enabled || echo disabled)
=====================================================
EOF

log "MOTD written."

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------
printf '\n[INFO]  Alpine hardening complete at %s.\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Self-destruct
rm -f -- "$0"
