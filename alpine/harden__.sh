#!/bin/sh
#
# Alpine Linux hardening script — 2025 Edition
# Inspired by:
#   - https://github.com/HazCod/hardened-alpine
#   - https://github.com/ellerbrock/docker-collection
#   - https://stribika.github.io/2015/01/04/secure-secure-shell.html
#
# Usage:
#   RUN ./alpine-harden.sh && rm -f ./alpine-harden.sh
#

set -euo pipefail
IFS="$(printf ' \t\n')"

echo "[+] Starting Alpine hardening at $(date -u)"

APP_USER="${APP_USER:-user}"
APP_UID="${APP_UID:-1000}"

# -----------------------------------------------------------------------------
# 1. Create non-root user
# -----------------------------------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
    adduser -D -s /bin/sh -u "$APP_UID" "$APP_USER"
    sed -i -r "s/^${APP_USER}:!/${APP_USER}:x/" /etc/shadow
fi

# -----------------------------------------------------------------------------
# 2. Remove cron jobs and periodic tasks
# -----------------------------------------------------------------------------
rm -rf /var/spool/cron /etc/crontabs /etc/periodic

# -----------------------------------------------------------------------------
# 3. Remove unnecessary admin utilities (retain bare minimum)
# -----------------------------------------------------------------------------
find /sbin /usr/sbin ! -type d \
  -a ! -name nologin \
  -a ! -name sshd \
  -a ! -name adduser \
  -a ! -name login_duo \
  -delete 2>/dev/null || true

# -----------------------------------------------------------------------------
# 4. Remove world-writable permissions except for /tmp
# -----------------------------------------------------------------------------
find / -xdev -type d -perm -0002 ! -path /tmp -exec chmod o-w {} +
find / -xdev -type f -perm -0002 -exec chmod o-w {} +

chmod 1777 /tmp  # restore sticky bit

# -----------------------------------------------------------------------------
# 5. Restrict user accounts
# -----------------------------------------------------------------------------
if [ -n "$APP_USER" ]; then
    sed -i -r "/^(${APP_USER}|root|sshd)/!d" /etc/group
    sed -i -r "/^(${APP_USER}|root|sshd)/!d" /etc/passwd
    sed -i -r "/^(${APP_USER}|root|nobody)/!d" /etc/shadow
    sed -i -r "/^${APP_USER}:/! s#^\([^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*\):[^:]*#\1:/sbin/nologin#" /etc/passwd
else
    sed -i -r '/^(root|sshd)/!d' /etc/{passwd,group,shadow}
fi

# Disable password login completely
awk -F: '{print $1}' /etc/passwd | while read -r u; do passwd -l "$u" 2>/dev/null || true; done

# -----------------------------------------------------------------------------
# 6. Harden SSH moduli for strong DH groups
# -----------------------------------------------------------------------------
if [ -f /etc/ssh/moduli ]; then
    awk '$5 >= 2000' /etc/ssh/moduli > /etc/ssh/moduli.safe
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
fi

# -----------------------------------------------------------------------------
# 7. Lock down system directories
# -----------------------------------------------------------------------------
sysdirs="/bin /etc /lib /sbin /usr"
for d in $sysdirs; do
    chown root:root "$d"
    chmod 0755 "$d"
done

# Remove backup files and apk metadata
find $sysdirs -xdev -type f -regex '.*-$' -delete
find $sysdirs -xdev -regex '.*apk.*' -delete

# -----------------------------------------------------------------------------
# 8. Remove dangerous or unneeded tools
# -----------------------------------------------------------------------------
find $sysdirs -xdev \( \
  -name hexdump -o \
  -name chgrp   -o \
  -name chmod   -o \
  -name chown   -o \
  -name ln      -o \
  -name od      -o \
  -name strings -o \
  -name su      \
\) -delete 2>/dev/null || true

# Remove all suid files
find $sysdirs -xdev -type f -perm -4000 -delete

# -----------------------------------------------------------------------------
# 9. Remove init/system configuration junk
# -----------------------------------------------------------------------------
rm -rf /etc/init.d /lib/rc /etc/conf.d /etc/inittab /etc/runlevels /etc/rc.conf
rm -rf /etc/sysctl* /etc/modprobe.d /etc/modules /etc/mdev.conf /etc/acpi
rm -f /etc/fstab

# -----------------------------------------------------------------------------
# 10. Housekeeping: cleanup and MOTD
# -----------------------------------------------------------------------------
rm -rf /root /etc/fstab /tmp/apk* /var/cache/apk/*
find $sysdirs -xdev -type l -exec test ! -e {} \; -delete

cat <<EOF > /etc/motd

=========================================================
 Hardened Alpine Image
 Built on: $(date -u)
 User: $APP_USER
=========================================================

EOF

echo "[+] Alpine hardening complete."
rm -f -- "$0"
