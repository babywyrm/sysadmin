#!/bin/sh
##
## https://gist.github.com/yesoreyeram/811b9fb6c337b8b50de56f5479df3a73
##
set -x
set -e
#
# Docker build calls this script to harden the image during build.
#
# NOTE: To build on CircleCI, you must take care to keep the `find`
# command out of the /proc filesystem to avoid errors like:
#
#    find: /proc/tty/driver: Permission denied
#    lxc-start: The container failed to start.
#    lxc-start: Additional information can be obtained by \
#        setting the --logfile and --logpriority options.

adduser -D -s /bin/sh -u 1000 user
sed -i -r 's/^user:!:/user:x:/' /etc/shadow

# Avoid error `Only root may specify -c or -f` when using
# ForceCommand with `-f` option at non-root ssh login.
# https://www.duosecurity.com/docs/duounix-faq#can-i-use-login_duo-to-protect-non-root-shared-accounts,-or-can-i-do-an-install-without-root-privileges?
chmod u-s /usr/sbin/login_duo

# /etc/duo/login_duo.conf must be readable only by user 'user'.
chown user:user /etc/duo/login_duo.conf
chmod 0400 /etc/duo/login_duo.conf

# Ensure strict ownership and perms.
chown root:root /usr/bin/github_pubkeys
chmod 0555 /usr/bin/github_pubkeys

# Be informative after successful login.
echo -e "\n\nApp container image built on $(date)." > /etc/motd

# Improve strength of diffie-hellman-group-exchange-sha256 (Custom DH with SHA2).
# See https://stribika.github.io/2015/01/04/secure-secure-shell.html
#
# Columns in the moduli file are:
# Time Type Tests Tries Size Generator Modulus
#
# This file is provided by the openssh package on Fedora.
moduli=/etc/ssh/moduli
if [[ -f ${moduli} ]]; then
  cp ${moduli} ${moduli}.orig
  awk '$5 >= 2000' ${moduli}.orig > ${moduli}
  rm -f ${moduli}.orig
fi

# Remove existing crontabs, if any.
rm -fr /var/spool/cron
rm -fr /etc/crontabs
rm -fr /etc/periodic

# Remove all but a handful of admin commands.
find /sbin /usr/sbin ! -type d \
  -a ! -name login_duo \
  -a ! -name nologin \
  -a ! -name setup-proxy \
  -a ! -name sshd \
  -a ! -name start.sh \
  -delete

# Remove world-writable permissions.
# This breaks apps that need to write to /tmp,
# such as ssh-agent.
find / -xdev -type d -perm +0002 -exec chmod o-w {} +
find / -xdev -type f -perm +0002 -exec chmod o-w {} +

# Remove unnecessary user accounts.
sed -i -r '/^(user|root|sshd)/!d' /etc/group
sed -i -r '/^(user|root|sshd)/!d' /etc/passwd

# Remove interactive login shell for everybody but user.
sed -i -r '/^user:/! s#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd

sysdirs="
  /bin
  /etc
  /lib
  /sbin
  /usr
"

# Remove apk configs.
find $sysdirs -xdev -regex '.*apk.*' -exec rm -fr {} +

# Remove crufty...
#   /etc/shadow-
#   /etc/passwd-
#   /etc/group-
find $sysdirs -xdev -type f -regex '.*-$' -exec rm -f {} +

# Ensure system dirs are owned by root and not writable by anybody else.
find $sysdirs -xdev -type d \
  -exec chown root:root {} \; \
  -exec chmod 0755 {} \;

# Remove all suid files.
find $sysdirs -xdev -type f -a -perm +4000 -delete

# Remove other programs that could be dangerous.
find $sysdirs -xdev \( \
  -name hexdump -o \
  -name chgrp -o \
  -name chmod -o \
  -name chown -o \
  -name ln -o \
  -name od -o \
  -name strings -o \
  -name su \
  \) -delete

# Remove init scripts since we do not use them.
rm -fr /etc/init.d
rm -fr /lib/rc
rm -fr /etc/conf.d
rm -fr /etc/inittab
rm -fr /etc/runlevels
rm -fr /etc/rc.conf

# Remove kernel tunables since we do not need them.
rm -fr /etc/sysctl*
rm -fr /etc/modprobe.d
rm -fr /etc/modules
rm -fr /etc/mdev.conf
rm -fr /etc/acpi

# Remove root homedir since we do not need it.
rm -fr /root

# Remove fstab since we do not need it.
rm -f /etc/fstab

# Remove broken symlinks (because we removed the targets above).
find $sysdirs -xdev -type l -exec test ! -e {} \; -delete

##
##


alpine-harden.sh
#!/bin/sh

# Credits: 
# https://github.com/ellerbrock/docker-collection/blob/master/dockerfiles/alpine-harden/harden.sh
# https://github.com/HazCod/hardened-alpine/blob/master/Dockerfile

set -euxo pipefail

# Remove existing crontabs, if any.
rm -rf /var/spool/cron
rm -rf /etc/crontabs
rm -rf /etc/periodic

# Remove all but a handful of admin commands.
find /sbin /usr/sbin ! -type d \
  -a ! -name nologin \
  -a ! -name sshd \
  -a ! -name apk \
  -a ! -name adduser \
  -delete

# Remove world-writable permissions.
# This breaks apps that need to write to /tmp,
# such as ssh-agent.
find / -xdev -type d -perm +0002 -exec chmod o-w {} +
find / -xdev -type f -perm +0002 -exec chmod o-w {} +

# Remove unnecessary user accounts.
# check if $APP_USER is set
if [ -z "$APP_USER" ]
then
  sed -i -r "/^(root|sshd)/!d" /etc/group
  sed -i -r "/^(root|sshd)/!d" /etc/passwd
  sed -i -r "/^(root|nobody)/!d" /etc/shadow
else
  sed -i -r "/^(${APP_USER}|root|sshd)/!d" /etc/group
  sed -i -r "/^(${APP_USER}|root|sshd)/!d" /etc/passwd
  sed -i -r "/^(${APP_USER}|root|nobody)/!d" /etc/shadow
  # Remove interactive login shell for everybody but user.
  sed -i -r '/^'${APP_USER}':/! s#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd
  # Remove root home dir
  rm -rf /root
fi

# Disable password login for everybody
while IFS=: read -r username _; do passwd -l "$username"; done < /etc/passwd || true

# Remove temp shadow,passwd,group
find /bin /etc /lib /sbin /usr -xdev -type f -regex '.*-$' -exec rm -f {} +

# Ensure system dirs are owned by root and not writable by anybody else.
find /bin /etc /lib /sbin /usr -xdev -type d \
  -exec chown root:root {} \; \
  -exec chmod 0755 {} \;

sysdirs="
  /bin
  /etc
  /lib
  /sbin
  /usr
"

# Remove other programs that could be dangerous.
find $sysdirs -xdev \( \
  -name hexdump -o \
  -name chgrp -o \
  -name chmod -o \
  -name chown -o \
  -name od -o \
  -name strings -o \
  -name su \
  \) -delete

# Remove init scripts since we do not use them.
rm -rf /etc/init.d
rm -rf /lib/rc
rm -rf /etc/conf.d
rm -rf /etc/inittab
rm -rf /etc/runlevels
rm -rf /etc/rc.conf

# Remove kernel tunables since we do not need them.
rm -rf /etc/sysctl*
rm -rf /etc/modprobe.d
rm -rf /etc/modules
rm -rf /etc/mdev.conf
rm -rf /etc/acpi

# Remove fstab
rm -f /etc/fstab

# Remove any symlinks that we broke during previous steps
find /bin /etc /lib /sbin /usr -xdev -type l -exec test ! -e {} \; -delete

# remove this file
rm -f "$0"
alpine-post-install.sh
#!/bin/sh

set -euxo pipefail

# remove adduser
rm -f /usr/sbin/adduser

# remove apk package manager
find / -type f -iname '*apk*' -xdev -delete
find / -type d -iname '*apk*' -print0 -xdev | xargs -0 rm -r --

# remove root directory
rm -rf /root

# finally remove this file
rm -f "$0"
