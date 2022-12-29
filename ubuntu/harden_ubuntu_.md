# Ubuntu-Server-Hardening

##
##

### 1. Secure Shared Memory
#### What is shared memory?
Shared memory is an efficient means of passing data between programs. Because two or more processes can use the same memory space, it has been discovered that, since shared memory is, by default, mounted as ` read/write`, the `/run/shm` space can be easily exploited.
 That translates to a weakened state of security.
 
 
If you’re unaware, shared memory can be used in an attack against a running service. Because of this, you’ll want to secure that portion of system memory. 

You can do this by modifying the `/etc/fstab` file.	
	
	sudo vim /etc/fstab 

Next, add the following line to the bottom of that file:

```bash
tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0
```
Save and close the file. In order for the changes to take effect, you must reboot the server with the command:

```bash
sudo reboot
```


### 2. Avoid Using FTP, Telnet, And Rlogin / Rsh Services on Linux
Under most network configurations, user names, passwords, `FTP / telnet / rsh`  commands and transferred files can be captured by anyone on the same network using a packet sniffer. The common solution to this problem is to use either `OpenSSH , SFTP, or FTPS (FTP over SSL),` which adds `SSL or TLS encryption to FTP`.
 
 Type the following command to delete NIS, rsh and other outdated service:
 ```bash
 sudo apt --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server
 ```

### 3. Make Sure No Non-Root Accounts Have UID Set To 0
Only root account have UID 0 with full permissions to access the system. Type the following command to display all accounts with UID set to 0:
````bash
awk -F: '($3 == "0") {print}' /etc/passwd
````
You should only see one line as follows:
```bash
root:x:0:0:root:/root:/bin/bash
```
### 4. Disable root login

Never ever login as root user. 
You should use sudo to execute root level commands as and when required. 
sudo does greatly enhances the security of the system without sharing root password with other users and admins.
sudo provides simple [auditing and tracking](https://www.cyberciti.biz/faq/sudo-send-e-mail-sudo-log-file/) features too
To disable root ssh access by editing `/etc/ssh/sshd_config` to contain:
```bash
sudo vim /etc/ssh/sshd_config
and set 
PermitRootLogin no
```

### 5. Enable SSH Login for Specific Users Only

Secure Shell (SSH) is the tool you’ll use to log into your remote Linux servers. 
Although SSH is fairly secure, by default, you can make it even more so, by enabling SSH login only for specific users. Let's say you want to only allow SSH entry for the user abc, from IP address 192.168.1.12. Here's how you would do this.

* Open a terminal window.
* Open the ssh config file for editing with the command `sudo vim /etc/ssh/sshd_config`.
* At the bottom of the file, add the line `AllowUsers abc@192.168.1.12`.
* Save and close the file.
* Restart `sshd` with the command `sudo systemctl restart sshd`.

Secure Shell will now only allow entry by user abc, from IP address 192.168.1.12. If a user, other than abc, attempts to SSH into the server, they will be prompted for a password, but the password will not be accepted (regardless if it's correct), and entrance will be denied.


### 6. Install fail2ban
The fail2ban system is an intrusion prevention system that monitors log files and searches for particular patterns that correspond to a failed login attempt. If a certain number of failed logins are detected from a specific IP address (within a specified amount of time), fail2ban will block access from that IP address.

To install fail2ban, open a terminal window and issue the command:
```bash
sudo apt install fail2ban
```
Within the directory /etc/fail2ban, you'll find the main configuration file, jail.conf. Also in that directory is the subdirectory, jail.d. The jail.conf file is the main configuration file and jail.d contains the secondary configuration files. Do not edit the jail.conf file. Instead, we’ll create a new configuration that will monitor SSH logins with the command:
```bash
sudo vim /etc/fail2ban/jail.local
```
In this new file add the following contents:
```bash
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
```
This configuration does the following:
* Enables the jail.
* Sets the SSH port to be monitored to 22.
* Uses the sshd filter.
* Sets the log file to be monitored.

Save and close that file. Restart fail2ban with the command:
```bash
sudo systemctl restart fail2ban
```

### 7. Physical server security
You must protect Linux servers physical console access. 
Configure the BIOS and disable the booting from external devices such as DVDs / CDs / USB pen. Set BIOS and grub boot loader password to protect these settings. All production boxes must be locked in IDCs (Internet Data Centers) and all persons must pass some sort of security checks before accessing your server.


#### Credits: 
* https://tek.io/2MhT1Re
* http://bit.ly/2VlX2s1
* http://bit.ly/2IwCpnw

##
##

## FOCAL ##

#!/bin/bash
# =============================================================================
# Harden Ubuntu Linux 20.04 (focal)
# Run commands as root (sudo su -)
# -----------------------------------------------------------------------------
# Developer.......: Andre Essing (https://www.andre-essing.de/)
#                                (https://github.com/aessing)
#                                (https://twitter.com/aessing)
#                                (https://www.linkedin.com/in/aessing/)
# -----------------------------------------------------------------------------
# THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# =============================================================================

# Set some variables
ADMINUSER='ubuntu'
ADMINNETWORK='192.168.1.0/24'
QUEMU_INSTALL='false'
SWAP_SIZE_MB=4096
TIMEZONE='Europe/Berlin'
NTPSERVER='de.pool.ntp.org'

# Set some variables that normally don't need to be changed
APT_INSTALL='auditd audispd-plugins fail2ban usbguard'
APT_PURGE='apport* autofs avahi* beep git pastebinit popularity-contest rsh* rsync talk* telnet* tftp* whoopsie xinetd yp-tools popularity-contest ubuntu-report'

CONFIG_ACCESS='/etc/security/access.conf'
CONFIG_ADDUSER='/etc/adduser.conf'
CONFIG_AUDITD='/etc/audit/auditd.conf'
CONFIG_AUDITDRULES='/etc/audit/rules.d/audit.rules'
CONFIG_AUDITDSERVICE='/lib/systemd/system/auditd.service'
CONFIG_AUTOUPDATE='/etc/apt/apt.conf.d/50unattended-upgrades'
CONFIG_DISABLENET='/etc/modprobe.d/CONFIG_DISABLENET.conf'
CONFIG_DISABLEFS='/etc/modprobe.d/CONFIG_DISABLEFS.conf'
CONFIG_DISABLEMOD='/etc/modprobe.d/CONFIG_DISABLEMOD.conf'
CONFIG_FAIL2BAN='/etc/fail2ban/jail.local'
CONFIG_LOGIN='/etc/login.defs'
CONFIG_MOTDNEWS='/etc/default/motd-news'
CONFIG_SECURETTY='/etc/securetty'
CONFIG_SSHD='/etc/ssh/sshd_config'
CONFIG_SYSCTL='/etc/sysctl.conf'
CONFIG_SYSTEM='/etc/systemd/system.conf'
CONFIG_TIME='/etc/systemd/timesyncd.conf'
CONFIG_UFW='/etc/default/ufw'
CONFIG_USBGUARDRULES='/etc/usbguard/rules.conf'
CONFIG_USERADD='/etc/default/useradd'

CONFIG_DISABLENET_MODULES='dccp sctp rds tipc'
CONFIG_DISABLEFS_MODULES='cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat'
CONFIG_DISABLEMOD_MODULES='bluetooth bnep btusb cpia2 firewire-core floppy n_hdlc net-pf-31 pcspkr soundcore thunderbolt usb-midi usb-storage uvcvideo v4l2_common'

SWAP_FILE='/swap.img'

###############################################################################
############################# MAGIC STARTS HERE ###############################
###############################################################################

# Update, install and uninstall requires packages
apt update -y
apt purge -y $APT_PURGE
apt-get install -y --no-install-recommends $APT_INSTALL
apt dist-upgrade -y
apt autoremove -y
apt autoclean -y

# Enable firewall
sed -i 's/IPV6=.*/IPV6=no/' "$CONFIG_UFW"
sed -i 's/IPT_SYSCTL=.*/IPT_SYSCTL=\/etc\/sysctl\.conf/' "$CONFIG_UFW"
ufw allow in on lo
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw deny from any to 224.0.0.1
ufw allow log from $ADMINNETWORK to any port 22 proto tcp
ufw default deny incoming
ufw --force enable

# Configure auto-update
sed -i -e 's/\/\/.*"\${distro_id}:\${distro_codename}-updates";/\t\"\${distro_id}:\${distro_codename}-updates\";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::AutoFixInterruptedDpkg.*;/Unattended-Upgrade::AutoFixInterruptedDpkg "true";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::Remove-Unused-Kernel-Packages.*;/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::Remove-Unused-Dependencies.*;/Unattended-Upgrade::Remove-Unused-Dependencies "true";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::Remove-New-Unused-Dependencies.*;/Unattended-Upgrade::Remove-New-Unused-Dependencies "true";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::Automatic-Reboot[^-].*;/Unattended-Upgrade::Automatic-Reboot "true";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::Automatic-Reboot-Time.*;/Unattended-Upgrade::Automatic-Reboot-Time "02:00";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::SyslogEnable.*;/Unattended-Upgrade::SyslogEnable "true";/' "$CONFIG_AUTOUPDATE"
sed -i -e 's/\/\/.*Unattended-Upgrade::SyslogFacility.*;/Unattended-Upgrade::SyslogFacility "upgrade";/' "$CONFIG_AUTOUPDATE"
systemctl restart unattended-upgrades.service

# Harden SSH
groupadd -r sshd_users
usermod -G sshd_users -a $ADMINUSER
sed -i -e 's/^Include \/etc\/ssh\/sshd_config.d\/\*.conf/#Include \/etc\/ssh\/sshd_config.d\/\*.conf/' "$CONFIG_SSHD"
sed -i -e 's/.*RekeyLimit.*/RekeyLimit 512M 1h/' "$CONFIG_SSHD"
sed -i -e 's/#LogLevel.*/LogLevel VERBOSE/' "$CONFIG_SSHD"
sed -i -e 's/#LoginGraceTime.*/LoginGraceTime 30s/' "$CONFIG_SSHD"
sed -i -e 's/#PermitRootLogin.*/PermitRootLogin no/' "$CONFIG_SSHD"
sed -i -e 's/#StrictModes.*/StrictModes yes/' "$CONFIG_SSHD"
sed -i -e 's/#MaxAuthTries.*/MaxAuthTries 3/' "$CONFIG_SSHD"
sed -i -e 's/#MaxSessions.*/MaxSessions 3/' "$CONFIG_SSHD"
sed -i -e 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' "$CONFIG_SSHD"
sed -i -e 's/#AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/' "$CONFIG_SSHD"
sed -i -e 's/#PasswordAuthentication.*/PasswordAuthentication no/' "$CONFIG_SSHD"
sed -i -e 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$CONFIG_SSHD"
sed -i -e 's/#AllowAgentForwarding.*/AllowAgentForwarding no/' "$CONFIG_SSHD"
sed -i -e 's/#AllowTcpForwarding.*/AllowTcpForwarding no/' "$CONFIG_SSHD"
sed -i -e 's/#GatewayPorts.*/GatewayPorts no/' "$CONFIG_SSHD"
sed -i -e 's/X11Forwarding.*/X11Forwarding no/' "$CONFIG_SSHD"
sed -i -e 's/#PrintLastLog.*/PrintLastLog yes/' "$CONFIG_SSHD"
sed -i -e 's/#TCPKeepAlive.*/TCPKeepAlive no/' "$CONFIG_SSHD"
sed -i -e 's/#PermitUserEnvironment.*/PermitUserEnvironment no/' "$CONFIG_SSHD"
sed -i -e 's/#Compression.*/Compression no/' "$CONFIG_SSHD"
sed -i -e 's/#ClientAliveCountMax.*/ClientAliveCountMax 2/' "$CONFIG_SSHD"
sed -i -e 's/#ClientAliveInterval.*/ClientAliveInterval 300/' "$CONFIG_SSHD"
sed -i -e 's/#UseDNS.*/UseDNS no/' "$CONFIG_SSHD"
sed -i -e 's/#MaxStartups.*/MaxStartups 10:30:60/' "$CONFIG_SSHD"
sed -i -e 's/#PermitTunnel.*/PermitTunnel no/' "$CONFIG_SSHD"
sed -i -e 's/#IgnoreUserKnownHosts.*/IgnoreUserKnownHosts yes/' "$CONFIG_SSHD"
sed -i -e 's/#HostbasedAuthentication.*/HostbasedAuthentication no/' "$CONFIG_SSHD"
sed -i -e 's/#KerberosAuthentication.*/KerberosAuthentication no/' "$CONFIG_SSHD"
sed -i -e 's/#GSSAPIAuthentication.*/GSSAPIAuthentication no/' "$CONFIG_SSHD"
sed -i -e 's/.*Subsystem.*sftp.*/Subsystem sftp internal-sftp/' "$CONFIG_SSHD"
echo "
AllowGroups sshd_users
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
" >> "$CONFIG_SSHD"
systemctl restart sshd.service

# Install fail2ban
cp /etc/fail2ban/jail.{conf,local}
sed -i -e 's/#bantime.increment =.*/bantime.increment = true/' "$CONFIG_FAIL2BAN"
sed -i -e 's/bantime  =.*/bantime  = 1h/' "$CONFIG_FAIL2BAN"
systemctl restart fail2ban.service

# Harden settings in sysctl.conf
sed -i -e 's/#net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter=1/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter=1/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv4.ip_forward.*/net.ipv4.ip_forward=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv6.conf.all.forwarding.*/net.ipv6.conf.all.forwarding=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv6.conf.all.accept_redirects.*/net.ipv6.conf.all.accept_redirects=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#.*net.ipv4.conf.all.secure_redirects.*/net.ipv4.conf.all.secure_redirects=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv4.conf.all.send_redirects.*/net.ipv4.conf.all.send_redirects=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv4.conf.all.accept_source_route.*/net.ipv4.conf.all.accept_source_route=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv6.conf.all.accept_source_route.*/net.ipv6.conf.all.accept_source_route=0/' "$CONFIG_SYSCTL"
sed -i -e 's/#net.ipv4.conf.all.log_martians.*/net.ipv4.conf.all.log_martians=1/' "$CONFIG_SYSCTL"
sed -i -e 's/#kernel.sysrq.*/kernel.sysrq=0/' "$CONFIG_SYSCTL"
echo "
###################################################################
# Custom added parameters
# Ubuntu server hardening
# Ignore ICMP redirects
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Ignore send redirects
net.ipv4.conf.default.send_redirects = 0
# Disable source packet routing
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Block SYN attacks
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
# Ignore ICMP bogus error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1
kernel.randomize_va_space = 1
# disable IPv6 if required (IPv6 might caus issues with the Internet connection being slow)
net.ipv6.conf.all.disable_ipv6 = 1/
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
# Log packets with impossible addresses to kernel log? yes
net.ipv4.conf.default.secure_redirects = 0
# [IPv6] Number of Router Solicitations to send until assuming no routers are present.
# This is host and not router.
net.ipv6.conf.default.router_solicitations = 0
# Accept Router Preference in RA?
net.ipv6.conf.default.accept_ra_rtr_pref = 0
# Learn prefix information in router advertisement.
net.ipv6.conf.default.accept_ra_pinfo = 0
# Setting controls whether the system will accept Hop Limit settings from a router advertisement.
net.ipv6.conf.default.accept_ra_defrtr = 0
# Router advertisements can cause the system to assign a global unicast address to an interface.
net.ipv6.conf.default.autoconf = 0
# How many neighbor solicitations to send out per address?
net.ipv6.conf.default.dad_transmits = 0
# How many global unicast IPv6 addresses can be assigned to each interface?
net.ipv6.conf.default.max_addresses = 1
# In rare occasions, it may be beneficial to reboot your server reboot if it runs out of memory.
# This simple solution can avoid you hours of down time. The vm.panic_on_oom=1 line enables panic
# on OOM; the kernel.panic=10 line tells the kernel to reboot ten seconds after panicking.
vm.panic_on_oom = 1
kernel.panic = 10
" >> "$CONFIG_SYSCTL"
sysctl -p
systemctl restart systemd-sysctl

# Configure time synchronisation
sed -i -e "s/#NTP=.*/NTP=$NTPSERVER/" "$CONFIG_TIME"
systemctl restart systemd-timesyncd

# Disable unused network protocols
for disable in $CONFIG_DISABLENET_MODULES; do
    if ! grep -q "$disable" "$CONFIG_DISABLENET" 2> /dev/null; then
        echo "install $disable /bin/true" >> "$CONFIG_DISABLENET"
    fi
done

# Disable unused filesystems
for disable in $CONFIG_DISABLEFS_MODULES; do
    if ! grep -q "$disable" "$CONFIG_DISABLEFS" 2> /dev/null; then
        echo "install $disable /bin/true" >> "$CONFIG_DISABLEFS"
    fi
done

# Disable unused modules
for disable in $CONFIG_DISABLEMOD_MODULES; do
    if ! grep -q "$disable" "$CONFIG_DISABLEMOD" 2> /dev/null; then
        echo "install $disable /bin/true" >> "$CONFIG_DISABLEMOD"
    fi
done

# Enable USB Guard
usbguard generate-policy > /tmp/rules.conf
install -m 0600 -o root -g root /tmp/rules.conf "$CONFIG_USBGUARDRULES"
rm /tmp/rules.conf
systemctl enable usbguard.service
systemctl start usbguard.service

# Disable CTRL+ALT+DEL
sed -i 's/^#CtrlAltDelBurstAction=.*/CtrlAltDelBurstAction=none/' "$CONFIG_SYSTEM"
systemctl mask ctrl-alt-del.target

# Set MOTD text
MOTD_TEXT="By accessing this system, you consent to the following conditions:
- This system is restricted to authorized users only.
- Any or all uses of this system and all files on this system may be monitored.
- Communications using, or data stored on, this system are not private.
"
echo -e "$MOTD_TEXT" > /etc/issue
echo -e "$MOTD_TEXT" > /etc/issue.net
echo -e "$MOTD_TEXT" > /etc/motd

# Disable MOTD NEWS
sed -i -e 's/ENABLED=.*/ENABLED=0/' "$CONFIG_MOTDNEWS"
systemctl stop motd-news.timer
systemctl mask motd-news.timer

# Disable ATD
systemctl mask atd.service
systemctl stop atd.service
systemctl daemon-reload

# Disable systemd-debug-generator
systemctl mask debug-shell.service
systemctl stop debug-shell.service
systemctl daemon-reload

# Configure dump and crash behavior
sed -i -e 's/^#DumpCore=.*/DumpCore=no/'  "$CONFIG_SYSTEM"
sed -i -e 's/^#CrashShell=.*/CrashShell=no/'  "$CONFIG_SYSTEM"

# Configure logins
sed -i -e 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS yes/' "$CONFIG_LOGIN"
sed -i -e 's/DEFAULT_HOME.*/DEFAULT_HOME no/' "$CONFIG_LOGIN"
sed -i -e 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' "$CONFIG_LOGIN"
sed -i -e 's/^# SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 10000/' "$CONFIG_LOGIN"
sed -i -e 's/^# SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 65536/' "$CONFIG_LOGIN"
sed -i -e 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' "$CONFIG_LOGIN"
sed -i -e 's/DIR_MODE=.*/DIR_MODE=0750/' "$CONFIG_ADDUSER"
sed -i -e 's/DSHELL=.*/DSHELL=\/bin\/false/' "$CONFIG_ADDUSER"
sed -i -e 's/SHELL=.*/SHELL=\/bin\/false/' "$CONFIG_USERADD"

# Set timezone
timedatectl set-timezone "$TIMEZONE"

# Lock and restrict root user
usermod -L root
sed -i -e 's/^#.*root.*:.*127.0.0.1$/+:root:127.0.0.1/' "$CONFIG_ACCESS"
echo "console" > "$CONFIG_SECURETTY"

# Configure users
usermod -G ${ADMINUSER},adm,sudo,sshd_users $ADMINUSER

# Configure Swap
swapoff -a
dd if=/dev/zero of="$SWAP_FILE" bs=1M count=$SWAP_SIZE_MB
chmod 600 "$SWAP_FILE"
mkswap "$SWAP_FILE"
swapon "$SWAP_FILE"

# Install Qemu Agent (PROXMOX VM ONLY)
if [[ "${QUEMU_INSTALL^^}" == "TRUE" ]]; then
  apt install -y qemu-guest-agent
  systemctl start qemu-guest-agent.service
fi

# Configure auditd
echo "
# First rule - delete all
-D
# Increase the buffers to survive stress events.
# Make this bigger for busy systems
-b 8192
# This determine how long to wait in burst of events
--backlog_wait_time 0
# Set failure mode to syslog
-f 1
# su and sudo
-w /bin/su -p x -k actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d -p wa -k actions
-w /usr/bin/sudo -p x -k actions
-a always,exit -S all -F dir=/home/ -F uid=0 -C auid!=obj_uid -k admin-user-home
# Apparmor configuration and tools
-w /etc/apparmor -p wa -k apparmor
-w /etc/apparmor.d -p wa -k apparmor
-w /sbin/apparmor_parser -p x -k apparmor-tools
-w /usr/sbin/aa-complain -p x -k apparmor-tools
-w /usr/sbin/aa-disable -p x -k apparmor-tools
-w /usr/sbin/aa-enforce -p x -k apparmor-tools
# Auditd configuration
-w /etc/audisp -p wa -k audispconfig
-w /etc/audit -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /var/log/audit -p rwxa -k auditlog
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
# Cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.d -p wa -k cron
-w /etc/cron.daily -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.hourly -p wa -k cron
-w /etc/cron.monthly -p wa -k cron
-w /etc/cron.weekly -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs -p rwxa -k cron
# Group modifications
-w /etc/group -p wa -k group-modification
-w /etc/gshadow -p wa -k group-modification
-w /etc/passwd -p wa -k group-modification
-w /etc/security/opasswd -p wa -k group-modification
-w /etc/shadow -p wa -k group-modification
-w /usr/sbin/addgroup -p x -k group-modification
-w /usr/sbin/groupadd -p x -k group-modification
-w /usr/sbin/groupmod -p x -k group-modification
# Startup scripts
-w /etc/init -p wa -k init
-w /etc/init.d -p wa -k init
-w /etc/inittab -p wa -k init
#
-w /etc/ld.so.conf -p wa -k libpath
# Local time
-w /etc/localtime -p wa -k localtime
# Login monitoring
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login
-w /var/run/faillock -p wa -k login
# SELinux configuration
-w /etc/selinux -p wa -k mac-policy
# Postfix configuration
-w /etc/aliases -p wa -k mail
-w /etc/postfix -p wa -k mail
# Kernel module configuration and tools
-w /etc/modprobe.conf -p wa -k modprobe
-w /etc/modprobe.d -p wa -k modprobe
-w /etc/modules -p wa -k modprobe
-a always,exit -F arch=b32 -S finit_module -k modules
-a always,exit -F arch=b32 -S init_module -k modules
-a always,exit -F arch=b64 -S finit_module -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
#
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
# Network configuration
-w /etc/hosts -p wa -k network-config
-w /etc/issue -p wa -k network-config
-w /etc/issue.net -p wa -k network-config
-w /etc/netplan -p wa -k network-config
-w /etc/network -p wa -k network-config
#-w /etc/sysconfig/network -p wa -k network-config
# PAM configuration
-w /etc/pam.d -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam
# Password modifications
-w /usr/bin/passwd -p x -k passwd-modification
# Power state
-w /sbin/halt -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/shutdown -p x -k power
# Use of privileged commands
-a always,exit -F path=/bin/fusermount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/bin/ntfs-3g -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/sbin/pam_extrausers_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/bsd-write -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/cgclassify -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/cgexec -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/dotlockfile -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/expiry -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/mlocate -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/traceroute6.iputils -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/userhelper -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/lib/dbus-1.0/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/lib/eject/dmcrypt-get-device -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/lib/policykit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
#-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/lib/snapd/snap-confine -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
#-a always,exit -F path=/usr/lib/x86_64-linux-gnu/utempter/utempter -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
#-a always,exit -F path=/usr/libexec/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
#-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
#-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/fping -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/fping6 -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/grub2-set-bootflag -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/mount.cifs -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/pam_extrausers_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/pam-tmpdir-helper -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/usernetct -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/sbin/vlock-main -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
#
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/run/utmp -p wa -k session
# Special files
-a always,exit -F arch=b32 -S mknod,mknodat -k specialfiles
-a always,exit -F arch=b64 -S mknod,mknodat -k specialfiles
# sshd configuration
-w /etc/ssh/sshd_config -p rwxa -k sshd
# Kernel modification
-w /etc/sysctl.conf -p wa -k sysctl
# Hostname changes
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
# systemd configuration and tools
-w /etc/systemd -p wa -k systemd
-w /lib/systemd -p wa -k systemd
-w /bin/journalctl -p x -k systemd-tools
-w /bin/systemctl -p x -k systemd-tools
# Time modification
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/timezone -p wa -k time-changezone
# /tmp directories
-w /tmp -p wxa -k tmp
-w /var/tmp -p wxa -k tmp
# User modification
-w /usr/sbin/adduser -p x -k user-modification
-w /usr/sbin/useradd -p x -k user-modification
-w /usr/sbin/usermod -p x -k user-modification
# Make the configuration immutable
-e 2
" > "$CONFIG_AUDITDRULES"
systemctl restart auditd.service

sed -i "4i RefuseManualStop=yes" "$CONFIG_AUDITDSERVICE"
systemctl daemon-reload

##
##
