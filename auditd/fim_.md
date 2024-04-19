

##
#
https://detect.fyi/file-integrity-monitoring-with-auditd-b9423a52feef
#
https://github.com/threathunters-io/laurel
#
https://github.com/mthcht/Purpleteam/
#
https://sysdig.com/blog/file-integrity-monitoring/
#
https://github.com/doksu/splunk_auditd
#
##

```
https://linux-audit.com/tuning-auditd-high-performance-linux-auditing/
auditctl -w /usr/local/nginx_cache/ -p wa
#auditctl -W /usr/local/nginx_cache/ -p wa
aureport -ts today -i -x –summary
auditctl -l
ausearch --start yesterday --end now -m SYSCALL -sv no -i
https://github.com/EricGershman/auditd-examples
http://linoxide.com/how-tos/auditd-tool-security-auditing/
```

System Auditing with Auditd:

About: auditd is the user-space component of the Linux auditing subsystem. When auditd is running audit messages sent by the kernel 
will be collected in the log file configured for auditd (normally /var/log/audit/audit.log). If auditd is not running for any reason
kernel audit messages will be sent to rsyslog.


Configuration files:
- /etc/sysconfig/auditd	(startup options) 
- /etc/audit/auditd.conf (main config file)
- /etc/audit/audit.rules (persistant sudit rules)


LOGGING:
All messages are logged to /var/log/audit/audit.log

Searching for Events:

The auditing system ships with a powerful tool for searching audit logs: ausearch. Not only does ausearch let you easily search for
various types of events and filter on those, it can also interpret events for you by translating numeric values into (more) readable
values like usernames or system call names.


Command options:
# ausearch

-i (Interpret log line, translate numeric values into names)

--raw (Print raw log entries, do not put record separators between entries.)

-a <EVENT-ID> (Show all lines for the event with <EVENT-ID> as the event ID.)

--file <FILENAME> (Search for all events touching a specific filename.)

-k <KEY> (Search for all events labeled with <KEY>)

--start [start-date] [start-time] (Only search for events after start-date and start-time.)


Reporting on certain events:
# aureport


Tracing a program:
# autrace /bin/command

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Remote Logging with auditd:


There are two main ways to send audit messages to a remote system. Both methods use custom Audit Dispatching with audispd. audispd is
configured in /etc/audisp/audispd.conf, with plug-ins being configured in /etc/audisp/plugins.d/*.conf

The first way to send messages to a remote server is to use syslog. By setting active = yes in /etc/audisp/plugins.d/syslog.conf all
audit messages will also be sent to syslog after restarting auditd. The log priority and service to be used can also be set in that 
same configuration file. After sending messages to syslog you can now configure your syslog server of choice to send these message to 
a remote server.

The second way of sending audit messages to a remote server is to use the native raw audit protocol over TCP. On the server that will
receive the message you will have to configure the tcp_listen_port setting in /etc/audit/auditd.conf, with the default port being 60.

On every client that will be sending audit messages to your central server you will have to install the audispd-plugins package. After
installation you can enable remote logging in /etc/audisp/plugins.d/au-remote.conf by setting active = yes. To configure where messages
are sent configure the remote_server setting in /etc/audisp/audisp-remote.conf.


```
# Linux Audit Daemon - Best Practice Configuration 
# /etc/audit/audit.rules
# 
# Based on rules published here:
# Gov.uk auditd rules
# https://github.com/gds-operations/puppet-auditd/pull/1
# CentOS 7 hardening
# https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon
# Linux audit repo 
# https://github.com/linux-audit/audit-userspace/tree/master/rules
# Auditd high performance linux auditing
# https://linux-audit.com/tuning-auditd-high-performance-linux-auditing/
#
# Further rules
# For PCI DSS compliance see: 
# https://github.com/linux-audit/audit-userspace/blob/master/rules/30-pci-dss-v31.rules
# For NISPOM compliance see:
# https://github.com/linux-audit/audit-userspace/blob/master/rules/30-nispom.rules
#
# Compiled by Florian Roth
# 2017/12/05

# Remove any existing rules
-D

# Buffer Size
## Feel free to increase this if the machine panic's
-b 8192

# Failure Mode
## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
-f 1

# Ignore errors
## e.g. caused by users or files not found in the local environment  
-i 

# Self Auditing ---------------------------------------------------------------

# Audit the audit logs
## Successful and unsuccessful attempts to read information from the audit records
-w /var/log/audit/ -k auditlog

# Auditd configuration
## Modifications to audit configuration that occur while the audit collection functions are operating
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

# Monitor for use of audit management tools
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Filters ---------------------------------------------------------------------

# This is for don't audit rules. We put these early because audit
# is a first match wins system.

# Cron jobs fill the logs with stuff we normally don't want
-a never,user -F subj_type=crond_t

# This prevents chrony from overwhelming the logs
#-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t

# This is not very interesting and wastes a lot of space if the server is public facing
-a always,exclude -F msgtype=CRYPTO_KEY_USER

# VMWare tools
-a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
-a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

# More information on how to filter events
# https://access.redhat.com/solutions/2482221

# Rules -----------------------------------------------------------------------

# Kernel parameters
-w /etc/sysctl.conf -p wa -k sysctl

# Kernel module loading and unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
# Modprobe configuration
-w /etc/modprobe.conf -p wa -k modprobe

# Special files
-a exit,always -F arch=b32 -S mknod -S mknodat -k specialfiles
-a exit,always -F arch=b64 -S mknod -S mknodat -k specialfiles

# Mount operations
-a exit,always -F arch=b32 -S mount -S umount -S umount2 -k mount
-a exit,always -F arch=b64 -S mount -S umount2 -k mount

# Time
-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
## Local time zone
-w /etc/localtime -p wa -k localtime

# Stunnel
-w /usr/sbin/stunnel -p x -k stunnel

# Cron configuration & scheduled jobs
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -k cron

# User, group, password databases
-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd

# Sudoers file changes
-w /etc/sudoers -p wa -k actions

# Passwd
-w /usr/bin/passwd -p x -k passwd_modification

# Tools to change group identifiers
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification

# Login configuration and information
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login

# Network Environment
## Changes to hostname
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
## Changes to other files
-w /etc/hosts -p wa -k network_modifications
-w /etc/sysconfig/network -p wa -k network_modifications
-w /etc/network/ -p wa -k network
-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k network_modifications
-w /etc/sysconfig/network -p wa -k network_modifications
## Changes to issue
-w /etc/issue -p wa -k etcissue
-w /etc/issue.net -p wa -k etcissue

# System startup scripts
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init

# Library search paths
-w /etc/ld.so.conf -p wa -k libpath

# Pam configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa  -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam

# GDS specific secrets
-w /etc/puppet/ssl -p wa -k puppet_ssl

# Postfix configuration
-w /etc/aliases -p wa -k mail
-w /etc/postfix/ -p wa -k mail

# SSH configuration
-w /etc/ssh/sshd_config -k sshd

# SELinux events that modify the system's Mandatory Access Controls (MAC)
-w /etc/selinux/ -p wa -k mac_policy

# Critical elements access failures 
-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileacess

# Process ID change (switching accounts) applications
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc

# Power state
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power

# Session initiation information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

# Discretionary Access Control (DAC) modifications
-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

# Special Rules ---------------------------------------------------------------

# 32bit API Exploitation
## If you are on a 64 bit platform, everything _should_ be running
## in 64 bit mode. This rule will detect any use of the 32 bit syscalls
## because this might be a sign of someone exploiting a hole in the 32
## bit API.
-a always,exit -F arch=b32 -S all -k 32bit_api

# Injection 
## These rules watch for code injection by the ptrace facility.
## This could indicate someone trying to do something bad or just debugging
#-a always,exit -F arch=b32 -S ptrace -k tracing
-a always,exit -F arch=b64 -S ptrace -k tracing
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection

# Privilege Abuse
## The purpose of this rule is to detect when an admin may be abusing power by looking in user's home dir.
-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k power_abuse

# High volume events ----------------------------------------------------------

# Root command executions 
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

# File Deletion Events by User
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

# File Access
## Unauthorized Access (unsuccessful)
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access

## Unsuccessful Creation
-a always,exit -F arch=b32 -S creat,link,mknod,mkdir,symlink,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
-a always,exit -F arch=b64 -S mkdir,creat,link,symlink,mknod,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
-a always,exit -F arch=b32 -S link,mkdir,symlink,mkdirat -F exit=-EPERM -k file_creation
-a always,exit -F arch=b64 -S mkdir,link,symlink,mkdirat -F exit=-EPERM -k file_creation

## Unsuccessful Modification
-a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
-a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
-a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification
-a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification

# Make the configuration immutable --------------------------------------------
#-e 2
