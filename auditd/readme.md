

##
#
https://github.com/konstruktoid/hardening
#
https://freelinuxtutorials.com/auditd-recommended-configuration-on-ubuntu-linux-for-system-auditing/
#
https://izyknows.medium.com/linux-auditd-for-threat-hunting-part-2-c75500f591e8
#
##


image::logo/horizontal.png[Ubuntu Hardening]
= Hardening Ubuntu. Systemd edition.

:icons: font

A quick way to make a Ubuntu server a bit more secure.

Use the newly installed and configured system as a reference,
or golden, image. Use that image as a baseline installation media and ensure
that any future installation comply with benchmarks and policies using a
configuration management tool, e.g https://www.ansible.com/[Ansible] or
https://puppet.com/[Puppet].

Tested on `Ubuntu 20.04 Focal Fossa` and `Ubuntu 22.04 Jammy Jellyfish`.

If you're just interested in the security focused systemd configuration, it's
available as a link:systemd.adoc[separate document].

If you're interested in testing your host settings, you'll find the
link:README.adoc#tests[instructions here].

NOTE: Read the code and do not run this script without first testing in a
non-operational environment. The code is *not* idempotent, use the https://github.com/konstruktoid/ansible-role-hardening[Ansible role] in production environments instead.

NOTE: There is a https://slsa.dev/[SLSA] artifact present under the
https://github.com/konstruktoid/hardening/actions/workflows/slsa.yml[slsa workflow]
for file checksum verification.

== Packer template and Ansible playbook

A https://www.packer.io/[Packer] template is available in the link:packer/[Packer directory].

An Ansible playbook is available in the https://github.com/konstruktoid/ansible-role-hardening[konstruktoid/ansible-role-hardening]
repository.

== Howto

. Start the server installation.
. Pick language and keyboard layout.
. Select "Ubuntu Server (minimized)".
. Configure network connections.
. Partition the system, see below for recommendations.
. Do not install the OpenSSH server, "Featured Server Snaps", or any other packages.
. Finish the installation and reboot.
. Log in.
. If wanted, set a Grub2 password with `grub-mkpasswd-pbkdf2`. See https://help.ubuntu.com/community/Grub2/Passwords[https://help.ubuntu.com/community/Grub2/Passwords]
for more information.
. Install necessary packages: `sudo apt-get -y install git net-tools procps --no-install-recommends`.
. Download the script: `git clone https://github.com/konstruktoid/hardening.git`.
. Change the configuration options in the `ubuntu.cfg` file.
. Run the script: `sudo bash ubuntu.sh`.
. Reboot.

=== Recommended partitions and options

[source,shell]
----
/boot (rw)
/home (rw,nosuid,nodev)
/var/log (rw,nosuid,nodev,noexec)
/var/log/audit (rw,nosuid,nodev,noexec)
/var/tmp (rw,nosuid,nodev,noexec)
----

Note that `/tmp` will be added automatically by the script.

== Configuration options

[source,shell]
----
FW_ADMIN='127.0.0.1' // <1>
SSH_GRPS='sudo' // <2>
SSH_PORT='22' // <3>
SYSCTL_CONF='./misc/sysctl.conf' // <4>
AUDITD_MODE='1' // <5>
AUDITD_RULES='./misc/audit-base.rules ./misc/audit-aggressive.rules ./misc/audit-docker.rules' // <6>
LOGROTATE_CONF='./misc/logrotate.conf' // <7>
NTPSERVERPOOL='0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org' // <8>
TIMEDATECTL='' // <9>
VERBOSE='N' // <10>
AUTOFILL='N' // <11>
ADMINEMAIL="root@localhost" // <12>
KEEP_SNAPD='Y' // <13>
CHANGEME='' // <14>

# Configuration files // <15>
ADDUSER='/etc/adduser.conf'
AUDITDCONF='/etc/audit/auditd.conf'
AUDITRULES='/etc/audit/rules.d/hardening.rules'
COMMONPASSWD='/etc/pam.d/common-password'
COMMONACCOUNT='/etc/pam.d/common-account'
COMMONAUTH='/etc/pam.d/common-auth'
COREDUMPCONF='/etc/systemd/coredump.conf'
DEFAULTGRUB='/etc/default/grub.d'
DISABLEFS='/etc/modprobe.d/disablefs.conf'
DISABLEMOD='/etc/modprobe.d/disablemod.conf'
DISABLENET='/etc/modprobe.d/disablenet.conf'
FAILLOCKCONF='/etc/security/faillock.conf'
JOURNALDCONF='/etc/systemd/journald.conf'
LIMITSCONF='/etc/security/limits.conf'
LOGINDCONF='/etc/systemd/logind.conf'
LOGINDEFS='/etc/login.defs'
LOGROTATE='/etc/logrotate.conf'
PAMLOGIN='/etc/pam.d/login'
PSADCONF='/etc/psad/psad.conf'
PSADDL='/etc/psad/auto_dl'
RESOLVEDCONF='/etc/systemd/resolved.conf'
RKHUNTERCONF='/etc/default/rkhunter'
RSYSLOGCONF='/etc/rsyslog.conf'
SECURITYACCESS='/etc/security/access.conf'
SSHFILE='/etc/ssh/ssh_config'
SSHDFILE='/etc/ssh/sshd_config'
SYSCTL='/etc/sysctl.conf'
SYSTEMCONF='/etc/systemd/system.conf'
TIMESYNCD='/etc/systemd/timesyncd.conf'
UFWDEFAULT='/etc/default/ufw'
USERADD='/etc/default/useradd'
USERCONF='/etc/systemd/user.conf'

----
<1> The IP addresses that will be able to connect with SSH, separated by spaces.
<2> Which group the users have to be member of in order to acess via SSH, separated by spaces.
<3> Configure SSH port.
<4> Stricter sysctl settings.
<5> Auditd failure mode. 0=silent 1=printk 2=panic.
<6> Auditd rules.
<7> Logrotate settings.
<8> NTP server pool.
<9> Add a specific time zone or use the system default by leaving it empty.
<10> If you want all the details or not.
<11> Let the script guess the `FW_ADMIN` and `SSH_GRPS` settings.
<12> Add a valid email address, so PSAD can send notifications.
<13> If `'Y'` then the `snapd` package will be held to prevent removal.
<14> Add something just to verify that you actually glanced the code.
<15> Default configuration file locations.

== Functions

=== Function list in execution order

Note that all functions has the `f_` prefix in the code.

==== `pre`

Sets `apt` flags and performs basic permission check.

The `pre` function is located in link:scripts/pre[./scripts/pre].

==== `kernel`

Sets https://github.com/jeffmurphy/NetPass/blob/master/doc/netfilter_conntrack_perf.txt#L175[/sys/module/nf_conntrack/parameters/hashsize]
to 1048576 if `hashsize` exists and is writable.

Sets https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html[/sys/kernel/security/lockdown]
to `confidentiality` if `lockdown` exists and is writable.

The `kernel` function is located in link:scripts/kernel[./scripts/kernel].

==== `firewall`

Configures https://help.ubuntu.com/community/UFW[UFW] if installed.

Allows connections from the adresses in `$FW_ADMIN` to the `$SSH_PORT`.

Sets logging and `IPT_SYSCTL=/etc/sysctl.conf`.

The `firewall` function is located in link:scripts/ufw[./scripts/ufw].

==== `disablenet`

Disables the `dccp`, `sctp`, `rds` and `tipc` kernel modules.

The `disablenet` function is located in link:scripts/disablenet[./scripts/disablenet].

==== `disablefs`

Disables the `cramfs` `freevxfs` `jffs2` `ksmbd` `hfs` `hfsplus` `udf` kernel
modules.

The `disablefs` function is located in link:scripts/disablefs[./scripts/disablefs].

==== `disablemod`

Disables the `bluetooth`, `bnep`, `btusb`, `cpia2`, `firewire-core`, `floppy`,
`n_hdlc`, `net-pf-31`, `pcspkr`, `soundcore`, `thunderbolt`, `usb-midi`,
`usb-storage`, `uvcvideo`, `v4l2_common` kernel modules.

Note that disabling the `usb-storage` module will disable any usage of USB
storage devices, if such devices are needed `USBGuard` should be configured
accordingly.

The `disablemod` function is located in link:scripts/disablemod[./scripts/disablemod].

==== `systemdconf`

Sets `CrashShell=no`, `DefaultLimitCORE=0`, `DefaultLimitNOFILE=1024`,
`DefaultLimitNPROC=1024`, `DumpCore=no` in `$SYSTEMCONF`
and `$USERCONF`.

The `systemdconf` function is located in link:scripts/systemdconf[./scripts/systemdconf].

==== `resolvedconf`

Sets `DNS=$dnslist`, `DNSOverTLS=opportunistic`, `DNSSEC=allow-downgrade`, `FallbackDNS=1.0.0.1`
in `$RESOLVEDCONF`, where `$dnslist` is an array with the nameservers present
in `/etc/resolv.conf`.

The `resolvedconf` function is located in link:scripts/resolvedconf[./scripts/resolvedconf].

==== `logindconf`

Sets `IdleAction=lock`, `IdleActionSec=15min`, `KillExcludeUsers=root`,
`KillUserProcesses=1`, `RemoveIPC=yes` in `$LOGINDCONF`.

The `logindconf` function is located in link:scripts/logindconf[./scripts/logindconf].

==== `journalctl`

Copies link:misc/logrotate.conf[./misc/logrotate.conf] to `$LOGROTATE`.

Sets `Compress=yes`, `ForwardToSyslog=yes`, `Storage=persistent` in
`$JOURNALDCONF`.

Sets `$FileCreateMode 0600/` in `$RSYSLOGCONF`.
if `RSYSLOGCONF` is writable.

The `journalctl` function is located in link:scripts/journalctl[./scripts/journalctl].

==== `timesyncd`

Sets `NTP=${SERVERARRAY}`, `FallbackNTP=${FALLBACKARRAY}`, `RootDistanceMaxSec=1`
in `$TIMESYNCD` where the arrays are up to four time servers with < 50ms
latency.

The `timesyncd` function is located in link:scripts/timesyncd[./scripts/timesyncd].

==== `fstab`

Configures the `/boot` and `/home` partitions with `defaults,nosuid,nodev` if
they are available in `/etc/fstab`.

Configures the `/var/log`, `/var/log/audit` and `/var/tmp` partitions with
`defaults,nosuid,nodev,noexec` if they are available in `/etc/fstab`.

Adds `/run/shm tmpfs rw,noexec,nosuid,nodev`,
`/dev/shm tmpfs rw,noexec,nosuid,nodev` and
`/proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2` to `/etc/fstab` if
the partition isn't present in `/etc/fstab`.

Removes any floppy drivers from `/etc/fstab`.

Copies ./config/tmp.mount[./config/tmp.mount] to
`/etc/systemd/system/tmp.mount`, removes `/tmp` from `/etc/fstab`
and enables the tmpfs `/tmp` mount instead.

The `/proc` `hidepid` option is described in https://www.kernel.org/doc/html/latest/filesystems/proc.html#mount-options[https://www.kernel.org/doc/html/latest/filesystems/proc.html#mount-options].

The `fstab` function is located in link:scripts/fstab[./scripts/fstab].

==== `prelink`

Reverts binaries and libraries to their original content before they were
prelinked and uninstalls `prelink`.

The `prelink` function is located in link:scripts/prelink[./scripts/prelink].

==== `aptget_configure`

Sets `apt` options `Acquire::http::AllowRedirect "false";`, `APT::Get::AllowUnauthenticated "false";`,
`APT::Periodic::AutocleanInterval "7";`,
`APT::Install-Recommends "false";`, `APT::Get::AutomaticRemove "true";`,
`APT::Install-Suggests "false";`, `Acquire::AllowDowngradeToInsecureRepositories "false";`,
`Acquire::AllowInsecureRepositories "false";`, `APT::Sandbox::Seccomp "1";`

See https://manpages.ubuntu.com/manpages/jammy/man5/apt.conf.5.html[https://manpages.ubuntu.com/manpages/jammy/man5/apt.conf.5.html].

The `aptget_configure` function is located in link:scripts/aptget[./scripts/aptget].

==== `aptget`

Upgrades installed packages.

The `aptget` function is located in link:scripts/aptget[./scripts/aptget].

==== `hosts`

Sets `sshd : ALL : ALLOW`, `ALL: LOCAL, 127.0.0.1` in `/etc/hosts.allow` and
`ALL: ALL` in `/etc/hosts.deny`.

See https://manpages.ubuntu.com/manpages/jammy/man5/hosts_access.5.html[https://manpages.ubuntu.com/manpages/jammy/man5/hosts_access.5.html]
for the format of host access control files.

The `hosts` function is located in link:scripts/hosts[./scripts/hosts].

==== `issue`

Writes a notice regarding authorized use only to `/etc/issue`, `/etc/issue.net`
and `/etc/motd`.

Removes the executable flag from every file in `/etc/update-motd.d/`.

The `issue` function is located in link:scripts/issue[./scripts/issue].

==== `sudo`

Restricts `su` access to members of the `sudo` group using
https://manpages.ubuntu.com/manpages/jammy/man8/pam_wheel.8.html[pam_wheel].

Sets `!pwfeedback`, `!visiblepw`, `logfile=/var/log/sudo.log`, `passwd_timeout=1`,
`timestamp_timeout=5`, `use_pty` https://manpages.ubuntu.com/manpages/jammy/man5/sudoers.5.html[sudo options].

The `sudo` function is located in link:scripts/sudo[./scripts/sudo].

==== `logindefs`

Writes `LOG_OK_LOGINS yes`, `UMASK 077`, `PASS_MIN_DAYS 1`, `PASS_MAX_DAYS 60`,
`DEFAULT_HOME no`, `ENCRYPT_METHOD SHA512`, `USERGROUPS_ENAB no`,
`SHA_CRYPT_MIN_ROUNDS 10000`, `SHA_CRYPT_MAX_ROUNDS 65536` to
https://manpages.ubuntu.com/manpages/jammy/man5/login.defs.5.html[$LOGINDEFS]

The `logindefs` function is located in link:scripts/logindefs[./scripts/logindefs].

==== `sysctl`

Copies link:misc/sysctl.conf[./misc/sysctl.conf] to `$SYSCTL`.

For an explanation of the options set, see
https://www.kernel.org/doc/html/latest/admin-guide/sysctl/[https://www.kernel.org/doc/html/latest/admin-guide/sysctl/].

The `sysctl` function is located in link:scripts/sysctl[./scripts/sysctl].

==== `limitsconf`

Sets `hard maxlogins 10`, `hard core 0`, `soft nproc 512`, `hard nproc 1024` in
https://manpages.ubuntu.com/manpages/jammy/en/man5/limits.conf.5.html[$LIMITSCONF]

The `limitsconf` function is located in link:scripts/limits[./scripts/limits].

==== `adduser`

Sets `DIR_MODE=0750`,`DSHELL=/bin/false`, and `USERGROUPS=yes` in `$ADDUSER`.

Sets `INACTIVE=30` and `SHELL=/bin/false` in `$USERADD`.

The `adduser` function is located in link:scripts/adduser[./scripts/adduser].

==== `rootaccess`

Writes `+:root:127.0.0.1/'` to `$SECURITYACCESS` and `console` to
`/etc/securetty`.

Masks https://freedesktop.org/wiki/Software/systemd/Debugging/[debug-shell].

The `rootaccess` function is located in link:scripts/rootaccess[./scripts/rootaccess].

==== `package_install`

Installs `acct`, `aide-common`, `cracklib-runtime`, `debsums`, `gnupg2`,
`haveged`, `libpam-pwquality`, `libpam-tmpdir`, `needrestart`, `openssh-server`,
`postfix`, `psad`, `rkhunter`, `sysstat`, `systemd-coredump`, `tcpd`,
`update-notifier-common`, `vlock`.

The `package_install` function is located in link:scripts/packages[./scripts/packages].

==== `psad`

Installs and configures https://cipherdyne.org/psad/[PSAD]

The `psad` function is located in link:scripts/psad[./scripts/psad].

==== `coredump`

Writes `Storage=none` and `ProcessSizeMax=0` to `$COREDUMPCONF`.

The `coredump` function is located in link:scripts/coredump[./scripts/coredump].

==== `usbguard`

Installs and configures https://usbguard.github.io/[USBGuard].

The `usbguard` function is located in link:scripts/usbguard[./scripts/usbguard].

==== `postfix`

Installs `postfix` and sets `disable_vrfy_command=yes`,
`inet_interfaces=loopback-only`,
`smtpd_banner="\$myhostname`,
`smtpd_client_restrictions=permit_mynetworks,reject` using https://manpages.ubuntu.com/manpages/jammy/en/man1/postconf.1.html[postconf].

The `postfix` function is located in link:scripts/postfix[./scripts/postfix].

==== `apport`

Disables
https://manpages.ubuntu.com/manpages/jammy/man1/apport-cli.1.html[apport],
https://github.com/Ubuntu/ubuntu-report[ubuntu-report] and
https://manpages.ubuntu.com/manpages/jammy/en/man8/popularity-contest.8.html[popularity-contest].

The `apport` function is located in link:scripts/apport[./scripts/apport].

==== `motdnews`

Disables `apt_news` and https://ubuntu.com/legal/motd[motd-news].

The `motdnews` function is located in link:scripts/motdnews[./scripts/motdnews].

==== `rkhunter`

Sets `CRON_DAILY_RUN="yes"`, `APT_AUTOGEN="yes"` in `$RKHUNTERCONF`.

The `rkhunter` function is located in link:scripts/rkhunter[./scripts/rkhunter].

==== `sshconfig`

Sets `HashKnownHosts yes`, `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr`
and `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256`
in `$SSHFILE`.

The `sshconfig` function is located in link:scripts/sshdconfig[./scripts/sshdconfig].

==== `sshdconfig`

Configures the `OpenSSH` daemon. The configuration changes will be placed in
the directory defined by the `Include` option if present, otherwise
https://manpages.ubuntu.com/manpages/jammy/en/man5/sshd_config.5.html[$SSHDFILE]
will be modified.

By default `/etc/ssh/sshd_config.d/hardening.conf` will contain the following:

[source,shell]
----
AcceptEnv LANG LC_*
AllowAgentForwarding no
AllowGroups sudo
AllowTcpForwarding no
Banner /etc/issue.net
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
ClientAliveCountMax 3
ClientAliveInterval 200
Compression no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreUserKnownHosts yes
KbdInteractiveAuthentication no
KerberosAuthentication no
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
LogLevel VERBOSE
LoginGraceTime 20
Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
MaxAuthTries 3
MaxSessions 3
MaxStartups 10:30:60
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PermitUserEnvironment no
Port 22
PrintLastLog yes
PrintMotd no
RekeyLimit 512M 1h
StrictModes yes
TCPKeepAlive no
UseDNS no
UsePAM yes
X11Forwarding no
----

The `sshdconfig` function is located in link:scripts/sshdconfig[./scripts/sshdconfig].

==== `password`

Copies ./config/pwquality.conf[./config/pwquality.conf] to `/etc/security/pwquality.conf`,

Removes `nullok` from https://manpages.ubuntu.com/manpages/jammy/man5/pam.conf.5.html[PAM]
`$COMMONAUTH`.

Configures https://manpages.ubuntu.com/manpages/jammy/en/man8/faillock.8.html[faillock]
or https://manpages.ubuntu.com/manpages/jammy/man8/pam_tally2.8.html[pam_tally2]
depending on which is installed.

Adds a link:misc/passwords.list[password list] to https://manpages.ubuntu.com/manpages/jammy/man8/update-cracklib.8.html[cracklib].

The `password` function is located in link:scripts/password[./scripts/password].

==== `cron`

Disables https://manpages.ubuntu.com/manpages/jammy/en/man8/atd.8.html[atd]
and only allow root to use https://manpages.ubuntu.com/manpages/jammy/en/man1/at.1.html[at]
or https://manpages.ubuntu.com/manpages/jammy/en/man8/cron.8.html[cron].

The `cron` function is located in link:scripts/cron[./scripts/cron].

==== `ctrlaltdel`

Masks https://manpages.ubuntu.com/manpages/jammy/man1/systemd.1.html#signals[ctrl-alt-del.target].

The `ctrlaltdel` function is located in link:scripts/ctraltdel[./scripts/ctraltdel].

==== `auditd`

Configures https://manpages.ubuntu.com/manpages/jammy/en/man8/auditd.8.html[auditd].

See link:misc/audit-base.rules[./misc/audit-base.rules],
link:misc/audit-aggressive.rules[./misc/audit-aggressive.rules] and link:misc/audit-docker.rules[./misc/audit-docker.rules]
for the rules used.

The `auditd` function is located in link:scripts/auditd[./scripts/auditd].

==== `aide`

Excludes `/var/lib/lxcfs/cgroup` and `/var/lib/docker` from https://manpages.ubuntu.com/manpages/jammy/en/man1/aide.1.html[AIDE].

The `aide` function is located in link:scripts/aide[./scripts/aide].

==== `rhosts`

Removes any existing `hosts.equiv` or `.rhosts` files.

The `rhosts` function is located in link:scripts/rhosts[./scripts/rhosts].

==== `users`

Removes the `games`, `gnats`, `irc`, `list`, `news`, `sync`, `uucp` users.

The `users` function is located in link:scripts/users[./scripts/users].

==== `lockroot`

Locks root account

The `lockroot` function is located in link:scripts/lockroot[./scripts/lockroot].

==== `package_remove`

Removes the `apport*`, `autofs`, `avahi*`, `beep`, `git`, `pastebinit`,
`popularity-contest`, `rsh*`, `rsync`, `talk*`, `telnet*`, `tftp*`, `whoopsie`,
`xinetd`, `yp-tools`, `ypbind` packages.

The `package_remove` function is located in link:scripts/packages[./scripts/packages].

==== `suid`

Ensures the executables in link:misc/suid.list[./misc/suid.list] don't have suid
bits set.

The `suid` function is located in link:scripts/suid[./scripts/suid].

==== `restrictcompilers`

Changes mode to `0750` on any installed compilers.

The `restrictcompilers` function is located in link:scripts/compilers[./scripts/compilers].

==== `umask`

Sets the default https://manpages.ubuntu.com/manpages/jammy/man2/umask.2.html[umask] to `077`

The `umask` function is located in link:scripts/umask[./scripts/umask].

==== `path`

Copies ./config/initpath.sh[./config/initpath.sh] to `/etc/profile.d/initpath.sh`
and sets `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin`
for the `root` user and `PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin:/snap/bin`
for everyone else.

The `path` function is located in link:scripts/path[./scripts/path].

==== `aa_enforce`

Enforces available https://manpages.ubuntu.com/manpages/jammy/en/man7/apparmor.7.html[apparmor]
profiles.

The `aa_enforce` function is located in link:scripts/apparmor[./scripts/apparmor].

==== `aide_post`

Creates a new AIDE database.

The `aide_post` function is located in link:scripts/aide[./scripts/aide].

==== `aide_timer`

Copies a systemd AIDE check service and timer to /etc/systemd/system/.

The `aide_timer` function is located in link:scripts/aide[./scripts/aide].

==== `aptget_noexec`

Adds a `DPkg::Pre-Invoke` and `DPkg::Post-Invoke` to ensure package updates
don't fail on a `noexec` `/tmp` partition.

The `aptget_noexec` function is located in link:scripts/aptget[./scripts/aptget].

==== `aptget_clean`

Runs https://manpages.ubuntu.com/manpages/jammy/en/man8/apt-get.8.html[apt-get] `clean` and `autoremove`.

The `aptget_clean` function is located in link:scripts/aptget[./scripts/aptget].

==== `systemddelta`

Runs https://manpages.ubuntu.com/manpages/jammy/man1/systemd-delta.1.html[systemd-delta] if running in verbose mode.

The `systemddelta` function is located in link:scripts/systemddelta[./scripts/systemddelta].

==== `post`

Ensures https://manpages.ubuntu.com/manpages/jammy/man1/fwupdmgr.1.html[fwupdmgr]
and https://packages.ubuntu.com/jammy/secureboot-db[secureboot-db] is installed
and GRUB is updated.

The `post` function is located in link:scripts/post[./scripts/post].

==== `checkreboot`

Checks if a reboot is required.

The `checkreboot` function is located in link:scripts/reboot[./scripts/reboot].

== Tests
There are approximately 760 https://github.com/bats-core/bats-core[Bats tests]
for most of the above settings available in the link:tests/[tests directory].

[source,shell]
----
sudo apt-get -y install bats
git clone https://github.com/konstruktoid/hardening.git
cd hardening/tests/
sudo bats .
----

=== Test automation using Vagrant
Running `bash ./runTests.sh` will use https://www.vagrantup.com/[Vagrant] to run
all above tests, https://github.com/CISOfy/Lynis[Lynis] and
https://www.open-scap.org/[OpenSCAP] with a
https://www.cisecurity.org/benchmark/ubuntu_linux[CIS Ubuntu benchmark] on all
supported Ubuntu versions.

The script will generate a file named `TESTRESULTS.adoc` and CIS report in
HTML-format.

=== Testing a host
Running `bash ./runHostTests.sh`, located in the link:tests/[tests directory],
will generate a `TESTRESULTS-<HOSTNAME>.adoc` report.

Running `bash ./runHostTestsCsv.sh`, located in the link:tests/[tests directory],
will generate a `TESTRESULTS-<HOSTNAME>.csv` report.


== Recommended reading
https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux[Canonical Ubuntu 20.04 LTS STIG - Ver 1, Rel 3] +
https://www.cisecurity.org/benchmark/distribution_independent_linux/[CIS Distribution Independent Linux Benchmark] +
https://www.cisecurity.org/benchmark/ubuntu_linux/[CIS Ubuntu Linux Benchmark] +
https://www.ncsc.gov.uk/collection/end-user-device-security/platform-specific-guidance/ubuntu-18-04-lts[EUD Security Guidance: Ubuntu 18.04 LTS] +
https://wiki.ubuntu.com/Security/Features +
https://help.ubuntu.com/community/StricterDefaults +

== Contributing
Do you want to contribute? That's great! Contributions are always welcome,
no matter how large or small. If you found something odd, feel free to
https://github.com/konstruktoid/hardening/issues/[submit a new issue],
improve the code by https://github.com/konstruktoid/hardening/pulls[creating a pull request],
or by https://github.com/sponsors/konstruktoid[sponsoring this project].

Logo by https://github.com/reallinfo[reallinfo].
