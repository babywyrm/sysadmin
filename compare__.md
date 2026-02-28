
# Ubuntu/Debian vs RHEL/CentOS – Comprehensive Sysadmin Reference

This document is a **practical, side-by-side reference** for system administrators and engineers who work across both Debian/Ubuntu and RHEL/CentOS/AlmaLinux/Rocky Linux environments.

It focuses on **real operational differences**:
- Exact command syntax
- Default file paths
- Package management quirks
- Networking, security, boot, filesystem, and development workflows
- Enterprise support differences

> **2026 Note:** CentOS 7 reached EOL June 2024. CentOS Stream continues as a rolling preview of RHEL. Most teams have migrated to **AlmaLinux** or **Rocky Linux** as drop-in RHEL binary-compatible replacements. This guide covers RHEL 9.x / AlmaLinux 9 / Rocky Linux 9 and Ubuntu 22.04 LTS / 24.04 LTS / Debian 12.

---

## Table of Contents
- [Package Management](#package-management)
- [Repository Management](#repository-management)
- [User and Group Management](#user-and-group-management)
- [Networking](#networking)
- [Firewalls](#firewalls)
- [Partitioning and Storage](#partitioning-and-storage)
- [System Configuration](#system-configuration)
- [Security and Access Control](#security-and-access-control)
- [Boot and System Management](#boot-and-system-management)
- [File System and Disk Management](#file-system-and-disk-management)
- [Software and Application Stacks](#software-and-application-stacks)
- [Containers and Orchestration](#containers-and-orchestration)
- [Logging and Monitoring](#logging-and-monitoring)
- [Enterprise Features and Support](#enterprise-features-and-support)
- [Development and Compilation](#development-and-compilation)

---

## Package Management

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | **APT** with `.deb` packages and PPA support | **DNF** with `.rpm` packages; YUM is a legacy alias for DNF on RHEL 9+ | DNF is the default on RHEL 8+. `yum` is now just a symlink to `dnf`. |
| Package Tool | — | `apt` | `dnf` | — |
| Package Format | — | `.deb` | `.rpm` | Fundamentally different formats |
| Install Package | — | `apt install nginx` | `dnf install nginx` | — |
| Remove Package | — | `apt remove nginx`<br>`apt purge nginx` ⚠️ removes config | `dnf remove nginx` | `purge` removes config files on Debian/Ubuntu |
| Update All Packages | — | `apt update && apt upgrade` | `dnf upgrade` | — |
| Update Single Package | — | `apt install --only-upgrade nginx` | `dnf upgrade nginx` | — |
| Search Package | — | `apt search keyword` | `dnf search keyword` | — |
| List Installed | — | `dpkg -l`<br>`apt list --installed` | `dnf list installed`<br>`rpm -qa` | — |
| Package Info | — | `apt show package`<br>`dpkg -s package` | `dnf info package`<br>`rpm -qi package` | — |
| File Ownership | — | `dpkg -S /path/to/file` | `rpm -qf /path/to/file` | Which package owns a file |
| List Package Files | — | `dpkg -L package` | `rpm -ql package` | — |
| Local Install | — | `apt install ./package.deb` | `dnf install ./package.rpm` | Preferred over `dpkg -i` / `rpm -ivh` — resolves deps |
| Package Verification | — | `debsums package` | `rpm -V package` | RPM has built-in verification |
| Dependencies | — | `apt-cache depends package`<br>`apt-cache rdepends package` | `dnf repoquery --requires --resolve package`<br>`dnf repoquery --whatrequires package` | — |
| Clean Cache | — | `apt clean`<br>`apt autoclean` | `dnf clean all` | — |
| Autoremove Orphans | — | `apt autoremove` | `dnf autoremove` | — |
| Package DB Location | — | `/var/lib/dpkg/status`<br>`/var/lib/apt/lists/` | `/var/lib/rpm/` (SQLite on RHEL 9+) | RHEL 9 migrated from Berkeley DB to SQLite |
| Hold Package Version | — | `apt-mark hold package` | `dnf versionlock add package` | Requires `python3-dnf-plugin-versionlock` on RHEL |
| Download Only | — | `apt download package` | `dnf download package` | — |
| Download Source | — | `apt source package` | `dnf download --source package` | — |
| Simulate Install | — | `apt install -s package` | `dnf install --assumeno package` | Dry run without changes |
| History / Rollback | — | `zcat /var/log/apt/history.log.*.gz` | `dnf history`<br>`dnf history undo <id>` | DNF supports transaction rollback natively |
| Modules (Streams) | — | Not applicable | `dnf module list`<br>`dnf module enable nodejs:20` | RHEL/AlmaLinux module streams allow parallel version management |

</details>

---

## Repository Management

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Repos in `/etc/apt/sources.list.d/` (modern: `.sources` format). PPAs via Launchpad. | `.repo` files in `/etc/yum.repos.d/`. EPEL is the go-to third-party source. | — |
| Repo Config Location | — | `/etc/apt/sources.list`<br>`/etc/apt/sources.list.d/*.list` or `*.sources` | `/etc/yum.repos.d/*.repo` | Ubuntu 24.04 uses new DEB822 `.sources` format |
| Modern Repo Format (Ubuntu 24.04) | — | `/etc/apt/sources.list.d/ubuntu.sources` (DEB822) | N/A | New format uses `Types: deb`, `URIs:`, `Suites:`, `Components:` |
| Add Repository | — | `add-apt-repository ppa:user/repo`<br>or drop `.sources` file | Create `.repo` file in `/etc/yum.repos.d/` or `dnf config-manager --add-repo URL` | — |
| Example Repo Config | — | `Types: deb`<br>`URIs: https://archive.ubuntu.com/ubuntu`<br>`Suites: noble`<br>`Components: main restricted universe multiverse` | `[baseos]`<br>`name=AlmaLinux 9 - BaseOS`<br>`mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/baseos`<br>`gpgcheck=1`<br>`gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9` | — |
| Enable EPEL (RHEL/Rocky/Alma) | — | N/A | `dnf install epel-release` | Essential for third-party packages on RHEL-family |
| Enable CRB / PowerTools | — | N/A | `dnf config-manager --set-enabled crb` (RHEL 9)<br>`dnf config-manager --set-enabled powertools` (Rocky 8) | Required for many EPEL build deps |
| Third-Party Repos | — | PPAs via `add-apt-repository` | EPEL, RPMFusion, Remi<br>`dnf install https://rpms.remirepo.net/enterprise/remi-release-9.rpm` | — |
| Disable a Repo (Temporary) | — | `apt install package -o Dir::Etc::sourcelist="sources.list"` | `dnf install package --disablerepo=epel` | — |
| Enable/Disable Repo Permanently | — | Comment out in `.list`/`.sources` | `dnf config-manager --set-disabled repo-id` | — |
| Update Repo Cache | — | `apt update` | Automatic with DNF | Ubuntu/Debian requires explicit cache refresh |
| Repo Priorities | — | `/etc/apt/preferences.d/` with `Pin-Priority:` | `priority=N` in `.repo` file | — |
| Local Mirror Tools | — | `apt-mirror`, `reprepro` | `createrepo_c`, `reposync` | `createrepo_c` replaced `createrepo` on RHEL 9 |
| GPG Key Import | — | `curl -fsSL URL \| sudo gpg --dearmor -o /etc/apt/keyrings/name.gpg` | `rpm --import URL` | Ubuntu 22.04+ recommends storing keys in `/etc/apt/keyrings/` |

</details>

---

## User and Group Management

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Sudo group is `sudo`. `adduser` is a friendlier Debian wrapper. | Sudo group is `wheel`. Standard `useradd` is default. | — |
| Add User | — | `adduser username` (interactive)<br>`useradd -m -s /bin/bash username` | `useradd -m -s /bin/bash username` | — |
| Set Password | — | `passwd username` | Same | — |
| Delete User | — | `deluser --remove-home username` | `userdel -r username` | — |
| Add to Sudo | — | `usermod -aG sudo username` | `usermod -aG wheel username` | Group name differs |
| List Groups | — | `groups username` | Same | — |
| Add Group | — | `addgroup groupname` | `groupadd groupname` | — |
| Lock Account | — | `passwd -l username` | Same | — |
| Unlock Account | — | `passwd -u username` | Same | — |
| User Expiry | — | `chage -E 2026-12-31 username` | Same | — |
| List Password Policy | — | `chage -l username` | Same | — |
| Sudoers File | — | `/etc/sudoers` via `visudo`<br>Drop-ins: `/etc/sudoers.d/` | Same | Always use `visudo` — validates syntax before saving |
| SSSD / LDAP Integration | — | `apt install sssd`<br>`/etc/sssd/sssd.conf` | `dnf install sssd`<br>`authselect select sssd` | RHEL 9 uses `authselect` instead of `authconfig` |
| Active Directory Join | — | `apt install realmd sssd`<br>`realm join domain.example.com` | `dnf install realmd sssd`<br>`realm join domain.example.com` | Same workflow, both use `realmd` |

</details>

---

## Networking

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | **Netplan** (Ubuntu 22.04+) or `/etc/network/interfaces` (Debian). DNS via `systemd-resolved`. | **NetworkManager** is default and preferred on RHEL 9. `nmcli` is the primary CLI tool. `network-scripts` removed in RHEL 9. | `iproute2` tools work on both. `net-tools` (`ifconfig`, `netstat`) deprecated on both. |
| Interface Naming | — | Predictable: `enp0s3`, `ens3`, `eth0` (cloud) | Predictable: `enp0s3`, `ens3`, `eth0` (cloud) | Cloud images often keep `eth0` |
| Network Config Tool | — | Netplan + `systemd-networkd` or NetworkManager | NetworkManager only (RHEL 9 removed legacy scripts) | — |
| Config File Location | — | `/etc/netplan/*.yaml` | Managed via `nmcli`; connection profiles in `/etc/NetworkManager/system-connections/` | RHEL 9 dropped `/etc/sysconfig/network-scripts/` entirely |
| Apply Network Changes | — | `sudo netplan apply` | `nmcli connection reload`<br>`nmcli connection up eth0` | — |
| Set Static IP | — | Edit `/etc/netplan/01-netcfg.yaml`, run `netplan apply` | `nmcli con mod eth0 ipv4.addresses 192.168.1.10/24`<br>`nmcli con mod eth0 ipv4.method manual`<br>`nmcli con up eth0` | — |
| Set DNS | — | In Netplan: `nameservers: addresses: [1.1.1.1]` | `nmcli con mod eth0 ipv4.dns "1.1.1.1 8.8.8.8"` | — |
| DHCP | — | In Netplan: `dhcp4: true` | `nmcli con mod eth0 ipv4.method auto` | — |
| Temporary IP | — | `ip addr add 192.168.1.100/24 dev eth0` | Same | — |
| DNS Resolution Config | — | `/etc/systemd/resolved.conf`<br>`resolvectl status` | `/etc/resolv.conf` (managed by NM) | Ubuntu: `/etc/resolv.conf` is a symlink to systemd-resolved stub |
| Flush DNS Cache | — | `resolvectl flush-caches` | `systemctl restart NetworkManager` | — |
| Routing Table | — | `ip route show` | Same | — |
| Add Static Route (Temp) | — | `ip route add 10.0.0.0/8 via 192.168.1.1` | Same | — |
| Add Static Route (Persistent) | — | Netplan `routes:` block | `nmcli con mod eth0 +ipv4.routes "10.0.0.0/8 192.168.1.1"` | — |
| Network Diagnostics | — | `ping`, `traceroute`, `mtr`, `dig`, `ss` | Same | — |
| Port Listening | — | `ss -tuln` | Same | `netstat` deprecated; use `ss` |
| Packet Capture | — | `tcpdump -i eth0 port 80` | Same | — |
| Network TUI | — | `nmtui` | `nmtui` | Both support it; RHEL has it by default |
| Bridge / Bond / VLAN | — | Netplan `bridges:` / `bonds:` / `vlans:` blocks | `nmcli` commands for each | — |
| WireGuard | — | `apt install wireguard`<br>`wg-quick up wg0` | `dnf install wireguard-tools`<br>`wg-quick up wg0` | Kernel module built-in since 5.6 |
| Network Namespaces | — | `ip netns add ns1`<br>`ip netns exec ns1 bash` | Same | — |

</details>

---

## Firewalls

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Defaults to **UFW**; nftables backend. | Defaults to **firewalld**; nftables backend on RHEL 9. `iptables` legacy mode available but not recommended. | Both distros now use nftables as the actual backend. Direct `iptables` rules still work but may conflict with firewalld/UFW. |
| Default Firewall Tool | — | UFW | firewalld | — |
| Enable Firewall | — | `ufw enable` | `systemctl enable --now firewalld` | — |
| Allow Port | — | `ufw allow 80/tcp` | `firewall-cmd --permanent --add-port=80/tcp`<br>`firewall-cmd --reload` | firewalld requires `--permanent` + `--reload` to persist |
| Allow Service by Name | — | `ufw allow 'Nginx Full'` | `firewall-cmd --permanent --add-service=http` | — |
| Deny Port | — | `ufw deny 23/tcp` | `firewall-cmd --permanent --remove-port=23/tcp` | — |
| List Rules | — | `ufw status verbose` | `firewall-cmd --list-all` | — |
| List Zones (firewalld) | — | N/A | `firewall-cmd --list-all-zones` | firewalld uses zones; default is `public` |
| Rich Rules | — | N/A | `firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port protocol="tcp" port="22" accept'` | — |
| Rate Limiting | — | `ufw limit 22/tcp` | `firewall-cmd --permanent --add-rich-rule='rule service name="ssh" limit value="10/m" accept'` | — |
| Direct nftables | — | `nft add rule inet filter input tcp dport 22 accept` | Same | — |
| nftables Config File | — | `/etc/nftables.conf` | `/etc/sysconfig/nftables.conf` | — |
| nftables Persistence | — | `systemctl enable nftables` | Same | — |
| iptables (Legacy) | — | `apt install iptables`<br>`iptables -A INPUT -p tcp --dport 22 -j ACCEPT` | Available but conflicts with firewalld if both active | On RHEL 9, `iptables` translates to nftables via `iptables-nft` |
| iptables Persist | — | `apt install iptables-persistent`<br>`netfilter-persistent save` | `iptables-save > /etc/sysconfig/iptables` | — |
| Block IP | — | `ufw deny from 1.2.3.4` | `firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="1.2.3.4" drop'` | — |
| Port Forwarding | — | Enable in `/etc/ufw/before.rules` with `PREROUTING` chain | `firewall-cmd --permanent --add-forward-port=port=80:proto=tcp:toport=8080` | — |

</details>

---

## Partitioning and Storage

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | ext4 default; excellent ZFS support (OpenZFS built-in). Stratis available. | XFS default; Stratis as optional advanced storage management layer. ZFS requires third-party repo. | — |
| Partition Tools | — | `fdisk`, `parted`, `gdisk` | Same | — |
| List Block Devices | — | `lsblk -f` | Same | — |
| Create Partition (GPT) | — | `parted -s /dev/sda mklabel gpt`<br>`parted -s /dev/sda mkpart primary ext4 1MiB 100GiB` | Same but XFS more common | — |
| LVM: PV / VG / LV Create | — | `pvcreate /dev/sda1`<br>`vgcreate vg0 /dev/sda1`<br>`lvcreate -n data -L 10G vg0` | Same | — |
| LVM: Extend | — | `lvextend -L +5G /dev/vg0/data`<br>`resize2fs /dev/vg0/data` | `lvextend -r -L +5G /dev/vg0/data` | RHEL: `-r` flag auto-resizes XFS; Ubuntu needs separate `resize2fs` |
| LVM: Thin Provisioning | — | `lvcreate --thin -L 100G vg0/thinpool`<br>`lvcreate --thin -n vol1 -V 50G vg0/thinpool` | Same | — |
| LVM Snapshots | — | `lvcreate -s -n snap -L 5G /dev/vg0/data` | Same | — |
| Create Filesystem | — | `mkfs.ext4 /dev/sda1`<br>`mkfs.xfs /dev/sda1` | `mkfs.xfs /dev/sda1` (default) | — |
| Resize ext4 | — | `resize2fs /dev/sda1` | Same | — |
| Resize XFS | — | `xfs_growfs /mountpoint` | Same | XFS cannot shrink |
| RAID (Software) | — | `mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sda1 /dev/sdb1` | Same | — |
| Stratis Storage | — | `apt install stratisd stratis-cli` | `dnf install stratisd stratis-cli`<br>`systemctl enable --now stratisd` | Thin provisioning + snapshots abstraction layer |
| ZFS | — | `apt install zfsutils-linux` (native, built-in) | Requires ZFS on Linux repo | Ubuntu has best native ZFS support |
| ZFS Pool Create | — | `zpool create tank mirror /dev/sda /dev/sdb` | Same (if ZFS installed) | — |
| Disk Encryption | — | `cryptsetup luksFormat /dev/sda1`<br>`cryptsetup open /dev/sda1 crypt0` | Same | — |
| LUKS2 (modern) | — | `cryptsetup luksFormat --type luks2 /dev/sda1` | Same | LUKS2 is default on both modern distros |
| Get UUID | — | `blkid /dev/sda1` | Same | — |
| Persistent Mounts | — | `/etc/fstab` with `UUID=` | Same | — |
| Mount Options (Performance) | — | `noatime,data=writeback` (ext4) | `noatime,logbufs=8` (XFS) | — |
| NFS Mount | — | `apt install nfs-common`<br>`mount -t nfs server:/share /mnt` | `dnf install nfs-utils`<br>`mount -t nfs server:/share /mnt` | — |
| NFS Server | — | `apt install nfs-kernel-server`<br>Edit `/etc/exports` | `dnf install nfs-utils`<br>Edit `/etc/exports`<br>`systemctl enable --now nfs-server` | — |

</details>

---

## System Configuration

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | AppArmor for MAC; Netplan for networking; `systemd` for services. | SELinux for MAC; NetworkManager for networking; `systemd` for services. RHEL 9 fully systemd-native. | — |
| Service Management | — | `systemctl start\|stop\|restart\|status nginx` | Same | — |
| Enable at Boot | — | `systemctl enable nginx` | Same | — |
| Enable + Start Now | — | `systemctl enable --now nginx` | Same | — |
| Service Config Locations | — | Unit files: `/lib/systemd/system/`<br>Overrides: `/etc/systemd/system/`<br>Env vars: `/etc/default/service` | Unit files: `/usr/lib/systemd/system/`<br>Overrides: `/etc/systemd/system/`<br>Env vars: `/etc/sysconfig/service` | — |
| Override Service Config | — | `systemctl edit nginx` (creates drop-in) | Same | Creates `/etc/systemd/system/nginx.service.d/override.conf` |
| Reload Systemd | — | `systemctl daemon-reload` | Same | Required after editing unit files |
| Hostname | — | `hostnamectl set-hostname myhost` | Same | — |
| Timezone | — | `timedatectl set-timezone America/New_York` | Same | — |
| Time Sync | — | `systemd-timesyncd` (default)<br>`apt install chrony` for enterprise | `chronyd` (default)<br>`timedatectl set-ntp true` | — |
| NTP Config | — | `/etc/systemd/timesyncd.conf` | `/etc/chrony.conf` | — |
| Locale | — | `locale-gen en_US.UTF-8`<br>`dpkg-reconfigure locales` | `localectl set-locale LANG=en_US.UTF-8` | — |
| Kernel Parameters (Runtime) | — | `sysctl -w net.ipv4.ip_forward=1` | Same | — |
| Kernel Parameters (Persistent) | — | `/etc/sysctl.d/99-custom.conf`<br>`sysctl --system` | Same | — |
| Resource Limits | — | `/etc/security/limits.conf`<br>`/etc/security/limits.d/` | Same | — |
| Systemd Resource Control | — | `systemctl set-property nginx.service MemoryMax=512M` | Same | cgroups v2 on both RHEL 9 and Ubuntu 22.04+ |

</details>

---

## Security and Access Control

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | **AppArmor** for MAC by default. `ufw` for firewall. `unattended-upgrades` for auto-patching. | **SELinux** enforcing by default. `firewalld` for firewall. RHEL 9 uses OpenSSL 3, stricter crypto policies. | Both support PAM, SSH hardening, FIPS mode, and audit logging. |
| MAC System | — | AppArmor | SELinux (targeted policy) | — |
| Check MAC Status | — | `sudo aa-status`<br>`sudo apparmor_status` | `getenforce`<br>`sestatus` | — |
| Set MAC Mode | — | `sudo aa-enforce /etc/apparmor.d/usr.bin.nginx`<br>`sudo aa-complain /etc/apparmor.d/usr.bin.nginx` | `setenforce 0` (permissive)<br>`setenforce 1` (enforcing) | SELinux persistence: set `SELINUX=enforcing` in `/etc/selinux/config` |
| Reload MAC Policy | — | `sudo apparmor_parser -r /etc/apparmor.d/usr.bin.nginx` | `restorecon -Rv /var/www/html` | — |
| Fix SELinux Denial | — | N/A | `ausearch -m avc -ts recent \| audit2allow -M mypol`<br>`semodule -i mypol.pp` | — |
| SELinux File Context | — | N/A | `chcon -t httpd_sys_content_t /var/www/html`<br>`semanage fcontext -a -t httpd_sys_content_t "/data(/.*)?"` | — |
| Crypto Policy (System-wide) | — | N/A (OpenSSL config) | `update-crypto-policies --set DEFAULT`<br>`update-crypto-policies --set FIPS` | RHEL 9 system-wide crypto policy is a key feature |
| FIPS Mode | — | `ua enable fips` (Ubuntu Pro required) | `fips-mode-setup --enable` | — |
| Add User to Sudo | — | `usermod -aG sudo username` | `usermod -aG wheel username` | — |
| SSH: Disable Root Login | — | `/etc/ssh/sshd_config`: `PermitRootLogin no` | Same | — |
| SSH: Key Only Auth | — | `PasswordAuthentication no` in `sshd_config` | Same | — |
| SSH: Change Port | — | `Port 2222` in `sshd_config` | Same + `semanage port -a -t ssh_port_t -p tcp 2222` | SELinux must allow new port on RHEL |
| SSH: Modern Hardening | — | Add to `sshd_config`:<br>`KexAlgorithms curve25519-sha256`<br>`Ciphers chacha20-poly1305@openssh.com`<br>`MACs hmac-sha2-256-etm@openssh.com` | Same | — |
| Generate SSH Key | — | `ssh-keygen -t ed25519 -C "user@host"` | Same | Ed25519 preferred over RSA in 2026 |
| 2FA for SSH | — | `apt install libpam-google-authenticator` | `dnf install google-authenticator` | Edit `/etc/pam.d/sshd` and set `ChallengeResponseAuthentication yes` |
| Fail2Ban | — | `apt install fail2ban`<br>`/etc/fail2ban/jail.local` | `dnf install fail2ban`<br>Same config | — |
| Auto Security Updates | — | `apt install unattended-upgrades`<br>`dpkg-reconfigure unattended-upgrades` | `dnf install dnf-automatic`<br>`systemctl enable --now dnf-automatic.timer` | — |
| Audit Framework | — | `apt install auditd`<br>`/etc/audit/rules.d/` | `auditd` installed by default<br>Same rules location | — |
| Audit: Watch File | — | `auditctl -w /etc/passwd -p wa -k passwd_changes` | Same | — |
| Audit: View Logs | — | `ausearch -k passwd_changes`<br>`aureport --summary` | Same | — |
| USBGuard | — | `apt install usbguard` | `dnf install usbguard` | Block unauthorized USB devices |
| OpenSCAP Scanning | — | `apt install libopenscap8`<br>`oscap xccdf eval ...` | `dnf install openscap-scanner scap-security-guide`<br>`oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis ...` | RHEL has more mature SCAP content |
| Password Policy | — | `/etc/login.defs`<br>PAM `pam_pwquality.so` | Same | — |

</details>

---

## Boot and System Management

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | GRUB2 + systemd. `update-grub` regenerates config. `update-initramfs` rebuilds initrd. | GRUB2 + systemd. `grub2-mkconfig` regenerates config. `dracut` rebuilds initrd. RHEL 9 supports Unified Kernel Images (UKI). | — |
| Bootloader Config | — | `/etc/default/grub` | `/etc/default/grub` | — |
| Regenerate GRUB (BIOS) | — | `update-grub` | `grub2-mkconfig -o /boot/grub2/grub.cfg` | — |
| Regenerate GRUB (UEFI) | — | `update-grub` | `grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg` | Path varies by distro: `almalinux`, `rocky`, `centos` |
| Rebuild Initramfs | — | `update-initramfs -u -k all` | `dracut --force --kver $(uname -r)` | — |
| List Available Kernels | — | `dpkg --list \| grep linux-image` | `rpm -q kernel`<br>`grubby --info=ALL` | — |
| Set Default Kernel | — | Edit `/etc/default/grub` `GRUB_DEFAULT=` | `grubby --set-default /boot/vmlinuz-<version>` | — |
| Kernel Parameters (Persistent) | — | Edit `/etc/default/grub` `GRUB_CMDLINE_LINUX`<br>Run `update-grub` | Same + `grub2-mkconfig` | — |
| Upgrade Kernel | — | `apt install --install-recommends linux-generic` | `dnf upgrade kernel` | — |
| Remove Old Kernels | — | `apt autoremove` | `dnf remove --oldinstallonly --setopt installonly_limit=2 kernel` | — |
| List Systemd Targets | — | `systemctl list-units --type=target` | Same | — |
| Change Default Target | — | `systemctl set-default multi-user.target` | Same | — |
| Rescue Mode | — | Append `systemd.unit=rescue.target` to kernel cmdline | Same | — |
| Emergency Mode | — | Append `systemd.unit=emergency.target` | Same | — |
| View Boot Logs | — | `journalctl -b` | Same | — |
| View Last Boot | — | `journalctl -b -1` | Same | — |
| Analyze Boot Performance | — | `systemd-analyze blame`<br>`systemd-analyze critical-chain` | Same | — |
| Watchdog | — | `systemd` watchdog via `WatchdogSec=` in unit file | Same | — |

</details>

---

## File System and Disk Management

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | ext4 default; excellent ZFS (OpenZFS). Btrfs available. | XFS default; ext4 supported. Btrfs tech preview only in RHEL 9, removed from RHEL 10 scope. | — |
| List Mounts | — | `findmnt`<br>`mount \| column -t` | Same | — |
| Disk Usage | — | `df -hT` | Same | `-T` shows filesystem type |
| Directory Usage | — | `du -sh /var/log/*` | Same | — |
| Inode Usage | — | `df -i` | Same | — |
| Find Large Files | — | `find / -xdev -type f -size +100M -exec ls -lh {} \;` | Same | — |
| Check Filesystem Type | — | `lsblk -f`<br>`blkid` | Same | — |
| Check / Repair ext4 | — | `fsck.ext4 -f /dev/sda1` | Same | Must be unmounted |
| Check / Repair XFS | — | `xfs_repair /dev/sda1` | Same | Must be unmounted |
| XFS Metadata Dump | — | `xfs_metadump /dev/sda1 dump.img` | Same | — |
| Resize ext4 Online | — | `resize2fs /dev/mapper/vg0-data` | Same | — |
| Resize XFS Online | — | `xfs_growfs /mountpoint` | Same | XFS can only grow, not shrink |
| Mount ISO | — | `mount -o loop,ro file.iso /mnt` | Same | — |
| Bind Mount | — | `mount --bind /source /dest` | Same | — |
| Persistent Bind Mount | — | Add to `/etc/fstab`: `/source /dest none bind 0 0` | Same | — |
| tmpfs (RAM disk) | — | `mount -t tmpfs -o size=512M tmpfs /mnt/ram` | Same | — |
| Disk Throughput Test | — | `dd if=/dev/zero of=/tmp/test bs=1M count=1024 oflag=dsync` | Same | — |
| Disk Read Speed | — | `hdparm -tT /dev/sda` | Same | — |
| SMART Status | — | `apt install smartmontools`<br>`smartctl -a /dev/sda` | `dnf install smartmontools`<br>Same | — |
| NVMe Info | — | `apt install nvme-cli`<br>`nvme list`<br>`nvme smart-log /dev/nvme0` | `dnf install nvme-cli`<br>Same | NVMe is now common; different tooling than SCSI/SAS |

</details>

---

## Software and Application Stacks

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | APT, Snap, Flatpak. More bleeding-edge package versions. | DNF modules, Flatpak. Slower release cadence = more stable. RHEL 9 ships Python 3.9 base, newer via modules. | — |
| Install Apache | — | `apt install apache2`<br>`systemctl enable --now apache2` | `dnf install httpd`<br>`systemctl enable --now httpd` | Service name differs: `apache2` vs `httpd` |
| Apache Config | — | `/etc/apache2/`<br>Sites: `/etc/apache2/sites-enabled/` | `/etc/httpd/`<br>Config: `/etc/httpd/conf.d/` | — |
| Install Nginx | — | `apt install nginx` | `dnf install nginx` | Same service name |
| Install MySQL 8 | — | `apt install mysql-server` | `dnf install mysql-server` | RHEL 9 defaults to MySQL 8.0 module |
| Install MariaDB | — | `apt install mariadb-server` | `dnf install mariadb-server` | — |
| Install PostgreSQL 16 | — | `apt install postgresql` or via official repo | `dnf install postgresql-server`<br>`postgresql-setup --initdb` | RHEL requires explicit `--initdb` step |
| Install PHP 8.x | — | `apt install php8.3 php8.3-fpm` | `dnf module enable php:8.3`<br>`dnf install php php-fpm` | Use modules on RHEL for newer PHP versions |
| Install Python 3 | — | `apt install python3 python3-pip python3-venv` | `dnf install python3 python3-pip` | — |
| Python Virtual Env | — | `python3 -m venv .venv && source .venv/bin/activate` | Same | Always use venvs; avoid `pip install` as root |
| Install Node.js 20 LTS | — | `curl -fsSL https://deb.nodesource.com/setup_20.x \| bash -`<br>`apt install nodejs` | `dnf module enable nodejs:20`<br>`dnf install nodejs` | — |
| Install Go | — | `apt install golang-go` or download from golang.org | `dnf install golang` | golang.org binary recommended for latest version |
| Install Java 21 | — | `apt install openjdk-21-jdk` | `dnf install java-21-openjdk-devel` | — |
| Install Redis | — | `apt install redis-server` | `dnf install redis`<br>`systemctl enable --now redis` | — |
| Install Memcached | — | `apt install memcached` | `dnf install memcached` | — |
| Install Certbot (Let's Encrypt) | — | `apt install certbot python3-certbot-nginx` | `dnf install certbot python3-certbot-nginx` | — |
| Snap Packages | — | `snap install package` | Not supported by default | Snap is Canonical-specific |
| Flatpak | — | `apt install flatpak`<br>`flatpak install flathub app.id` | `dnf install flatpak`<br>Same | Both support Flatpak |

</details>

---

## Containers and Orchestration

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Docker is the traditional default. Podman available. | RHEL 9 ships **Podman** as the default OCI runtime. Docker not in official RHEL repos. Both support Kubernetes via kubeadm or managed services. | Podman is daemonless and rootless by default — preferred in enterprise. |
| Install Docker | — | `apt install docker.io`<br>or official: `curl -fsSL https://get.docker.com \| bash` | Not in official repos; install from Docker's own repo or use Podman | — |
| Install Podman | — | `apt install podman` | `dnf install podman` (pre-installed on RHEL 9) | — |
| Run Container | — | `docker run -d -p 80:80 nginx` | `podman run -d -p 80:80 nginx` | Commands are largely compatible |
| Rootless Containers | — | `docker` (rootless mode available)<br>`podman` (rootless by default) | `podman` (rootless by default) | — |
| Build Image | — | `docker build -t myapp .` | `podman build -t myapp .`<br>or `buildah bud -t myapp .` | — |
| Docker Compose | — | `apt install docker-compose-plugin`<br>`docker compose up -d` | `dnf install docker-compose-plugin` or use Podman: `podman-compose up -d` | — |
| Podman Systemd Integration | — | `podman generate systemd --new mycontainer` | Same | Run containers as systemd services; native on RHEL 9 |
| Podman Quadlet (RHEL 9.3+) | — | Available | `~/.config/containers/systemd/myapp.container` | Quadlet replaces `podman generate systemd` for modern use |
| List Containers | — | `docker ps -a` | `podman ps -a` | — |
| Container Images | — | `docker images` | `podman images` | — |
| Container Logs | — | `docker logs -f container` | `podman logs -f container` | — |
| Container Registry Login | — | `docker login registry.example.com` | `podman login registry.example.com` | — |
| Install kubectl | — | `curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key \| gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg`<br>`apt install kubectl` | `cat <<EOF > /etc/yum.repos.d/kubernetes.repo`...<br>`dnf install kubectl` | Use official Kubernetes repos for latest |
| Install kubeadm / kubelet | — | `apt install kubeadm kubelet` | `dnf install kubeadm kubelet` | — |
| Install Helm | — | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` | Same | — |
| CRI-O (Container Runtime) | — | Available | Preferred runtime for OpenShift/Kubernetes on RHEL | — |
| Podman Desktop | — | Available | Available | GUI for managing containers locally |

</details>

---

## Logging and Monitoring

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | `rsyslog` + `systemd-journald`. Logs in `/var/log/`. `journalctl` is primary tool. | Same defaults on RHEL 9. `rsyslog` ships by default alongside journald. Log file names differ (e.g., `secure` vs `auth.log`). | — |
| View System Journal | — | `journalctl -xe` | Same | — |
| Follow Live Logs | — | `journalctl -f` | Same | — |
| Service Logs | — | `journalctl -u nginx -f` | Same | — |
| Logs Since Boot | — | `journalctl -b` | Same | — |
| Filter by Time | — | `journalctl --since "1 hour ago"` | Same | — |
| Filter by Priority | — | `journalctl -p err` | Same | — |
| Auth Log | — | `/var/log/auth.log` | `/var/log/secure` | File name differs |
| Syslog | — | `/var/log/syslog` | `/var/log/messages` | File name differs |
| Kernel Log | — | `dmesg -T \| tail -50` | Same | — |
| Journal Persistence | — | Set `Storage=persistent` in `/etc/systemd/journald.conf` | Same | Default may be volatile on minimal installs |
| Journal Size Limit | — | `SystemMaxUse=2G` in `journald.conf` | Same | — |
| Process Monitoring | — | `top`, `htop`, `btop` | Same | `btop` modern TUI resource monitor |
| System Overview | — | `vmstat 1`, `iostat -x 1`, `mpstat 1` | Same | Requires `sysstat` package |
| Disk IO | — | `iotop -ao` | Same | — |
| Network Bandwidth | — | `iftop`, `nload`, `nethogs` | Same | — |
| System Performance Snapshot | — | `sar -u 1 10` | Same | Requires `sysstat` |
| Prometheus Node Exporter | — | `apt install prometheus-node-exporter` or binary | Binary from GitHub releases | De facto standard for metrics collection |
| Logs Forwarding | — | `rsyslog` → remote syslog or Loki | Same | — |
| Centralized Logging | — | Elasticsearch/OpenSearch + Filebeat/Fluent Bit | Same | Platform-agnostic tooling |

</details>

---

## Enterprise Features and Support

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | **Ubuntu Pro** for 10-year LTS support, FIPS, Livepatch, ESM. Canonical support contracts available. | **RHEL Subscription** via Red Hat. **AlmaLinux** and **Rocky Linux** are free, community-supported binary-compatible rebuilds with no official vendor SLA. | CentOS 7 EOL: June 30, 2024. CentOS Stream is upstream of RHEL, not a stable clone. |
| Distribution Status (2026) | — | Ubuntu 22.04 LTS: support until 2032 (Pro)<br>Ubuntu 24.04 LTS: support until 2034 (Pro)<br>Debian 12: supported | RHEL 9: supported until 2032<br>AlmaLinux 9: community-supported until 2032<br>Rocky Linux 9: community-supported until 2032<br>CentOS 7: **EOL** | CentOS Stream 9/10: rolling; not a server OS replacement |
| Live Kernel Patching | — | **Canonical Livepatch** (Ubuntu Pro)<br>`pro enable livepatch` | **kpatch** (RHEL subscription)<br>`dnf install kpatch` | — |
| Extended Security Maintenance | — | Ubuntu Pro ESM: 10 years total LTS support | RHEL EUS: extended update support per minor release | — |
| FIPS 140-3 | — | `pro enable fips-updates` (Ubuntu Pro) | `fips-mode-setup --enable` (subscription) | — |
| Compliance Tooling | — | Ubuntu Security Guide (USG)<br>`apt install ubuntu-security-guide`<br>`usg fix cis_level1_server` | OpenSCAP + SCAP Security Guide<br>`oscap xccdf eval --profile cis` | — |
| Subscription/Registration | — | `pro attach <token>` | `subscription-manager register`<br>`subscription-manager attach --auto` | — |
| Configuration Management | — | Ansible, Puppet, Chef, Salt all supported | Same — Ansible is the Red Hat-native choice (Ansible Automation Platform) | — |
| Satellite / Landscape | — | **Canonical Landscape** for fleet management | **Red Hat Satellite** for patch/config management | — |
| Container Platform | — | Docker, Podman, MicroK8s (Canonical) | **OpenShift** (Red Hat), Podman, CRI-O | — |
| Image Building | — | `cloud-init`, `packer` | Same + **RHEL Image Builder** (`composer-cli`) | — |
| Supported Cloud Images | — | Official images on AWS, Azure, GCP, Oracle | Same | Both have certified marketplace images |

</details>

---

## Development and Compilation

<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/AlmaLinux/Rocky | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Rich PPAs for bleeding-edge compiler/runtime versions. `apt build-dep` for source builds. | DNF modules and SCLs (deprecated in RHEL 9; fully replaced by modules) for alternate versions. More conservative defaults. | — |
| Install Build Tools | — | `apt install build-essential` | `dnf groupinstall "Development Tools"` | — |
| Install GCC | — | `apt install gcc g++` | `dnf install gcc gcc-c++` | RHEL 9 ships GCC 11; Ubuntu 24.04 ships GCC 13 |
| Install Clang | — | `apt install clang` | `dnf install clang` | — |
| Install Make / CMake | — | `apt install make cmake` | `dnf install make cmake` | — |
| Install Git | — | `apt install git` | `dnf install git` | — |
| Install Python Dev Headers | — | `apt install python3-dev python3-venv` | `dnf install python3-devel` | — |
| Install Ruby Dev | — | `apt install ruby-dev` | `dnf install ruby-devel` | — |
| Install Java 21 JDK | — | `apt install openjdk-21-jdk` | `dnf install java-21-openjdk-devel` | — |
| Install Rust | — | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | Same | `rustup` is preferred over distro packages for both |
| Install Go | — | Download from golang.org/dl (recommended)<br>or `apt install golang-go` | Download from golang.org/dl (recommended)<br>or `dnf install golang` | Distro packages often lag behind latest Go releases |
| Install Node.js (via nvm) | — | `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh \| bash`<br>`nvm install 20` | Same | `nvm` recommended for per-user Node management |
| Package Source Build | — | `apt build-dep package`<br>`apt source package` | `dnf builddep package`<br>`dnf download --source package` | — |
| Debug Symbols | — | `apt install package-dbgsym` (from dbgsym repo) | `dnf debuginfo-install package` | — |
| Static Analysis | — | `apt install cppcheck clang-tidy` | `dnf install cppcheck clang-tools-extra` | — |
| Profiling | — | `apt install linux-perf valgrind` | `dnf install perf valgrind` | — |
| Cross Compilation | — | `apt install gcc-aarch64-linux-gnu` | `dnf install gcc-aarch64-linux-gnu` | — |
| Build Containers (Reproducible) | — | `docker build` or `buildah` | `buildah bud` (preferred on RHEL) | Buildah is daemonless and rootless |

</details>

---

> **Key 2026 Takeaways:**
> - CentOS is dead as a stable server OS. Migrate to **AlmaLinux 9** or **Rocky Linux 9**.
> - `yum` is now just `dnf`. Use `dnf` everywhere on RHEL-family.
> - RHEL 9 removed legacy network scripts. Use `nmcli` or `nmtui`.
> - Containers: Ubuntu → Docker is still common. RHEL → **Podman** is the default and preferred.
> - Both distros now run on **nftables** as the firewall backend.
> - **Ed25519** SSH keys everywhere. Drop RSA 2048.
> - Python 2 is gone. Stop referencing it.


##
##
