---
title: Ubuntu/Debian vs RHEL/CentOS Comprehensive Comparison
description: Full command, config, and feature comparison between Debian-based and RHEL-based Linux distributions for professional sysadmins.
last_updated: 2025-08-10
maintainer: your_github_username
tags:
  - linux
  - ubuntu
  - debian
  - rhel
  - centos
  - sysadmin
  - commands
---

# Comprehensive Comparison: Ubuntu/Debian vs RHEL/CentOS

This is a **complete reference** for administrators and engineers who manage both Debian/Ubuntu and RHEL/CentOS systems.  
It covers **package management, repositories, networking, firewalls, storage, system configuration, security, boot, filesystems, software stacks, logging, enterprise support, and development tooling**.

---

## 📑 Table of Contents
- [Package Management](#package-management)
- [Repository Management](#repository-management)
- [Networking](#networking)
- [Firewalls](#firewalls)
- [Partitioning and Storage](#partitioning-and-storage)
- [System Configuration](#system-configuration)
- [Security and Access Control](#security-and-access-control)
- [Boot and System Management](#boot-and-system-management)
- [File System and Disk Management](#file-system-and-disk-management)
- [Software and Application Stacks](#software-and-application-stacks)
- [Logging and Monitoring](#logging-and-monitoring)
- [Enterprise Features and Support](#enterprise-features-and-support)
- [Development and Compilation](#development-and-compilation)

---

## Package Management
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | **APT** with `.deb` packages and PPA support | **YUM/DNF** with `.rpm` packages, stronger dependency enforcement | — |
| **Package Management** | Main Package Tool | APT (Advanced Package Tool) | YUM/DNF (Yellowdog Updater, Modified) | DNF is the next-generation version of YUM used in RHEL/CentOS 8+ |
| | Package Format | `.deb` | `.rpm` | Fundamentally different package formats |
| | Install Package | `apt install nginx` | `yum install nginx`<br>`dnf install nginx` | — |
| | Remove Package | `apt remove nginx`<br>`apt purge nginx` (:warning: removes config) | `yum remove nginx`<br>`dnf remove nginx` | `"purge"` in Ubuntu/Debian removes config files |
| | Update Package | `apt update && apt upgrade` | `yum update`<br>`dnf update` | — |
| | Search Package | `apt search keyword`<br>`apt-cache search keyword` | `yum search keyword`<br>`dnf search keyword` | — |
| | List Installed | `dpkg -l`<br>`apt list --installed` | `rpm -qa`<br>`dnf list installed` | — |
| | Package Info | `apt show package`<br>`dpkg -s package` | `yum info package`<br>`dnf info package`<br>`rpm -qi package` | — |
| | File Ownership | `dpkg -S /path/to/file` | `rpm -qf /path/to/file` | Determines which package owns a file |
| | Package Files | `dpkg -L package` | `rpm -ql package` | Lists files installed by a package |
| | Local Install | `dpkg -i package.deb`<br>`apt install ./package.deb` | `rpm -ivh package.rpm`<br>`dnf install ./package.rpm` | — |
| | Package Verification | `debsums package` | `rpm -V package` | RPM has built-in verification |
| | Dependencies | `apt-cache depends package`<br>`apt-cache rdepends package` | `dnf repoquery --requires --resolve package`<br>`dnf repoquery --whatrequires package` | — |
| | Clean Cache | `apt clean`<br>`apt autoclean` | `yum clean all`<br>`dnf clean all` | — |
| | Package Database Location | `/var/lib/dpkg/status`<br>`/var/lib/apt/lists/` | `/var/lib/rpm/` (Berkeley DB format) | — |
| | Exclude Packages | In `apt.conf`: `APT::Get::Exclude` | In `/etc/yum.conf` or repo file: `exclude=` | — |
| | Hold Package Version | `apt-mark hold package` | `yum versionlock add package`<br>`dnf versionlock add package` | Prevents package from upgrading |
| | Dependency Resolution | Sometimes less aggressive | Very aggressive | RHEL/CentOS more strictly resolves dependencies |
| | Download Only | `apt download package` | `yum download package`<br>`dnf download package` | Downloads package without installing |
| | Download Source | `apt source package` | `dnf download --source package` | — |

</details>

---

## Repository Management
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Repos in `/etc/apt/sources.list` and `/etc/apt/sources.list.d/` | `.repo` files in `/etc/yum.repos.d/` | — |
| **Repository Management** | Repository Config Location | `/etc/apt/sources.list`<br>`/etc/apt/sources.list.d/*.list` | `/etc/yum.repos.d/*.repo` | — |
| | Add Repository | `add-apt-repository ppa:user/repo`<br>or edit sources.list | Create `.repo` file in yum.repos.d/ | — |
| | Example Repo Config | `deb http://archive.ubuntu.com/ubuntu focal main restricted universe multiverse` | `[base]`<br>`name=CentOS-$releasever - Base`<br>`mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os&infra=$infra`<br>`#baseurl=http://mirror.centos.org/centos/$releasever/os/$basearch/`<br>`gpgcheck=1`<br>`gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7` | — |
| | Third-Party Repos | PPAs (Personal Package Archives)<br>`add-apt-repository ppa:name/here` | EPEL, RPMFusion, Remi, IUS<br>Install repo RPM, then enable | Ubuntu PPAs are easier to add but less vetted |
| | Backports | `deb http://archive.ubuntu.com/ubuntu focal-backports main`<br>Debian: `deb http://deb.debian.org/debian buster-backports main` | EPEL serves a similar function<br>SCLs (Software Collections) | — |
| | Security Updates | `deb http://security.ubuntu.com/ubuntu focal-security main`<br>Debian: `deb http://security.debian.org/debian-security buster/updates main` | Built into base repos | — |
| | Commercial Repos | Ubuntu Pro/Advantage<br>Canonical Partners | RHEL Subscription<br>Red Hat Satellite | — |
| | Local Repository | `apt-mirror`<br>`reprepro` | `createrepo`<br>`reposync` | — |
| | Update Repo Cache | `apt update` | Automatic with YUM/DNF | Ubuntu/Debian requires explicit cache update |
| | Repository Priorities | `apt preferences` in `/etc/apt/preferences.d/` | `priority=N` in `.repo` files | RHEL/CentOS has simpler priority management |
| | Repository Management Tools | `apt-add-repository`<br>`software-properties-gtk` | `yum-config-manager`<br>`dnf config-manager` | — |

</details>

---

## Networking
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Netplan (modern Ubuntu) or `/etc/network/interfaces` (legacy Debian). DNS often via `systemd-resolved`. Predictable interface names. | NetworkManager (modern) or `/etc/sysconfig/network-scripts/` (legacy). DNS typically from `/etc/resolv.conf`. Predictable interface names. | `iproute2` tools (`ip addr`, `ip route`) work on both. |
| Interface Naming | — | Predictable: `enp0s3`, `wlp3s0`<br>Legacy: `eth0`, `wlan0` | Predictable: `enp0s3`, `wlp3s0`<br>Legacy: `eth0`, `wlan0` | — |
| Configure Interface (Modern) | — | Netplan YAML in `/etc/netplan/`<br>`sudo netplan apply` | NetworkManager via `nmcli` or GUI | Netplan generates configs for NM or systemd-networkd. |
| Configure Interface (Legacy) | — | `/etc/network/interfaces` syntax | `/etc/sysconfig/network-scripts/ifcfg-eth0` syntax | Legacy but still supported |
| Apply Network Changes | — | `sudo netplan apply`<br>`sudo systemctl restart networking` | `nmcli connection up eth0`<br>`sudo systemctl restart network` | — |
| Temporary IP Config | — | `sudo ip addr add 192.168.1.100/24 dev eth0` | Same as Ubuntu | — |
| DNS Client Config | — | `/etc/systemd/resolved.conf` or `/etc/resolv.conf` | `/etc/resolv.conf` | On Ubuntu `/etc/resolv.conf` may be symlinked. |
| DHCP Client | — | `dhclient` | `dhclient` | Both supported |
| Routing Table | — | `ip route`<br>`route -n` | Same as Ubuntu | — |
| Static Route (Temporary) | — | `sudo ip route add 10.0.0.0/8 via 192.168.1.254` | Same | — |
| Static Route (Persistent) | — | Netplan `routes:` block | `/etc/sysconfig/network-scripts/route-eth0` | — |
| Network Diagnostics | — | `ping`, `traceroute`, `mtr` | Same | Some require package install |
| Network Statistics | — | `ss -tuln`<br>`ip -s link` | Same | `netstat` requires `net-tools` |
| Packet Capture | — | `sudo tcpdump -i eth0 port 80` | Same | Requires `tcpdump` |
| Network Manager TUI | — | `nmtui` if installed | `nmtui` | RHEL has by default |
| Bridge Configuration | — | Netplan `bridges:` block | `nmcli` bridge commands | — |
| Bond Configuration | — | Netplan `bonds:` block | `nmcli` bond commands | — |
| VLAN Configuration | — | Netplan `vlans:` block | `nmcli` vlan commands | — |
| Wireless (CLI) | — | `iwconfig`, `nmcli` | Same | — |
| VPN Support | — | NetworkManager, OpenVPN, WireGuard | Same | — |

</details>

---

## Firewalls
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Defaults to **UFW** (Uncomplicated Firewall) for ease of use; nftables/iptables available. | Defaults to **firewalld**; nftables/iptables available. | Both can bypass frontend and configure iptables directly. |
| Default Firewall | — | `ufw enable`<br>`ufw allow 22/tcp` | `systemctl enable firewalld`<br>`firewall-cmd --permanent --add-service=ssh` | — |
| Advanced Firewall Frontend | — | `gufw` (GUI) | `firewall-config` (GUI) | — |
| Firewall Backend | — | nftables (modern), iptables (legacy) | nftables (modern), iptables (legacy) | Same backends |
| List Firewall Rules | — | `ufw status verbose` | `firewall-cmd --list-all` | — |
| Rule Persistence | — | UFW persistent by default | firewalld requires `--permanent` and `--reload` | — |
| Direct iptables (Basic) | — | `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` | Same | — |
| Direct iptables (Advanced) | — | `iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT`<br>`iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT` | Same | — |
| iptables NAT Example | — | `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` | Same | — |
| iptables Port Forwarding | — | `iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080` | Same | — |
| iptables Rate Limiting | — | `iptables -A INPUT -p tcp --dport 22 -m recent --set`<br>`iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 -j DROP` | Same | — |
| iptables Persistence | — | `apt install iptables-persistent`<br>`netfilter-persistent save` | `iptables-save > /etc/sysconfig/iptables`<br>`systemctl enable iptables` | — |
| nftables Example | — | `nft add rule ip filter input tcp dport 22 accept` | Same | — |
| nftables Ruleset File | — | `/etc/nftables.conf` | `/etc/sysconfig/nftables.conf` | Default file paths differ |
| CSF Firewall | — | `apt install csf` | `yum install csf` | Config file same: `/etc/csf/csf.conf` |
| CSF Allow IP/Port | — | `csf -a 192.168.1.100` | Same | — |
| CSF Deny IP | — | `csf -d 192.168.1.200` | Same | — |
| CSF Temporary Allow | — | `csf -ta 192.168.1.100 3600 "Temporary access"` | Same | — |
| CSF Reload | — | `csf -r` | Same | — |
| CSF LFD Config | — | `/etc/csf/csf.conf` (LFD_* options) | Same | LFD = Login Failure Daemon |

</details>

---

## Partitioning and Storage
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Same core storage tools as RHEL; defaults to ext4. Netboot uses preseed configs. | Same core storage tools as Ubuntu; defaults to XFS. Kickstart used for auto-provisioning. | — |
| Partition Tools (CLI) | — | `fdisk`, `parted`, `gdisk` | Same | — |
| Partition Tools (GUI) | — | `gparted` | `gparted` if installed | — |
| List Partitions | — | `lsblk`<br>`fdisk -l` | Same | — |
| Create Partition (MBR) | — | `fdisk /dev/sda` (`n`, `w`) | Same | — |
| Create Partition (GPT) | — | `parted /dev/sda mklabel gpt`<br>`parted /dev/sda mkpart primary ext4 1MiB 100GiB` | Same but often uses XFS instead of ext4 | — |
| Non-interactive Partitioning | — | `parted -s /dev/sda mklabel msdos` | Same | — |
| View Partition Table | — | `parted /dev/sda print` | Same | — |
| LVM: PV Create | — | `pvcreate /dev/sda1` | Same | — |
| LVM: VG Create | — | `vgcreate vg_data /dev/sda1 /dev/sdb1` | Same | — |
| LVM: LV Create | — | `lvcreate -n lv_data -L 10G vg_data` | Same | — |
| LVM: VG Extend | — | `vgextend vg_data /dev/sdc1` | Same | — |
| LVM: LV Extend | — | `lvextend -L +5G /dev/vg_data/lv_data`<br>`resize2fs /dev/vg_data/lv_data` | `lvextend -L +5G /dev/vg_data/lv_data`<br>`xfs_growfs /dev/vg_data/lv_data` | Filesystem resize differs (ext4 vs XFS) |
| Create ext4 Filesystem | — | `mkfs.ext4 /dev/sda1` | Same | — |
| Create XFS Filesystem | — | `mkfs.xfs /dev/sda1` | Same | — |
| Label Filesystem ext4 | — | `e2label /dev/sda1 data` | Same | — |
| Label Filesystem XFS | — | `xfs_admin -L data /dev/sda1` | Same | — |
| FS Check ext4 | — | `fsck.ext4 -f /dev/sda1` | Same | — |
| FS Check XFS | — | `xfs_repair /dev/sda1` | Same | — |
| Mount Filesystem | — | `mount /dev/sda1 /mnt` | Same | — |
| Mount Options | — | `mount -o noatime,data=writeback /dev/sda1 /mnt` | `mount -o noatime,logbufs=8 /dev/sda1 /mnt` | Optimized per FS type |
| Persistent Mounts | — | `/etc/fstab` with UUID | Same | — |
| Get UUID | — | `blkid /dev/sda1` | Same | — |
| Create RAID | — | `mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sda1 /dev/sdb1` | Same | — |
| RAID Status | — | `cat /proc/mdstat` | Same | — |
| Disk Encryption | — | `cryptsetup luksFormat /dev/sda1` | Same | — |
| ZFS Support | — | Built-in | Requires third-party repo | Ubuntu has better native ZFS support |
| Swap Partition | — | `mkswap /dev/sda2`<br>`swapon /dev/sda2` | Same | — |
| Swap File | — | `dd if=/dev/zero of=/swapfile bs=1M count=1024`<br>`chmod 600 /swapfile`<br>`mkswap /swapfile`<br>`swapon /swapfile` | Same | — |

</details>

---

## System Configuration
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Uses Netplan for network config; AppArmor for MAC. Systemd for services. | Uses NetworkManager for network config; SELinux for MAC. Systemd for services. | — |
| Service Management | — | `systemctl start nginx`<br>`systemctl enable nginx` | Same | — |
| Legacy Service Commands | — | `service nginx start` | `chkconfig nginx on` | Legacy only |
| Service Config Location | — | `/lib/systemd/system/`<br>`/etc/systemd/system/`<br>`/etc/default/service` | `/usr/lib/systemd/system/`<br>`/etc/systemd/system/`<br>`/etc/sysconfig/service` | Env var file differs |
| Network Config | — | Netplan `/etc/netplan/*.yaml` | `/etc/sysconfig/network-scripts/ifcfg-*` | — |
| Hostname Config | — | `/etc/hostname`<br>`hostnamectl set-hostname` | Same | — |
| DNS Resolution | — | `/etc/systemd/resolved.conf` | `/etc/resolv.conf` | — |
| Time Sync | — | `systemd-timesyncd` or `ntp` | `chronyd` | — |
| Locale Config | — | `dpkg-reconfigure locales` | `localectl set-locale LANG=en_US.UTF-8` | — |
| Timezone Config | — | `timedatectl set-timezone Europe/London` | Same | — |

</details>

---

## Security and Access Control
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Uses **AppArmor** for Mandatory Access Control (MAC) by default; SELinux optional. Simpler sudoers configuration. | Uses **SELinux** for MAC by default; AppArmor not used. Sudoers config similar but placed differently. | Both support PAM, SSH hardening, 2FA, and encryption tools. |
| Mandatory Access Control | — | AppArmor enabled by default (Ubuntu), disabled in Debian minimal installs. | SELinux enabled in enforcing mode by default. | Different syntax and tooling: `aa-*` for AppArmor, `semanage` for SELinux. |
| Check MAC Status | — | `sudo apparmor_status` | `getenforce` | — |
| Change MAC Mode | — | `sudo aa-disable /etc/apparmor.d/usr.bin.nginx` | `setenforce 0` (permissive), `setenforce 1` (enforcing) | SELinux changes may need `SELINUX=` in `/etc/selinux/config` for persistence. |
| Edit MAC Policy | — | `/etc/apparmor.d/` profiles, edited directly | `vi /etc/selinux/targeted/modules/active/modules/httpd.pp` (via `audit2allow`) | Tooling differs heavily. |
| Sudoers File | — | `/etc/sudoers` (edited with `visudo`) | `/etc/sudoers` (same), or `/etc/sudoers.d/*` | Both distros recommend drop-in files in `/etc/sudoers.d`. |
| Add User to Sudo | — | `usermod -aG sudo username` | `usermod -aG wheel username` | Group names differ. |
| PAM Config Location | — | `/etc/pam.d/` | `/etc/pam.d/` | Same location but different defaults. |
| Disable Root SSH Login | — | `/etc/ssh/sshd_config`: `PermitRootLogin no` | Same | — |
| Change SSH Port | — | `/etc/ssh/sshd_config`: `Port 2222` | Same | SELinux must allow new port on RHEL: `semanage port -a -t ssh_port_t -p tcp 2222`. |
| SSH Key Authentication | — | `~/.ssh/authorized_keys` | Same | — |
| Generate SSH Key | — | `ssh-keygen -t ed25519 -C "comment"` | Same | — |
| Fail2Ban Install | — | `apt install fail2ban` | `yum install fail2ban` or `dnf install fail2ban` | — |
| Fail2Ban Config | — | `/etc/fail2ban/jail.local` | Same | — |
| Firewall SSH Whitelist | — | `ufw allow from 192.168.1.0/24 to any port 22` | `firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port protocol="tcp" port="22" accept'` | — |
| 2FA for SSH | — | `apt install libpam-google-authenticator`<br>Edit `/etc/pam.d/sshd` and `/etc/ssh/sshd_config` | Same | — |
| Disk Encryption | — | `cryptsetup luksFormat /dev/sda1` | Same | — |
| GPG Encryption | — | `gpg -c file.txt`<br>`gpg file.txt.gpg` | Same | — |
| Password Policy Config | — | `/etc/login.defs` and PAM modules (`pam_pwquality`) | Same | — |

</details>

---

## Boot and System Management
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Both use GRUB2 and systemd; differences in bootloader config location. Ubuntu often has `grub` config in `/etc/default/grub`; RHEL uses `/etc/default/grub` + `grub2-mkconfig`. | RHEL separates EFI and BIOS boot commands; uses dracut for initramfs management. |
| Bootloader Config | — | `/etc/default/grub` | `/etc/default/grub` | Both require regenerating GRUB config. |
| Regenerate GRUB | — | `update-grub` | `grub2-mkconfig -o /boot/grub2/grub.cfg` (BIOS)<br>`grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg` (UEFI) | — |
| Initramfs Rebuild | — | `update-initramfs -u` | `dracut --force` | — |
| List Systemd Services | — | `systemctl list-units --type=service` | Same | — |
| Change Default Target | — | `systemctl set-default multi-user.target` | Same | — |
| View Boot Logs | — | `journalctl -b` | Same | — |
| Kernel Upgrade | — | `apt install --install-recommends linux-generic` | `yum update kernel` | — |
| Kernel Parameters (Temp) | — | Edit GRUB boot entry at boot time | Same | — |
| Kernel Parameters (Persistent) | — | Edit `/etc/default/grub`, run `update-grub` | Edit `/etc/default/grub`, run `grub2-mkconfig` | — |

</details>

---

## File System and Disk Management
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Uses ext4 by default; supports XFS, Btrfs, ZFS. | Uses XFS by default; ext4 supported, Btrfs disabled in older RHEL. |
| List Mounted Filesystems | — | `mount`<br>`findmnt` | Same | — |
| Show Disk Usage | — | `df -h` | Same | — |
| Show Inode Usage | — | `df -i` | Same | — |
| Find Largest Files | — | `find / -type f -size +100M -exec ls -lh {} \;` | Same | — |
| Check FS Type | — | `lsblk -f` | Same | — |
| Resize ext4 | — | `resize2fs /dev/sda1` | Same | — |
| Resize XFS | — | `xfs_growfs /mountpoint` | Same | — |
| Mount ISO | — | `mount -o loop file.iso /mnt` | Same | — |
| Bind Mount | — | `mount --bind /source /dest` | Same | — |
| Unmount | — | `umount /mnt` | Same | — |

</details>

---

## Software and Application Stacks
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Uses APT, Snap packages. | Uses YUM/DNF, modules. |
| Install Apache | — | `apt install apache2` | `yum install httpd` | — |
| Start Apache | — | `systemctl start apache2` | `systemctl start httpd` | — |
| Install MySQL | — | `apt install mysql-server` | `yum install mysql-server` | — |
| Install PHP | — | `apt install php` | `yum install php` | — |
| Install Python 3 | — | `apt install python3` | `yum install python3` | — |
| Install Node.js | — | `apt install nodejs npm` | `yum install nodejs npm` | — |
| Install Docker | — | `apt install docker.io` | `yum install docker` | — |
| Install Kubernetes CLI | — | `apt install kubectl` | `yum install kubectl` | — |

</details>

---

## Logging and Monitoring
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Uses `rsyslog` + `systemd-journald`; logs in `/var/log/`. | Same defaults. |
| View Syslog | — | `journalctl -xe` | Same | — |
| View Auth Log | — | `cat /var/log/auth.log` | `cat /var/log/secure` | Log file names differ. |
| Follow Logs | — | `journalctl -f` | Same | — |
| Service Logs | — | `journalctl -u nginx` | Same | — |
| Monitor Processes | — | `top`, `htop` | Same | — |
| Monitor Disk IO | — | `iotop` | Same | — |
| Monitor Network | — | `iftop` | Same | — |

</details>

---

## Enterprise Features and Support
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Ubuntu Pro for extended support; Canonical Livepatch. | RHEL Subscription for support; EUS for long-term stability. |
| Live Kernel Patching | — | Canonical Livepatch | kpatch | — |
| Extended Security Updates | — | Ubuntu Pro | EUS | — |
| Vendor Support | — | Canonical | Red Hat | — |

</details>

---

## Development and Compilation
<details>
<summary>Expand table</summary>

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Quick Summary** | — | Rich PPAs for packages; `apt build-dep` simplifies source builds. | RHEL uses Software Collections (SCL) or modules for alternate compiler/runtime versions. |
| Install Build Tools | — | `apt install build-essential` | `yum groupinstall "Development Tools"` | — |
| Install GCC | — | `apt install gcc` | `yum install gcc` | — |
| Install Make | — | `apt install make` | `yum install make` | — |
| Install Git | — | `apt install git` | `yum install git` | — |
| Install CMake | — | `apt install cmake` | `yum install cmake` | — |
| Install Go | — | `apt install golang` | `yum install golang` | — |
| Install Java | — | `apt install default-jdk` | `yum install java-11-openjdk` | — |
| Install Python Dev | — | `apt install python3-dev` | `yum install python3-devel` | — |
| Install Ruby Dev | — | `apt install ruby-dev` | `yum install ruby-devel` | — |
| Install Node.js | — | `apt install nodejs npm` | `yum install nodejs npm` | — |

</details>


##
##
