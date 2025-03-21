# Comprehensive Comparison: Ubuntu/Debian vs RHEL/CentOS

| Category | Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|----------|---------|---------------|-------------|-------|
| **Package Management** | Main Package Tool | APT (Advanced Package Tool) | YUM/DNF (Yellowdog Updater, Modified) | DNF is the next-generation version of YUM used in RHEL/CentOS 8+ |
| | Package Format | .deb | .rpm | Fundamentally different package formats |
| | Install Package | `apt install nginx` | `yum install nginx`<br>`dnf install nginx` | |
| | Remove Package | `apt remove nginx`<br>`apt purge nginx` (removes config) | `yum remove nginx`<br>`dnf remove nginx` | "purge" in Ubuntu/Debian removes config files |
| | Update Package | `apt update && apt upgrade` | `yum update`<br>`dnf update` | |
| | Search Package | `apt search keyword`<br>`apt-cache search keyword` | `yum search keyword`<br>`dnf search keyword` | |
| | List Installed | `dpkg -l`<br>`apt list --installed` | `rpm -qa`<br>`dnf list installed` | |
| | Package Info | `apt show package`<br>`dpkg -s package` | `yum info package`<br>`dnf info package`<br>`rpm -qi package` | |
| | File Ownership | `dpkg -S /path/to/file` | `rpm -qf /path/to/file` | Determines which package owns a file |
| | Package Files | `dpkg -L package` | `rpm -ql package` | Lists files installed by a package |
| | Local Install | `dpkg -i package.deb`<br>`apt install ./package.deb` | `rpm -ivh package.rpm`<br>`dnf install ./package.rpm` | |
| | Package Verification | `debsums package` | `rpm -V package` | RPM has built-in verification |
| | Dependencies | `apt-cache depends package`<br>`apt-cache rdepends package` | `dnf repoquery --requires --resolve package`<br>`dnf repoquery --whatrequires package` | |
| | Clean Cache | `apt clean`<br>`apt autoclean` | `yum clean all`<br>`dnf clean all` | |
| | Package Database Location | `/var/lib/dpkg/status`<br>`/var/lib/apt/lists/` | `/var/lib/rpm/` (Berkeley DB format) | |
| | Exclude Packages | In `apt.conf`: `APT::Get::Exclude` | In `/etc/yum.conf` or repo file: `exclude=` | |
| | Hold Package Version | `apt-mark hold package` | `yum versionlock add package`<br>`dnf versionlock add package` | Prevents package from upgrading |
| | Dependency Resolution | Sometimes less aggressive | Very aggressive | RHEL/CentOS more strictly resolves dependencies |
| | Download Only | `apt download package` | `yum download package`<br>`dnf download package` | Downloads package without installing |
| | Download Source | `apt source package` | `dnf download --source package` | |
| **Repository Management** | Repository Config Location | `/etc/apt/sources.list`<br>`/etc/apt/sources.list.d/*.list` | `/etc/yum.repos.d/*.repo` | |
| | Add Repository | `add-apt-repository ppa:user/repo`<br>or edit sources.list | Create .repo file in yum.repos.d/ | |
| | Example Repo Config | `deb http://archive.ubuntu.com/ubuntu focal main restricted universe multiverse` | `[base]`<br>`name=CentOS-$releasever - Base`<br>`mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os&infra=$infra`<br>`#baseurl=http://mirror.centos.org/centos/$releasever/os/$basearch/`<br>`gpgcheck=1`<br>`gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7` | |
| | Third-Party Repos | PPAs (Personal Package Archives)<br>`add-apt-repository ppa:name/here` | EPEL, RPMFusion, Remi, IUS<br>Install repo RPM, then enable | Ubuntu PPAs are easier to add but less vetted |
| | Backports | `deb http://archive.ubuntu.com/ubuntu focal-backports main`<br>Debian: `deb http://deb.debian.org/debian buster-backports main` | EPEL serves a similar function<br>SCLs (Software Collections) | |
| | Security Updates | `deb http://security.ubuntu.com/ubuntu focal-security main`<br>Debian: `deb http://security.debian.org/debian-security buster/updates main` | Built into base repos | |
| | Commercial Repos | Ubuntu Pro/Advantage<br>Canonical Partners | RHEL Subscription<br>Red Hat Satellite | |
| | Local Repository | `apt-mirror`<br>`reprepro` | `createrepo`<br>`reposync` | |
| | Update Repo Cache | `apt update` | Automatic with YUM/DNF | Ubuntu/Debian requires explicit cache update |
| | Repository Priorities | `apt preferences` in `/etc/apt/preferences.d/` | `priority=N` in .repo files | RHEL/CentOS has simpler priority management |
| | Repository Management Tools | `apt-add-repository`<br>`software-properties-gtk` | `yum-config-manager`<br>`dnf config-manager` | |
| **Networking** | Interface Naming | Predictable: `enp0s3`, `wlp3s0`<br>Legacy: `eth0`, `wlan0` | Predictable: `enp0s3`, `wlp3s0`<br>Legacy: `eth0`, `wlan0` | Both use predictable naming by default |
| | Configure Interface (Modern) | Netplan (Ubuntu 18.04+):<br>`/etc/netplan/01-netcfg.yaml` | NetworkManager:<br>`nmcli connection modify eth0 ipv4.addresses 192.168.1.100/24` | Different configuration systems |
| | Configure Interface (Legacy) | `/etc/network/interfaces`:<br>`auto eth0`<br>`iface eth0 inet static`<br>`  address 192.168.1.100/24`<br>`  gateway 192.168.1.1` | `/etc/sysconfig/network-scripts/ifcfg-eth0` | |
| | Apply Network Changes | `netplan apply` (modern)<br>`systemctl restart networking` (legacy) | `nmcli connection up eth0`<br>`systemctl restart network` (legacy) | |
| | Temporary IP Config | `ip addr add 192.168.1.100/24 dev eth0` | `ip addr add 192.168.1.100/24 dev eth0` | Same tool (iproute2) |
| | DNS Client Config | `/etc/systemd/resolved.conf`<br>Ubuntu: NetworkManager<br>Legacy: `/etc/resolv.conf` | `/etc/resolv.conf`<br>NetworkManager | systemd-resolved is more common in Ubuntu |
| | DHCP Client | dhclient, systemd-networkd | dhclient, NetworkManager | |
| | Routing Table | `ip route`<br>`route -n` (legacy) | `ip route`<br>`route -n` (legacy) | Same tools |
| | Static Route (Temporary) | `ip route add 10.0.0.0/8 via 192.168.1.254` | `ip route add 10.0.0.0/8 via 192.168.1.254` | Same command |
| | Static Route (Persistent) | Netplan:<br>`routes:`<br>`  - to: 10.0.0.0/8`<br>`    via: 192.168.1.254` | `/etc/sysconfig/network-scripts/route-eth0`:<br>`10.0.0.0/8 via 192.168.1.254` | Different config files |
| | Network Diagnostics | `ping`, `traceroute`, `mtr` | `ping`, `traceroute`, `mtr` | Same tools |
| | Network Statistics | `ss -tuln`, `netstat -tuln` (legacy)<br>`ip -s link` | `ss -tuln`, `netstat -tuln` (legacy)<br>`ip -s link` | Same tools |
| | Packet Capture | `tcpdump -i eth0 port 80` | `tcpdump -i eth0 port 80` | Same tool |
| | Network Manager TUI | `nmtui` (if installed) | `nmtui` | More common in RHEL/CentOS |
| | Bridge Configuration | Netplan:<br>`bridges:`<br>`  br0:`<br>`    interfaces: [enp0s3]` | `nmcli con add type bridge con-name br0 ifname br0`<br>`nmcli con add type bridge-slave con-name br0-port1 ifname enp0s3 master br0` | |
| | Bond Configuration | Netplan:<br>`bonds:`<br>`  bond0:`<br>`    interfaces: [enp0s3, enp0s8]`<br>`    parameters:`<br>`      mode: 802.3ad` | `nmcli con add type bond con-name bond0 ifname bond0 bond.options "mode=802.3ad"`<br>`nmcli con add type bond-slave ifname enp0s3 master bond0` | |
| | VLAN Configuration | Netplan:<br>`vlans:`<br>`  vlan10:`<br>`    id: 10`<br>`    link: enp0s3` | `nmcli con add type vlan con-name vlan10 ifname vlan10 dev enp0s3 id 10` | |
| | Wireless (CLI) | `iwconfig`, `nmcli` | `iwconfig`, `nmcli` | Same tools |
| | VPN Support | NetworkManager, OpenVPN, WireGuard | NetworkManager, OpenVPN, WireGuard | Similar support |
| **Firewalls** | Default Firewall | UFW (Uncomplicated Firewall)<br>`ufw enable`<br>`ufw allow 22/tcp` | firewalld<br>`systemctl enable firewalld`<br>`firewall-cmd --permanent --add-service=ssh` | Different front-ends |
| | Advanced Firewall Frontend | `gufw` (GUI for UFW) | `firewall-config` (GUI for firewalld) | |
| | Firewall Backend | nftables (newer)<br>iptables (legacy) | nftables (newer)<br>iptables (legacy) | Same backends, different front-ends |
| | List Firewall Rules (UFW/firewalld) | `ufw status verbose` | `firewall-cmd --list-all` | |
| | Rule Persistence | UFW rules are persistent by default | firewalld: `--permanent` flag needed<br>Must run `firewall-cmd --reload` | firewalld requires explicit persistence |
| | Direct iptables (Basic) | `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`<br>`iptables -A INPUT -j DROP` | `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`<br>`iptables -A INPUT -j DROP` | Same syntax when using iptables directly |
| | Direct iptables (Advanced) | `iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT`<br>`iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT` | `iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT`<br>`iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT` | Same syntax |
| | iptables NAT Example | `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`<br>`iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT` | `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`<br>`iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT` | Same syntax |
| | iptables Port Forwarding | `iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080` | `iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080` | Same syntax |
| | iptables Rate Limiting | `iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set`<br>`iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP` | `iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set`<br>`iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP` | Same syntax |
| | iptables Persistence | `apt install iptables-persistent`<br>`netfilter-persistent save` | `iptables-save > /etc/sysconfig/iptables`<br>`systemctl enable iptables` | Different persistence methods |
| | nftables Example | `nft add rule ip filter input tcp dport 22 accept` | `nft add rule ip filter input tcp dport 22 accept` | Same syntax |
| | nftables Ruleset File | `/etc/nftables.conf` | `/etc/sysconfig/nftables.conf` | Different default locations |
| | CSF (ConfigServer Firewall) | `apt install csf`<br>Config: `/etc/csf/csf.conf` | `yum install csf`<br>Config: `/etc/csf/csf.conf` | Third-party firewall, same usage |
| | CSF Allow IP/Port | `csf -a 192.168.1.100`<br>In csf.conf: `TCP_IN = "22,80,443"` | `csf -a 192.168.1.100`<br>In csf.conf: `TCP_IN = "22,80,443"` | Same syntax |
| | CSF Deny IP | `csf -d 192.168.1.200` | `csf -d 192.168.1.200` | Same syntax |
| | CSF Temporary Allow | `csf -ta 192.168.1.100 3600 "Temporary access"` | `csf -ta 192.168.1.100 3600 "Temporary access"` | Same syntax |
| | CSF Reload | `csf -r` | `csf -r` | Same syntax |
| | CSF LFD Config | `/etc/csf/csf.conf` (LFD_* options)<br>`RESTRICT_SYSLOG = "3"` | `/etc/csf/csf.conf` (LFD_* options)<br>`RESTRICT_SYSLOG = "3"` | Login Failure Daemon settings |
| **Partitioning and Storage** | Partition Tools (CLI) | `fdisk`, `parted`, `gdisk` | `fdisk`, `parted`, `gdisk` | Same tools available |
| | Partition Tools (GUI) | `gparted` | `gparted` (if installed) | |
| | List Partitions | `lsblk`<br>`fdisk -l` | `lsblk`<br>`fdisk -l` | Same commands |
| | Create Partition (MBR) | `fdisk /dev/sda`<br>Interactive commands: `n` (new), `w` (write) | `fdisk /dev/sda`<br>Interactive commands: `n` (new), `w` (write) | Same syntax |
| | Create Partition (GPT) | `gdisk /dev/sda` or<br>`parted /dev/sda`<br>`parted /dev/sda mklabel gpt`<br>`parted /dev/sda mkpart primary ext4 1MiB 100GiB` | `gdisk /dev/sda` or<br>`parted /dev/sda`<br>`parted /dev/sda mklabel gpt`<br>`parted /dev/sda mkpart primary xfs 1MiB 100GiB` | Same tools, different default filesystem |
| | Non-interactive Partitioning | `parted -s /dev/sda mklabel msdos`<br>`parted -s /dev/sda mkpart primary ext4 1MiB 100%` | `parted -s /dev/sda mklabel msdos`<br>`parted -s /dev/sda mkpart primary xfs 1MiB 100%` | Same syntax |
| | View Partition Table | `parted /dev/sda print` | `parted /dev/sda print` | Same syntax |
| | Creating LVM Physical Volume | `pvcreate /dev/sda1` | `pvcreate /dev/sda1` | Same syntax |
| | Creating Volume Group | `vgcreate vg_data /dev/sda1 /dev/sdb1` | `vgcreate vg_data /dev/sda1 /dev/sdb1` | Same syntax |
| | Creating Logical Volume | `lvcreate -n lv_data -L 10G vg_data` | `lvcreate -n lv_data -L 10G vg_data` | Same syntax |
| | Extending Volume Group | `vgextend vg_data /dev/sdc1` | `vgextend vg_data /dev/sdc1` | Same syntax |
| | Extending Logical Volume | `lvextend -L +5G /dev/vg_data/lv_data`<br>`resize2fs /dev/vg_data/lv_data` | `lvextend -L +5G /dev/vg_data/lv_data`<br>`xfs_growfs /dev/vg_data/lv_data` | Different filesystem resize commands |
| | LVM Management GUI | `system-config-lvm` (if installed) | `system-config-lvm` (if installed) | |
| | Create ext4 Filesystem | `mkfs.ext4 /dev/sda1` | `mkfs.ext4 /dev/sda1` | Same syntax |
| | Create XFS Filesystem | `mkfs.xfs /dev/sda1` | `mkfs.xfs /dev/sda1` | Same syntax |
| | Label Filesystem (ext4) | `e2label /dev/sda1 data` | `e2label /dev/sda1 data` | Same syntax |
| | Label Filesystem (XFS) | `xfs_admin -L data /dev/sda1` | `xfs_admin -L data /dev/sda1` | Same syntax |
| | Check/Repair Filesystem (ext4) | `fsck.ext4 -f /dev/sda1` | `fsck.ext4 -f /dev/sda1` | Same syntax |
| | Check/Repair Filesystem (XFS) | `xfs_repair /dev/sda1` | `xfs_repair /dev/sda1` | Same syntax |
| | Mount Filesystem | `mount /dev/sda1 /mnt` | `mount /dev/sda1 /mnt` | Same syntax |
| | Mount Options | `mount -o noatime,data=writeback /dev/sda1 /mnt` | `mount -o noatime,logbufs=8 /dev/sda1 /mnt` | Different optimal options for different filesystems |
| | Persistent Mounts | `/etc/fstab` entry:<br>`UUID=abcd1234 /data ext4 defaults 0 2` | `/etc/fstab` entry:<br>`UUID=abcd1234 /data xfs defaults 0 2` | Same format, different filesystem |
| | Find UUID of Device | `blkid /dev/sda1` | `blkid /dev/sda1` | Same syntax |
| | Create RAID (Software) | `mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sda1 /dev/sdb1` | `mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/sda1 /dev/sdb1` | Same syntax |
| | RAID Status | `cat /proc/mdstat`<br>`mdadm --detail /dev/md0` | `cat /proc/mdstat`<br>`mdadm --detail /dev/md0` | Same syntax |
| | Disk Encryption | `cryptsetup luksFormat /dev/sda1`<br>`cryptsetup luksOpen /dev/sda1 encrypted_volume` | `cryptsetup luksFormat /dev/sda1`<br>`cryptsetup luksOpen /dev/sda1 encrypted_volume` | Same syntax |
| | ZFS Support | `apt install zfsutils-linux`<br>Supported in stock kernel | Requires third-party repo<br>e.g., `dnf install https://zfsonlinux.org/epel/zfs-release-2-1$(rpm --eval "%{dist}").noarch.rpm` | Better ZFS support in Ubuntu |
| | Swap Partition | Create partition with `fdisk`, then:<br>`mkswap /dev/sda2`<br>`swapon /dev/sda2` | Create partition with `fdisk`, then:<br>`mkswap /dev/sda2`<br>`swapon /dev/sda2` | Same syntax |
| | Swap File | `dd if=/dev/zero of=/swapfile bs=1M count=1024`<br>`chmod 600 /swapfile`<br>`mkswap /swapfile`<br>`swapon /swapfile` | `dd if=/dev/zero of=/swapfile bs=1M count=1024`<br>`chmod 600 /swapfile`<br>`mkswap /swapfile`<br>`swapon /swapfile` | Same syntax |
| | Storage Monitoring | `iostat`, `iotop` | `iostat`, `iotop` | Same tools |
| | System Storage Manager | Not standard | `dnf install system-storage-manager`<br>`ssm list`, `ssm create` | RHEL-specific tool |
| | Automatic Partition Tool | `d-i partman-auto/method` (in preseed) | Kickstart: `autopart --type=lvm` | Different auto-partitioning approaches |
| **System Configuration** | Service Management | systemd:<br>`systemctl start nginx`<br>`systemctl enable nginx` | systemd:<br>`systemctl start nginx`<br>`systemctl enable nginx` | Both use systemd now |
| | Legacy Service Commands | `service nginx start`<br>`update-rc.d nginx defaults` | `service nginx start`<br>`chkconfig nginx on` | For older systems |
| | Service Config Location | Unit files: `/lib/systemd/system/`<br>Overrides: `/etc/systemd/system/`<br>Env vars: `/etc/default/service` | Unit files: `/usr/lib/systemd/system/`<br>Overrides: `/etc/systemd/system/`<br>Env vars: `/etc/sysconfig/service` | Different paths for service defaults |
| | Network Config | Ubuntu: Netplan<br>`/etc/netplan/*.yaml`<br>Debian/Legacy: `/etc/network/interfaces` | NetworkManager<br>`/etc/sysconfig/network-scripts/ifcfg-*`<br>`nmcli`, `nmtui` tools | Dramatically different network configuration |
| | Netplan Example | `network:`<br>`  version: 2`<br>`  ethernets:`<br>`    enp0s3:`<br>`      dhcp4: no`<br>`      addresses: [192.168.1.100/24]`<br>`      gateway4: 192.168.1.1`<br>`      nameservers:`<br>`        addresses: [8.8.8.8, 8.8.4.4]` | N/A | |
| | NetworkManager Example | NetworkManager also works on Ubuntu/Debian | `# /etc/sysconfig/network-scripts/ifcfg-eth0`<br>`TYPE=Ethernet`<br>`BOOTPROTO=none`<br>`IPADDR=192.168.1.100`<br>`PREFIX=24`<br>`GATEWAY=192.168.1.1`<br>`DNS1=8.8.8.8`<br>`DNS2=8.8.4.4`<br>`DEFROUTE=yes`<br>`IPV4_FAILURE_FATAL=no`<br>`NAME=eth0`<br>`DEVICE=eth0`<br>`ONBOOT=yes` | |
| | Network CLI Tools | `ip addr`, `ip route`<br>Legacy: `ifconfig`, `route` | `ip addr`, `ip route`<br>Legacy: `ifconfig`, `route` | Modern versions use iproute2 tools |
| | Hostname Config | `/etc/hostname`<br>`hostnamectl set-hostname` | `/etc/hostname`<br>`hostnamectl set-hostname` | Similar in modern versions |
| | DNS Resolution | `/etc/systemd/resolved.conf`<br>Legacy: `/etc/resolv.conf` | `/etc/resolv.conf`<br>NetworkManager can manage this | |
| | Host Config | `/etc/hosts` | `/etc/hosts` | Same across distributions |
| | Time Synchronization | systemd-timesyncd (default)<br>Or NTP: `apt install ntp` | chronyd (default)<br>`chronyc sources` | |
| | Time Config | `timedatectl set-timezone Europe/London` | `timedatectl set-timezone Europe/London` | |
| | System Locale | `dpkg-reconfigure locales`<br>`update-locale LANG=en_US.UTF-8` | `localectl set-locale LANG=en_US.UTF-8` | |
| | System Time | `dpkg-reconfigure tzdata`<br>`timedatectl` | `tzselect`<br>`timedatectl` | |
| **Security and Access Control** | Firewall System | UFW (Uncomplicated Firewall)<br>nftables/iptables directly | firewalld<br>nftables/iptables directly | Different default firewall frontends |
| | Firewall Examples | `# UFW`<br>`ufw allow 22/tcp`<br>`ufw allow http`<br>`ufw enable`<br>`ufw status` | `# firewalld`<br>`firewall-cmd --permanent --add-service=ssh`<br>`firewall-cmd --permanent --add-service=http`<br>`firewall-cmd --reload`<br>`firewall-cmd --list-all` | |
| | Mandatory Access Control | AppArmor<br>`aa-status`<br>Profiles in `/etc/apparmor.d/` | SELinux<br>`sestatus`<br>Policies in `/etc/selinux/` | Major philosophical differences |
| | Enable Security System | `aa-enforce /etc/apparmor.d/profile`<br>`systemctl enable apparmor` | `setenforce 1`<br>Edit `/etc/selinux/config` | |
| | Security Troubleshooting | `aa-complain /etc/apparmor.d/profile`<br>`aa-logprof` | `setenforce 0` (permissive)<br>`audit2allow -a -M mymodule` | SELinux is more complex but powerful |
| | Security File Context | N/A | `ls -Z file`<br>`chcon -t httpd_sys_content_t file`<br>`restorecon -v file` | SELinux uses file contexts |
| | User Management | `adduser username` (interactive)<br>`useradd username` (basic) | `useradd username` | Ubuntu's adduser is more user-friendly |
| | User Management Config | `/etc/adduser.conf`<br>`/etc/login.defs` | `/etc/login.defs` | |
| | Password Expiry | `chage -M 90 username` | `chage -M 90 username` | Same tool |
| | Sudo Config | `/etc/sudoers`<br>`visudo` to edit | `/etc/sudoers`<br>`visudo` to edit | Same approach |
| | Privilege Escalation | `# /etc/sudoers.d/user`<br>`user ALL=(ALL) NOPASSWD: /usr/bin/apt` | `# /etc/sudoers.d/user`<br>`user ALL=(ALL) NOPASSWD: /usr/bin/dnf` | |
| | PAM Configuration | `/etc/pam.d/` | `/etc/pam.d/` | Same system, different defaults |
| | SSH Config | `/etc/ssh/sshd_config` | `/etc/ssh/sshd_config` | Same paths |
| **Boot and System Management** | Boot Loader | GRUB2<br>`/boot/grub/` | GRUB2<br>`/boot/grub2/` | Slight path differences |
| | Update GRUB Config | `update-grub` | `grub2-mkconfig -o /boot/grub2/grub.cfg` | Different commands |
| | GRUB Config File | `/etc/default/grub` | `/etc/default/grub` | Same configuration file |
| | Kernel Parameters | Edit `/etc/default/grub` then `update-grub` | Edit `/etc/default/grub` then run grub2-mkconfig | |
| | Default Runlevel | systemd target:<br>`systemctl set-default multi-user.target` | systemd target:<br>`systemctl set-default multi-user.target` | Same in modern versions |
| | Emergency Boot | GRUB menu: recovery mode<br>Kernel param: `emergency` | GRUB menu: select kernel<br>Kernel param: `emergency` | |
| | Kernel Location | `/boot/vmlinuz-*` | `/boot/vmlinuz-*` | Same location |
| | Initramfs/Initrd | `/boot/initrd.img-*`<br>Rebuild: `update-initramfs -u` | `/boot/initramfs-*.img`<br>Rebuild: `dracut -f` | Different tools for initramfs |
| | System Journal | `journalctl`<br>`/var/log/journal/` | `journalctl`<br>`/var/log/journal/` | Same in modern versions |
| | Journal Persistence | Edit `/etc/systemd/journald.conf`<br>Set `Storage=persistent` | Edit `/etc/systemd/journald.conf`<br>Set `Storage=persistent` | |
| | System Rescue | Boot from live USB<br>Use recovery mode | Boot from live USB<br>Use rescue mode | |
| **File System and Disk Management** | Default File System | ext4 | XFS (RHEL 7+)<br>ext4 (older) | RHEL/CentOS prefers XFS |
| | Partition Tools | `fdisk`, `parted`, `gdisk` | `fdisk`, `parted`, `gdisk` | Same tools available |
| | LVM Management | `pvcreate`, `vgcreate`, `lvcreate` | `pvcreate`, `vgcreate`, `lvcreate` | Same LVM tools |
| | File System Creation | `mkfs.ext4 /dev/sda1` | `mkfs.xfs /dev/sda1` | Different default filesystem tools |
| | File System Check | `fsck.ext4 /dev/sda1` | `xfs_repair /dev/sda1` | Different filesystem check tools |
| | Mount Configuration | `/etc/fstab` | `/etc/fstab` | Same configuration file |
| | Automount | `/etc/fstab` or autofs | `/etc/fstab` or autofs | |
| | Disk Quotas | `apt install quota`<br>Edit `/etc/fstab` to add usrquota | `dnf install quota`<br>Edit `/etc/fstab` to add usrquota | |
| | Disk Usage | `df -h`, `du -sh` | `df -h`, `du -sh` | Same tools |
| | System Storage Manager | Not default | `system-storage-manager` in RHEL/CentOS | RHEL-specific tool |
| | RAID Management | `mdadm` | `mdadm` | Same tools |
| | Swap Management | `swapon`, `swapoff`<br>`/etc/fstab` for persistence | `swapon`, `swapoff`<br>`/etc/fstab` for persistence | Same approach |
| | Disk Encryption | LUKS<br>`cryptsetup luksFormat /dev/sda1` | LUKS<br>`cryptsetup luksFormat /dev/sda1` | Same encryption technology |
| **Software and Application Stacks** | Web Server | Apache: `apt install apache2`<br>Config: `/etc/apache2/`<br>Sites: `/etc/apache2/sites-available/` and `/etc/apache2/sites-enabled/` | Apache: `dnf install httpd`<br>Config: `/etc/httpd/`<br>Sites: `/etc/httpd/conf.d/` | Different paths and management tools |
| | Apache Commands | `a2ensite`, `a2dissite`<br>`a2enmod`, `a2dismod` | Manual file management<br>No equivalent tools | Ubuntu/Debian has helper tools |
| | Nginx | `apt install nginx`<br>Config: `/etc/nginx/`<br>Sites: `/etc/nginx/sites-available/` and `/etc/nginx/sites-enabled/` | `dnf install nginx`<br>Config: `/etc/nginx/`<br>Sites: `/etc/nginx/conf.d/` | Similar but slight path differences |
| | PHP | `apt install php`<br>Config: `/etc/php/7.4/` | `dnf install php`<br>Config: `/etc/php.ini` and `/etc/php.d/` | Different default config locations |
| | MariaDB/MySQL | `apt install mariadb-server`<br>Config: `/etc/mysql/mariadb.cnf` | `dnf install mariadb-server`<br>Config: `/etc/my.cnf` and `/etc/my.cnf.d/` | |
| | PostgreSQL | `apt install postgresql`<br>Config: `/etc/postgresql/12/main/` | `dnf install postgresql-server`<br>Config: `/var/lib/pgsql/data/` | |
| | Container Management | Docker: `apt install docker.io`<br>Podman also available | Podman: `dnf install podman`<br>Docker available but not preferred | RHEL/CentOS emphasizes Podman |
| | Container Orchestration | Kubernetes: `apt install kubernetes-*` | OpenShift (commercial)<br>Kubernetes available | Red Hat pushes OpenShift |
| | Java | `apt install default-jdk`<br>Alternatives: `update-alternatives --config java` | `dnf install java-11-openjdk`<br>Alternatives: `alternatives --config java` | |
| | Python | `apt install python3`<br>Multiple versions coexist | `dnf install python3`<br>SCL for alternate versions | |
| | Ruby | `apt install ruby`<br>RVM or rbenv for version management | `dnf install ruby`<br>SCL for alternate versions | Software Collections in RHEL |
| | Node.js | `apt install nodejs npm`<br>NVM for version management | `dnf install nodejs npm`<br>NVM or SCL for version management | |
| **Logging and Monitoring** | System Logs | `/var/log/syslog`<br>`/var/log/auth.log` | `/var/log/messages`<br>`/var/log/secure` | Different default log files |
| | Journal | `journalctl`<br>`journalctl -u nginx.service` | `journalctl`<br>`journalctl -u nginx.service` | Same journal commands |
| | Boot Logs | `journalctl -b`<br>`/var/log/boot.log` | `journalctl -b`<br>`/var/log/boot.log` | |
| | Apache/Httpd Logs | `/var/log/apache2/access.log`<br>`/var/log/apache2/error.log` | `/var/log/httpd/access_log`<br>`/var/log/httpd/error_log` | Different paths |
| | Nginx Logs | `/var/log/nginx/access.log`<br>`/var/log/nginx/error.log` | `/var/log/nginx/access.log`<br>`/var/log/nginx/error.log` | Same paths typically |
| | MySQL/MariaDB Logs | `/var/log/mysql/`<br>Can vary by configuration | `/var/log/mariadb/`<br>Can vary by configuration | |
| | Log Rotation | `logrotate`<br>Config: `/etc/logrotate.d/` | `logrotate`<br>Config: `/etc/logrotate.d/` | Same tool |
| | System Monitoring | `top`, `htop`, `atop` | `top`, `htop`, `atop` | Same tools available |
| | Process Monitoring | `ps aux`, `pstree` | `ps aux`, `pstree` | Same commands |
| | Resource Usage | `free -m`, `vmstat`, `iostat` | `free -m`, `vmstat`, `iostat` | Same tools |
| | Network Monitoring | `netstat`, `ss`, `iftop` | `netstat`, `ss`, `iftop` | Same tools available |
| | System Auditing | `auditd`<br>`apt install auditd` | `auditd`<br>Installed by default | More emphasis on auditing in RHEL |
| | System Statistics | `sar`<br>`apt install sysstat` | `sar`<br>`dnf install sysstat` | Same tool |
| **Enterprise Features and Support** | Commercial Support | Ubuntu: Canonical support available<br>Debian: Various vendors | Red Hat subscription | RHEL support is comprehensive but costly |
| | Support Lifetime | Ubuntu LTS: 5 years (10 with ESM)<br>Debian: ~3-5 years | RHEL: 10 years<br>CentOS: Follows RHEL (traditional) | RHEL has longer support cycles |
| | Release Cycle | Ubuntu: 6 months, LTS every 2 years<br>Debian: ~2 years | RHEL: ~2-3 years<br>CentOS Stream: Rolling | RHEL has slower, more conservative releases |
| | Enterprise Management | Canonical Landscape (commercial) | Red Hat Satellite<br>Foreman/Katello (open) | More management tools for RHEL |
| | System Certification | Less formal certification for hardware | Red Hat Certified hardware | Better hardware certification with RHEL |
| | Cloud Integration | Strong integration with major clouds | Strong integration with major clouds<br>Deeper integration with OpenStack | Both well-supported in cloud |
| | Security Compliance | FIPS, Common Criteria available<br>Less common in regular use | FIPS, Common Criteria, DISA STIG<br>Built-in compliance scanning | RHEL more focused on compliance |
| | Configuration Management | Puppet, Chef, Ansible support | Ansible (Red Hat product)<br>Puppet, Chef support | Red Hat promotes Ansible |
| | Backup Solutions | Various tools, no default enterprise solution | Various tools, no default enterprise solution | |
| | Container Platform | Kubernetes, Docker | OpenShift (commercial)<br>Kubernetes, Podman | Red Hat pushes OpenShift |
| | Virtualization | KVM, QEMU | KVM, QEMU<br>Red Hat Virtualization (commercial) | |
| | High Availability | Heartbeat, Corosync, Pacemaker | Red Hat High Availability Add-On<br>Based on Corosync, Pacemaker | Better integration in RHEL |
| | Identity Management | Various tools, often FreeIPA | Red Hat Identity Management<br>Based on FreeIPA | Better integration in RHEL |
| **Development and Compilation** | Development Tools | `apt install build-essential` | `dnf group install "Development Tools"` | Meta-packages that pull in compilation tools |
| | Compiler | GCC: `apt install gcc` | GCC: `dnf install gcc` | Same toolchain |
| | Make | `apt install make` | `dnf install make` | Same tool |
| | Debugger | `apt install gdb` | `dnf install gdb` | Same tool |
| | Headers | `apt install linux-headers-$(uname -r)` | `dnf install kernel-devel` | Different package names |
| | Developer Libraries | `-dev` suffix<br>`apt install libssl-dev` | `-devel` suffix<br>`dnf install openssl-devel` | Different naming conventions |
| | Version Control | `apt install git` | `dnf install git` | Same tools |
| | Development Environments | Many available in repositories<br>Often newer versions | Fewer in base repositories<br>Often use SCLs for newer versions | Ubuntu typically has newer tools |
| | Software Collections | PPA system for newer versions | Software Collections (SCL)<br>`dnf install scl-utils` | Different approaches to newer software |
