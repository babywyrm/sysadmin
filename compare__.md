| **Third-Party Repos** | PPAs (Personal Package Archives)<br>`add-apt-repository ppa:name/here` | EPEL, RPMFusion, Remi, IUS<br>Install repo RPM, then enable | Ubuntu PPAs are easier to add but less vetted |
| **Backports** | `deb http://archive.ubuntu.com/ubuntu focal-backports main`<br>Debian: `deb http://deb.debian.org/debian buster-backports main` | EPEL serves a similar function<br>SCLs (Software Collections) | |
| **Security Updates** | `deb http://security.ubuntu.com/ubuntu focal-security main`<br>Debian: `deb http://security.debian.org/debian-security buster/updates main` | Built into base repos | |
| **Commercial Repos** | Ubuntu Pro/Advantage<br>Canonical Partners | RHEL Subscription<br>Red Hat Satellite | |
| **Local Repository** | `apt-mirror`<br>`reprepro` | `createrepo`<br>`reposync` | |
| **Update Repo Cache** | `apt update` | Automatic with YUM/DNF | Ubuntu/Debian requires explicit cache update |

## System Configuration

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **Service Management** | systemd:<br>`systemctl start nginx`<br>`systemctl enable nginx` | systemd:<br>`systemctl start nginx`<br>`systemctl enable nginx` | Both use systemd now |
| **Legacy Service Commands** | `service nginx start`<br>`update-rc.d nginx defaults` | `service nginx start`<br>`chkconfig nginx on` | For older systems |
| **Service Config Location** | Unit files: `/lib/systemd/system/`<br>Overrides: `/etc/systemd/system/`<br>Env vars: `/etc/default/service` | Unit files: `/usr/lib/systemd/system/`<br>Overrides: `/etc/systemd/system/`<br>Env vars: `/etc/sysconfig/service` | Different paths for service defaults |
| **Network Config** | Ubuntu: Netplan<br>`/etc/netplan/*.yaml`<br>Debian/Legacy: `/etc/network/interfaces` | NetworkManager<br>`/etc/sysconfig/network-scripts/ifcfg-*`<br>`nmcli`, `nmtui` tools | Dramatically different network configuration |
| **Netplan Example** | ```
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [192.168.1.100/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
``` | N/A | |
| **NetworkManager Example** | NetworkManager also works on Ubuntu/Debian | ```
# /etc/sysconfig/network-scripts/ifcfg-eth0
TYPE=Ethernet
BOOTPROTO=none
IPADDR=192.168.1.100
PREFIX=24
GATEWAY=192.168.1.1
DNS1=8.8.8.8
DNS2=8.8.4.4
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
NAME=eth0
DEVICE=eth0
ONBOOT=yes
``` | |
| **Network CLI Tools** | `ip addr`, `ip route`<br>Legacy: `ifconfig`, `route` | `ip addr`, `ip route`<br>Legacy: `ifconfig`, `route` | Modern versions use iproute2 tools |
| **Hostname Config** | `/etc/hostname`<br>`hostnamectl set-hostname` | `/etc/hostname`<br>`hostnamectl set-hostname` | Similar in modern versions |
| **DNS Resolution** | `/etc/systemd/resolved.conf`<br>Legacy: `/etc/resolv.conf` | `/etc/resolv.conf`<br>NetworkManager can manage this | |
| **Host Config** | `/etc/hosts` | `/etc/hosts` | Same across distributions |
| **Time Synchronization** | systemd-timesyncd (default)<br>Or NTP: `apt install ntp` | chronyd (default)<br>`chronyc sources` | |
| **Time Config** | `timedatectl set-timezone Europe/London` | `timedatectl set-timezone Europe/London` | |
| **System Locale** | `dpkg-reconfigure locales`<br>`update-locale LANG=en_US.UTF-8` | `localectl set-locale LANG=en_US.UTF-8` | |
| **System Time** | `dpkg-reconfigure tzdata`<br>`timedatectl` | `tzselect`<br>`timedatectl` | |

## Security and Access Control

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **Firewall System** | UFW (Uncomplicated Firewall)<br>nftables/iptables directly | firewalld<br>nftables/iptables directly | Different default firewall frontends |
| **Firewall Examples** | ```
# UFW
ufw allow 22/tcp
ufw allow http
ufw enable
ufw status
``` | ```
# firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --reload
firewall-cmd --list-all
``` | |
| **Mandatory Access Control** | AppArmor<br>`aa-status`<br>Profiles in `/etc/apparmor.d/` | SELinux<br>`sestatus`<br>Policies in `/etc/selinux/` | Major philosophical differences |
| **Enable Security System** | `aa-enforce /etc/apparmor.d/profile`<br>`systemctl enable apparmor` | `setenforce 1`<br>Edit `/etc/selinux/config` | |
| **Security Troubleshooting** | `aa-complain /etc/apparmor.d/profile`<br>`aa-logprof` | `setenforce 0` (permissive)<br>`audit2allow -a -M mymodule` | SELinux is more complex but powerful |
| **Security File Context** | N/A | `ls -Z file`<br>`chcon -t httpd_sys_content_t file`<br>`restorecon -v file` | SELinux uses file contexts |
| **User Management** | `adduser username` (interactive)<br>`useradd username` (basic) | `useradd username` | Ubuntu's adduser is more user-friendly |
| **User Management Config** | `/etc/adduser.conf`<br>`/etc/login.defs` | `/etc/login.defs` | |
| **Password Expiry** | `chage -M 90 username` | `chage -M 90 username` | Same tool |
| **Sudo Config** | `/etc/sudoers`<br>`visudo` to edit | `/etc/sudoers`<br>`visudo` to edit | Same approach |
| **Privilege Escalation** | ```
# /etc/sudoers.d/user
user ALL=(ALL) NOPASSWD: /usr/bin/apt
``` | ```
# /etc/sudoers.d/user
user ALL=(ALL) NOPASSWD: /usr/bin/dnf
``` | |
| **PAM Configuration** | `/etc/pam.d/` | `/etc/pam.d/` | Same system, different defaults |
| **SSH Config** | `/etc/ssh/sshd_config` | `/etc/ssh/sshd_config` | Same paths |

## Boot and System Management

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **Boot Loader** | GRUB2<br>`/boot/grub/` | GRUB2<br>`/boot/grub2/` | Slight path differences |
| **Update GRUB Config** | `update-grub` | `grub2-mkconfig -o /boot/grub2/grub.cfg` | Different commands |
| **GRUB Config File** | `/etc/default/grub` | `/etc/default/grub` | Same configuration file |
| **Kernel Parameters** | Edit `/etc/default/grub` then `update-grub` | Edit `/etc/default/grub` then run grub2-mkconfig | |
| **Default Runlevel** | systemd target:<br>`systemctl set-default multi-user.target` | systemd target:<br>`systemctl set-default multi-user.target` | Same in modern versions |
| **Emergency Boot** | GRUB menu: recovery mode<br>Kernel param: `emergency` | GRUB menu: select kernel<br>Kernel param: `emergency` | |
| **Kernel Location** | `/boot/vmlinuz-*` | `/boot/vmlinuz-*` | Same location |
| **Initramfs/Initrd** | `/boot/initrd.img-*`<br>Rebuild: `update-initramfs -u` | `/boot/initramfs-*.img`<br>Rebuild: `dracut -f` | Different tools for initramfs |
| **System Journal** | `journalctl`<br>`/var/log/journal/` | `journalctl`<br>`/var/log/journal/` | Same in modern versions |
| **Journal Persistence** | Edit `/etc/systemd/journald.conf`<br>Set `Storage=persistent` | Edit `/etc/systemd/journald.conf`<br>Set `Storage=persistent` | |
| **System Rescue** | Boot from live USB<br>Use recovery mode | Boot from live USB<br>Use rescue mode | |

## File System and Disk Management

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **Default File System** | ext4 | XFS (RHEL 7+)<br>ext4 (older) | RHEL/CentOS prefers XFS |
| **Partition Tools** | `fdisk`, `parted`, `gdisk` | `fdisk`, `parted`, `gdisk` | Same tools available |
| **LVM Management** | `pvcreate`, `vgcreate`, `lvcreate` | `pvcreate`, `vgcreate`, `lvcreate` | Same LVM tools |
| **File System Creation** | `mkfs.ext4 /dev/sda1` | `mkfs.xfs /dev/sda1` | Different default filesystem tools |
| **File System Check** | `fsck.ext4 /dev/sda1` | `xfs_repair /dev/sda1` | Different filesystem check tools |
| **Mount Configuration** | `/etc/fstab` | `/etc/fstab` | Same configuration file |
| **Automount** | `/etc/fstab` or autofs | `/etc/fstab` or autofs | |
| **Disk Quotas** | `apt install quota`<br>Edit `/etc/fstab` to add usrquota | `dnf install quota`<br>Edit `/etc/fstab` to add usrquota | |
| **Disk Usage** | `df -h`, `du -sh` | `df -h`, `du -sh` | Same tools |
| **System Storage Manager** | Not default | `system-storage-manager` in RHEL/CentOS | RHEL-specific tool |
| **RAID Management** | `mdadm` | `mdadm` | Same tools |
| **Swap Management** | `swapon`, `swapoff`<br>`/etc/fstab` for persistence | `swapon`, `swapoff`<br>`/etc/fstab` for persistence | Same approach |
| **Disk Encryption** | LUKS<br>`cryptsetup luksFormat /dev/sda1` | LUKS<br>`cryptsetup luksFormat /dev/sda1` | Same encryption technology |

## Software and Application Stacks

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **Web Server** | Apache: `apt install apache2`<br>Config: `/etc/apache2/`<br>Sites: `/etc/apache2/sites-available/` and `/etc/apache2/sites-enabled/` | Apache: `dnf install httpd`<br>Config: `/etc/httpd/`<br>Sites: `/etc/httpd/conf.d/` | Different paths and management tools |
| **Apache Commands** | `a2ensite`, `a2dissite`<br>`a2enmod`, `a2dismod` | Manual file management<br>No equivalent tools | Ubuntu/Debian has helper tools |
| **Nginx** | `apt install nginx`<br>Config: `/etc/nginx/`<br>Sites: `/etc/nginx/sites-available/` and `/etc/nginx/sites-enabled/` | `dnf install nginx`<br>Config: `/etc/nginx/`<br>Sites: `/etc/nginx/conf.d/` | Similar but slight path differences |
| **PHP** | `apt install php`<br>Config: `/etc/php/7.4/` | `dnf install php`<br>Config: `/etc/php.ini` and `/etc/php.d/` | Different default config locations |
| **MariaDB/MySQL** | `apt install mariadb-server`<br>Config: `/etc/mysql/mariadb.cnf` | `dnf install mariadb-server`<br>Config: `/etc/my.cnf` and `/etc/my.cnf.d/` | |
| **PostgreSQL** | `apt install postgresql`<br>Config: `/etc/postgresql/12/main/` | `dnf install postgresql-server`<br>Config: `/var/lib/pgsql/data/` | |
| **Container Management** | Docker: `apt install docker.io`<br>Podman also available | Podman: `dnf install podman`<br>Docker available but not preferred | RHEL/CentOS emphasizes Podman |
| **Container Orchestration** | Kubernetes: `apt install kubernetes-*` | OpenShift (commercial)<br>Kubernetes available | Red Hat pushes OpenShift |
| **Java** | `apt install default-jdk`<br>Alternatives: `update-alternatives --config java` | `dnf install java-11-openjdk`<br>Alternatives: `alternatives --config java` | |
| **Python** | `apt install python3`<br>Multiple versions coexist | `dnf install python3`<br>SCL for alternate versions | |
| **Ruby** | `apt install ruby`<br>RVM or rbenv for version management | `dnf install ruby`<br>SCL for alternate versions | Software Collections in RHEL |
| **Node.js** | `apt install nodejs npm`<br>NVM for version management | `dnf install nodejs npm`<br>NVM or SCL for version management | |

## Logging and Monitoring

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **System Logs** | `/var/log/syslog`<br>`/var/log/auth.log` | `/var/log/messages`<br>`/var/log/secure` | Different default log files |
| **Journal** | `journalctl`<br>`journalctl -u nginx.service` | `journalctl`<br>`journalctl -u nginx.service` | Same journal commands |
| **Boot Logs** | `journalctl -b`<br>`/var/log/boot.log` | `journalctl -b`<br>`/var/log/boot.log` | |
| **Apache/Httpd Logs** | `/var/log/apache2/access.log`<br>`/var/log/apache2/error.log` | `/var/log/httpd/access_log`<br>`/var/log/httpd/error_log` | Different paths |
| **Nginx Logs** | `/var/log/nginx/access.log`<br>`/var/log/nginx/error.log` | `/var/log/nginx/access.log`<br>`/var/log/nginx/error.log` | Same paths typically |
| **MySQL/MariaDB Logs** | `/var/log/mysql/`<br>Can vary by configuration | `/var/log/mariadb/`<br>Can vary by configuration | |
| **Log Rotation** | `logrotate`<br>Config: `/etc/logrotate.d/` | `logrotate`<br>Config: `/etc/logrotate.d/` | Same tool |
| **System Monitoring** | `top`, `htop`, `atop` | `top`, `htop`, `atop` | Same tools available |
| **Process Monitoring** | `ps aux`, `pstree` | `ps aux`, `pstree` | Same commands |
| **Resource Usage** | `free -m`, `vmstat`, `iostat` | `free -m`, `vmstat`, `iostat` | Same tools |
| **Network Monitoring** | `netstat`, `ss`, `iftop` | `netstat`, `ss`, `iftop` | Same tools available |
| **System Auditing** | `auditd`<br>`apt install auditd` | `auditd`<br>Installed by default | More emphasis on auditing in RHEL |
| **System Statistics** | `sar`<br>`apt install sysstat` | `sar`<br>`dnf install sysstat` | Same tool |

## Enterprise Features and Support

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **Commercial Support** | Ubuntu: Canonical support available<br>Debian: Various vendors | Red Hat subscription | RHEL support is comprehensive but costly |
| **Support Lifetime** | Ubuntu LTS: 5 years (10 with ESM)<br>Debian: ~3-5 years | RHEL: 10 years<br>CentOS: Follows RHEL (traditional) | RHEL has longer support cycles |
| **Release Cycle** | Ubuntu: 6 months, LTS every 2 years<br>Debian: ~2 years | RHEL: ~2-3 years<br>CentOS Stream: Rolling | RHEL has slower, more conservative releases |
| **Enterprise Management** | Canonical Landscape (commercial) | Red Hat Satellite<br>Foreman/Katello (open) | More management tools for RHEL |
| **System Certification** | Less formal certification for hardware | Red Hat Certified hardware | Better hardware certification with RHEL |
| **Cloud Integration** | Strong integration with major clouds | Strong integration with major clouds<br>Deeper integration with OpenStack | Both well-supported in cloud |
| **Security Compliance** | FIPS, Common Criteria available<br>Less common in regular use | FIPS, Common Criteria, DISA STIG<br>Built-in compliance scanning | RHEL more focused on compliance |
| **Configuration Management** | Puppet, Chef, Ansible support | Ansible (Red Hat product)<br>Puppet, Chef support | Red Hat promotes Ansible |
| **Backup Solutions** | Various tools, no default enterprise solution | Various tools, no default enterprise solution | |
| **Container Platform** | Kubernetes, Docker | OpenShift (commercial)<br>Kubernetes, Podman | Red Hat pushes OpenShift |
| **Virtualization** | KVM, QEMU | KVM, QEMU<br>Red Hat Virtualization (commercial) | |
| **High Availability** | Heartbeat, Corosync, Pacemaker | Red Hat High Availability Add-On<br>Based on Corosync, Pacemaker | Better integration in RHEL |
| **Identity Management** | Various tools, often FreeIPA | Red Hat Identity Management<br>Based on FreeIPA | Better integration in RHEL |

## Development and Compilation

| Feature | Ubuntu/Debian | RHEL/CentOS | Notes |
|---------|---------------|-------------|-------|
| **Development Tools** | `apt install build-essential` | `dnf group install "Development Tools"` | Meta-packages that pull in compilation tools |
| **Compiler** | GCC: `apt install gcc` | GCC: `dnf install gcc` | Same toolchain |
| **Make** | `apt install make` | `dnf install make` | Same tool |
| **Debugger** | `apt install gdb` | `dnf install gdb` | Same tool |
| **Headers** | `apt install linux-headers-$(uname -r)` | `dnf install kernel-devel` | Different package names |
| **Developer Libraries** | `-dev` suffix<br>`apt install libssl-dev` | `-devel` suffix<br>`dnf install openssl-devel` | Different naming conventions |
| **Version Control** | `apt install git` | `dnf install git` | Same tools |
| **Development Environments** | Many available in repositories<br>Often newer versions | Fewer in base repositories<br>Often use SCLs for newer versions | Ubuntu typically has newer tools |
| **Software Collections** | PPA system for newer versions | Software Collections (SCL)<br>`dnf install scl-utils` | Different approaches to newer software |
