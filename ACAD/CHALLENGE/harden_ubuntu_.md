### System Updates
**http://bookofzeus.com/harden-ubuntu/initial-setup/system-updates/**

Keeping the system updated is vital before starting anything on your system. This will prevent people to use known vulnerabilities to enter in your system.

    sudo apt-get update
    sudo apt-get upgrade
    sudo apt-get autoremove
    sudo apt-get autoclean

Enable automatic updates can be crucial for your server security. It is very important to stay up to date.

    sudo apt-get install unattended-upgrades
    sudo dpkg-reconfigure -plow unattended-upgrades

To enable ONLY security updates, please change the code to look like this:

    sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
    : Unattended-Upgrade::Allowed-Origins {
    :     "${distro_id}:${distro_codename}-security";
    : //  "${distro_id}:${distro_codename}-updates";
    : //  "${distro_id}:${distro_codename}-proposed";
    : //  "${distro_id}:${distro_codename}-backports";
    : };
    : // Unattended-Upgrade::Mail "my_user@my_domain.com";

### Disable Root Account
**http://bookofzeus.com/harden-ubuntu/initial-setup/disable-root-account/**

For security reasons, it is safe to disable the root account. Removing the account might not be a good idea at first, instead we simply need to disable it.

    # To disable the root account, simply use the -l option.
    sudo passwd -l root
    
    # If for some valid reason you need to re-enable the account, simply use the -u option.
    sudo passwd -u root

### Add Swap
**http://bookofzeus.com/harden-ubuntu/server-setup/add-swap/**

Some pre-installed Ubuntu Server are not configured with SWAP. Linux swaps allow a system to harness more memory than was originally physically available

    # Let's check if a SWAP file exists and it's enabled before we create one.
    sudo swapon -s
    
    # To create the SWAP file, you will need to use this.
    sudo fallocate -l 4G /swapfile	# same as "sudo dd if=/dev/zero of=/swapfile bs=1G count=4"
    
    # Secure swap.
    sudo chown root:root /swapfile
    sudo chmod 0600 /swapfile
    
    # Prepare the swap file by creating a Linux swap area.
    sudo mkswap /swapfile
    
    # Activate the swap file.
    sudo swapon /swapfile
    
    # Confirm that the swap partition exists.
    sudo swapon -s
    
    # This will last until the server reboots. Let's create the entry in the fstab.
    sudo nano /etc/fstab
    : /swapfile	none	swap	sw	0 0
    
    # Swappiness in the file should be set to 0. Skipping this step may cause both poor performance,
    # whereas setting it to 0 will cause swap to act as an emergency buffer, preventing out-of-memory crashes.
    echo 0 | sudo tee /proc/sys/vm/swappiness
    echo vm.swappiness = 0 | sudo tee -a /etc/sysctl.conf

### sysctl.conf
**http://bookofzeus.com/harden-ubuntu/hardening/sysctl-conf/**

These settings can:
- Limit network-transmitted configuration for IPv4
- Limit network-transmitted configuration for IPv6
- Turn on execshield protection
- Prevent against the common 'syn flood attack'
- Turn on source IP address verification
- Prevents a cracker from using a spoofing attack against the IP address of the server.
- Logs several types of suspicious packets, such as spoofed packets, source-routed packets, and redirects.

"/etc/sysctl.conf" file is used to configure kernel parameters at runtime. Linux reads and applies settings from this file.

    sudo nano /etc/sysctl.conf

    # IP Spoofing protection
    : net.ipv4.conf.default.rp_filter = 1
    : net.ipv4.conf.all.rp_filter = 1
    # Block SYN attacks
    : net.ipv4.tcp_syncookies = 1
    # Controls IP packet forwarding
    : net.ipv4.ip_forward = 0
    # Ignore ICMP redirects
    : net.ipv4.conf.all.accept_redirects = 0
    : net.ipv6.conf.all.accept_redirects = 0
    : net.ipv4.conf.default.accept_redirects = 0
    : net.ipv6.conf.default.accept_redirects = 0
    # Ignore send redirects
    : net.ipv4.conf.all.send_redirects = 0
    : net.ipv4.conf.default.send_redirects = 0
    # Disable source packet routing
    : net.ipv4.conf.all.accept_source_route = 0
    : net.ipv6.conf.all.accept_source_route = 0
    : net.ipv4.conf.default.accept_source_route = 0
    : net.ipv6.conf.default.accept_source_route = 0
    # Log Martians
    : net.ipv4.conf.all.log_martians = 1
    # Block SYN attacks
    : net.ipv4.tcp_max_syn_backlog = 2048
    : net.ipv4.tcp_synack_retries = 2
    : net.ipv4.tcp_syn_retries = 5
    # Log Martians
    : net.ipv4.icmp_ignore_bogus_error_responses = 1
    # Ignore ICMP broadcast requests
    : net.ipv4.icmp_echo_ignore_broadcasts = 1
    # Ignore Directed pings
    : net.ipv4.icmp_echo_ignore_all = 1
    : kernel.exec-shield = 1
    : kernel.randomize_va_space = 1
    # disable IPv6 if required (IPv6 might caus issues with the Internet connection being slow)
    : net.ipv6.conf.all.disable_ipv6 = 1
    : net.ipv6.conf.default.disable_ipv6 = 1
    : net.ipv6.conf.lo.disable_ipv6 = 1
    # Accept Redirects? No, this is not router
    : net.ipv4.conf.all.secure_redirects = 0
    # Log packets with impossible addresses to kernel log? yes
    : net.ipv4.conf.default.secure_redirects = 0
    
    # [IPv6] Number of Router Solicitations to send until assuming no routers are present.
    # This is host and not router.
    : net.ipv6.conf.default.router_solicitations = 0
    # Accept Router Preference in RA?
    : net.ipv6.conf.default.accept_ra_rtr_pref = 0
    # Learn prefix information in router advertisement.
    : net.ipv6.conf.default.accept_ra_pinfo = 0
    # Setting controls whether the system will accept Hop Limit settings from a router advertisement.
    : net.ipv6.conf.default.accept_ra_defrtr = 0
    # Router advertisements can cause the system to assign a global unicast address to an interface.
    : net.ipv6.conf.default.autoconf = 0
    # How many neighbor solicitations to send out per address?
    : net.ipv6.conf.default.dad_transmits = 0
    # How many global unicast IPv6 addresses can be assigned to each interface?
    : net.ipv6.conf.default.max_addresses = 1
    
    # In rare occasions, it may be beneficial to reboot your server reboot if it runs out of memory.
    # This simple solution can avoid you hours of down time. The vm.panic_on_oom=1 line enables panic
    # on OOM; the kernel.panic=10 line tells the kernel to reboot ten seconds after panicking.
    : vm.panic_on_oom = 1
    : kernel.panic = 10

    # Apply new settings
    sudo sysctl -p

### Disable IRQ Balance
**http://bookofzeus.com/harden-ubuntu/server-setup/disable-irqbalance/**

You should turn off IRQ Balance to make sure you do not get hardware interrupts in your threads. Turning off IRQ Balance, will optimize the balance between power savings and performance through distribution of hardware interrupts across multiple processors.

    sudo nano /etc/default/irqbalance
    : ENABLED="0"

### OpenSSL Heartbleed Bug
**http://bookofzeus.com/harden-ubuntu/server-setup/fix-openssl-heartbleed/**

The OpenSSL heartbleed bug (CVE-2014-0160) bug allows a hacker to leak the memory in up to 64k chunks. Repetitively trying, he can get crutial informations about your system.

The worst a hacker can retrieve are the private keys. Which means now he has the keys to decrypt the encrypted any data. The other information a hacker can get are users' cookies information or even users' username and passwords.

It is crutial to fix this issue to version greater or equal to 1.0.1g. You also have to revoke and regenerate new keys and certificates and re-issuing of CA certs and the like in the coming days.

    openssl version -v
    
    # above should be not 1.0.1f or below, otherwise:
    sudo apt-get update
    sudo apt-get upgrade openssl libssl-dev
    apt-cache policy openssl libssl-dev
    
    sudo apt-get install make
    curl https://www.openssl.org/source/openssl-1.0.2f.tar.gz | tar xz && cd openssl-1.0.2f && sudo ./config && sudo make && sudo make install
    sudo ln -sf /usr/local/ssl/bin/openssl `which openssl`
    
    openssl version

### Secure `/tmp` and `/var/tmp`
**http://bookofzeus.com/harden-ubuntu/server-setup/secure-tmp-var-tmp/**

Temporary storage directories such as /tmp, /var/tmp and /dev/shm gives the ability to hackers to provide storage space for malicious executables.

    # Let's create a 1GB (or what is best for you) filesystem file for the /tmp parition.
    sudo fallocate -l 1G /tmpdisk
    sudo mkfs.ext4 /tmpdisk
    sudo chmod 0600 /tmpdisk
    
    # Mount the new /tmp partition and set the right permissions.
    sudo mount -o loop,noexec,nosuid,rw /tmpdisk /tmp
    sudo chmod 1777 /tmp
    
    # Set the /tmp in the fstab.
    sudo nano /etc/fstab
    : /tmpdisk	/tmp	ext4	loop,nosuid,noexec,rw	0 0
    sudo mount -o remount /tmp
    
    # Secure /var/tmp.
    sudo mv /var/tmp /var/tmpold
    sudo ln -s /tmp /var/tmp
    sudo cp -prf /var/tmpold/* /tmp/
    sudo rm -rf /var/tmpold/

### Secure Shared Memory
**http://bookofzeus.com/harden-ubuntu/server-setup/secure-shared-memory/**

Shared memory can be used in an attack against a running service, apache2 or httpd for example. 

    sudo nano /etc/fstab
    : tmpfs	/run/shm	tmpfs	ro,noexec,nosuid	0 0

### Set Hostname and Host File
**http://bookofzeus.com/harden-ubuntu/server-setup/set-hostname-and-host/**

The hostname uniquely identifies your computer on the local network. The hostname can be use in many services or applications. Once the hostname is set, it is not recommended to change it.

    sudo nano /etc/hostname
    : <ip/hostname>
    
    sudo nano /etc/hosts
    : 127.0.0.1	localhost localhost.localdomain <ip/hostname>

### Set Locale and Timezone
**http://bookofzeus.com/harden-ubuntu/server-setup/set-timezone/**

    sudo locale-gen en_GB.UTF-8
    sudo update-locale LANG=en_GB.UTF-8
    sudo dpkg-reconfigure tzdata

### Set Security Limits
**http://bookofzeus.com/harden-ubuntu/server-setup/set-security-limits/**

You might need to protect your system against fork bomb attacks. A simple way to prevent this is by setitng up processes limit for your users. All the limits can be configured in the `/etc/security/limits.conf` file.

    sudo nano /etc/security/limits.conf
    : user1 hard nproc 100
    : @group1 hard nproc 20

This will prevent users from a specific group from having a maximum of 20 processs and maximize the number of processes to 100 to user1.

### IP Spoofing
**http://hardenubuntu.com/hardening/ip-spoofing/**

IP spoofing is the creation of Internet Protocol (IP) packets with a forged source IP address, with the purpose of concealing the identity of the sender or impersonating another computing system.

    sudo nano /etc/host.conf
    : order bind,hosts
    : nospoof on

### PHP
**http://bookofzeus.com/harden-ubuntu/hardening/php/**

    sudo nano /etc/php/fpm/php.ini
    : safe_mode = On
    : safe_mode_gid = On
    : sql.safe_mode = On
    
    : register_globals = Off
    : magic_quotes_gpc = Off
    
    : expose_php = Off
    : track_errors = Off
    : html_errors = Off
    : display_errors = Off
    
    : disable_functions = ... system,exec,shell_exec,php_uname,getmyuid,getmypid,leak,listen,diskfreespace,link,ignore_user_abord,dl,set_time_limit,highlight_file,source,show_source,passthru,fpaththru,virtual,posix_ctermid,posix_getcwd,posix_getegid,posix_geteuid,posix_getgid,posix_getgrgid,posix_getgrnam,posix_getgroups,posix_getlogin,posix_getpgid,posix_getpgrp,posix_getpid,posix,_getppid,posix_getpwnam,posix_getpwuid,posix_getrlimit,posix_getsid,posix_getuid,posix_isatty,posix_kill,posix_mkfifo,posix_setegid,posix_seteuid,posix_setgid,posix_setpgid,posix_setsid,posix_setuid,posix_times,posix_ttyname,posix_uname,proc_open,proc_close,proc_get_status,proc_nice,proc_terminate,phpinfo
    # exceptions: getmypid
    
    : allow_url_fopen = Off
    : allow_url_include = Off
    
    : sql.safe_mode = On
    
    : session.cookie_httponly = 1
    : session.referer_check = mydomain.com

### SSH
**http://bookofzeus.com/harden-ubuntu/hardening/ssh/**

SSH can be very helpful when configuring your server, setup domains or anything else you need to do. It also one of the first point of entry of hackers. This is why it is very important to secure your SSH.

The basic rules of hardening SSH are:
- No password for SSH access (use private key)
- Don't allow root to SSH (the appropriate users should SSH in, then `su` or `sudo`)
- Use `sudo` for users so commands are logged
- Log unauthorised login attempts (and consider software to block/ban users who try to access your server too many times, like fail2ban)
- Lock down SSH to only the ip range your require (if you feel like it)

It is recommended to use SSH keys.

    sudo nano /etc/ssh/sshd_config
    : Port <port>
    : Protocol 2
    : LogLevel VERBOSE
    : PermitRootLogin no
    : StrictModes yes
    : RSAAuthentication yes
    : IgnoreRhosts yes
    : RhostsAuthentication no
    : RhostsRSAAuthentication no
    : PermitEmptyPasswords no
    : PasswordAuthentication no
    : ClientAliveInterval 300
    : ClientAliveCountMax 0
    : AllowTcpForwarding no
    : X11Forwarding no
    : UseDNS no
    
    sudo nano /etc/pam.d/sshd	(comment lines below)
    : #session	optional	pam_motd.so motd=/run/motd.dynamic noupdate
    : #session	optional	pam_motd.so # [1]
    
    sudo service ssh restart

### Antivirus (clamav)

    sudo apt-get install clamav
    sudo freshclam
    sudo apt-get install clamav-daemon
    sudo crontab -e
    : 00 00 * * * clamscan -r /location_of_files_or_folder | grep FOUND >> /path/to/save/report/myfile.txt
