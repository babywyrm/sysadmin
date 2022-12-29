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
