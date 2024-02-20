

##
#
https://www.sshaudit.com/hardening_guides.html
#
https://github.com/k4yt3x/sshd_config/blob/master/sshd_config
#
##


```
# Name: K4YT3X Hardened OpenSSH Configuration
# Author: K4YT3X
# Contributor: IceCodeNew
# Contributor: brxken128
# Date Created: October 5, 2020
# Last Updated: February 12, 2024

# Licensed under the GNU General Public License Version 3 (GNU GPL v3),
#   available at: https://www.gnu.org/licenses/gpl-3.0.txt
# (C) 2020-2024 K4YT3X

########## Binding ##########

# SSH server listening address and port
#Port 22
#ListenAddress 0.0.0.0
#ListenAddress ::

# only listen to IPv4
#AddressFamily inet

# only listen to IPv6
#AddressFamily inet6

########## Features ##########

# accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

# disallow ssh-agent forwarding to prevent lateral movement
AllowAgentForwarding no

# prevent TCP ports from being forwarded over SSH tunnels
# **please be aware that disabling TCP forwarding does not prevent port forwarding**
# any user with an interactive login shell can spin up his/her own instance of sshd
AllowTcpForwarding no

# prevent StreamLocal (Unix-domain socket) forwarding
AllowStreamLocalForwarding no

# disables all forwarding features
# overrides all other forwarding switches
DisableForwarding yes

# disallow remote hosts from connecting to forwarded ports
# i.e. forwarded ports are forced to bind to 127.0.0.1 instead of 0.0.0.0
GatewayPorts no

# prevent tun device forwarding
PermitTunnel no

# suppress MOTD
PrintMotd no

# disable X11 forwarding since it is not necessary
X11Forwarding no

########## Authentication ##########

# permit only the specified users to login
#AllowUsers k4yt3x

# permit only users within the specified groups to login
#AllowGroups k4yt3x

# uncomment the following options to permit only pubkey authentication
# be aware that this will disable password authentication
#   - AuthenticationMethods: permitted authentication methods
#   - PasswordAuthentication: set to no to disable password authentication
#   - UsePAM: set to no to disable all PAM authentication, also disables PasswordAuthentication when set to no
#AuthenticationMethods publickey
#PasswordAuthentication no
#UsePAM no

# PAM authentication enabled to make password authentication available
# remove this if password authentication is not needed
UsePAM yes

# challenge-response authentication backend it not configured by default
# therefore, it is set to "no" by default to avoid the use of an unconfigured backend
ChallengeResponseAuthentication no

# set maximum authentication retries to prevent brute force attacks
MaxAuthTries 3

# disallow connecting using empty passwords
PermitEmptyPasswords no

# prevent root from being logged in via SSH
PermitRootLogin no

# enable pubkey authentication
PubkeyAuthentication yes

########## Cryptography ##########

# explicitly define cryptography algorithms to avoid the use of weak algorithms
# AES-CTR and Chacha20-Poly1305 modes have been removed to mitigate the Terrapin attack
#   https://terrapin-attack.com/
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# short moduli should be deactivated before enabling the use of diffie-hellman-group-exchange-sha256
#   see this link for more details: https://github.com/k4yt3x/sshd_config#deactivating-short-diffie-hellman-moduli
# AES-CTR and Chacha20-Poly1305 modes have been removed to mitigate the Terrapin attack
#   https://terrapin-attack.com/
# ecdh-sha2-nistp* algorithms have been removed due to concerns around NIST P-curves' design
#   https://github.com/jtesta/ssh-audit/issues/213#issuecomment-1774204745
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512

########## Connection Preferences ##########

# number of client alive messages sent without client responding
ClientAliveCountMax 2

# send a keepalive message to the client when the session has been idle for 300 seconds
# this prevents/detects connection timeouts
ClientAliveInterval 300

# compression before encryption might cause security issues
Compression no

# prevent SSH trust relationships from allowing lateral movements
IgnoreRhosts yes

# log verbosely for additional information
#LogLevel VERBOSE

# allow a maximum of two multiplexed sessions over a single TCP connection
MaxSessions 2

# enforce SSH server to only use SSH protocol version 2
# SSHv1 contains security issues and should be avoided at all costs
# SSHv1 is disabled by default after OpenSSH 7.0, but this option is
#   specified anyways to ensure this configuration file's compatibility
#   with older versions of OpenSSH server
Protocol 2

# override default of no subsystems
# path to the sftp-server binary depends on your distribution
#Subsystem sftp /usr/lib/openssh/sftp-server
#Subsystem sftp /usr/libexec/openssh/sftp-server
Subsystem sftp internal-sftp

# let ClientAliveInterval handle keepalive
TCPKeepAlive no

# disable reverse DNS lookups
UseDNS no
```


SSH Hardening Guides
Below are guides to hardening SSH on various systems. Note that following them may not result in a perfect auditing score, as not all packaged SSH server versions support the required options. However, these instructions will result in the best possible score.

These guides were inspired by this document (which is now out-dated).

Server Guides:
Amazon Linux 2023
Debian 11 (Bullseye)
Debian 12 (Bookworm)
RedHat Enterprise Linux 7 / CentOS 7
RedHat Enterprise Linux 8 / CentOS 8
Rocky Linux 9
Ubuntu 18.04 LTS
Ubuntu 20.04 LTS
Ubuntu 22.04 LTS
Client Guides:
Ubuntu 18.04 LTS / Linux Mint 19
Ubuntu 20.04 LTS / Linux Mint 20
Ubuntu 22.04 LTS / Linux Mint 21
Community-Developed Guides:
The following guides have been written by the community. They have not been officially tested, and are not officially supported:

ArubaOS Switch (AOS S) 16.11
Dropbear 2022.83
Fortinet FortiOS
FreeBSD (various versions)
Mac OS 13 (Ventura) & 14 (Sonoma)
Mikrotik RouterOS
OPNsense 20.7 and newer
Proxmox-VE-7.3-6
Synology DSM
Void Linux
Instructions for submitting a hardening guide can be found here.

Legacy Guides:
Debian Buster (Debian 10)
OpenBSD 6.2
pfSense 2.4
Ubuntu 14.04 LTS
Ubuntu 16.04 LTS (Server)
Ubuntu 16.04 LTS / Linux Mint 18 (Client)
Ubuntu Core 18
Ubuntu Core 16
 Ubuntu 22.04 LTS Server Last modified: November 27, 2023
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Enable the RSA and ED25519 keys
Enable the RSA and ED25519 HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
Restart OpenSSH server
service ssh restart

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 Ubuntu 20.04 LTS Server Last modified: July 27, 2020
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Enable the RSA and ED25519 keys
Enable the RSA and ED25519 HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
Restart OpenSSH server
service ssh restart

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 Ubuntu 18.04 LTS Server Last modified: February 8, 2020
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Disable the DSA and ECDSA host keys
Comment out the DSA and ECDSA HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
service ssh restart

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 Ubuntu 16.04 LTS Server Last modified: July 6, 2020
Note: all commands below are to be executed as the root user.

Re-generate ED25519 key
rm /etc/ssh/ssh_host_*
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Disable the RSA, DSA, and ECDSA host keys
Comment out the RSA, DSA and ECDSA HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
service ssh restart

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 Ubuntu 14.04 LTS Server Last modified: October 17, 2017
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Disable the DSA and ECDSA host keys
Comment out the DSA and ECDSA HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
service ssh restart

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 Ubuntu Core 18 Server Last modified: October 6, 2019
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
Note: It is highly recommended that you run the ssh-keygen commands below on another host. Some IoT devices do not have good entropy sources to generate sufficient keys with!

ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ""

Be sure to upload the following 4 files to the target device's /etc/ssh directory:
ssh_host_ed25519_key
ssh_host_ed25519_key.pub
ssh_host_rsa_key
ssh_host_rsa_key.pub
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Only enable RSA and ED25519 host keys.\nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
service ssh reload

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 Ubuntu Core 16 Server Last modified: October 17, 2017
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
Note: It is highly recommended that you run the ssh-keygen commands below on another host. Some IoT devices do not have good entropy sources to generate sufficient keys with!

ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ""

Be sure to upload the following 4 files to the target device's /etc/ssh directory:
ssh_host_ed25519_key
ssh_host_ed25519_key.pub
ssh_host_rsa_key
ssh_host_rsa_key.pub
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
sed -i 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config
echo -e "\n# Restrict MAC algorithms, as per sshaudit.com hardening guide.\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
service ssh reload

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
Debian Bookworm (Debian 12) Last modified: November 27, 2023
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\n KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nRequiredRSASize 3072\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
Restart OpenSSH server
service ssh restart
Debian Bullseye (Debian 11) Last modified: September 17, 2021
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Enable the RSA and ED25519 keys
Enable the RSA and ED25519 HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
Restart OpenSSH server
service ssh restart
Debian Buster (Debian 10) Last modified: September 17, 2021
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Enable the RSA and ED25519 keys
Enable the RSA and ED25519 HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
service ssh restart
Rocky Linux 9 Last modified: November 27, 2023
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nRequiredRSASize 3072\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n" > /etc/crypto-policies/back-ends/opensshserver.config
Restart OpenSSH server
systemctl restart sshd
RedHat Enterprise Linux 8 Server / CentOS 8 Server Last modified: October 20, 2020
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
chgrp ssh_keys /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
chmod g+r /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
Disable ECDSA host key
Comment out the ECDSA HostKey directive in the /etc/ssh/sshd_config file:

sed -i 's/^HostKey \/etc\/ssh\/ssh_host_ecdsa_key$/\#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
cp /etc/crypto-policies/back-ends/opensshserver.config /etc/crypto-policies/back-ends/opensshserver.config.orig
echo -e "CRYPTO_POLICY='-oCiphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com -oGSSAPIKexAlgorithms=gss-curve25519-sha256- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256 -oHostKeyAlgorithms=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512 -oPubkeyAcceptedKeyTypes=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512'" > /etc/crypto-policies/back-ends/opensshserver.config
Restart OpenSSH server
systemctl restart sshd.service
RedHat Enterprise Linux 7 Server / CentOS 7 Server Last modified: February 18, 2024
Note: all commands below are to be executed as the root user.

Disable automatic re-generation of RSA & ECDSA keys
mkdir -p /etc/systemd/system/sshd-keygen.service.d
cat << EOF > /etc/systemd/system/sshd-keygen.service.d/ssh-audit.conf
[Unit]
ConditionFileNotEmpty=
ConditionFileNotEmpty=!/etc/ssh/ssh_host_ed25519_key
EOF
systemctl daemon-reload
Re-generate the ED25519 key
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
chgrp ssh_keys /etc/ssh/ssh_host_ed25519_key
chmod g+r /etc/ssh/ssh_host_ed25519_key
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
Disable the RSA, DSA, and ECDSA host keys
Comment out the RSA, DSA, and ECDSA HostKey directives in the /etc/ssh/sshd_config file:

sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
systemctl restart sshd.service
Amazon Linux 2023 Last modified: November 27, 2023
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n" > /etc/crypto-policies/back-ends/opensshserver.config
Restart OpenSSH server
systemctl restart sshd
 pfSense 2.4 Last modified: October 17, 2017
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
Restrict supported key exchange, cipher, and MAC algorithms
sed -i.bak 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config && rm /etc/ssh/sshd_config.bak
echo "" | echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
service sshd onerestart

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 OpenBSD 6.2 Server Last modified: October 20, 2020
Note: all commands below are to be executed as the root user.

Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
Create custom Diffie-Hellman groups
ssh-keygen -G /etc/ssh/moduli -b 3072

Note: This will likely take some time to complete.
Disable the DSA and ECDSA host keys
echo -e "\n# Restrict host keys to ED25519 and RSA only.\nHostKeyAlgorithms ssh-ed25519\n" >> /etc/ssh/sshd_config
Restrict supported key exchange, cipher, and MAC algorithms
echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
Restart OpenSSH server
kill -HUP `cat /var/run/sshd.pid`

Note: Because of a bug in OpenSSH, 2048-bit DH moduli will still be used in some limited circumstances. Only a maximum score of 95% is possible.
 Ubuntu 22.04 LTS Client /  Linux Mint 21 ClientLast modified: November 27, 2023
Run the following in a terminal to harden the SSH client for the local user:
mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config
 Ubuntu 20.04 LTS Client /  Linux Mint 20 ClientLast modified: October 20, 2020
Run the following in a terminal to harden the SSH client for the local user:
mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com\n" >> ~/.ssh/config
 Ubuntu 18.04 LTS Client /  Linux Mint 19 ClientLast modified: October 20, 2020
Run the following in a terminal to harden the SSH client for the local user:
mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512\n" >> ~/.ssh/config
 Ubuntu 16.04 LTS Client /  Linux Mint 18 ClientLast modified: October 20, 2020
Run the following in a terminal to harden the SSH client for the local user:
mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512\n" >> ~/.ssh/config
