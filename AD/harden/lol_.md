
##
## https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6
##

```
::##########################################################################################################################
::
:: This script can ruin your day, if you run it without fully understanding what it does, you don't know what you are doing,
::
::                             OR BOTH!!!
:: 
::                     YOU HAVE BEEN WARNED!!!!!!!!!!
:: 
:: This script is provided "AS IS" with no warranties, and confers no rights.
:: Feel free to challenge me, disagree with me, or tell me I'm completely nuts in the comments section, 
:: but I reserve the right to delete any comment for any reason whatsoever so keep it polite, please.
:: 
:: This script is intended for and tested on Windows 10, so do not run it in a production Windows Server!!!
:: 
::                     YOU HAVE BEEN WARNED.... AGAIN!!!!!!!!!!
::
::                 Still don't believe me? Read the comment section...
:: 
::                     THIS WAS YOUR LAST AND FINAL WARNING!!!
:: 
::##########################################################################################################################
:: Credits and More info: https://gist.github.com/mackwage/08604751462126599d7e52f233490efe
::                        https://gist.github.com/subinacls/84b1831cc053859d169941693be822d2
::                        https://github.com/LOLBAS-Project/LOLBAS
::                        https://lolbas-project.github.io/
::                        https://github.com/Disassembler0/Win10-Initial-Setup-Script
::                        https://github.com/cryps1s/DARKSURGEON/tree/master/configuration/configuration-scripts
::                        https://gist.github.com/alirobe/7f3b34ad89a159e6daa1#file-reclaimwindows10-ps1-L71
::                        https://github.com/teusink/Home-Security-by-W10-Hardening
::                        https://github.com/Sycnex/Windows10Debloater
::                        https://github.com/atlantsecurity/windows-hardening-scripts/blob/main/Windows-10-Hardening-script.cmd
::
::########################################################################################################################
:: Change file associations to protect against common ransomware attacks
:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershell
:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :) 
:: ---------------------
:: Changing back example (x64):
:: ftype htafile=C:\Windows\SysWOW64\mshta.exe "%1" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}%U{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} %*
ftype batfile="%systemroot%\system32\notepad.exe" "%1"
ftype chmfile="%systemroot%\system32\notepad.exe" "%1"
ftype cmdfile="%systemroot%\system32\notepad.exe" "%1"
ftype htafile="%systemroot%\system32\notepad.exe" "%1"
ftype jsefile="%systemroot%\system32\notepad.exe" "%1"
ftype jsfile="%systemroot%\system32\notepad.exe" "%1"
ftype vbefile="%systemroot%\system32\notepad.exe" "%1"
ftype vbsfile="%systemroot%\system32\notepad.exe" "%1"
ftype wscfile="%systemroot%\system32\notepad.exe" "%1"
ftype wsffile="%systemroot%\system32\notepad.exe" "%1"
ftype wsfile="%systemroot%\system32\notepad.exe" "%1"
ftype wshfile="%systemroot%\system32\notepad.exe" "%1"
ftype sctfile="%systemroot%\system32\notepad.exe" "%1"
ftype urlfile="%systemroot%\system32\notepad.exe" "%1"
:: Change back the above
:: ftype urlfile="C:\Program Files\Google\Chrome\Application\chrome.exe" "%1"
:: https://seclists.org/fulldisclosure/2019/Mar/27
ftype regfile="%systemroot%\system32\notepad.exe" "%1"
:: https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
ftype wcxfile="%systemroot%\system32\notepad.exe" "%1"
:: https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
ftype mscfile="%systemroot%\system32\notepad.exe" "%1"
:: Change back the above
:: mscfile="C:\Windows\system32\mmc.exe" "%1"
:: https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
:: ftype wsxfile="%systemroot%\system32\notepad.exe" "%1" :: does not work use mitigation from the article above
:: https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39
:: Changing back:
:: reg add "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "{0c194cb2-2959-4d14-8964-37fd3e48c32d}" /f
reg delete "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /f
reg add "HKCR\SettingContent\Shell\Open\Command" /v DelegateExecute /t REG_SZ /d "" /f
:: https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html
ftype slkfile="%systemroot%\system32\notepad.exe" "%1"
ftype iqyfile="%systemroot%\system32\notepad.exe" "%1"
ftype prnfile="%systemroot%\system32\notepad.exe" "%1"
ftype diffile="%systemroot%\system32\notepad.exe" "%1"
:: https://posts.specterops.io/remote-code-execution-via-path-traversal-in-the-device-metadata-authoring-wizard-a0d5839fc54f
reg delete "HKLM\SOFTWARE\Classes\.devicemetadata-ms" /f
reg delete "HKLM\SOFTWARE\Classes\.devicemanifest-ms" /f
:: CVE-2020-0765 impacting Remote Desktop Connection Manager (RDCMan) configuration files - MS won't fix
ftype rdgfile="%systemroot%\system32\notepad.exe" "%1"
:: Mitigate ClickOnce .application and .deploy files vector
:: https://blog.redxorblue.com/2020/07/one-click-to-compromise-fun-with.html
ftype applicationfile="%systemroot%\system32\notepad.exe" "%1"
ftype deployfile="%systemroot%\system32\notepad.exe" "%1"
:: TODO mitigate ClickOnce .appref-ms files vector
:: https://www.blackhat.com/us-19/briefings/schedule/#clickonce-and-youre-in---when-appref-ms-abuse-is-operating-as-intended-15375
:: reg delete "HKLM\SOFTWARE\Classes\.appref-ms" /f
:: Prevent Local windows wireless exploitation: the Airstrike attack https://shenaniganslabs.io/2021/04/13/Airstrike.html
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f
::
:: Workarround for CoronaBlue/SMBGhost Worm exploiting CVE-2020-0796
:: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005
:: Active Directory Administrative Templates
:: https://github.com/technion/DisableSMBCompression
:: Disable SMBv3 compression
:: You can disable compression to block unauthenticated attackers from exploiting the vulnerability against an SMBv3 Server with the PowerShell command below.
:: No reboot is needed after making the change. This workaround does not prevent exploitation of SMB clients.
powershell.exe Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
:: You can disable the workaround with the PowerShell command below.
:: powershell.exe Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 0 -Force
:: 
:: Block tools which remotely install services, such as psexec!
:: EDIT: Run the command below manually! It does not work in a script. 
:: FOR /F "usebackq tokens=2 delims=:" %a IN (`sc.exe sdshow scmanager`) DO  sc.exe sdset scmanager D:(D;;GA;;;NU)%a
:: Block remote commands https://docs.microsoft.com/en-us/windows/win32/com/enabledcom
reg add HKEY_LOCAL_MACHINE\Software\Microsoft\OLE /v EnableDCOM /t REG_SZ /d N /F
::
::##########################################################################################################################
:: Windows Defender Device Guard - Exploit Guard Policies (Windows 10 Only)
:: Enable ASR rules in Win10 ExploitGuard (>= 1709) to mitigate Office malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
:: Sources:
:: https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
:: https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guard-asr-obfuscated-script-rule
:: https://www.darkoperator.com/blog/2017/11/6/windows-defender-exploit-guard-asr-vbscriptjs-rule
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
:: https://demo.wd.microsoft.com/Page/ASR2
:: https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSettings/1.2/Content/WindowsDefender_InternalEvaluationSettings.ps1
:: https://0ut3r.space/2022/03/06/windows-defender/
:: https://jacksonvd.com/levelling-up-windows-defender/
:: ---------------------
::%programfiles%\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
::
::Enable Windows Defender sandboxing
setx /M MP_FORCE_USE_SANDBOX 1
:: Update signatures
"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
:: Enable Defender signatures for Potentially Unwanted Applications (PUA)
powershell.exe Set-MpPreference -PUAProtection enable
:: https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps
:: Reduce Defender CPU Fingerprint 
:: Windows Defender does not exceed the percentage of CPU usage that you specify. The default value is 50%.
powershell.exe Set-MpPreference -ScanAvgCPULoadFactor 25
:: Enable Defender periodic scanning
reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
::
:: Enable Windows Defender real time monitoring
:: Commented out given consumers often run third party anti-virus. You can run either. 
:: powershell.exe Set-MpPreference -DisableRealtimeMonitoring $false
:: reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
::
:: Signature Update Interval to every 4 hours.
powershell.exe Set-MpPreference -SignatureUpdateInterval 4
:: force update new signatures before each scan starts
powershell.exe Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
:: 
:: Enable early launch antimalware driver for scan of boot-start drivers
:: 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
::
:: Enable Microsoft Defender Antivirus Attack Surface Reduction Rules
:: https://twitter.com/duff22b/status/1280166329660497920
:: https://thalpius.com/2020/11/02/microsoft-defender-antivirus-attack-surface-reduction-rules-bypasses/
:: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide
::
:: Verify Microsoft Defender Antivirus Attack Surface Reduction Rules Status
:: Get-MpPreference | select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
:: Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
:: Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
::
:: Block Office applications from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Office applications from injecting code into other processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Win32 API calls from Office macro
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Office applications from creating executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Office communication application from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
::
:: Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
::
:: Block executable files from running unless they meet a prevalence, age, or trusted list criteria
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
::
:: Use advanced protection against ransomware
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block credential stealing from the Windows local security authority subsystem (lsass.exe)
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
::
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled
::
:: Block process creations originating from PSExec and WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
::
:: Block abuse of exploited vulnerable signed drivers
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 56A863A9-875E-4185-98A7-B882C64B5CE5 -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Controlled Folder
powershell.exe Set-MpPreference -EnableControlledFolderAccess Enabled
::
:: Enable Cloud functionality of Windows Defender
powershell.exe Set-MpPreference -MAPSReporting 2
powershell.exe Set-MpPreference -SubmitSamplesConsent 3
:: Levels Default,Moderate,High,HighPlus, or ZeroTolerance
powershell.exe Set-MpPreference -CloudBlockLevel ZeroTolerance
powershell.exe Set-MpPreference -CloudExtendedTimeout 50
::
:: Enable Defender exploit system-wide protection
:: The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
:: powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError
::
:: Enable Windows Defender Application Guard for Microsoft Edge
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
:: powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
:: Dism /online /Enable-Feature /FeatureName:"Windows-Defender-ApplicationGuard"
::
:: Enable Windows Defender Credential Guard / Core Isolation
:: https://old.reddit.com/r/virtualbox/comments/e4khzp/core_isolation_incompatibility/
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products like VMWare, Virtualbox and HypeV unsuable.
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /t REG_DWORD /d 1 /f
::
:: Enable Network protection
:: Enabled - Users will not be able to access malicious IP addresses and domains
:: Disable (Default) - The Network protection feature will not work. Users will not be blocked from accessing malicious domains
:: AuditMode - If a user visits a malicious IP address or domain, an event will be recorded in the Windows event log but the user will not be blocked from visiting the address.
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled 
::
::##########################################################################################################################
:: Enable exploit protection (EMET on Windows 10)
:: Sources:
:: https://www.wilderssecurity.com/threads/process-mitigation-management-tool.393096/
:: https://blogs.windows.com/windowsexperience/2018/03/20/announcing-windows-server-vnext-ltsc-build-17623/
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exploit-protection-reference
:: https://gunnarhaslinger.github.io/Windows-Defender-Exploit-Guard-Configuration/
:: https://github.com/gunnarhaslinger/Windows-Defender-Exploit-Guard-Configuration/find/master
:: ---------------------
:: powershell.exe Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile ProcessMitigation.xml
powershell.exe Invoke-WebRequest -Uri https://raw.githubusercontent.com/gunnarhaslinger/Windows-Defender-Exploit-Guard-Configuration/master/Windows10-v2104_ExploitGuard-Security-Baseline.xml -OutFile ProcessMitigation.xml
powershell.exe -Command "Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml"
del ProcessMitigation.xml
::
::##########################################################################################################################
:: Windows Defender Device Guard - Application Control Policies (Windows 10 Only)
:: https://www.petri.com/enabling-windows-10-device-guard
:: http://flemmingriis.com/building-a-secure-workstation-one-step-at-a-time-part1/
:: http://www.exploit-monday.com/2016/12/updating-device-guard-code-integrity.html
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/merge-windows-defender-application-control-policies
:: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-windows-defender-application-control-policies-using-group-policy
:: https://github.com/MicrosoftDocs/windows-powershell-docs/blob/master/docset/windows/configci/new-cipolicy.md
:: https://github.com/MicrosoftDocs/windows-powershell-docs/blob/master/docset/windows/configci/merge-cipolicy.md
:: https://github.com/MicrosoftDocs/windows-powershell-docs/blob/master/docset/windows/configci/get-cipolicy.md
:: https://docs.microsoft.com/en-us/powershell/module/configci/new-cipolicy?view=win10-ps
:: https://docs.microsoft.com/en-us/powershell/module/configci/merge-cipolicy?view=win10-ps
:: https://docs.microsoft.com/en-us/powershell/module/configci/get-cipolicy?view=win10-ps
:: https://insights.adaptiva.com/2018/windows-defender-application-control-configmgr-intune/
:: https://improsec.com/tech-blog/one-thousand-and-one-application-blocks
:: --------|> TODO <|--------
::
::##########################################################################################################################
:: Harden all version of MS Office against common malspam attacks
:: Disables Macros, enables ProtectedView
:: Sources:
:: https://decentsecurity.com/block-office-macros/
:: ---------------------
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
::
:: Block OneNote malware
:: https://www.huntress.com/blog/addressing-initial-access
::
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Onenote\options\embeddedfileopenoptions" /v blockedextensions /t REG_SZ /d ".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps" /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Onenote\options\embeddedfileopenoptions" /v blockedextensions /t REG_SZ /d ".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps" /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Onenote\options\embeddedfileopenoptions" /v blockedextensions /t REG_SZ /d ".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps" /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Onenote\options\embeddedfileopenoptions" /v blockedextensions /t REG_SZ /d ".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps" /f
::
:: Enable AMSI for all documents by setting the following registry key - Office 2016 or Office 365 installed
:: https://getadmx.com/?Category=Office2016&Policy=office16.Office.Microsoft.Policies.Windows::L_MacroRuntimeScanScope
:: https://malwaretips.com/threads/office-365-and-amsi-support-for-vba-macros.87281/
reg add "HKCU\Software\Microsoft\Office\16.0\Common\Security" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Common\Security" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f
:: ---------------------
:: Source: https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
:: ---------------------
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
::
:: ---------------------
:: File Block policy to prevent Office from opening RTF documents
:: CVE-2023-21716 and CVE-2022-30190
:: ---------------------
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Security\FileBlock" /v RtfFiles /t REG_DWORD /d 00000002 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Security\FileBlock" /v RtfFiles /t REG_DWORD /d 00000002 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security\FileBlock" /v RtfFiles /t REG_DWORD /d 00000002 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Security\FileBlock" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Security\FileBlock" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security\FileBlock" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f
::
::##########################################################################################################################
:: Harden Adobe Acrobat Reader against embeded malicious files
:: Sources:
:: https://blog.nviso.be/2018/07/26/shortcomings-of-blacklisting-in-adobe-reader-and-what-you-can-do-about-it/
:: https://www.adobe.com/devnet-docs/acrobatetk/tools/Wizard/WizardDC/attachments.html
:: Adobe Reader DC STIG
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" /f
reg add "HKLM\Software\Adobe\Acrobat Reader\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bAcroSuppressUpsell" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisablePDFHandlerSwitching" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisableTrustedFolders" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisableTrustedSites" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnableFlash" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bProtectedMode" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "iFileAttachmentPerms" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "iProtectedView" /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" /v "bAdobeSendPluginToggle" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /v "iURLPerms" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /v "iUnknownURLPerms" /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleAdobeDocumentServices" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleAdobeSign" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bTogglePrefsSync" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleWebConnectors" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" /v "bDisableSharePointFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" /v "bDisableWebmail" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" /v "bShowWelcomeScreen" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: General OS hardening
:: Disable DNS Multicast, NTLM, SMBv1, NetBIOS over TCP/IP, PowerShellV2, AutoRun, 8.3 names, Last Access timestamp and weak TLS/SSL ciphers and protocols
:: Enables UAC, SMB/LDAP Signing, Show hidden files
:: ---------------------
:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f
::
:: May break RDP NLA see comments
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f
::
:: Requiring Strong Remote Desktop Encryption if enabled and forcing TLS Authentication"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 00000003 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 00000002 /f
::
:: https://www.top-password.com/blog/prevent-ntlm-credentials-from-being-sent-to-remote-servers/
:: Whitelist IPS for NTLM usage
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v ClientAllowedNTLMServers /t REG_MULTI_SZ /d "127.0.0.1"\0"127.0.0.2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f
:: https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
:: https://en.hackndo.com/pass-the-hash/
:: Affects Windows Remoting (WinRM) deployments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
:: 
:: https://4sysops.com/archives/mitigating-powershell-risks-with-constrained-language-mode/
:: Disable Powershell Constrained Language Mode (CLM) - (revert to Full Language Mode) needs reboot
:: setx __PSLockdownPolicy "0" /M
:: Enable Powershell Constrained Language Mode (CLM)
setx __PSLockdownPolicy "4" /M
::
:: Always re-process Group Policy even if no changes
:: Commented out as consumers don't typically use Domain joined computers and GPO's
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f
::
:: Force logoff if smart card removed
:: Set to "2" for logoff, set to "1" for lock
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f
::
:: Prevent unauthenticated RPC connections
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
::
:: Disable need to run Internet Explorer's first launch configuration
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v DisableFirstRunCustomize /t REG_DWORD /d 2 /f
::
:: Disable internet connection sharing
:: Commented out as it's not enabled by default and if it is enabled, may be for a reason
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f
::
:: Enable SMB/LDAP Signing
:: Sources:
:: http://eddiejackson.net/wp/?p=15812
:: https://en.hackndo.com/ntlm-relay/
:: ---------------------
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
:: 1- Negotiated; 2-Required
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f
::
:: Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
:: Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
:: Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
:: Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
::
:: Enforce NTLMv2 and refuse NTLM and LM authentication
:: Can impact access to consumer-grade file shares / NAS but it's a recommended setting
:: http://systemmanager.ru/win2k_regestry.en/76052.htm
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
::
:: Prevent unencrypted passwords being sent to third-party SMB servers
:: Can impact access to consumer-grade file shares / NAS but it's a recommended setting
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
::
:: Prevent guest logons to SMB servers
:: Can impact access to consumer-grade file shares / NAS but it's a recommended setting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
::
:: Prevent (remote) DLL Hijacking
:: Sources:
:: https://www.greyhathacker.net/?p=235
:: https://www.verifyit.nl/wp/?p=175464
:: https://support.microsoft.com/en-us/help/2264107/a-new-cwdillegalindllsearch-registry-entry-is-available-to-control-the
:: The value data can be 0x1, 0x2 or 0xFFFFFFFF. If the value name CWDIllegalInDllSearch does not exist or the value data is 0 then the machine will still be vulnerable to attack.
:: Please be aware that the value 0xFFFFFFFF could break certain applications (also blocks dll loading from USB).
:: Blocks a DLL Load from the current working directory if the current working directory is set to a WebDAV folder  (set it to 0x1)
:: Blocks a DLL Load from the current working directory if the current working directory is set to a remote folder (such as a WebDAV or UNC location) (set it to 0x2)
:: ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
::
:: Disable (c|w)script.exe to prevent the system from running VBS scripts
:: ---------------------
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v ActiveDebugging /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v DisplayLogo /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v SilentTerminate /t REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v UseWINSAFER /t REG_SZ /d 1 /f
::
:: Block ISO based malware downloads
:: https://winaero.com/remove-mount-context-menu-windows-10/
reg add "HKEY_CLASSES_ROOT\Windows.IsoFile\shell\mount" /v ProgrammaticAccessOnly /t REG_SZ /f
reg add "HKEY_CLASSES_ROOT\Windows.VhdFile\shell\mount" /v ProgrammaticAccessOnly /t REG_SZ /f
::
:: Disable IPv6
:: https://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
:: ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
:: Windows Update Settings
:: Prevent Delivery Optimization from downloading Updates from other computers across the internet
:: 1 will restrict to LAN only. 0 will disable the feature entirely
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v DODownloadMode /t REG_DWORD /d 0 /f
:: Set screen saver inactivity timeout to 15 minutes
::reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
:: Enable password prompt on sleep resume while plugged in and on battery
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
::
:: Windows Remote Access Settings
:: Disable solicited remote assistance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
:: Require encrypted RPC connections to Remote Desktop
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
:: Prevent sharing of local drives via Remote Desktop Session Hosts
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
:: 
:: Removal Media Settings - Disable Autorun/Autoplay on all drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsHistory /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 1 /f
::
:: Blocking ISO mounting for non admin users
:: REF: https://malicious.link/post/2022/blocking-iso-mounting/
reg add "HKEY_CLASSES_ROOT\Windows.IsoFile\shell\mount" /v ProgrammaticAccessOnly /t REG_SZ /f
reg add "HKEY_CLASSES_ROOT\Windows.VhdFile\shell\mount" /v ProgrammaticAccessOnly /t REG_SZ /f
::
:: Disable Sticky keys prompt
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
::
reg add "HKLU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f
reg add "HKLU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f
:: Changing default Explorer view to Computer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
::
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AlwaysShowMenus" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowRecent" /t REG_DWORD /d 0 /f
::
:: https://www.techspot.com/guides/1703-remove-3d-objects-shortcut-windows-file-explorer/
:: Remove Explorer QuickAccess
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d 1 /f
::
:: Stop WinRM Service
net stop WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
:: Disable WinRM Client Digiest authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f
:: Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
:: Disabling RPC usage from a remote asset interacting with services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
::
:: Stop NetBIOS over TCP/IP
wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
:: Disable NTLMv1
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
:: Disable Powershellv2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
::
::##########################################################################################################################
:: Harden lsass to help protect against credential dumping (Mimikatz)
:: Configures lsass.exe as a protected process and disables wdigest
:: Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
:: https://technet.microsoft.com/en-us/library/dn408187(v=ws.11).aspx
:: https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5
:: ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: Disable the ClickOnce trust prompt
:: this only partially mitigates the risk of malicious ClickOnce Appps - the ability to run the manifest is disabled, but hash retrieval is still possible
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v MyComputer /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v LocalIntranet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v Internet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v TrustedSites /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v UntrustedSites /t REG_SZ /d "Disabled" /f
::
::##########################################################################################################################
:: Enable Windows Firewall and configure some advanced options
:: Block Win32/64 binaries (LOLBins) from making net connections when they shouldn't
:: ---------------------
netsh Advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\system32\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any

netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\SysWOW64\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
::
:: Enable Firewall Logging
:: ---------------------
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
::
:: Block all inbound connections on Public profile
:: ---------------------
netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
::
::Show known file extensions and hidden files
:: ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
::
::Disable 8.3 names (Mitigate Microsoft IIS tilde directory enumeration) and Last Access timestamp for files and folder (Performance)
:: ---------------------
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0
::
:: Disable Windows FastBoot (Improve SSD Health)
:: ---------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f
::
:: Disable Windows Hibernate and delete c:\hiberfil.sys
powercfg -h off
::
:: Set the Wifi NIC Advanced Settings
:: https://wizardfi.com/dev/2018/08/23/configuring_wlan_nic_parameters_with_powershell.html
:: https://p0w3rsh3ll.wordpress.com/2023/07/29/prefer-5ghz/
:: https://wizardfi.com/dev/2018/08/23/configuring_wlan_nic_parameters_with_powershell.html
powershell.exe -Command "$FormatEnumerationLimit = -1;Get-NetAdapterAdvancedProperty -Name 'Wi-Fi' | ft DisplayName, DisplayValue, ValidDisplayValues -Wrap -Autosize"
powershell.exe -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -DisplayName 'Throughput Booster' -DisplayValue 'Enabled'"
powershell.exe -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -DisplayName 'Wake on Magic Packet' -DisplayValue 'Disabled'"
powershell.exe -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -DisplayName 'Wake on Pattern Match' -DisplayValue 'Disabled'"
::powershell.exe -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -DisplayName '802.11a/b/g Wireless Mode' -DisplayValue '1. 5GHz  802.11a'"
powershell.exe -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -DisplayName '802.11a/b/g Wireless Mode' -DisplayValue '5. Dual Band 802.11a/g'"
powershell.exe -Command "Set-NetAdapterAdvancedProperty -Name 'Wi-Fi' -DisplayName 'Preferred Band' -DisplayValue '3. Prefer 5GHz band'"
powershell.exe -Command "$FormatEnumerationLimit = -1;Get-NetAdapterAdvancedProperty -Name 'Wi-Fi' | ft DisplayName, DisplayValue, ValidDisplayValues -Wrap -Autosize"
::
:: Biometrics
:: Enable anti-spoofing for facial recognition
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
:: Disable other camera use while screen is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
:: Prevent Windows app voice activation while locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
:: Prevent Windows app voice activation entirely (be mindful of those with accesibility needs)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
::
:: Disable weak TLS/SSL ciphers and protocols
:: ---------------------
:: https://www.nartac.com/Products/IISCrypto
:: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs
:: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786418(v=ws.11)
:: https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
:: Encryption - Ciphers: AES only - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v Enabled /t REG_DWORD /d 0 /f
:: Encryption - Hashes: All allowed - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" /v Enabled /t REG_DWORD /d 0xffffffff /f
:: Encryption - Key Exchanges: All allowed
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" /v Enabled /t REG_DWORD /d 0xffffffff /f
:: Encryption - Protocols: TLS 1.0 and higher - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f

:: Encryption - Cipher Suites (order) - All cipher included to avoid application problems
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v Functions /t REG_SZ /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" /f
:: Prioritize ECC Curves with longer keys - IISCrypto (recommended options)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d NistP384,NistP256 /f
::
:: OCSP stapling - Enabling this registry key has a potential performance impact
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v EnableOcspStaplingForSni /t REG_DWORD /d 1 /f
::
:: Enabling Strong Authentication for .NET Framework
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
::
:: Mitigation for CVE-2013-3900 - WinVerifyTrust Signature Validation Vulnerability
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f
::
:: Mitigation for CVE-2021-40444 and other future ActiveX related attacks 
:: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444
:: https://www.huntress.com/blog/cybersecurity-advisory-hackers-are-exploiting-cve-2021-40444
:: https://nitter.unixfox.eu/wdormann/status/1437530613536501765
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d 00000003 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1004" /t REG_DWORD /d 00000003 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1004" /t REG_DWORD /d 00000003 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1004" /t REG_DWORD /d 00000003 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1004" /t REG_DWORD /d 00000003 /f
:: Mitigation for CVE-2022-30190 MS Office Follina vulnerability
reg delete HKEY_CLASSES_ROOT\ms-msdt /f

::##########################################################################################################################
:: Enable and Configure Edge Internet Browser Settings
::##########################################################################################################################
::
:: Prevent Edge from running in background
reg add "HKLM\Software\Policies\Microsoft\Edge" /f
reg add "HKLM\Software\Policies\Microsoft\Edge"  /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
:: Enable SmartScreen for Edge
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
:: Enable Notifications in IE when a site attempts to install software
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
:: Disable Edge password manager to encourage use of proper password manager
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
:: More hardening
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLVersionMin" /t REG_SZ /d "tls1.2^@" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NativeMessagingUserLevelHosts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverrideForFiles" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLErrorOverrideAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0x00000000" /f
::
::##########################################################################################################################
:: Enable and Configure Google Chrome Internet Browser Settings
::##########################################################################################################################
:: 
:: https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome
::
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d "tls1.2" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowFileSelectionDialogs" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AutoFillEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AutofillAddressEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AutofillCreditCardEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PasswordManagerEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ImportSavedPasswords" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintSubmitEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
:: This overrides normal DNS and DoH of Windows for Chrome - you will possibly need to add entries to the hosts file for local netowrk services
:: https://www.ghacks.net/2020/05/20/chrome-83-rollout-of-dns-over-https-secure-dns-begins/
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d "automatic" /f
:: reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d "secure" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://1.1.1.2/dns-query" /f
:: reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://cloudflare-dns.com/dns-query" /f
:: reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://dns.google/dns-query" /f
::
:: This setting affects certain Data Loss Prevention (DLP) Software  
reg add "HKLM\Software\Policies\Google\Chrome" /v "NetworkServiceSandbox" /t REG_DWORD /d 0 /f
::
reg add "HKLM\Software\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "BlockThirdPartyCookies" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "ImportAutofillFormData" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "UrlKeyedAnonymizedDataCollectionEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "WebRtcEventLogCollectionAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "PasswordLeakDetectionEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "RemoteDebuggingAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DNSInterceptionChecksEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "RestoreOnStartup" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "TranslateEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "DefaultDownloadDirectory" /t REG_SZ /d "C:\Users\vibrio\Desktop" /f
reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "DownloadDirectory" /t REG_SZ /d "C:\Users\vibrio\Desktop" /f


::##########################################################################################################################
:: Windows 10 Privacy Settings
::##########################################################################################################################
::
:: Not working on Windows 10 21H1?
:: Enable DoH (support appeared on Windows 10 2004 build (May 2020 Update)
:: http://woshub.com/enable-dns-over-https-windows/
powershell.exe -Command "$PhysAdapter = Get-NetAdapter -Physical;$PhysAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses '1.1.1.1','8.8.8.8'"
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableAutoDoh /t REG_DWORD /d 2 /f
::
:: Set Windows Analytics to limited enhanced if enhanced is enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
:: Set Windows Telemetry to security only
:: If you intend to use Enhanced for Windows Analytics then set this to "2" instead
:: Note my understanding is W10 Home edition will do a minimum of "Basic"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
:: Disable location data
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
:: Prevent the Start Menu Search from providing internet results and using your location
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
:: Disable publishing of Win10 user activity 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
:: Disable Win10 settings sync to cloud
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
:: Disable the advertising ID
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
::
:: Disable Windows GameDVR (Broadcasting and Recording)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
:: Disable Microsoft consumer experience which prevent notifications of suggested applications to install
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
:: Disable websites accessing local language list
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
:: Prevent toast notifications from appearing on lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f
::
::##########################################################################################################################
:: Enable Advanced Windows Logging
::##########################################################################################################################
::
:: Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
:: Record command line data in process creation events eventid 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
::
:: Enabled Advanced Settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
:: Enable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
::
:: Enable Windows Event Detailed Logging
:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
::##########################################################################################################################
:: Force Update Flash
:: ---------------------
::%WINDIR%\system32\macromed\flash\FlashUtil_ActiveX.exe -update activex
::%WINDIR%\system32\macromed\flash\FlashUtil_Plugin.exe -update plugin
::
::##########################################################################################################################
:: Uninstall dangerous apps with browser extentions
:: ---------------------
:: wmic /interactive:off product where "name like 'Adobe Air%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'Adobe Flash%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'Java%' and version like'%'" call uninstall
::
::##########################################################################################################################
:: Uninstall pups
:: ---------------------
:: wmic /interactive:off product where "name like 'Ask Part%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'searchAssistant%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'Weatherbug%' and version like'%'" call uninstall
:: wmic /interactive:off product where "name like 'ShopAtHome%' and version like'%'" call uninstall
::
:: Uninstall common extra apps found on a lot of Win10 installs
:: Obviously do a quick review to ensure it isn't removing any apps you or your user need to use.
:: https://docs.microsoft.com/en-us/windows/application-management/apps-in-windows-10
:: PowerShell command to reinstall all pre-installed apps below
:: Get-AppxPackage -AllUsers| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
powershell.exe -command "Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *ActiproSoftwareLLC* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *BubbleWitch3Saga* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *CandyCrush* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Dolby* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Duolingo-LearnLanguagesforFree* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Facebook* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Flipboard* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.DesktopAppInstaller* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MixedReality.Portal* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.NetworkSpeedTest* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.News* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.Lens* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.Todo.List* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.RemoteDesktop* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Services.Store.Engagement* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.StorePurchaseApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebMediaExtensions* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebpImageExtension* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Whiteboard* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxTCUI* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Minecraft* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *PandoraMediaInc* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Royal Revolt* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Speed Test* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Spotify* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Sway* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Twitter* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Wunderlist* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage Microsoft.549981C3F5F10 -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Disney* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Office* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Disney* -AllUsers | Remove-AppxPackage"

:: Removed Provisioned Apps
:: This will prevent these apps from being reinstalled on new user first logon
:: Obviously I manually chose this list. If you truly want to nuke all the provisioned apps, you can use the below commented command in PowerShell
:: Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingNews'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Messaging'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Microsoft3DViewer'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MixedReality.Portal'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.NetworkSpeedTest'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.News'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Lens'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.OneNote'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Sway'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Todo.List'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.OneConnect'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.People'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Print3D'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.RemoteDesktop'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.StorePurchaseApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Whiteboard'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsCamera'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsSoundRecorder'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Xbox.TCUI'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGameOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxIdentityProvider'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxSpeechToTextOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxTCUI'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*ActiproSoftwareLLC*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*AdobeSystemsIncorporated.AdobePhotoshopExpress*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*BubbleWitch3Saga*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*CandyCrush*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Dolby*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Duolingo-LearnLanguagesforFree*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*EclipseManager*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Facebook*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Flipboard*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.BingWeather**'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Minecraft*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*PandoraMediaInc*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Royal Revolt*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Speed Test*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Spotify*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Sway*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Twitter*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Wunderlist*'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Advertising.Xaml'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.OneNote'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.People'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Xbox.TCUI'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGameOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxIdentityProvider'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxSpeechToTextOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Disney'} | Remove-AppxProvisionedPackage -Online"
::
:: completely uninstall onedrive
taskkill /f /im OneDrive.exe
powershell.exe -command "$env:SystemRoot\SysWOW64\OneDriveSetup.exe /uninstall"
::##########################################################################################################################
:: Disable Windows Store From Running in the Background
:: [Fix taskbar unresponsiveness and RPC errors related to Clevo Software]
::
:: Start > Settings > Privacy > Background apps > Toggle Microsoft Store Off
:: 
:: Start > gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Store > Turn off the Store application > Enable
::
::##########################################################################################################################
:: Disables scheduled tasks that are considered unnecessary 
powershell.exe -command "Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask Consolidator | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask UsbCeip | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask DmClient | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask"

:: Check "Use the desktop language bar when it's available" and uncheck "Let me use a different input method for each app window".
:: This hides the taskbar language bar selector
:: https://social.technet.microsoft.com/Forums/windows/en-US/c436b33d-7864-43b4-8e29-2b6fdcb9b3d3/disabling-language-bar-via-registry?forum=w7itproinstall
:: https://www.elevenforum.com/t/show-language-bar-on-desktop-or-taskbar-in-windows-11.4107/
powershell.exe -command "Set-WinLanguageBarOption -UseLegacyLanguageBar"

::##########################################################################################################################
:: To disable mitigations for Intel® Transactional Synchronization Extensions (Intel® TSX) Transaction Asynchronous Abort vulnerability (CVE-2019-11135) and  Microarchitectural Data Sampling ( CVE-2019-11091 , CVE-2018-12126 , CVE-2018-12127 , CVE-2018-12130 ) along with Spectre (CVE-2017-5753 & CVE-2017-5715) and Meltdown (CVE-2017-5754) variants, including Speculative Store Bypass Disable (SSBD) (CVE-2018-3639) as well as L1 Terminal Fault (L1TF) (CVE-2018-3615, CVE-2018-3620, and CVE-2018-3646)
::
:: https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
