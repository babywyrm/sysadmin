


##
#
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer
#
##


https://github.com/itm4n/FullPowers

On Windows, some services executed as LOCAL SERVICE or NETWORK SERVICE are configured to run with a restricted set of privileges. 
Therefore, even if the service is compromised, you won't get the golden impersonation privileges and privilege escalation to LOCAL SYSTEM should be more complicated. 
However, I found that, when you create a scheduled task, the new process created by the Task Scheduler Service has all the default privileges of the associated user account (except SeImpersonate). 
Therefore, with some token manipulations, you can spawn a new process with all the missing privileges.

For more information: https://itm4n.github.io/localservice-privileges/

https://itm4n.github.io/localservice-privileges/
( RANDOM )


##
##

https://github.com/BeichenDream/GodPotato

https://www.kitploit.com/2023/05/godpotato-local-privilege-escalation.html


Based on the history of Potato privilege escalation for 6 years, from the beginning of RottenPotato to the end of JuicyPotatoNG, I discovered a new technology by researching DCOM, which enables privilege escalation in Windows 2012 - Windows 2022, now as long as you have "ImpersonatePrivilege" permission. Then you are "NT AUTHORITY\SYSTEM", usually WEB services and database services have "ImpersonatePrivilege" permissions.



##
##

Potato privilege escalation is usually used when we obtain WEB/database privileges. We can elevate a service user with low privileges to "NT AUTHORITY\SYSTEM" privileges. However, the historical Potato has no way to run on the latest Windows system. When I was researching DCOM, I found a new method that can perform privilege escalation. There are some defects in rpcss when dealing with oxid, and rpcss is a service that must be opened by the system. , so it can run on almost any Windows OS, I named it GodPotato

Affected version
Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11

##
##

This gaudy repository is a derivative of the GodPotato project, aiming to enhance the original work's functionality and user-friendliness.
With my bread-and-butter generally being PowerShell implementation and visual formatting, the primary focus is on enhancing PowerShell support and output verbosity for a more intuitive and effective user experience.

https://github.com/tylerdotrar/SigmaPotato

##
##



FullPowers - Recover the default privilege set of a LOCAL/NETWORK SERVICE account
https://github.com/itm4n/FullPowers

CVE-2019-1405 and CVE-2019-1322 – Elevation to SYSTEM via the UPnP Device Host Service and the Update Orchestrator Service
https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/

Enabling and Disabling Privileges in C++
https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c–

NirSoft - RunFromProcess Tool
https://www.nirsoft.net/utils/run_from_process.html

powercat
https://github.com/besimorhino/powercat

MSDN - LocalService Account
https://docs.microsoft.com/en-us/windows/win32/services/localservice-account

MSDN - Task Security Hardening
https://docs.microsoft.com/en-us/windows/win32/taskschd/task-security-hardening

MSDN - PowerShell - Register-ScheduledTask
https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=win10-ps

MSDN - PowerShell - New-ScheduledTaskPrincipal
https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=win10-ps

MSDN - Privilege Constants
https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants


