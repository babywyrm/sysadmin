


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



##
##

https://github.com/BeichenDream/GodPotato

##
##

This gaudy repository is a derivative of the GodPotato project, aiming to enhance the original work's functionality and user-friendliness.
With my bread-and-butter generally being PowerShell implementation and visual formatting, the primary focus is on enhancing PowerShell support and output verbosity for a more intuitive and effective user experience.

https://github.com/tylerdotrar/SigmaPotato

##
##
