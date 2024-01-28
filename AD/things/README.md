https://offsec.tools/tool/godpotato


GodPotato
GodPotato
Privilege escalation tool for Windows.
#privesc   #windows  
https://github.com/BeichenDream/GodPotato
Potato privilege escalation is usually used when we obtain WEB/database privileges. We can elevate a service user with low privileges to "NT AUTHORITY\SYSTEM" privileges. However, the historical Potato has no way to run on the latest Windows system. When I was researching DCOM, I found a new method that can perform privilege escalation. There are some defects in rpcss when dealing with oxid, and rpcss is a service that must be opened by the system. , so it can run on almost any Windows OS, I named it GodPotato
