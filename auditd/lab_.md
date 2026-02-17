
# Linux File Access Monitoring in 2026 ..beta..

## 1. Context: Why auditd Still Matters (and Where It Doesn’t)

Linux monitoring in 2026 typically falls into three categories:

| Layer        | Technology        | Purpose |
|--------------|------------------|---------|
| Kernel-level | auditd, eBPF     | Syscall visibility |
| Runtime      | Falco, Tetragon  | Behavior detection |
| Centralized  | Auditbeat, Wazuh | Aggregation + alerting |

auditd remains:

- Deterministic
- Kernel-native
- Compliance-friendly (PCI, HIPAA, ISO)
- Stable across distros

However:

- It is syscall-based (not behavior-based)
- It is verbose
- It can be performance-heavy
- It is blind to certain container abstractions

---

# 2. Architecture Overview

```
                +-------------------+
                |   Userspace Apps  |
                +---------+---------+
                          |
                          v
                +-------------------+
                |   Linux Kernel    |
                |   (Audit Hooks)   |
                +---------+---------+
                          |
                          v
                +-------------------+
                |      auditd       |
                +---------+---------+
                          |
                          v
                +-------------------+
                |   /var/log/audit  |
                +---------+---------+
                          |
          +---------------+----------------+
          |                                |
          v                                v
   SIEM (ELK/Splunk)                Auditbeat/Wazuh
```

auditd receives events from the kernel audit subsystem via netlink.

---

# 3. Modern Threat Model (2026)

File access monitoring should focus on:

1. Identity manipulation
2. Privilege escalation
3. Persistence installation
4. Lateral movement
5. Kernel tampering
6. Container breakout
7. Log tampering

Monitoring “everything” is not viable.

Monitoring *sensitive transitions* is.

---

# 4. Modern Hardened auditd Configuration

File: `/etc/audit/auditd.conf`

Recommended 2026 hardened baseline:

```
log_file = /var/log/audit/audit.log
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 200
num_logs = 20
max_log_file_action = ROTATE
space_left_action = SYSLOG
admin_space_left_action = SUSPEND
disk_full_action = HALT
disk_error_action = HALT
name_format = HOSTNAME
transport = TCP
```

Critical additions:

- ENRICHED format
- Controlled rotation
- Disk failure halt
- Hostname tagging
- Network forwarding capability

---

# 5. Modern Audit Rule Engineering

Audit rules should be layered:

Layer 1: Identity controls  
Layer 2: Privilege escalation  
Layer 3: Execution tracking  
Layer 4: Kernel integrity  
Layer 5: Persistence paths  

---

## 5.1 Identity Monitoring

```
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
```

Detects:
- User creation
- Password changes
- Group privilege changes

---

## 5.2 Privilege Escalation

```
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k setid
-a always,exit -F arch=b64 -S execve -C uid!=euid -k privilege_escalation
```

The second rule detects UID transitions.

Example detection:

```
uid=1001 euid=0
```

This is sudo or exploit.

---

## 5.3 Execution Monitoring

```
-a always,exit -F arch=b64 -S execve -k exec_monitor
```

Modern enhancement (filter out noise):

```
-a always,exit -F arch=b64 -S execve -F exe!=/usr/bin/ls -k exec_monitor
```

Better:

Target high-risk binaries:

```
-w /usr/bin/nc -p x -k lateral_movement
-w /usr/bin/socat -p x -k lateral_movement
-w /usr/bin/curl -p x -k exfiltration
-w /usr/bin/wget -p x -k exfiltration
```

---

## 5.4 Persistence Monitoring

```
-w /etc/cron.d -p wa -k persistence
-w /etc/cron.daily -p wa -k persistence
-w /etc/systemd/system -p wa -k persistence
-w /etc/ld.so.preload -p wa -k persistence
-w /root/.ssh/authorized_keys -p wa -k persistence
```

These catch:

- Cron backdoors
- Systemd backdoors
- LD_PRELOAD hijacking
- SSH persistence

---

## 5.5 Kernel Integrity

```
-a always,exit -S init_module,finit_module,delete_module -k kernel_module
```

Kernel module insertion is high-risk.

---

# 6. Locking Configuration (Tamper Resistance)

After rules are loaded:

```
auditctl -e 2
```

State:

```
auditctl -s
```

Output should show:

```
enabled 2
```

Meaning:
- Immutable until reboot

---

# 7. Advanced Querying

Modern workflow is not manual log parsing.

Instead use:

```
ausearch -k identity -ts today -i
ausearch -k privilege_escalation -i
aureport --summary
aureport --failed
```

---

# 8. Forensic Event Reconstruction

Example: File deleted

```
ausearch --file /etc/passwd -i
```

Key fields:

| Field | Meaning |
|-------|---------|
| uid   | real user |
| auid  | original login UID |
| euid  | effective UID |
| exe   | executed binary |
| syscall | system call |
| key   | matched rule key |

auid is critical in investigations.

---

# 9. Performance Considerations

auditd overhead increases with:

- execve monitoring
- high event rate
- large rule sets

Tune:

```
-b 16384
--backlog_wait_time 60000
```

Monitor dropped events:

```
auditctl -s
```

If:

```
lost > 0
```

You are losing audit events.

---

# 10. Containers (2026 Reality)

auditd does not fully understand:

- Namespaces
- OverlayFS
- Container context

Modern hybrid approach:

| Tool | Purpose |
|------|---------|
| auditd | Compliance |
| Falco | Runtime detection |
| Tetragon | eBPF-based enforcement |

---

# 11. Modern eBPF Alternative

auditd is syscall-based.

eBPF tools provide:

- Lower overhead
- Context-aware detection
- Container identity
- Behavioral detection

Examples:

```
tracee
falco
tetragon
```

---

# 12. Advanced Deployment Model (Enterprise)

```
Nodes
  |
  v
auditd
  |
  v
auditbeat
  |
  v
Kafka
  |
  v
SIEM
```

Modern practice includes:

- Log signing
- TLS transport
- Central correlation
- Rule-based alerting

---

# 13. Detection Engineering Approach

Instead of generic monitoring:

Create detections for:

Example: Unauthorized SSH key injection

```
if key == "persistence" AND path == "/root/.ssh/authorized_keys"
alert CRITICAL
```

Example: Privilege escalation chain

```
execve + setuid + file write in /etc
```

---

# 14. Modern Minimal Baseline Ruleset (2026 Recommended)

```
-D
-b 16384
-f 1

-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /root/.ssh/authorized_keys -p wa -k persistence

-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S setuid,setgid -k setid
-a always,exit -S init_module,finit_module -k kernel_module

-w /tmp -p x -k tmp_exec
```

Load:

```
augenrules --load
auditctl -e 2
```

---

# 15. Summary

In 2026:

- auditd is still valuable
- Must be hardened
- Must be immutable
- Must be tuned
- Must integrate with SIEM
- Should be paired with eBPF for runtime detection
- Should focus on transitions, not noise

##
##
