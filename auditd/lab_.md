
# 🚀 Modern Linux File Monitoring (2025 Edition)

Instead of just “how to use auditd”, we’ll structure this as:

1. Threat model
2. Modern auditing architecture
3. Hardened configuration
4. Advanced rule tuning
5. Forensics workflows
6. Detection engineering
7. Tamper protection
8. Central log forwarding

---

# 🧠 1️⃣ Threat Model First

Before enabling auditd, ask:

What are we defending against?

Typical scenarios:

• Insider data theft  
• Ransomware execution  
• Webshell persistence  
• Unauthorized config changes  
• SSH key manipulation  
• Privilege escalation  
• Container breakout  

Audit rules should reflect that.

---

# 🛠 2️⃣ Modern Audit Architecture

In 2025, Linux auditing typically looks like:

```
Kernel → auditd → journald → SIEM
```

Or:

```
Kernel → auditd → filebeat / fluentbit → ELK / Splunk
```

Also common:

• Wazuh  
• Falco (Kubernetes)  
• OSSEC  
• Auditbeat  

auditd alone is rarely enough — it should feed a detection pipeline.

---

# ✅ 3️⃣ Modern Installation

Ubuntu / Debian:

```bash
sudo apt install auditd audispd-plugins
```

RHEL / Rocky:

```bash
sudo dnf install audit audit-libs
```

Verify:

```bash
sudo systemctl status auditd
```

---

# 🔐 4️⃣ Hardened auditd.conf

Instead of defaults, use hardened config:

```
log_file = /var/log/audit/audit.log
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 100
num_logs = 10
max_log_file_action = ROTATE
space_left_action = EMAIL
admin_space_left_action = SUSPEND
disk_full_action = HALT
disk_error_action = HALT
```

Key upgrades:

✅ Enriched logging  
✅ Log rotation  
✅ Disk failure protection  
✅ Auto suspend on exhaustion  

---

# 🧾 5️⃣ Modern Rule Design

Do not monitor entire directories blindly.

Monitor:

• /etc  
• /usr/bin  
• /bin  
• SSH keys  
• Critical services  
• Container runtime  
• Privilege escalation syscalls  

---

## 🔎 Monitor Sensitive Files

```bash
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /root/.ssh/authorized_keys -p wa -k ssh_mod
-w /etc/ssh/sshd_config -p wa -k ssh_config
```

---

## 🔥 Monitor Execution in Temp Directories

```bash
-w /tmp -p x -k tmp_exec
-w /var/tmp -p x -k tmp_exec
-w /dev/shm -p x -k tmp_exec
```

This catches:

• Malware staging  
• Reverse shells  
• Droppers  

---

## ⚔ Monitor Privilege Escalation

```bash
-a always,exit -F arch=b64 -S execve -C uid!=euid -k privilege_escalation
-a always,exit -F arch=b64 -S setuid,setgid -k setid_changes
```

---

## 🐳 Monitor Container Runtime (Modern Linux)

```bash
-w /usr/bin/docker -p x -k docker_exec
-w /usr/bin/runc -p x -k container_runtime
```

---

# 🧬 6️⃣ Modern Syscall Monitoring

Example: monitor hostname changes

```bash
-a always,exit -S sethostname -k hostname_change
```

Example: monitor module loading (rootkits)

```bash
-a always,exit -S init_module,finit_module -k kernel_module
```

---

# 🧠 7️⃣ Modern Forensics Workflow

Instead of manually parsing `/var/log/audit/audit.log`, use:

```bash
ausearch -k ssh_mod -i
ausearch -k privilege_escalation -ts today -i
```

Or generate reports:

```bash
aureport --summary
aureport --failed
aureport --login
```

---

# 📊 8️⃣ Export to SIEM (Modern Practice)

auditd → Auditbeat

Install:

```bash
sudo apt install auditbeat
```

Enable:

```yaml
auditbeat.modules:
  - module: auditd
    resolve_ids: true
```

Now events go to ELK / Splunk.

---

# 🛡 9️⃣ Protect the Logs

Audit logs are sensitive.

Restrict:

```bash
chmod 600 /var/log/audit/audit.log
chown root:root /var/log/audit/audit.log
```

Also protect:

```bash
chattr +a /var/log/audit/audit.log
```

Append-only mode.

---

# ⚠ 10️⃣ Tamper Resistance (Advanced)

Attackers often:

• Disable auditd  
• Remove rules  
• Clear logs  

Protect against this:

```bash
auditctl -e 2
```

This locks the audit configuration until reboot.

Now rules cannot be modified without reboot.

---

# 🧪 11️⃣ Testing Your Rules

Test file deletion:

```bash
touch /etc/testfile
rm /etc/testfile
ausearch -k identity -i
```

Test privilege escalation:

```bash
sudo -u nobody id
ausearch -k privilege_escalation -i
```

---

# ☸ 12️⃣ Kubernetes / Cloud Era Notes

auditd does NOT see:

• Container filesystem overlays properly  
• Namespaced process isolation clearly  

For Kubernetes:

Use:

• Falco  
• Audit Policy  
• eBPF tracing  

auditd alone is insufficient in cloud-native infra.

---

# 🧠 13️⃣ When to Use eBPF Instead

Modern alternative:

• Tracee  
• Tetragon  
• Falco  

These are event-driven and better for runtime threat detection.

auditd is still useful but heavy.

---

# ✅ 14️⃣ Modern Minimal Rule Set (Production-Ready)

If you just want a strong modern baseline:

```
-D
-b 8192
-f 1

-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /root/.ssh/authorized_keys -p wa -k ssh_mod

-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S init_module,finit_module -k kernel_module

-w /tmp -p x -k tmp_exec
```

Load:

```bash
augenrules --load
```

Lock:

```bash
auditctl -e 2
```

---

# 🏁 Modern Conclusion

In 2025:

✅ auditd is still valid  
✅ But must be hardened  
✅ Must integrate with SIEM  
✅ Must protect itself  
✅ Should focus on high-risk events  
✅ Combine with eBPF tools in cloud systems  

##
##
