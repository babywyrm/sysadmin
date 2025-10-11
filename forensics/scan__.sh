#!/bin/bash
# linux_persistence_scan.sh ..beta..
# Forensic triage tool for persistence/backdoor detection
# Compatible with Ubuntu/Debian and RHEL/CentOS/Fedora systems

LOGFILE="/tmp/persist_scan_$(date +%F_%H-%M-%S).log"
echo "[*] Linux Persistence & Backdoor Scan - $(date)" | tee "$LOGFILE"

section() {
  echo -e "\n=== $1 ===" | tee -a "$LOGFILE"
}

# 1. Suspicious Processes
section "Running Processes"
ps aux --sort=-%mem | head -n 20 | tee -a "$LOGFILE"
ps aux | grep -E "nc |bash -i|dev/tcp|curl|wget|python.*http.server" | tee -a "$LOGFILE"

# 2. Cron Jobs
section "Cron Jobs"
ls -la /etc/cron* 2>/dev/null | tee -a "$LOGFILE"
crontab -l 2>/dev/null | tee -a "$LOGFILE"
grep -R "wget\|curl\|nc\|/dev/tcp" /etc/cron* 2>/dev/null | tee -a "$LOGFILE"

# 3. Shell Init Scripts
section "Shell Init Scripts"
grep -R "bash -i\|/dev/tcp\|nc\|curl" /root/.bash* /home/*/.bash* /etc/profile* 2>/dev/null | tee -a "$LOGFILE"

# 4. SUID/SGID Binaries
section "SUID/SGID Binaries"
find / -perm /6000 -type f 2>/dev/null | tee -a "$LOGFILE"

# 5. SSH Keys
section "SSH Authorized Keys"
grep -H "." /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null | tee -a "$LOGFILE"

# 6. Suspicious Users
section "User Accounts with Shell Access"
awk -F: '$7 ~ /bash/ {print $1":"$7}' /etc/passwd | tee -a "$LOGFILE"
awk -F: '$3 == 0 {print "Root-equivalent user: "$1}' /etc/passwd | tee -a "$LOGFILE"

# 7. Systemd and Init Scripts
section "Systemd/Init Services"
systemctl list-unit-files --type service 2>/dev/null | grep enabled | tee -a "$LOGFILE"
grep -R "ExecStart=.*(nc |bash |python |curl |wget)" /etc/systemd/system /etc/init.d 2>/dev/null | tee -a "$LOGFILE"

# 8. Network Listeners
section "Network Listeners"
ss -tulpn 2>/dev/null | tee -a "$LOGFILE"

# 9. Suspicious Temp Files
section "Temp Directories"
find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | tee -a "$LOGFILE"

# 10. Integrity Check
section "Binary Integrity"
if command -v rpm &>/dev/null; then
  rpm -Va | grep '^..5' | tee -a "$LOGFILE"
elif command -v debsums &>/dev/null; then
  debsums -s 2>/dev/null | tee -a "$LOGFILE"
else
  echo "No package integrity tool available (rpm/debsums missing)" | tee -a "$LOGFILE"
fi

echo -e "\n[*] Scan complete. Report saved to $LOGFILE"
