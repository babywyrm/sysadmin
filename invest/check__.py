from fabric import Connection, Config
from termcolor import cprint
import socket
import os, sys, re

# Hosts file
with open("hosts", "r") as hostfile:
    hosts = hostfile.read().splitlines()

# Legitimate processes
legitimate_processes = ["fail2ban", "up2date", "unattended-upgrades"]

# Common rogue/bad processes
rogue_processes = [
    "admin_panel", "miner", "xmrig", "ngrok", "netcat", "ncat", "socat",
    "proxychains", "sshpass", "tunnel", "reverse", "backconnect"
]

# Suspicious backdoor filenames
backdoor_files = ["backdoor", "evil.sh", "malicious.py", ".tmphack", ".hidden", "rootkit"]

# Suspicious TCP ports
suspicious_ports = [8080, 9999, 12345, 31337, 4444]

# Fabric config
config = Config(overrides={"run": {"warn": True}})
config.run.forward_agent = True

def log_event(host, message, level="INFO"):
    prefix = f"[{host}]"
    if level == "ALERT":
        cprint(f"{prefix} {message}", "red")
    elif level == "WARN":
        cprint(f"{prefix} {message}", "yellow")
    else:
        cprint(f"{prefix} {message}", "green")

def check_rogue_processes(c):
    for name in rogue_processes:
        result = c.run(f"ps aux | grep {name} | grep -v grep")
        for line in result.stdout.splitlines():
            if not any(legit in line for legit in legitimate_processes):
                log_event(c.host, f"Rogue process detected: {name} → {line}", "ALERT")

def check_for_backdoors(c):
    # Backdoor files
    for fname in backdoor_files:
        result = c.run(f"find / -type f -name '{fname}' 2>/dev/null")
        if result.stdout.strip():
            log_event(c.host, f"Suspicious file found: {fname}", "ALERT")

    # Hidden binaries in /tmp or /dev
    tmp_check = c.run("find /tmp /dev -type f -executable 2>/dev/null")
    if tmp_check.stdout.strip():
        for path in tmp_check.stdout.strip().splitlines():
            log_event(c.host, f"Executable in tmp/dev: {path}", "WARN")

    # SSH keys (all users)
    users_result = c.run("awk -F: '$3 >= 1000 {print $1}' /etc/passwd")
    for user in users_result.stdout.splitlines():
        key_check = c.run(f"cat /home/{user}/.ssh/authorized_keys", warn=True)
        if key_check.ok and key_check.stdout.strip():
            log_event(c.host, f"User {user} has SSH keys installed", "WARN")

    # Cron jobs
    cron_result = c.run("for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null; done")
    if cron_result.stdout.strip():
        log_event(c.host, "User crontabs found (check for unauthorized jobs)", "WARN")

def check_rogue_tcp_bindings(c):
    result = c.run("ss -tulpen | grep LISTEN", warn=True)
    for port in suspicious_ports:
        if f":{port} " in result.stdout:
            log_event(c.host, f"Suspicious TCP binding on port {port}", "ALERT")

def check_suspicious_users(c):
    passwd_check = c.run("awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd")
    for user in passwd_check.stdout.splitlines():
        if user not in ["ubuntu", "ec2-user", "admin", "debian"]:
            log_event(c.host, f"Suspicious user account detected: {user}", "WARN")

def main():
    for host in hosts:
        try:
            c = Connection(host, config=config)
            log_event(host, "Connected", "INFO")
            check_rogue_processes(c)
            check_for_backdoors(c)
            check_rogue_tcp_bindings(c)
            check_suspicious_users(c)
        except Exception as e:
            log_event(host, f"Connection failed: {e}", "ALERT")

if __name__ == "__main__":
    main()
