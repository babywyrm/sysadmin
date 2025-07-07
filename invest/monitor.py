from fabric import Connection, Config
from termcolor import cprint
import socket, os, sys, argparse
from pathlib import Path
from alert import send_alert

state_dir = Path("state")
state_dir.mkdir(exist_ok=True)

config = Config(overrides={"run": {"warn": True}})
config.run.forward_agent = True

with open("hosts", "r") as hostfile:
    hosts = hostfile.read().splitlines()

legitimate_processes = ["fail2ban", "unattended-upgrades"]
rogue_processes = ["miner", "xmrig", "ngrok", "ncat", "proxychains", "tunnel"]
backdoor_files = ["backdoor", "evil.sh", "malicious.py", ".hidden"]
suspicious_ports = [4444, 8080, 31337]

def log_event(host, msg, level="INFO"):
    color = {"INFO": "green", "WARN": "yellow", "ALERT": "red"}.get(level, "white")
    cprint(f"[{host}] {msg}", color)
    send_alert(host, msg, level)

def diff_snapshot(c, name, current):
    host_id = c.host.replace(".", "_")
    file_path = state_dir / f"{host_id}_{name}.txt"
    prev = file_path.read_text().splitlines() if file_path.exists() else []
    added = sorted(set(current) - set(prev))
    removed = sorted(set(prev) - set(current))
    file_path.write_text("\n".join(current))
    return added, removed

def check_rogue_processes(c):
    for name in rogue_processes:
        res = c.run(f"ps aux | grep {name} | grep -v grep")
        for line in res.stdout.splitlines():
            if not any(legit in line for legit in legitimate_processes):
                log_event(c.host, f"Rogue process: {name} → {line}", "ALERT")

def check_backdoors(c):
    for f in backdoor_files:
        res = c.run(f"find / -type f -name '{f}' 2>/dev/null")
        for path in res.stdout.splitlines():
            log_event(c.host, f"Backdoor file found: {path}", "ALERT")

def check_tcp_ports(c):
    res = c.run("ss -tulpen | grep LISTEN", warn=True)
    for port in suspicious_ports:
        if f":{port} " in res.stdout:
            log_event(c.host, f"Rogue port open: {port}", "ALERT")

def check_users(c):
    res = c.run("awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd")
    current_users = sorted(res.stdout.splitlines())
    added, removed = diff_snapshot(c, "users", current_users)
    for user in added:
        log_event(c.host, f"New user created: {user}", "WARN")
    for user in removed:
        log_event(c.host, f"User deleted: {user}", "WARN")

def check_crons(c):
    res = c.run("for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done", warn=True)
    current_crons = sorted(res.stdout.splitlines())
    added, removed = diff_snapshot(c, "crons", current_crons)
    for job in added:
        log_event(c.host, f"New cron job: {job}", "WARN")
    for job in removed:
        log_event(c.host, f"Cron job removed: {job}", "WARN")

def main(args):
    for host in hosts:
        try:
            c = Connection(host, config=config)
            log_event(host, "Connected", "INFO")
            if args.proc: check_rogue_processes(c)
            if args.backdoor: check_backdoors(c)
            if args.ports: check_tcp_ports(c)
            if args.users: check_users(c)
            if args.cron: check_crons(c)
        except Exception as e:
            log_event(host, f"Connection failed: {e}", "ALERT")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor remote Linux hosts for rogue activity")
    parser.add_argument("--proc", action="store_true", help="Check for rogue processes")
    parser.add_argument("--backdoor", action="store_true", help="Check for suspicious files or SSH keys")
    parser.add_argument("--ports", action="store_true", help="Check for rogue TCP ports")
    parser.add_argument("--users", action="store_true", help="Check for new or deleted users")
    parser.add_argument("--cron", action="store_true", help="Check for new or deleted cron jobs")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    args = parser.parse_args()

    if args.all:
        args.proc = args.backdoor = args.ports = args.users = args.cron = True

    main(args)
##
##
