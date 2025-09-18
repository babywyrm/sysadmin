#!/usr/bin/env python3
"""
rootkit_scan.py — wrapper for chkrootkit & rkhunter
2025 update with optional systemd timer install
"""

import subprocess, datetime, os, json, sys

LOG_DIR = "/var/log/rootkit-scan"
os.makedirs(LOG_DIR, exist_ok=True)

timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
outfile = os.path.join(LOG_DIR, f"scan-{timestamp}.json")

results = {"timestamp": timestamp, "chkrootkit": None, "rkhunter": None}

def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out.strip()
    except subprocess.CalledProcessError as e:
        return f"Error running {cmd[0]}: {e.output}"

def install_timer():
    print("[*] Installing systemd service + timer...")
    service_file = "/etc/systemd/system/rootkit-scan.service"
    timer_file = "/etc/systemd/system/rootkit-scan.timer"
    script_path = os.path.realpath(__file__)

    service_unit = f"""[Unit]
Description=Rootkit Scan Wrapper (Python)

[Service]
Type=oneshot
ExecStart=/usr/bin/env python3 {script_path}
"""

    timer_unit = """[Unit]
Description=Daily Rootkit Scan Timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
"""

    with open("/tmp/rootkit-scan.service", "w") as f:
        f.write(service_unit)
    with open("/tmp/rootkit-scan.timer", "w") as f:
        f.write(timer_unit)

    subprocess.run(["sudo", "mv", "/tmp/rootkit-scan.service", service_file], check=True)
    subprocess.run(["sudo", "mv", "/tmp/rootkit-scan.timer", timer_file], check=True)
    subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
    subprocess.run(["sudo", "systemctl", "enable", "--now", "rootkit-scan.timer"], check=True)

    print("[+] Systemd timer installed: runs daily")
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--install-timer":
    install_timer()

# Run chkrootkit
if subprocess.call(["which", "chkrootkit"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
    print("[*] Running chkrootkit...")
    results["chkrootkit"] = run_cmd(["sudo", "chkrootkit"])
else:
    results["chkrootkit"] = "chkrootkit not installed"

# Run rkhunter
if subprocess.call(["which", "rkhunter"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
    print("[*] Updating rkhunter...")
    _ = run_cmd(["sudo", "rkhunter", "--update"])
    _ = run_cmd(["sudo", "rkhunter", "--propupd"])

    print("[*] Running rkhunter...")
    results["rkhunter"] = run_cmd(["sudo", "rkhunter", "--check", "--sk"])
else:
    results["rkhunter"] = "rkhunter not installed"

# Save JSON log
with open(outfile, "w") as f:
    json.dump(results, f, indent=2)

print(f"=== Scan complete: {outfile} ===")
