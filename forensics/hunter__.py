#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import argparse
import signal
import hashlib
import psutil
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---
VERSION = "3.1.0"
DEFAULT_LOG_DIR = "/var/log/hunter"

# Expanded target list for persistence and backdoors
SENSITIVE_TARGETS = {
    "persistence_dirs": [
        "/etc/init.d",
        "/etc/systemd/system",
        "/etc/rc.local",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/var/spool/cron/crontabs",
        "/usr/lib/systemd/system",
    ],
    "boot_critical": [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/etc/default/grub",
    ],
    "shell_configs": [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/root/.bashrc",
        "/root/.profile",
        "/home/*/.bashrc",
        "/home/*/.ssh/authorized_keys",
    ],
    "system_identity": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/sudoers.d/",
        "/etc/ld.so.preload" # Highly critical for rootkits
    ]
}

THREAT_SIGNATURES = [
    "nc -e", "bash -i", "python -c", "perl -e", "socat exec",
    "xmrig", "stratum+tcp", "wget http", "curl http", "base64 -d"
]

# --- Real-time Monitor Engine ---
class FIMHandler(FileSystemEventHandler):
    """Real-time File Integrity Monitoring."""
    def __init__(self, hunter):
        self.hunter = hunter

    def on_modified(self, event):
        if not event.is_directory:
            self.hunter.record_finding(
                "FIM_EVENT", "HIGH", 
                f"File Modified: {event.src_path}", 
                {"action": "modify", "path": event.src_path}
            )

    def on_created(self, event):
        self.hunter.record_finding(
            "FIM_EVENT", "MEDIUM", 
            f"New File Created in sensitive dir: {event.src_path}", 
            {"action": "create", "path": event.src_path}
        )

# --- Core Investigator Engine ---
class SystemHunter:
    def __init__(self, log_dir=DEFAULT_LOG_DIR, verbose=False):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.logger = self._setup_logging()
        self.findings = []
        
    def _setup_logging(self):
        logger = logging.getLogger("Hunter")
        level = logging.DEBUG if self.verbose else logging.INFO
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        
        # File Handler
        fh = logging.FileHandler(self.log_dir / "hunter.log")
        fh.setFormatter(formatter)
        # Stream Handler
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        
        logger.setLevel(level)
        logger.addHandler(fh)
        logger.addHandler(sh)
        return logger

    def record_finding(self, category, severity, message, details=None):
        finding = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "severity": severity,
            "message": message,
            "details": details or {}
        }
        self.findings.append(finding)
        self.logger.warning(f"[{severity}] {category}: {message}")

    def scan_processes(self):
        self.logger.info("Engaging Process Engine...")
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'exe']):
            try:
                pinfo = proc.info
                cmd = " ".join(pinfo['cmdline']) if pinfo['cmdline'] else ""
                
                # Check for signatures
                if any(sig in cmd.lower() for sig in THREAT_SIGNATURES):
                    self.record_finding("PROCESS", "CRITICAL", f"Malicious string in PID {pinfo['pid']}", {"cmd": cmd})

                # Check for "Hidden" or Unlinked processes
                if pinfo['exe'] and "(deleted)" in pinfo['exe']:
                    self.record_finding("PROCESS", "CRITICAL", f"Fileless Malware Indicator (deleted exe) in PID {pinfo['pid']}", {"path": pinfo['exe']})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def scan_network(self):
        self.logger.info("Engaging Network Engine...")
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                # Check for high ports or unusual listeners
                if conn.laddr.port > 30000 or conn.laddr.port in [1337, 4444, 31337]:
                    self.record_finding("NETWORK", "HIGH", f"Suspicious Listener on Port {conn.laddr.port}", {"pid": conn.pid})

    def scan_persistence(self):
        """Deep dive into persistence configurations."""
        self.logger.info("Engaging Persistence Engine...")
        
        # Check Systemd/Init
        for d in SENSITIVE_TARGETS["persistence_dirs"]:
            path = Path(d)
            if path.exists():
                # Look for very recently modified files
                for f in path.iterdir():
                    try:
                        mtime = f.stat().st_mtime
                        if (time.time() - mtime) < 86400: # Last 24 hours
                            self.record_finding("PERSISTENCE", "MEDIUM", f"Recent change in persistence dir: {f}", {"mtime": mtime})
                    except Exception: continue

        # Check for Ld.so.preload (Classic Rootkit persistence)
        preload = Path("/etc/ld.so.preload")
        if preload.exists() and preload.stat().st_size > 0:
            self.record_finding("ROOTKIT", "CRITICAL", "Suspicious /etc/ld.so.preload detected", {"content": preload.read_text()})

    def run_full_scan(self):
        self.logger.info("--- Starting Comprehensive Investigation ---")
        self.findings = []
        self.scan_processes()
        self.scan_network()
        self.scan_persistence()
        
        if self.findings:
            report_name = f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(self.log_dir / report_name, 'w') as f:
                json.dump(self.findings, f, indent=4)
            self.logger.info(f"Full report generated: {report_name}")

# --- Main Execution Loop ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--daemon", action="store_true", help="Enable Real-time FIM & Background Monitoring")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Must be run as root to access /etc/shadow, /proc, and systemd dirs.")
        sys.exit(1)

    hunter = SystemHunter(verbose=args.verbose)

    if args.daemon:
        hunter.logger.info("Initializing Real-time Monitor (Daemon Mode)...")
        
        # Setup FIM
        observer = Observer()
        handler = FIMHandler(hunter)
        
        # Watch sensitive directories
        watched_dirs = SENSITIVE_TARGETS["persistence_dirs"] + ["/etc", "/boot"]
        for d in watched_dirs:
            if os.path.exists(d):
                observer.schedule(handler, d, recursive=True)
        
        observer.start()
        
        try:
            while True:
                hunter.run_full_scan()
                time.sleep(300) # Full scan every 5 minutes in daemon mode
        except KeyboardInterrupt:
            observer.stop()
            hunter.logger.info("Shutting down...")
        observer.join()
    else:
        hunter.run_full_scan()

if __name__ == "__main__":
    main()
