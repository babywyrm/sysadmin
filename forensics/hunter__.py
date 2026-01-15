#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import argparse
import signal
import platform
import psutil
import hashlib
import socket
from datetime import datetime
from pathlib import Path

# --- Configuration & Constants ---
VERSION = "3.0.0"
DEFAULT_LOG_DIR = "/var/log/hunter"
DEFAULT_INTERVAL = 60  # Seconds between scans when daemonized

# --- Threat Patterns ---
THREAT_DB = {
    "suspicious_cmds": [
        "nc -e", "bash -i", "python -c", "perl -e", "socat exec",
        "curl http", "wget http", "xmrig", "minergate"
    ],
    "sensitive_files": [
        "/etc/shadow", "/etc/passwd", "/root/.ssh/authorized_keys",
        "/home/*/.ssh/authorized_keys", "/etc/sudoers"
    ],
    "backdoor_ports": [31337, 4444, 5555, 6666, 1337]
}

class SystemHunter:
    def __init__(self, log_dir=DEFAULT_LOG_DIR, verbose=False):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.findings = []
        
        self._setup_logging()
        
    def _setup_logging(self):
        log_file = self.log_dir / "hunter.log"
        level = logging.DEBUG if self.verbose else logging.INFO
        
        logging.basicConfig(
            level=level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("Hunter")

    def get_file_hash(self, path):
        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def record_finding(self, category, severity, message, details=None):
        finding = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "severity": severity,
            "message": message,
            "details": details or {}
        }
        self.findings.append(finding)
        log_func = self.logger.error if severity in ["CRITICAL", "HIGH"] else self.logger.warning
        log_func(f"[{severity}] {category}: {message}")

    # --- Scanning Engines ---

    def check_processes(self):
        """Analyze running processes for malicious indicators."""
        self.logger.info("Scanning processes...")
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'exe']):
            try:
                pinfo = proc.info
                cmdline = " ".join(pinfo['cmdline']) if pinfo['cmdline'] else ""
                
                # Check suspicious command lines
                for pattern in THREAT_DB["suspicious_cmds"]:
                    if pattern in cmdline.lower():
                        self.record_finding("PROCESS", "HIGH", 
                            f"Suspicious cmdline in PID {pinfo['pid']}", 
                            {"cmd": cmdline, "user": pinfo['username']})

                # Check for deleted executables (common in fileless malware)
                if pinfo['exe'] and "(deleted)" in pinfo['exe']:
                    self.record_finding("PROCESS", "CRITICAL", 
                        f"Process executing from deleted file: PID {pinfo['pid']}", 
                        {"exe": pinfo['exe']})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def check_network(self):
        """Analyze network connections for backdoors."""
        self.logger.info("Scanning network connections...")
        for conn in psutil.net_connections(kind='inet'):
            lport = conn.laddr.port if conn.laddr else None
            
            # Check for known backdoor ports
            if lport in THREAT_DB["backdoor_ports"] and conn.status == "LISTEN":
                self.record_finding("NETWORK", "CRITICAL", 
                    f"Listening on known backdoor port: {lport}", 
                    {"pid": conn.pid})

    def check_persistence(self):
        """Check common persistence locations."""
        self.logger.info("Checking persistence locations...")
        # Check for SSH key changes
        ssh_keys = Path("/root/.ssh/authorized_keys")
        if ssh_keys.exists():
            mtime = datetime.fromtimestamp(ssh_keys.stat().st_mtime)
            if (datetime.now() - mtime).days < 1:
                self.record_finding("PERSISTENCE", "MEDIUM", 
                    "Root authorized_keys modified in last 24h", 
                    {"last_modified": mtime.isoformat()})

    def run_full_scan(self):
        self.findings = []
        start_time = time.time()
        
        self.check_processes()
        self.check_network()
        self.check_persistence()
        
        duration = time.time() - start_time
        self.logger.info(f"Scan complete. Duration: {duration:.2f}s. Findings: {len(self.findings)}")
        
        if self.findings:
            report_path = self.log_dir / f"report_{int(time.time())}.json"
            with open(report_path, "w") as f:
                json.dump(self.findings, f, indent=4)
            self.logger.info(f"Full report saved to {report_path}")

def daemonize(hunter, interval):
    """Run the hunter as a background daemon."""
    print(f"[*] Daemonizing Hunter (Interval: {interval}s)...")
    print(f"[*] Logs: {hunter.log_dir}/hunter.log")
    
    # Simple signal handling for clean exit
    def signal_handler(sig, frame):
        logging.info("Daemon stopping...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        try:
            hunter.run_full_scan()
            time.sleep(interval)
        except Exception as e:
            logging.error(f"Daemon Loop Error: {e}")
            time.sleep(10)

def main():
    parser = argparse.ArgumentParser(description=f"System Investigator v{VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-l", "--log-dir", default=DEFAULT_LOG_DIR, help="Where to store results")
    parser.add_argument("-d", "--daemon", action="store_true", help="Run as a daemon")
    parser.add_argument("-i", "--interval", type=int, default=DEFAULT_INTERVAL, help="Daemon scan interval")
    
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] This script must be run as root (to inspect processes/network)")
        sys.exit(1)

    hunter = SystemHunter(log_dir=args.log_dir, verbose=args.verbose)

    if args.daemon:
        daemonize(hunter, args.interval)
    else:
        hunter.run_full_scan()

if __name__ == "__main__":
    main()
