#!/usr/bin/env python3
"""
cursor-audit.py — Remote host security audit tool using Fabric.

Connects to a list of hosts and checks for:
  - Rogue/malicious processes
  - Backdoor files and executables
  - Suspicious TCP bindings
  - Unauthorized user accounts
  - Suspicious cron jobs
  - SSH key anomalies
  - SUID/SGID binaries
  - Recently modified system files

Usage:
    python audit.py [--hosts hosts.txt] [--output report.json] [--concurrency 5]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from fabric import Connection, Config
from termcolor import cprint

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

LEGITIMATE_PROCESSES = frozenset(["fail2ban", "unattended-upgrades", "up2date"])

ROGUE_PROCESSES = frozenset([
    "xmrig", "minerd", "cpuminer",           # miners
    "ngrok", "frp", "chisel",                # tunnels
    "netcat", "ncat", "socat",               # raw sockets
    "proxychains", "sshpass",                # proxy/auth abuse
    "reverse", "backconnect", "admin_panel", # generic backdoors
    "msfconsole", "msfvenom",                # metasploit
    "empire", "cobalt",                      # C2 frameworks
])

BACKDOOR_FILENAMES = frozenset([
    "backdoor", "evil.sh", "malicious.py",
    ".tmphack", ".hidden", "rootkit",
    "shell.php", "cmd.php", "r57.php", "c99.php",
])

SUSPICIOUS_PORTS = frozenset([
    4444,   # Metasploit default
    1337,   # common backdoor
    31337,  # "elite" backdoor
    9999,   # common C2
    12345,  # common backdoor
    8888,   # Jupyter (if unexpected)
])

KNOWN_SYSTEM_USERS = frozenset([
    "ubuntu", "ec2-user", "admin", "debian",
    "centos", "fedora", "vagrant",
])

SENSITIVE_DIRS = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"]

FABRIC_CONFIG = Config(overrides={"run": {"warn": True, "hide": True}})

# ------------------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------------------

@dataclass
class Finding:
    host: str
    check: str
    level: str  # INFO | WARN | ALERT
    message: str
    detail: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "check": self.check,
            "level": self.level,
            "message": self.message,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


@dataclass
class HostReport:
    host: str
    success: bool
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    duration_seconds: float = 0.0

    def add(self, check: str, level: str, message: str, detail: str = "") -> None:
        self.findings.append(Finding(
            host=self.host,
            check=check,
            level=level,
            message=message,
            detail=detail,
        ))

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "success": self.success,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 2),
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "alerts": sum(1 for f in self.findings if f.level == "ALERT"),
                "warnings": sum(1 for f in self.findings if f.level == "WARN"),
                "info": sum(1 for f in self.findings if f.level == "INFO"),
            },
        }

# ------------------------------------------------------------------------------
# Console output
# ------------------------------------------------------------------------------

LEVEL_COLORS = {
    "ALERT": "red",
    "WARN":  "yellow",
    "INFO":  "green",
}

def log_finding(finding: Finding) -> None:
    color = LEVEL_COLORS.get(finding.level, "white")
    label = f"[{finding.level:<5}]"
    cprint(f"  [{finding.host}] {label} [{finding.check}] {finding.message}", color)
    if finding.detail:
        cprint(f"           {finding.detail}", color, attrs=["dark"])


def print_section(host: str, title: str) -> None:
    cprint(f"\n  -- {host}: {title} --", "cyan", attrs=["bold"])

# ------------------------------------------------------------------------------
# Remote command helper
# ------------------------------------------------------------------------------

def remote(c: Connection, cmd: str) -> tuple[str, str, int]:
    """Run a remote command, returning (stdout, stderr, exit_code)."""
    result = c.run(cmd, warn=True, hide=True)
    return (
        result.stdout.strip(),
        result.stderr.strip(),
        result.return_code,
    )

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

def check_rogue_processes(c: Connection, report: HostReport) -> None:
    print_section(c.host, "Processes")
    stdout, _, _ = remote(c, "ps aux --no-headers")
    for line in stdout.splitlines():
        lower = line.lower()
        for name in ROGUE_PROCESSES:
            if name in lower and not any(legit in lower for legit in LEGITIMATE_PROCESSES):
                report.add(
                    check="processes",
                    level="ALERT",
                    message=f"Rogue process detected: {name}",
                    detail=line.strip(),
                )


def check_backdoor_files(c: Connection, report: HostReport) -> None:
    print_section(c.host, "Backdoor Files")

    # Known bad filenames
    for fname in BACKDOOR_FILENAMES:
        stdout, _, _ = remote(
            c, f"find / -xdev -type f -name '{fname}' 2>/dev/null"
        )
        for path in stdout.splitlines():
            report.add(
                check="backdoor_files",
                level="ALERT",
                message=f"Suspicious file found: {fname}",
                detail=path,
            )

    # Executables in world-writable/temp directories
    dirs = " ".join(SENSITIVE_DIRS)
    stdout, _, _ = remote(
        c, f"find {dirs} -type f -executable 2>/dev/null"
    )
    for path in stdout.splitlines():
        report.add(
            check="backdoor_files",
            level="WARN",
            message=f"Executable in sensitive directory",
            detail=path,
        )


def check_tcp_bindings(c: Connection, report: HostReport) -> None:
    print_section(c.host, "TCP Bindings")
    stdout, _, _ = remote(c, "ss -tulpen")
    for line in stdout.splitlines():
        for port in SUSPICIOUS_PORTS:
            if f":{port} " in line or f":{port}\t" in line:
                report.add(
                    check="tcp_bindings",
                    level="ALERT",
                    message=f"Suspicious port bound: {port}",
                    detail=line.strip(),
                )


def check_user_accounts(c: Connection, report: HostReport) -> None:
    print_section(c.host, "User Accounts")

    # Unexpected UID >= 1000 accounts
    stdout, _, _ = remote(
        c, "awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd"
    )
    for user in stdout.splitlines():
        if user not in KNOWN_SYSTEM_USERS:
            report.add(
                check="user_accounts",
                level="WARN",
                message=f"Unexpected user account: {user}",
            )

    # Accounts with UID 0 other than root
    stdout, _, _ = remote(
        c, "awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd"
    )
    for user in stdout.splitlines():
        report.add(
            check="user_accounts",
            level="ALERT",
            message=f"Non-root account with UID 0: {user}",
        )

    # Password-less accounts with a shell
    stdout, _, _ = remote(
        c,
        "awk -F: '($2 == \"\" || $2 == \"!\") && $7 !~ /nologin|false/ "
        "{print $1}' /etc/shadow",
    )
    for user in stdout.splitlines():
        report.add(
            check="user_accounts",
            level="ALERT",
            message=f"Account with no password and a valid shell: {user}",
        )


def check_ssh_keys(c: Connection, report: HostReport) -> None:
    print_section(c.host, "SSH Keys")
    stdout, _, _ = remote(
        c, "awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd"
    )
    for user in stdout.splitlines():
        key_stdout, _, rc = remote(
            c, f"cat /home/{user}/.ssh/authorized_keys 2>/dev/null"
        )
        if rc == 0 and key_stdout:
            key_count = len([
                l for l in key_stdout.splitlines() if l.strip() and not l.startswith("#")
            ])
            report.add(
                check="ssh_keys",
                level="WARN",
                message=f"User '{user}' has {key_count} authorized SSH key(s)",
            )


def check_cron_jobs(c: Connection, report: HostReport) -> None:
    print_section(c.host, "Cron Jobs")

    # Per-user crontabs
    stdout, _, _ = remote(
        c,
        "for user in $(cut -f1 -d: /etc/passwd); do "
        "  crontab -l -u $user 2>/dev/null | grep -v '^#' | grep -v '^$' "
        "  | sed \"s/^/$user: /\"; "
        "done",
    )
    for line in stdout.splitlines():
        report.add(
            check="cron_jobs",
            level="WARN",
            message="Active crontab entry found",
            detail=line.strip(),
        )

    # System-wide cron directories
    stdout, _, _ = remote(
        c,
        "find /etc/cron* /etc/cron.d /var/spool/cron -type f 2>/dev/null "
        "| xargs grep -l '.' 2>/dev/null",
    )
    for path in stdout.splitlines():
        report.add(
            check="cron_jobs",
            level="INFO",
            message="System cron file present",
            detail=path,
        )


def check_suid_sgid(c: Connection, report: HostReport) -> None:
    print_section(c.host, "SUID/SGID Binaries")
    stdout, _, _ = remote(
        c,
        "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) "
        "-not -path '/proc/*' 2>/dev/null",
    )
    known_suid = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/bin/su",
        "/bin/mount", "/bin/umount", "/usr/bin/chfn", "/usr/bin/chsh",
    }
    for path in stdout.splitlines():
        level = "INFO" if path.strip() in known_suid else "WARN"
        report.add(
            check="suid_sgid",
            level=level,
            message=f"{'Known' if level == 'INFO' else 'Unexpected'} SUID/SGID binary",
            detail=path.strip(),
        )


def check_recently_modified_system_files(c: Connection, report: HostReport) -> None:
    print_section(c.host, "Recently Modified System Files")
    stdout, _, _ = remote(
        c,
        "find /etc /bin /sbin /usr/bin /usr/sbin -xdev -type f "
        "-mtime -7 2>/dev/null",
    )
    for path in stdout.splitlines():
        report.add(
            check="modified_system_files",
            level="WARN",
            message="System file modified in the last 7 days",
            detail=path.strip(),
        )

# ------------------------------------------------------------------------------
# All checks in order
# ------------------------------------------------------------------------------

CHECKS: list[Callable[[Connection, HostReport], None]] = [
    check_rogue_processes,
    check_backdoor_files,
    check_tcp_bindings,
    check_user_accounts,
    check_ssh_keys,
    check_cron_jobs,
    check_suid_sgid,
    check_recently_modified_system_files,
]

# ------------------------------------------------------------------------------
# Per-host audit
# ------------------------------------------------------------------------------

def audit_host(host: str) -> HostReport:
    report = HostReport(host=host, success=False)
    start = datetime.now(timezone.utc)

    try:
        c = Connection(host, config=FABRIC_CONFIG)
        report.success = True
        cprint(f"\n[{host}] Connected", "cyan", attrs=["bold"])

        for check_fn in CHECKS:
            try:
                check_fn(c, report)
            except Exception as e:
                report.add(
                    check=check_fn.__name__,
                    level="WARN",
                    message=f"Check failed: {e}",
                )

        for finding in report.findings:
            log_finding(finding)

    except Exception as e:
        report.error = str(e)
        cprint(f"\n[{host}] Connection failed: {e}", "red")

    finally:
        report.duration_seconds = (
            datetime.now(timezone.utc) - start
        ).total_seconds()

    return report

# ------------------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------------------

def write_json_report(reports: list[HostReport], path: str) -> None:
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts_audited": len(reports),
        "hosts_failed": sum(1 for r in reports if not r.success),
        "total_alerts": sum(
            f.level == "ALERT"
            for r in reports
            for f in r.findings
        ),
        "total_warnings": sum(
            f.level == "WARN"
            for r in reports
            for f in r.findings
        ),
        "reports": [r.to_dict() for r in reports],
    }
    Path(path).write_text(json.dumps(output, indent=2))
    cprint(f"\nReport written to: {path}", "cyan")


def print_summary(reports: list[HostReport]) -> None:
    cprint(
        "\n====================================================================",
        "cyan", attrs=["bold"],
    )
    cprint("  Audit Summary", "cyan", attrs=["bold"])
    cprint(
        "====================================================================",
        "cyan", attrs=["bold"],
    )
    for r in reports:
        alerts   = sum(1 for f in r.findings if f.level == "ALERT")
        warnings = sum(1 for f in r.findings if f.level == "WARN")
        status   = "FAILED" if not r.success else (
            "CLEAN" if alerts == 0 and warnings == 0 else "FINDINGS"
        )
        color = "red" if status in ("FAILED", "FINDINGS") else "green"
        cprint(
            f"  {r.host:<30} {status:<10} "
            f"alerts={alerts}  warnings={warnings}  ({r.duration_seconds:.1f}s)",
            color,
        )

# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remote host security audit tool"
    )
    parser.add_argument(
        "--hosts",
        default="hosts",
        help="Path to newline-delimited hosts file (default: hosts)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON report to this file",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of hosts to audit in parallel (default: 5)",
    )
    parser.add_argument(
        "--checks",
        nargs="*",
        choices=[fn.__name__ for fn in CHECKS],
        help="Run only these specific checks (default: all)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Load hosts
    hosts_path = Path(args.hosts)
    if not hosts_path.exists():
        cprint(f"Hosts file not found: {hosts_path}", "red")
        sys.exit(1)

    hosts = [
        line.strip()
        for line in hosts_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not hosts:
        cprint("No hosts found in hosts file.", "red")
        sys.exit(1)

    # Optionally restrict which checks run
    if args.checks:
        check_names = set(args.checks)
        active_checks = [fn for fn in CHECKS if fn.__name__ in check_names]
        # Patch module-level list used by audit_host
        CHECKS.clear()
        CHECKS.extend(active_checks)

    cprint(f"\nAuditing {len(hosts)} host(s) with concurrency={args.concurrency}", "cyan")

    # Run audits in parallel
    reports: list[HostReport] = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(audit_host, host): host for host in hosts}
        for future in as_completed(futures):
            reports.append(future.result())

    print_summary(reports)

    if args.output:
        write_json_report(reports, args.output)


if __name__ == "__main__":
    main()
