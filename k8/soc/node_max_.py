#!/usr/bin/env python3
"""
k8s-triage — Kubernetes Node Persistence & Compromise Triage Tool
==================================================================
Collects forensic exhibits from EKS / vanilla k8s nodes.
Designed for use during incident response or red team debriefs.

Targets:
  - Node-level OS artifacts (cron, users, SUID, rc files, etc.)
  - Kubernetes-specific artifacts (pods, service accounts, secrets, RBAC)
  - Container runtime artifacts (Docker / containerd)
  - Network indicators
  - Log artifacts

Usage:
    # Full triage (requires kubectl + node access)
    python3 k8s_triage.py --all --output ./triage_out

    # K8s API checks only (no node shell needed)
    python3 k8s_triage.py --k8s-only --namespace kube-system

    # Node OS checks only (run directly on the node)
    python3 k8s_triage.py --node-only

    # Specific checks
    python3 k8s_triage.py --check cron --check suid --check network

Requirements:
    pip install kubernetes rich
    kubectl configured with appropriate context (for k8s checks)

Notes:
  - This tool is read-only by design.
  - Secret *data* is NOT collected by default (metadata only). Use --include-secret-data to include data.
"""

from __future__ import annotations

import argparse
import datetime
import grp
import hashlib
import json
import os
import platform
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

# ----------------------------
# Optional dependencies
# ----------------------------

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    client = None  # type: ignore
    config = None  # type: ignore
    ApiException = Exception  # type: ignore

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import print as rprint

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None  # type: ignore


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_COLORS: dict[Severity, str] = {
    Severity.INFO: "cyan",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.INFO: "ℹ️ ",
    Severity.LOW: "🟢",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🔴",
    Severity.CRITICAL: "💀",
}


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    mitre: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class TriageResult:
    node: str
    timestamp: str
    findings: list[Finding] = field(default_factory=list)
    exhibits: dict[str, str] = field(default_factory=dict)  # label -> content

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_exhibit(self, label: str, content: str) -> None:
        # avoid accidental huge memory blowups
        if content is None:
            return
        self.exhibits[label] = content

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


# ---------------------------------------------------------------------------
# Output / reporting
# ---------------------------------------------------------------------------

def print_banner() -> None:
    banner = """
██╗  ██╗ █████╗ ███████╗    ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗
██║ ██╔╝██╔══██╗██╔════╝    ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
█████╔╝ ╚█████╔╝███████╗       ██║   ██████╔╝██║███████║██║  ███╗█████╗
██╔═██╗ ██╔══██╗╚════██║       ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝
██║  ██╗╚█████╔╝███████║       ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝ ╚════╝ ╚══════╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

k8s Node Persistence & Compromise Triage Tool
"""
    if RICH_AVAILABLE:
        console.print(Panel(banner, style="bold blue"))  # type: ignore[union-attr]
    else:
        print(banner)


def section(title: str) -> None:
    if RICH_AVAILABLE:
        console.rule(f"[bold cyan]{title}[/bold cyan]")  # type: ignore[union-attr]
    else:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")


def emit(
    result: TriageResult,
    check: str,
    severity: Severity,
    title: str,
    detail: str,
    evidence: Optional[list[str]] = None,
    mitre: Optional[str] = None,
    recommendation: Optional[str] = None,
    quiet: bool = False,
) -> None:
    finding = Finding(
        check=check,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence or [],
        mitre=mitre,
        recommendation=recommendation,
    )
    result.add_finding(finding)

    if quiet:
        return

    if RICH_AVAILABLE:
        color = SEVERITY_COLORS[severity]
        emoji = SEVERITY_EMOJI[severity]
        console.print(f"  {emoji}  [{color}][{severity.upper()}][/{color}] {title}")  # type: ignore[union-attr]
        if detail:
            console.print(f"       [dim]{detail}[/dim]")  # type: ignore[union-attr]
        if evidence:
            for e in (evidence or [])[:5]:
                console.print(f"       [dim white]  → {e.strip()}[/dim white]")  # type: ignore[union-attr]
            if len(evidence or []) > 5:
                console.print(f"       [dim]  ... and {len(evidence or []) - 5} more (see report)[/dim]")  # type: ignore[union-attr]
    else:
        print(f"  [{severity.upper()}] {title}")
        print(f"    {detail}")
        for e in evidence or []:
            print(f"    → {e.strip()}")


def render_summary_table(result: TriageResult) -> None:
    if not RICH_AVAILABLE:
        return

    counts = result.summary()
    tbl = Table(title="Triage Summary", show_header=True, header_style="bold magenta")
    tbl.add_column("Severity", style="bold")
    tbl.add_column("Count", justify="right")

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        tbl.add_row(sev.value, str(counts.get(sev.value, 0)))

    console.print(tbl)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def run_cmd(
    cmd: str | list[str],
    timeout: int = 30,
    shell: bool = False,
) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"[timeout after {timeout}s]", 1
    except FileNotFoundError:
        return "", f"[command not found: {cmd}]", 127
    except OSError as e:
        return "", str(e), 1


def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def is_root() -> bool:
    return os.geteuid() == 0


def get_node_name() -> str:
    return socket.gethostname()


def now_utc_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def safe_read_text(path: Path, max_bytes: int = 2_000_000) -> Optional[str]:
    try:
        if not path.exists() or not path.is_file():
            return None
        # cap reads
        data = path.read_bytes()
        if len(data) > max_bytes:
            data = data[:max_bytes] + b"\n\n[TRUNCATED]\n"
        return data.decode(errors="replace")
    except OSError:
        return None


def mkdirp(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    mkdirp(path.parent)
    path.write_text(content, errors="replace")


def sanitize_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-+=" else "_" for c in s)


# ---------------------------------------------------------------------------
# Node OS checks
# ---------------------------------------------------------------------------

def check_cron(result: TriageResult, quiet: bool = False) -> None:
    section("Scheduled Tasks — Cron & Systemd Timers")

    cron_paths = [
        Path("/etc/crontab"),
        *Path("/etc/cron.d").glob("*"),
        *Path("/etc/cron.hourly").glob("*"),
        *Path("/etc/cron.daily").glob("*"),
        *Path("/etc/cron.weekly").glob("*"),
        *Path("/etc/cron.monthly").glob("*"),
    ]

    suspicious_kw = [
        "/dev/tcp",
        "ncat",
        "netcat",
        "nc ",
        "bash -i",
        "python",
        "socat",
        "curl",
        "wget",
        "base64",
    ]

    for p in cron_paths:
        if p.is_file():
            content = safe_read_text(p) or ""
            if not content:
                continue
            result.add_exhibit(f"cron:{p}", content)

            suspicious = [
                ln
                for ln in content.splitlines()
                if any(kw in ln for kw in suspicious_kw) and not ln.strip().startswith("#")
            ]
            if suspicious:
                emit(
                    result,
                    "cron",
                    Severity.CRITICAL,
                    f"Suspicious cron entry in {p}",
                    "Cron entry contains network/shell callback indicators",
                    evidence=suspicious,
                    mitre="T1053.003",
                    recommendation="Remove entry and investigate associated binary/script",
                    quiet=quiet,
                )
            else:
                emit(
                    result,
                    "cron",
                    Severity.INFO,
                    f"Cron file present: {p}",
                    f"{len(content.splitlines())} lines",
                    quiet=quiet,
                )

    # User crontabs (Debian/Ubuntu path)
    stdout, _, _ = run_cmd(["ls", "/var/spool/cron/crontabs"], shell=False)
    for user in stdout.splitlines():
        user = user.strip()
        cron_file = Path(f"/var/spool/cron/crontabs/{user}")
        if cron_file.exists():
            content = safe_read_text(cron_file) or ""
            if not content:
                continue
            result.add_exhibit(f"usercron:{user}", content)
            emit(
                result,
                "cron",
                Severity.INFO,
                f"User crontab exists: {user}",
                content[:200].replace("\n", "\\n"),
                quiet=quiet,
            )

    # Systemd timers
    stdout, _, rc = run_cmd(["systemctl", "list-timers", "--all", "--no-pager"])
    if rc == 0 and stdout.strip():
        result.add_exhibit("systemd:timers", stdout)
        emit(result, "cron", Severity.INFO, "Systemd timers collected", "See exhibit systemd:timers", quiet=quiet)

    # Systemd unit files
    unit_dirs = [Path("/etc/systemd/system"), Path("/lib/systemd/system")]
    unit_kw = ["/dev/tcp", "ncat", "bash -i", "python -c", "socat", "curl", "wget"]
    for d in unit_dirs:
        if not d.exists():
            continue
        for unit in d.glob("*.service"):
            content = safe_read_text(unit)
            if not content:
                continue
            suspicious_lines = [ln for ln in content.splitlines() if any(kw in ln for kw in unit_kw)]
            if suspicious_lines:
                emit(
                    result,
                    "cron",
                    Severity.CRITICAL,
                    f"Suspicious systemd unit: {unit.name}",
                    "Unit content contains network/shell callback indicators",
                    evidence=suspicious_lines,
                    mitre="T1543.002",
                    recommendation="Disable unit, investigate referenced binaries/scripts",
                    quiet=quiet,
                )


def check_users(result: TriageResult, quiet: bool = False) -> None:
    section("User Accounts & Privileges")

    uid0 = [p for p in pwd.getpwall() if p.pw_uid == 0]
    if len(uid0) > 1:
        emit(
            result,
            "users",
            Severity.CRITICAL,
            f"{len(uid0)} accounts with UID 0 detected",
            "Multiple root-equivalent accounts",
            evidence=[f"{p.pw_name} (shell: {p.pw_shell})" for p in uid0],
            mitre="T1136.001",
            recommendation="Investigate non-root UID 0 accounts immediately",
            quiet=quiet,
        )
    else:
        emit(result, "users", Severity.INFO, "UID 0 accounts: only root", "Expected", quiet=quiet)

    passwd_path = Path("/etc/passwd")
    if passwd_path.exists():
        content = safe_read_text(passwd_path) or ""
        if content:
            result.add_exhibit("users:passwd", content)
        try:
            mtime = datetime.datetime.fromtimestamp(passwd_path.stat().st_mtime)
            age_hours = (datetime.datetime.now() - mtime).total_seconds() / 3600
            if age_hours < 48:
                emit(
                    result,
                    "users",
                    Severity.HIGH,
                    f"/etc/passwd modified {age_hours:.1f} hours ago",
                    "Recent modification is suspicious on a stable node",
                    mitre="T1136.001",
                    recommendation="Diff against known-good baseline; inspect account adds/UID changes",
                    quiet=quiet,
                )
        except OSError:
            pass

    sudoers_paths = [Path("/etc/sudoers"), *Path("/etc/sudoers.d").glob("*")]
    for p in sudoers_paths:
        if p.is_file():
            content = safe_read_text(p) or ""
            if not content:
                continue
            result.add_exhibit(f"sudo:{p.name}", content)
            nopasswd = [ln for ln in content.splitlines() if "NOPASSWD" in ln and not ln.strip().startswith("#")]
            if nopasswd:
                emit(
                    result,
                    "users",
                    Severity.HIGH,
                    f"NOPASSWD sudo rules in {p.name}",
                    "Passwordless sudo can be used for persistence",
                    evidence=nopasswd,
                    mitre="T1548",
                    recommendation="Audit and remove unnecessary NOPASSWD rules",
                    quiet=quiet,
                )

    # authorized_keys
    for p in pwd.getpwall():
        ak_path = Path(p.pw_dir) / ".ssh" / "authorized_keys"
        if ak_path.exists():
            content = safe_read_text(ak_path) or ""
            if not content:
                continue
            keys = [ln for ln in content.splitlines() if ln.strip() and not ln.startswith("#")]
            result.add_exhibit(f"ssh:authorized_keys:{p.pw_name}", content)
            emit(
                result,
                "users",
                Severity.MEDIUM,
                f"SSH authorized_keys: {p.pw_name} ({len(keys)} key(s))",
                str(ak_path),
                evidence=keys[:25],
                mitre="T1098.004",
                recommendation="Verify all keys are authorized; rotate keys if suspicious",
                quiet=quiet,
            )


def check_suid(result: TriageResult, quiet: bool = False) -> None:
    section("SUID / SGID Binaries")

    known_suid: set[str] = {
        "/usr/bin/sudo",
        "/usr/bin/passwd",
        "/usr/bin/su",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/bin/ping",
        "/bin/su",
        "/bin/mount",
        "/bin/umount",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    }

    search_roots = [Path("/usr"), Path("/bin"), Path("/sbin"), Path("/var"), Path("/tmp"), Path("/dev/shm")]
    found_suid: list[str] = []

    for root in search_roots:
        if not root.exists():
            continue
        try:
            for f in root.rglob("*"):
                try:
                    if not f.is_file():
                        continue
                    mode = f.stat().st_mode
                    if mode & (stat.S_ISUID | stat.S_ISGID):
                        found_suid.append(str(f))
                        if str(f) not in known_suid:
                            try:
                                owner = pwd.getpwuid(f.stat().st_uid).pw_name
                            except KeyError:
                                owner = str(f.stat().st_uid)
                            sha = sha256_file(f)
                            emit(
                                result,
                                "suid",
                                Severity.HIGH,
                                f"Unexpected SUID/SGID binary: {f}",
                                f"owner={owner}  sha256={sha}",
                                mitre="T1548.001",
                                recommendation="Investigate origin; remove/quarantine if unauthorized",
                                quiet=quiet,
                            )
                except OSError:
                    pass
        except OSError:
            pass

    result.add_exhibit("suid:all_found", "\n".join(found_suid))
    emit(
        result,
        "suid",
        Severity.INFO,
        f"SUID/SGID scan complete — {len(found_suid)} binaries found",
        "See exhibit suid:all_found for full list",
        quiet=quiet,
    )


def check_shell_rc(result: TriageResult, quiet: bool = False) -> None:
    section("Shell RC / Profile Backdoors")

    rc_files = [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".config/fish/config.fish",
    ]

    suspicious_keywords = [
        "/dev/tcp",
        "ncat",
        "netcat",
        "nc ",
        "bash -i",
        "socat",
        "curl",
        "wget",
        "base64",
        "python -c",
        "perl -e",
        "ruby -e",
        "alias sudo",
        "LD_PRELOAD",
        "PROMPT_COMMAND",
    ]

    for p in pwd.getpwall():
        if not Path(p.pw_dir).exists():
            continue
        for rc in rc_files:
            rc_path = Path(p.pw_dir) / rc
            if rc_path.exists():
                content = safe_read_text(rc_path) or ""
                if not content:
                    continue
                result.add_exhibit(f"shellrc:{p.pw_name}:{rc}", content)
                hits = [
                    ln
                    for ln in content.splitlines()
                    if any(kw in ln for kw in suspicious_keywords) and not ln.strip().startswith("#")
                ]
                if hits:
                    emit(
                        result,
                        "shellrc",
                        Severity.HIGH,
                        f"Suspicious content in ~{p.pw_name}/{rc}",
                        "Shell RC file contains persistence indicators",
                        evidence=hits[:50],
                        mitre="T1546.004",
                        recommendation="Review RC file; remove malicious lines; rotate creds if needed",
                        quiet=quiet,
                    )
                else:
                    emit(
                        result,
                        "shellrc",
                        Severity.INFO,
                        f"RC file checked: ~{p.pw_name}/{rc}",
                        f"{len(content.splitlines())} lines — no obvious indicators",
                        quiet=quiet,
                    )


def check_network(result: TriageResult, quiet: bool = False) -> None:
    section("Network — Connections & Listeners")

    stdout, _, rc = run_cmd(["ss", "-tulpn"])
    if rc == 0 and stdout.strip():
        result.add_exhibit("network:listeners", stdout)
        emit(result, "network", Severity.INFO, "Active listeners collected", "See exhibit network:listeners", quiet=quiet)

        # Heuristic: flag unexpected listener ports
        allow_ports = {22, 80, 443, 2376, 2377, 6443, 10250, 10255, 179, 30000, 30001}
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[4]
            try:
                port = int(local_addr.split(":")[-1])
                if port not in allow_ports:
                    emit(
                        result,
                        "network",
                        Severity.MEDIUM,
                        f"Unexpected listener on port {port}",
                        line.strip(),
                        mitre="T1049",
                        recommendation="Identify process owning this port; validate against intended node services",
                        quiet=quiet,
                    )
            except (ValueError, IndexError):
                pass

    stdout, _, _ = run_cmd(["ss", "-tnp", "state", "established"])
    if stdout.strip():
        result.add_exhibit("network:established", stdout)
        emit(result, "network", Severity.INFO, "Established connections collected", "See exhibit network:established", quiet=quiet)

    hosts_path = Path("/etc/hosts")
    content = safe_read_text(hosts_path) or ""
    if content:
        result.add_exhibit("network:hosts", content)
        non_standard = [
            ln
            for ln in content.splitlines()
            if ln.strip()
            and not ln.startswith("#")
            and not any(ln.startswith(p) for p in ["127.", "::1", "fe80", "0.0.0.0"])
        ]
        if non_standard:
            emit(
                result,
                "network",
                Severity.MEDIUM,
                f"/etc/hosts has {len(non_standard)} non-loopback entries",
                "Could indicate DNS hijacking / host redirection",
                evidence=non_standard,
                mitre="T1565.001",
                recommendation="Validate entries; compare with baseline; check resolv.conf and DNS settings",
                quiet=quiet,
            )

    stdout, _, rc = run_cmd(["iptables", "-S"])
    if rc == 0 and stdout.strip():
        result.add_exhibit("network:iptables_rules", stdout)


def check_processes(result: TriageResult, quiet: bool = False) -> None:
    section("Running Processes")

    stdout, _, rc = run_cmd(["ps", "auxf"])
    if rc == 0 and stdout.strip():
        result.add_exhibit("processes:ps_auxf", stdout)

    suspicious_patterns = [
        "ncat", "netcat", " nc ", "socat", "/dev/tcp",
        "meterpreter", "metasploit", "cobalt", "beacon",
        "mimikatz", "bloodhound", "chisel", "ligolo",
        "bash -i", "python -c", "perl -e",
    ]
    stdout, _, _ = run_cmd(["ps", "-eo", "pid,user,cmd"])
    hits: list[str] = []
    for line in stdout.splitlines():
        lower = line.lower()
        if any(pat in lower for pat in suspicious_patterns):
            hits.append(line.strip())

    if hits:
        emit(
            result,
            "processes",
            Severity.CRITICAL,
            "Suspicious process patterns detected",
            "One or more running processes match common C2/lateral movement indicators",
            evidence=hits[:200],
            mitre="T1059",
            recommendation="Verify legitimacy; capture process tree; consider containment",
            quiet=quiet,
        )
    else:
        emit(result, "processes", Severity.INFO, "Process scan complete", "No obvious suspicious patterns", quiet=quiet)


def check_motd_and_init(result: TriageResult, quiet: bool = False) -> None:
    section("MOTD & Init Scripts")

    motd_dir = Path("/etc/update-motd.d")
    if motd_dir.exists():
        for f in sorted(motd_dir.iterdir()):
            if f.is_file():
                content = safe_read_text(f) or ""
                if not content:
                    continue
                result.add_exhibit(f"motd:{f.name}", content)
                hits = [
                    ln
                    for ln in content.splitlines()
                    if any(kw in ln for kw in ["/dev/tcp", "ncat", "bash -i", "curl", "wget"])
                    and not ln.strip().startswith("#")
                ]
                if hits:
                    emit(
                        result,
                        "motd",
                        Severity.CRITICAL,
                        f"Suspicious MOTD script: {f.name}",
                        "MOTD contains network/shell callback indicators",
                        evidence=hits[:50],
                        mitre="T1546",
                        recommendation="Review and remediate MOTD scripts; confirm package ownership",
                        quiet=quiet,
                    )

    rc_local = Path("/etc/rc.local")
    content = safe_read_text(rc_local) or ""
    if content:
        result.add_exhibit("init:rc.local", content)
        emit(result, "init", Severity.INFO, "/etc/rc.local exists", "Review content in exhibit init:rc.local", quiet=quiet)


def check_udev(result: TriageResult, quiet: bool = False) -> None:
    section("udev Rules")

    rules_dir = Path("/etc/udev/rules.d")
    if rules_dir.exists():
        for f in sorted(rules_dir.iterdir()):
            if f.is_file():
                content = safe_read_text(f) or ""
                if not content:
                    continue
                result.add_exhibit(f"udev:{f.name}", content)
                hits = [ln for ln in content.splitlines() if "RUN+=" in ln]
                if hits:
                    emit(
                        result,
                        "udev",
                        Severity.HIGH,
                        f"udev rule with RUN+= in {f.name}",
                        "udev RUN+= executes commands on device events",
                        evidence=hits[:50],
                        mitre="T1546",
                        recommendation="Verify RUN+= commands are legitimate",
                        quiet=quiet,
                    )


def check_ld_preload(result: TriageResult, quiet: bool = False) -> None:
    section("LD_PRELOAD / Shared Library Hijacking")

    preload_path = Path("/etc/ld.so.preload")
    content = safe_read_text(preload_path) or ""
    if content.strip():
        emit(
            result,
            "ldpreload",
            Severity.CRITICAL,
            "/etc/ld.so.preload is populated",
            "Preloaded libraries affect ALL dynamic binaries on the system",
            evidence=content.splitlines(),
            mitre="T1574.006",
            recommendation="Verify each listed library is legitimate; compare with baseline",
            quiet=quiet,
        )
        result.add_exhibit("ldpreload:ld.so.preload", content)

    lib_dirs = [Path("/usr/lib"), Path("/lib")]
    recent: list[str] = []
    for d in lib_dirs:
        if not d.exists():
            continue
        for so in d.rglob("*.so*"):
            try:
                mtime = datetime.datetime.fromtimestamp(so.stat().st_mtime)
                age_days = (datetime.datetime.now() - mtime).total_seconds() / 86400
                if age_days < 7:
                    recent.append(f"{so} (mtime={mtime.isoformat()})")
            except OSError:
                pass

    if recent:
        emit(
            result,
            "ldpreload",
            Severity.MEDIUM,
            f"{len(recent)} recently modified shared libraries found",
            "Recent .so changes can indicate injection/hijacking",
            evidence=recent[:200],
            mitre="T1574.006",
            recommendation="Validate package ownership; compare hashes to golden AMI/base image",
            quiet=quiet,
        )
        result.add_exhibit("ldpreload:recent_shared_libs", "\n".join(recent))


def check_apt_hooks(result: TriageResult, quiet: bool = False) -> None:
    section("Package Manager Hooks")

    apt_conf_dir = Path("/etc/apt/apt.conf.d")
    if apt_conf_dir.exists():
        for f in sorted(apt_conf_dir.iterdir()):
            if f.is_file():
                content = safe_read_text(f) or ""
                if not content:
                    continue
                result.add_exhibit(f"apt:{f.name}", content)
                if "Pre-Invoke" in content or "Post-Invoke" in content:
                    emit(
                        result,
                        "pkgmgr",
                        Severity.HIGH,
                        f"APT invoke hook in {f.name}",
                        "Hook executes commands during apt operations",
                        evidence=[ln for ln in content.splitlines() if "Invoke" in ln][:50],
                        mitre="T1554",
                        recommendation="Verify hook commands are legitimate; remove malicious hooks",
                        quiet=quiet,
                    )


def check_git_config(result: TriageResult, quiet: bool = False) -> None:
    section("Git Backdoors")

    suspicious_git_keys = ["editor", "pager", "sshcommand", "hookspath"]
    hits_all: list[str] = []

    for p in pwd.getpwall():
        gitconfig = Path(p.pw_dir) / ".gitconfig"
        if gitconfig.exists():
            content = safe_read_text(gitconfig) or ""
            if not content:
                continue
            result.add_exhibit(f"git:config:{p.pw_name}", content)
            hits = [ln for ln in content.splitlines() if any(k in ln.lower() for k in suspicious_git_keys)]
            if hits:
                hits_all.extend([f"{p.pw_name}: {ln}" for ln in hits])

    if hits_all:
        emit(
            result,
            "git",
            Severity.MEDIUM,
            "Git config entries that can execute commands detected",
            "Review for malicious editor/pager/sshCommand/hooksPath",
            evidence=hits_all[:200],
            mitre="T1546",
            recommendation="Audit git config values for unexpected commands/paths",
            quiet=quiet,
        )
    else:
        emit(result, "git", Severity.INFO, "Git config scan complete", "No obvious executable-config indicators", quiet=quiet)


def check_kubelet_and_pki(result: TriageResult, quiet: bool = False) -> None:
    section("Kubernetes Node Credentials & Kubelet Config")

    interesting_paths = [
        Path("/etc/kubernetes"),
        Path("/var/lib/kubelet"),
        Path("/var/lib/kubelet/pki"),
        Path("/etc/systemd/system/kubelet.service.d"),
        Path("/etc/systemd/system/kubelet.service"),
        Path("/etc/kubelet.conf"),
    ]

    found: list[str] = []
    for p in interesting_paths:
        if p.exists():
            found.append(str(p))

    if found:
        emit(
            result,
            "kubelet",
            Severity.INFO,
            "Kubernetes node config paths present",
            "Collected directory listings (metadata only) and key config files when readable",
            evidence=found,
            quiet=quiet,
        )

    # capture kubelet args/systemd drop-in
    for p in [Path("/etc/systemd/system/kubelet.service"), Path("/etc/systemd/system/kubelet.service.d/10-kubeadm.conf")]:
        if p.exists() and p.is_file():
            content = safe_read_text(p) or ""
            if content:
                result.add_exhibit(f"kubelet:systemd:{p}", content)

    # kubelet config YAML (common path variants)
    for p in [Path("/var/lib/kubelet/config.yaml"), Path("/etc/kubernetes/kubelet.conf"), Path("/etc/kubernetes/admin.conf")]:
        content = safe_read_text(p)
        if content:
            # WARNING: kubeconfigs can contain certs. Still useful in IR; keep in exhibits.
            result.add_exhibit(f"kubelet:file:{p}", content)

    # list cert/key files (names + mtimes + sha256)
    pki_dir = Path("/var/lib/kubelet/pki")
    if pki_dir.exists():
        meta_lines: list[str] = []
        for f in sorted(pki_dir.glob("*")):
            try:
                if f.is_file():
                    st = f.stat()
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime).isoformat()
                    sha = sha256_file(f)
                    meta_lines.append(f"{f.name}\t{st.st_size}\tmtime={mtime}\tsha256={sha}")
            except OSError:
                pass
        if meta_lines:
            result.add_exhibit("kubelet:pki_metadata", "\n".join(meta_lines))
            # heuristically flag very recent cert changes
            recent = [ln for ln in meta_lines if "mtime=" in ln]
            if recent:
                emit(
                    result,
                    "kubelet",
                    Severity.LOW,
                    "Kubelet PKI metadata collected",
                    "Review for unexpected recent rotations on compromised nodes",
                    quiet=quiet,
                )


def check_container_runtime(result: TriageResult, quiet: bool = False) -> None:
    section("Container Runtime — Docker / containerd / crictl")

    # Sockets commonly used for breakout / lateral movement
    sockets = [
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
        Path("/run/containerd/containerd.sock"),
        Path("/var/run/containerd/containerd.sock"),
        Path("/run/crio/crio.sock"),
    ]
    present = [str(s) for s in sockets if s.exists()]
    if present:
        emit(
            result,
            "runtime",
            Severity.HIGH,
            "Container runtime sockets present on node",
            "If accessible to untrusted processes, sockets can lead to host takeover",
            evidence=present,
            mitre="T1611",
            recommendation="Restrict socket permissions; avoid mounting into pods; enforce least privilege",
            quiet=quiet,
        )

    # containerd config
    cfg = Path("/etc/containerd/config.toml")
    c = safe_read_text(cfg)
    if c:
        result.add_exhibit("runtime:containerd_config", c)

    # runtime process info
    stdout, _, _ = run_cmd(["ps", "-eo", "pid,user,cmd"])
    runtime_hits = [ln for ln in stdout.splitlines() if any(x in ln for x in ["containerd", "dockerd", "cri-o", "kubelet"])]
    if runtime_hits:
        result.add_exhibit("runtime:processes", "\n".join(runtime_hits[:2000]))

    # docker
    stdout, stderr, rc = run_cmd(["docker", "ps", "--no-trunc"], timeout=45)
    if rc == 0 and stdout.strip():
        result.add_exhibit("runtime:docker_ps", stdout)
    elif rc not in (0, 127) and stderr.strip():
        result.add_exhibit("runtime:docker_ps_err", stderr)

    # crictl
    stdout, stderr, rc = run_cmd(["crictl", "ps", "-a"], timeout=45)
    if rc == 0 and stdout.strip():
        result.add_exhibit("runtime:crictl_ps", stdout)
    elif rc not in (0, 127) and stderr.strip():
        result.add_exhibit("runtime:crictl_ps_err", stderr)

    stdout, stderr, rc = run_cmd(["crictl", "pods"], timeout=45)
    if rc == 0 and stdout.strip():
        result.add_exhibit("runtime:crictl_pods", stdout)
    elif rc not in (0, 127) and stderr.strip():
        result.add_exhibit("runtime:crictl_pods_err", stderr)

    emit(result, "runtime", Severity.INFO, "Runtime checks complete", "Collected what was available", quiet=quiet)


def check_logs(result: TriageResult, quiet: bool = False) -> None:
    section("Logs — journald / syslog (best effort)")

    # journald snapshots (small time range to avoid huge output)
    cmds = [
        (["journalctl", "-u", "kubelet", "--no-pager", "--since", "24 hours ago"], "logs:journald:kubelet_24h"),
        (["journalctl", "-u", "containerd", "--no-pager", "--since", "24 hours ago"], "logs:journald:containerd_24h"),
        (["journalctl", "-u", "sshd", "--no-pager", "--since", "24 hours ago"], "logs:journald:sshd_24h"),
    ]
    for cmd, label in cmds:
        stdout, stderr, rc = run_cmd(cmd, timeout=60)
        if rc == 0 and stdout.strip():
            result.add_exhibit(label, stdout)
        elif stderr.strip():
            result.add_exhibit(label + "_err", stderr)

    # syslog/auth.log
    for p in [Path("/var/log/auth.log"), Path("/var/log/secure"), Path("/var/log/syslog"), Path("/var/log/messages")]:
        c = safe_read_text(p, max_bytes=2_000_000)
        if c:
            result.add_exhibit(f"logs:file:{p}", c)

    emit(result, "logs", Severity.INFO, "Log collection complete", "Best-effort; availability varies by distro", quiet=quiet)


def check_filesystem_hotspots(result: TriageResult, quiet: bool = False) -> None:
    section("Filesystem Hotspots — tmp, /usr/local/bin, recent executables")

    # recent executable files in common drop locations
    hotspots = [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), Path("/usr/local/bin"), Path("/opt")]
    recent_exec: list[str] = []
    cutoff = datetime.datetime.now() - datetime.timedelta(days=2)

    for root in hotspots:
        if not root.exists():
            continue
        try:
            for f in root.rglob("*"):
                try:
                    if not f.is_file():
                        continue
                    st = f.stat()
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime)
                    if mtime < cutoff:
                        continue
                    # executable bit
                    if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                        sha = sha256_file(f)
                        recent_exec.append(f"{f}\tmtime={mtime.isoformat()}\tsha256={sha}")
                except OSError:
                    pass
        except OSError:
            pass

    if recent_exec:
        emit(
            result,
            "fs",
            Severity.HIGH,
            f"{len(recent_exec)} recently modified executables in hotspots",
            "Common persistence drop locations had recent executable changes",
            evidence=recent_exec[:200],
            mitre="T1036",
            recommendation="Validate file provenance; compare with baseline; quarantine suspicious binaries",
            quiet=quiet,
        )
        result.add_exhibit("fs:recent_executables", "\n".join(recent_exec))
    else:
        emit(result, "fs", Severity.INFO, "Hotspot scan complete", "No recent executables found in key hotspots", quiet=quiet)


# ---------------------------------------------------------------------------
# Kubernetes API checks
# ---------------------------------------------------------------------------

def k8s_load_config(context: Optional[str] = None) -> tuple[bool, str]:
    if not K8S_AVAILABLE:
        return False, "kubernetes python client not installed"

    try:
        # Prefer kubeconfig; fall back to in-cluster
        if context:
            config.load_kube_config(context=context)
        else:
            config.load_kube_config()
        return True, "loaded kubeconfig"
    except Exception as e1:
        try:
            config.load_incluster_config()
            return True, "loaded in-cluster config"
        except Exception as e2:
            return False, f"could not load kubeconfig or incluster config: {e1} / {e2}"


def check_k8s_privileged_pods(result: TriageResult, v1: Any, namespace: str, quiet: bool = False) -> None:
    section("K8s — Privileged / HostPath Pods")

    try:
        pods = v1.list_namespaced_pod(namespace) if namespace != "all" else v1.list_pod_for_all_namespaces()
        items = pods.items

        for pod in items:
            ns = pod.metadata.namespace
            name = pod.metadata.name

            # Container security context checks
            for container in (pod.spec.containers or []):
                sc = container.security_context
                if sc:
                    if getattr(sc, "privileged", False):
                        emit(
                            result,
                            "k8s_pods",
                            Severity.CRITICAL,
                            f"Privileged container: {ns}/{name}/{container.name}",
                            "Privileged containers can escape to the host",
                            mitre="T1611",
                            recommendation="Remove privileged flag unless absolutely required",
                            quiet=quiet,
                        )
                    if getattr(sc, "run_as_user", None) == 0:
                        emit(
                            result,
                            "k8s_pods",
                            Severity.HIGH,
                            f"Container running as root: {ns}/{name}/{container.name}",
                            "runAsUser: 0",
                            mitre="T1611",
                            recommendation="Set runAsNonRoot + non-zero runAsUser where possible",
                            quiet=quiet,
                        )
                    if getattr(sc, "allow_privilege_escalation", False):
                        emit(
                            result,
                            "k8s_pods",
                            Severity.HIGH,
                            f"allowPrivilegeEscalation=true: {ns}/{name}/{container.name}",
                            "Container can gain more privileges than parent process",
                            mitre="T1548",
                            recommendation="Set allowPrivilegeEscalation=false",
                            quiet=quiet,
                        )

            # HostPath volumes
            for vol in (pod.spec.volumes or []):
                if getattr(vol, "host_path", None):
                    path = vol.host_path.path
                    severity = Severity.CRITICAL if path in ("/", "/etc", "/var/run", "/proc", "/sys") else Severity.HIGH
                    emit(
                        result,
                        "k8s_pods",
                        severity,
                        f"HostPath volume in {ns}/{name}: {path}",
                        "HostPath mounts can expose sensitive host files",
                        mitre="T1611",
                        recommendation="Restrict HostPath usage via PodSecurityAdmission / policies",
                        quiet=quiet,
                    )

            if getattr(pod.spec, "host_network", False):
                emit(
                    result,
                    "k8s_pods",
                    Severity.HIGH,
                    f"hostNetwork=true: {ns}/{name}",
                    "Pod shares host network namespace",
                    mitre="T1611",
                    recommendation="Avoid hostNetwork unless required; enforce policy",
                    quiet=quiet,
                )
            if getattr(pod.spec, "host_pid", False):
                emit(
                    result,
                    "k8s_pods",
                    Severity.CRITICAL,
                    f"hostPID=true: {ns}/{name}",
                    "Pod can see and signal all host processes",
                    mitre="T1611",
                    recommendation="Disallow hostPID except tightly controlled components",
                    quiet=quiet,
                )

        emit(result, "k8s_pods", Severity.INFO, "Pod posture scan complete", f"Pods scanned in namespace={namespace}", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_pods", Severity.INFO, "Could not list pods", str(e), quiet=quiet)


def _rule_is_dangerous(rule: Any) -> tuple[bool, list[str]]:
    # Best-effort evaluation of PolicyRules
    dangerous_verbs = {"*", "escalate", "bind", "impersonate"}
    dangerous_resources = {"*", "secrets", "nodes", "pods/exec", "clusterrolebindings", "rolebindings"}
    hits: list[str] = []

    verbs = set(getattr(rule, "verbs", []) or [])
    resources = set(getattr(rule, "resources", []) or [])
    api_groups = set(getattr(rule, "api_groups", []) or [])

    if verbs & dangerous_verbs:
        hits.append(f"verbs={sorted(list(verbs & dangerous_verbs))}")
    if resources & dangerous_resources:
        hits.append(f"resources={sorted(list(resources & dangerous_resources))}")
    if "*" in verbs and "*" in resources:
        hits.append("wildcard-admin=*/*")

    # Extra: secrets in core group is very common privilege escalation target
    if "secrets" in resources and ("" in api_groups or "core" in api_groups):
        hits.append("secrets-core-group")

    return (len(hits) > 0), hits


def check_k8s_rbac(result: TriageResult, rbac: Any, namespace: str, quiet: bool = False) -> None:
    section("K8s — RBAC: Overprivileged Roles & Bindings")

    try:
        # ClusterRoles
        cr_list = rbac.list_cluster_role()
        dangerous_roles: dict[str, list[str]] = {}

        for cr in cr_list.items:
            role_name = cr.metadata.name
            for rule in (cr.rules or []):
                is_bad, why = _rule_is_dangerous(rule)
                if is_bad:
                    dangerous_roles.setdefault(role_name, []).extend(why)

        if dangerous_roles:
            top = sorted(dangerous_roles.items(), key=lambda kv: len(kv[1]), reverse=True)
            emit(
                result,
                "k8s_rbac",
                Severity.HIGH,
                f"{len(dangerous_roles)} potentially dangerous ClusterRoles detected",
                "ClusterRoles with wildcard / sensitive verbs/resources can enable escalation",
                evidence=[f"{name}: {sorted(set(reasons))}" for name, reasons in top[:50]],
                mitre="T1068",
                recommendation="Review least-privilege; restrict secrets/nodes/exec; avoid wildcards",
                quiet=quiet,
            )
            result.add_exhibit("k8s:rbac:dangerous_clusterroles", json.dumps(dangerous_roles, indent=2))

        # ClusterRoleBindings
        crb_list = rbac.list_cluster_role_binding()
        risky_bindings: list[str] = []
        for b in crb_list.items:
            role_ref = getattr(b, "role_ref", None)
            role_name = getattr(role_ref, "name", "") if role_ref else ""
            subjects = getattr(b, "subjects", []) or []
            subj_str = []
            for s in subjects:
                kind = getattr(s, "kind", "")
                name = getattr(s, "name", "")
                ns = getattr(s, "namespace", "")
                subj_str.append(f"{kind}:{ns + '/' if ns else ''}{name}")

            # Heuristics: bindings to system:anonymous, system:authenticated, or any SA in kube-system
            subject_joined = ", ".join(subj_str)
            if any(x in subject_joined for x in ["system:anonymous", "system:authenticated", "system:unauthenticated"]):
                risky_bindings.append(f"{b.metadata.name} -> {role_name} [{subject_joined}]")
            if "kube-system/" in subject_joined and role_name in dangerous_roles:
                risky_bindings.append(f"{b.metadata.name} -> {role_name} [{subject_joined}]")

        if risky_bindings:
            emit(
                result,
                "k8s_rbac",
                Severity.CRITICAL,
                f"{len(risky_bindings)} risky ClusterRoleBindings detected",
                "Bindings grant powerful roles to broad or sensitive subjects",
                evidence=risky_bindings[:200],
                mitre="T1098",
                recommendation="Tighten subjects; avoid binding powerful roles broadly; audit kube-system bindings",
                quiet=quiet,
            )
            result.add_exhibit("k8s:rbac:risky_clusterrolebindings", "\n".join(risky_bindings))

        # Namespaced RoleBindings (optional)
        if namespace != "all":
            rbs = rbac.list_namespaced_role_binding(namespace)
            rb_lines: list[str] = []
            for b in rbs.items:
                role_ref = getattr(b, "role_ref", None)
                role_name = getattr(role_ref, "name", "") if role_ref else ""
                subjects = getattr(b, "subjects", []) or []
                subject_joined = ", ".join(
                    f"{getattr(s,'kind','')}:{getattr(s,'namespace','') + '/' if getattr(s,'namespace','') else ''}{getattr(s,'name','')}"
                    for s in subjects
                )
                rb_lines.append(f"{namespace}/{b.metadata.name} -> {role_name} [{subject_joined}]")
            if rb_lines:
                result.add_exhibit(f"k8s:rbac:rolebindings:{namespace}", "\n".join(rb_lines))

        emit(result, "k8s_rbac", Severity.INFO, "RBAC checks complete", f"namespace={namespace}", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_rbac", Severity.INFO, "Could not read RBAC objects", str(e), quiet=quiet)


def check_k8s_service_accounts(result: TriageResult, v1: Any, namespace: str, quiet: bool = False) -> None:
    section("K8s — ServiceAccounts & Token Mounting")

    try:
        sas = v1.list_namespaced_service_account(namespace) if namespace != "all" else v1.list_service_account_for_all_namespaces()
        lines: list[str] = []
        risky: list[str] = []

        for sa in sas.items:
            ns = sa.metadata.namespace
            name = sa.metadata.name
            automount = getattr(sa, "automount_service_account_token", None)
            ips = getattr(sa, "image_pull_secrets", []) or []
            ip_names = [getattr(x, "name", "") for x in ips if getattr(x, "name", "")]
            lines.append(f"{ns}/{name}\tautomount={automount}\timagePullSecrets={ip_names}")

            if automount is True:
                risky.append(f"{ns}/{name} automountServiceAccountToken=true")
            if ns == "kube-system" and name not in ("default",):
                # kube-system SAs often are powerful; highlight for review
                risky.append(f"{ns}/{name} (kube-system SA)")

        result.add_exhibit("k8s:serviceaccounts", "\n".join(lines))

        if risky:
            emit(
                result,
                "k8s_sa",
                Severity.MEDIUM,
                f"{len(risky)} ServiceAccounts to review",
                "Automounting tokens or kube-system SAs may enable lateral movement if compromised",
                evidence=risky[:200],
                mitre="T1552",
                recommendation="Disable automount where not needed; scope RBAC; use IRSA on EKS",
                quiet=quiet,
            )
        else:
            emit(result, "k8s_sa", Severity.INFO, "ServiceAccount scan complete", "No obvious SA token-mount risks detected", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_sa", Severity.INFO, "Could not list service accounts", str(e), quiet=quiet)


def check_k8s_secrets(result: TriageResult, v1: Any, namespace: str, include_secret_data: bool, quiet: bool = False) -> None:
    section("K8s — Secrets (metadata by default)")

    try:
        secrets = v1.list_namespaced_secret(namespace) if namespace != "all" else v1.list_secret_for_all_namespaces()
        meta: list[dict[str, Any]] = []
        risky: list[str] = []

        for s in secrets.items:
            ns = s.metadata.namespace
            name = s.metadata.name
            stype = s.type or ""
            keys = sorted(list((s.data or {}).keys())) if getattr(s, "data", None) else []
            meta.append(
                {
                    "namespace": ns,
                    "name": name,
                    "type": stype,
                    "keys": keys,
                    "labels": s.metadata.labels or {},
                    "annotations": s.metadata.annotations or {},
                }
            )

            if stype in ("kubernetes.io/service-account-token",):
                risky.append(f"{ns}/{name} type={stype} (SA token)")
            if stype in ("kubernetes.io/dockerconfigjson", "kubernetes.io/basic-auth", "kubernetes.io/ssh-auth"):
                risky.append(f"{ns}/{name} type={stype} (credentials)")
            if "bootstrap.kubernetes.io/token" in (s.metadata.name or ""):
                risky.append(f"{ns}/{name} (bootstrap token?)")
            if ns == "kube-system" and stype not in ("kubernetes.io/service-account-token",):
                risky.append(f"{ns}/{name} type={stype} (kube-system secret)")

            if include_secret_data:
                # WARNING: this is sensitive; still sometimes needed in IR.
                # The API returns base64-encoded values; we keep as-is.
                if getattr(s, "data", None):
                    result.add_exhibit(f"k8s:secretdata:{ns}/{name}", json.dumps(s.data, indent=2))

        result.add_exhibit("k8s:secrets:metadata", json.dumps(meta, indent=2))

        if risky:
            emit(
                result,
                "k8s_secrets",
                Severity.HIGH,
                f"{len(risky)} notable secrets detected",
                "Secrets are common targets for credential theft and lateral movement",
                evidence=risky[:200],
                mitre="T1552.001",
                recommendation="Audit access; rotate credentials; prefer external secret stores; restrict RBAC",
                quiet=quiet,
            )
        else:
            emit(result, "k8s_secrets", Severity.INFO, "Secrets scan complete", "No obvious notable secrets flagged", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_secrets", Severity.INFO, "Could not list secrets", str(e), quiet=quiet)


def check_k8s_workloads(result: TriageResult, apps: Any, namespace: str, quiet: bool = False) -> None:
    section("K8s — Workloads: DaemonSets/Deployments posture (host access)")

    def flag_podspec(ns: str, owner: str, podspec: Any) -> None:
        # HostNetwork/HostPID
        if getattr(podspec, "host_network", False):
            emit(result, "k8s_workloads", Severity.HIGH, f"hostNetwork=true: {ns}/{owner}", "Workload shares host network", mitre="T1611", quiet=quiet)
        if getattr(podspec, "host_pid", False):
            emit(result, "k8s_workloads", Severity.CRITICAL, f"hostPID=true: {ns}/{owner}", "Workload shares host PID", mitre="T1611", quiet=quiet)

        # HostPath volumes
        for vol in (getattr(podspec, "volumes", None) or []):
            hp = getattr(vol, "host_path", None)
            if hp:
                path = hp.path
                sev = Severity.CRITICAL if path in ("/", "/etc", "/var/run", "/proc", "/sys") else Severity.HIGH
                emit(result, "k8s_workloads", sev, f"HostPath in {ns}/{owner}: {path}", "HostPath mount", mitre="T1611", quiet=quiet)

        # Privileged containers
        for c in (getattr(podspec, "containers", None) or []):
            sc = getattr(c, "security_context", None)
            if sc and getattr(sc, "privileged", False):
                emit(result, "k8s_workloads", Severity.CRITICAL, f"Privileged container in {ns}/{owner}: {c.name}", "privileged=true", mitre="T1611", quiet=quiet)

    try:
        if namespace == "all":
            dss = apps.list_daemon_set_for_all_namespaces().items
            deps = apps.list_deployment_for_all_namespaces().items
        else:
            dss = apps.list_namespaced_daemon_set(namespace).items
            deps = apps.list_namespaced_deployment(namespace).items

        # Save inventories
        ds_lines = [f"{ds.metadata.namespace}/{ds.metadata.name}" for ds in dss]
        dep_lines = [f"{dp.metadata.namespace}/{dp.metadata.name}" for dp in deps]
        result.add_exhibit("k8s:daemonsets", "\n".join(ds_lines))
        result.add_exhibit("k8s:deployments", "\n".join(dep_lines))

        for ds in dss:
            ns = ds.metadata.namespace
            owner = f"daemonset/{ds.metadata.name}"
            flag_podspec(ns, owner, ds.spec.template.spec)

        for dp in deps:
            ns = dp.metadata.namespace
            owner = f"deployment/{dp.metadata.name}"
            flag_podspec(ns, owner, dp.spec.template.spec)

        emit(result, "k8s_workloads", Severity.INFO, "Workload posture scan complete", f"namespace={namespace}", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_workloads", Severity.INFO, "Could not list workloads", str(e), quiet=quiet)


def check_k8s_events(result: TriageResult, v1: Any, namespace: str, quiet: bool = False) -> None:
    section("K8s — Events (recent signals)")

    try:
        # Events API moved in newer versions, but CoreV1 still works in many clusters
        if namespace == "all":
            ev = v1.list_event_for_all_namespaces()
        else:
            ev = v1.list_namespaced_event(namespace)
        items = ev.items

        lines: list[str] = []
        interesting: list[str] = []
        for e in items:
            ns = e.metadata.namespace
            reason = getattr(e, "reason", "")
            msg = getattr(e, "message", "")
            typ = getattr(e, "type", "")
            involved = getattr(e, "involved_object", None)
            obj = ""
            if involved:
                obj = f"{getattr(involved,'kind','')}/{getattr(involved,'name','')}"
            line = f"{ns}\t{typ}\t{reason}\t{obj}\t{msg}"
            lines.append(line)

            low = (reason or "").lower() + " " + (msg or "").lower()
            if any(k in low for k in ["failed", "back-off", "pull", "forbidden", "unauthorized", "denied", "oom", "kill", "node not ready"]):
                interesting.append(line)

        result.add_exhibit(f"k8s:events:{namespace}", "\n".join(lines[:5000]))

        if interesting:
            emit(
                result,
                "k8s_events",
                Severity.MEDIUM,
                f"{len(interesting)} notable events (signals/errors)",
                "Recent failures can highlight compromise, resource abuse, or policy blocks",
                evidence=interesting[:200],
                recommendation="Pivot on involved objects; check node logs and audit logs",
                quiet=quiet,
            )
        else:
            emit(result, "k8s_events", Severity.INFO, "Events collected", "No obvious error-heavy patterns detected", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_events", Severity.INFO, "Could not list events", str(e), quiet=quiet)


def check_k8s_nodes(result: TriageResult, v1: Any, quiet: bool = False) -> None:
    section("K8s — Nodes (conditions & taints)")

    try:
        nodes = v1.list_node().items
        lines: list[str] = []
        not_ready: list[str] = []

        for n in nodes:
            name = n.metadata.name
            conds = getattr(n.status, "conditions", []) or []
            cond_map = {c.type: c.status for c in conds if getattr(c, "type", None)}
            ready = cond_map.get("Ready", "Unknown")
            taints = getattr(n.spec, "taints", []) or []
            ta = [f"{t.key}={t.value}:{t.effect}" for t in taints if getattr(t, "key", None)]

            lines.append(f"{name}\tReady={ready}\ttaints={ta}")
            if ready != "True":
                not_ready.append(lines[-1])

        result.add_exhibit("k8s:nodes", "\n".join(lines))

        if not_ready:
            emit(
                result,
                "k8s_nodes",
                Severity.MEDIUM,
                f"{len(not_ready)} nodes not Ready",
                "Node instability can be caused by resource exhaustion or malicious activity",
                evidence=not_ready[:100],
                recommendation="Inspect kubelet/container runtime logs; check for OOMKills or disk pressure",
                quiet=quiet,
            )
        else:
            emit(result, "k8s_nodes", Severity.INFO, "Nodes collected", "All nodes Ready=True (at time of scan)", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_nodes", Severity.INFO, "Could not list nodes", str(e), quiet=quiet)


# ---------------------------------------------------------------------------
# Reporting / persistence
# ---------------------------------------------------------------------------

def serialize_result(result: TriageResult) -> dict[str, Any]:
    return {
        "node": result.node,
        "timestamp": result.timestamp,
        "summary": result.summary(),
        "findings": [
            {
                "check": f.check,
                "severity": f.severity.value,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "mitre": f.mitre,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
        "exhibits": result.exhibits,  # label -> content (may be large)
    }


def write_report_files(result: TriageResult, output_dir: Path, make_tar: bool = True, quiet: bool = False) -> tuple[Path, Optional[Path]]:
    mkdirp(output_dir)
    ts = result.timestamp.replace(":", "").replace("-", "").replace("Z", "Z")
    node = sanitize_filename(result.node)
    base = f"k8s-triage_{node}_{ts}"

    report_json = output_dir / f"{base}.json"
    report_md = output_dir / f"{base}.md"
    exhibits_dir = output_dir / f"{base}_exhibits"

    mkdirp(exhibits_dir)

    # Write exhibits as separate files (easier to browse than embedding in JSON only)
    index_lines: list[str] = []
    for label, content in sorted(result.exhibits.items()):
        fname = sanitize_filename(label) + ".txt"
        fpath = exhibits_dir / fname
        write_text(fpath, content)
        index_lines.append(f"- {label} -> {fname} ({len(content)} chars)")

    # JSON report (includes exhibits inline too)
    write_text(report_json, json.dumps(serialize_result(result), indent=2))

    # Markdown report (human-friendly)
    counts = result.summary()
    md_lines: list[str] = []
    md_lines.append(f"# k8s-triage Report\n")
    md_lines.append(f"- Node: `{result.node}`")
    md_lines.append(f"- Timestamp (UTC): `{result.timestamp}`\n")
    md_lines.append("## Summary\n")
    md_lines.append("| Severity | Count |")
    md_lines.append("|---|---:|")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        md_lines.append(f"| {sev.value} | {counts.get(sev.value, 0)} |")
    md_lines.append("\n## Findings\n")

    # Sort findings by severity
    sev_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    for f in sorted(result.findings, key=lambda x: sev_rank.get(x.severity, 99)):
        md_lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        md_lines.append(f"- Check: `{f.check}`")
        if f.mitre:
            md_lines.append(f"- MITRE: `{f.mitre}`")
        if f.recommendation:
            md_lines.append(f"- Recommendation: {f.recommendation}")
        if f.detail:
            md_lines.append(f"\n{f.detail}\n")
        if f.evidence:
            md_lines.append("**Evidence (truncated):**")
            md_lines.append("```text")
            md_lines.extend(f.evidence[:50])
            if len(f.evidence) > 50:
                md_lines.append(f"... ({len(f.evidence) - 50} more)")
            md_lines.append("```")
        md_lines.append("")

    md_lines.append("## Exhibits Index\n")
    md_lines.extend(index_lines)
    md_lines.append("\n> Full exhibit files are in the exhibits directory.\n")

    write_text(report_md, "\n".join(md_lines))

    tar_path: Optional[Path] = None
    if make_tar:
        tar_path = output_dir / f"{base}.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(report_json, arcname=report_json.name)
            tf.add(report_md, arcname=report_md.name)
            tf.add(exhibits_dir, arcname=exhibits_dir.name)

    if not quiet:
        if RICH_AVAILABLE:
            console.print(f"\n[bold green]Wrote[/bold green] {report_json}")  # type: ignore[union-attr]
            console.print(f"[bold green]Wrote[/bold green] {report_md}")  # type: ignore[union-attr]
            console.print(f"[bold green]Wrote[/bold green] {exhibits_dir}/")  # type: ignore[union-attr]
            if tar_path:
                console.print(f"[bold green]Wrote[/bold green] {tar_path}")  # type: ignore[union-attr]
        else:
            print(f"\nWrote {report_json}\nWrote {report_md}\nWrote {exhibits_dir}/")
            if tar_path:
                print(f"Wrote {tar_path}")

    return report_json, tar_path


# ---------------------------------------------------------------------------
# Check registry / CLI
# ---------------------------------------------------------------------------

CHECKS_NODE: dict[str, Callable[..., None]] = {
    "cron": check_cron,
    "users": check_users,
    "suid": check_suid,
    "shellrc": check_shell_rc,
    "network": check_network,
    "processes": check_processes,
    "motd": check_motd_and_init,
    "udev": check_udev,
    "ldpreload": check_ld_preload,
    "pkgmgr": check_apt_hooks,
    "git": check_git_config,
    "kubelet": check_kubelet_and_pki,
    "runtime": check_container_runtime,
    "logs": check_logs,
    "fs": check_filesystem_hotspots,
}

CHECKS_K8S = {
    "k8s_pods": check_k8s_privileged_pods,
    "k8s_rbac": check_k8s_rbac,
    "k8s_sa": check_k8s_service_accounts,
    "k8s_secrets": check_k8s_secrets,
    "k8s_workloads": check_k8s_workloads,
    "k8s_events": check_k8s_events,
    "k8s_nodes": check_k8s_nodes,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="k8s-triage — Kubernetes Node Persistence & Compromise Triage Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="Run all node + k8s checks (best-effort)")
    mode.add_argument("--k8s-only", action="store_true", help="Run Kubernetes API checks only")
    mode.add_argument("--node-only", action="store_true", help="Run node OS checks only")

    p.add_argument("--check", action="append", default=[], help="Run a specific check (repeatable). Examples: cron, suid, network, k8s_rbac, k8s_secrets")

    p.add_argument("--namespace", default="all", help="Namespace for k8s checks (or 'all')")
    p.add_argument("--context", default=None, help="kubeconfig context name (optional)")
    p.add_argument("--output", default="./triage_out", help="Output directory")
    p.add_argument("--no-tar", action="store_true", help="Do not produce a tar.gz bundle")
    p.add_argument("--quiet", action="store_true", help="Less console output")
    p.add_argument("--include-secret-data", action="store_true", help="Include secret data (base64 as returned by API). DEFAULT OFF for safety.")

    return p.parse_args()


def main() -> int:
    args = parse_args()

    print_banner()

    result = TriageResult(node=get_node_name(), timestamp=now_utc_iso())

    # Basic environment exhibit
    env = {
        "node": result.node,
        "timestamp": result.timestamp,
        "user": pwd.getpwuid(os.geteuid()).pw_name,
        "euid": os.geteuid(),
        "is_root": is_root(),
        "platform": platform.platform(),
        "python": sys.version,
        "cwd": os.getcwd(),
    }
    result.add_exhibit("env:basic", json.dumps(env, indent=2))

    requested = set(args.check or [])
    run_all = args.all or (not args.k8s_only and not args.node_only and not requested)

    # Decide which checks to run
    run_node = args.node_only or args.all or (run_all and not args.k8s_only)
    run_k8s = args.k8s_only or args.all or (run_all and not args.node_only)

    # If user specified --check, it overrides default mode selection (but we’ll still best-effort)
    if requested:
        run_node = any(c in CHECKS_NODE for c in requested)
        run_k8s = any(c in CHECKS_K8S for c in requested)

    # -------------------
    # Node checks
    # -------------------
    if run_node:
        section("NODE CHECKS")
        if requested:
            for name in requested:
                fn = CHECKS_NODE.get(name)
                if not fn:
                    continue
                try:
                    fn(result, quiet=args.quiet)  # type: ignore[misc]
                except TypeError:
                    fn(result)  # legacy signature
                except Exception as e:
                    emit(result, name, Severity.INFO, f"Check failed: {name}", str(e), quiet=args.quiet)
        else:
            for name, fn in CHECKS_NODE.items():
                try:
                    fn(result, quiet=args.quiet)  # type: ignore[misc]
                except TypeError:
                    fn(result)
                except Exception as e:
                    emit(result, name, Severity.INFO, f"Check failed: {name}", str(e), quiet=args.quiet)

    # -------------------
    # Kubernetes checks
    # -------------------
    if run_k8s:
        section("K8S API CHECKS")
        ok, msg = k8s_load_config(context=args.context)
        if not ok:
            emit(
                result,
                "k8s",
                Severity.INFO,
                "Kubernetes client not available / config not loaded",
                msg,
                recommendation="Install kubernetes python package and configure kubeconfig, or run in-cluster",
                quiet=args.quiet,
            )
        else:
            emit(result, "k8s", Severity.INFO, "Kubernetes config loaded", msg, quiet=args.quiet)

            v1 = client.CoreV1Api()
            apps = client.AppsV1Api()
            rbac = client.RbacAuthorizationV1Api()

            # If user specified checks, run only those.
            if requested:
                for name in requested:
                    fn = CHECKS_K8S.get(name)
                    if not fn:
                        continue
                    try:
                        if name == "k8s_pods":
                            fn(result, v1, args.namespace, quiet=args.quiet)  # type: ignore[misc]
                        elif name == "k8s_rbac":
                            fn(result, rbac, args.namespace, quiet=args.quiet)  # type: ignore[misc]
                        elif name == "k8s_sa":
                            fn(result, v1, args.namespace, quiet=args.quiet)  # type: ignore[misc]
                        elif name == "k8s_secrets":
                            fn(result, v1, args.namespace, args.include_secret_data, quiet=args.quiet)  # type: ignore[misc]
                        elif name == "k8s_workloads":
                            fn(result, apps, args.namespace, quiet=args.quiet)  # type: ignore[misc]
                        elif name == "k8s_events":
                            fn(result, v1, args.namespace, quiet=args.quiet)  # type: ignore[misc]
                        elif name == "k8s_nodes":
                            fn(result, v1, quiet=args.quiet)  # type: ignore[misc]
                        else:
                            fn(result)  # fallback
                    except Exception as e:
                        emit(result, name, Severity.INFO, f"Check failed: {name}", str(e), quiet=args.quiet)
            else:
                # default suite
                check_k8s_nodes(result, v1, quiet=args.quiet)
                check_k8s_privileged_pods(result, v1, args.namespace, quiet=args.quiet)
                check_k8s_workloads(result, apps, args.namespace, quiet=args.quiet)
                check_k8s_service_accounts(result, v1, args.namespace, quiet=args.quiet)
                check_k8s_secrets(result, v1, args.namespace, args.include_secret_data, quiet=args.quiet)
                check_k8s_rbac(result, rbac, args.namespace, quiet=args.quiet)
                check_k8s_events(result, v1, args.namespace, quiet=args.quiet)

    # Summary + write outputs
    render_summary_table(result)

    output_dir = Path(args.output)
    write_report_files(result, output_dir, make_tar=(not args.no_tar), quiet=args.quiet)

    # Exit code: 2 if any CRITICAL, 1 if any HIGH, else 0
    counts = result.summary()
    if counts.get(Severity.CRITICAL.value, 0) > 0:
        return 2
    if counts.get(Severity.HIGH.value, 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
