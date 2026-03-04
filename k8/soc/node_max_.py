#!/usr/bin/env python3
"""
k8s-triage — Kubernetes Node Persistence & Compromise Triage Tool
=================================================================
Collects forensic exhibits from EKS / k3s / vanilla k8s nodes.
Designed for incident response triage, red team debriefs, and hunting.

What it does (best-effort):
  Node OS:
    - Cron + systemd timers/units (persistence)
    - Users/UID0/sudoers/authorized_keys
    - SUID/SGID binaries (noise-reduced; avoids container overlays)
    - Shell RC/profile backdoors
    - Network listeners + established connections
    - Process sweep (regex-based)
    - MOTD/init scripts, udev rules, ld.so.preload, apt hooks, git configs
    - Kubelet/node credentials/config paths
    - Container runtime sockets and basic runtime inventory
    - Logs (journald/syslog best effort)
    - Filesystem hotspots (recent executables in common drop locations)

  Kubernetes API (if kubernetes python client + kubeconfig available):
    - Privileged pods, hostPath, hostNetwork, hostPID
    - RBAC over-privilege (clusterrolebindings/rolebindings)
    - ServiceAccount token automount checks
    - Secrets inventory (content only if --include-secret-data)

Safety / hygiene:
  - No shell=True command execution
  - Output truncation for hostile/huge command output
  - Secret data is OFF by default
  - Tar bundling avoids following symlinks

Usage examples:
    # Full triage (node + k8s checks, best-effort)
    python3 k8s_triage.py --all --output ./triage_out

    # K8s API checks only
    python3 k8s_triage.py --k8s-only --namespace kube-system

    # Node OS checks only
    python3 k8s_triage.py --node-only

    # Specific checks (repeatable)
    python3 k8s_triage.py --check cron --check suid --check network

Requirements:
    pip install kubernetes rich
    kubectl configured with appropriate context (for kubeconfig discovery)
"""

from __future__ import annotations

import argparse
import base64
import datetime
from datetime import timezone
import grp
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# Optional dependencies
try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Models
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
        self.exhibits[label] = content

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


# ---------------------------------------------------------------------------
# Globals: exclusions / heuristics (noise control)
# ---------------------------------------------------------------------------

EXCLUDE_PREFIXES_DEFAULT: tuple[str, ...] = (
    "/proc",
    "/sys",
    "/run",
    "/dev",
    # Container overlays / snapshotters: massive noise for SUID and file scans
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/rancher/k3s/agent/containerd",
)

DEFAULT_SUID_ROOTS: tuple[Path, ...] = (
    Path("/bin"),
    Path("/sbin"),
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/usr/lib"),
    Path("/usr/libexec"),
)

HOTSPOT_DIRS: tuple[Path, ...] = (
    Path("/tmp"),
    Path("/var/tmp"),
    Path("/dev/shm"),
    Path("/usr/local/bin"),
    Path("/usr/local/sbin"),
    Path("/opt"),
)

# Common infra ports that are frequently legitimate on nodes
COMMON_NODE_PORTS: set[int] = {
    22, 53, 68, 80, 443, 179,
    2376, 2377,
    6443, 6444,
    8472,  # flannel vxlan
    10248, 10249, 10250, 10255, 10256, 10257, 10258, 10259,
    11434,  # ollama, in some labs
}

BENIGN_LISTENER_PROCS: set[str] = {
    "systemd-resolve",
    "systemd-networkd",
    "systemd-network",
    "containerd",
    "dockerd",
    "kubelet",
    "k3s-server",
    "k3s-agent",
    "flanneld",
    "coredns",
}


# ---------------------------------------------------------------------------
# Output / UI
# ---------------------------------------------------------------------------

def print_banner() -> None:
    banner = r"""
██╗  ██╗ █████╗ ███████╗    ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗
██║ ██╔╝██╔══██╗██╔════╝    ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
█████╔╝ ╚█████╔╝███████╗       ██║   ██████╔╝██║███████║██║  ███╗█████╗
██╔═██╗ ██╔══██╗╚════██║       ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝
██║  ██╗╚█████╔╝███████║       ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝ ╚════╝ ╚══════╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

k8s Node Persistence & Compromise Triage Tool
"""
    if RICH_AVAILABLE:
        console.print(Panel(banner, style="bold blue"))
    else:
        print(banner)


def section(title: str) -> None:
    if RICH_AVAILABLE:
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{'='*72}\n{title}\n{'='*72}")


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
        console.print(f"  {emoji}  [{color}][{severity.upper()}][/{color}] {title}")
        if detail:
            console.print(f"       [dim]{detail}[/dim]")
        if evidence:
            for e in evidence[:5]:
                console.print(f"       [dim white]  → {e.strip()}[/dim white]")
            if len(evidence) > 5:
                console.print(f"       [dim]  ... and {len(evidence)-5} more (see report)[/dim]")
    else:
        print(f"  [{severity.upper()}] {title}\n    {detail}")
        for e in (evidence or [])[:5]:
            print(f"    → {e.strip()}")


# ---------------------------------------------------------------------------
# Time / safe helpers
# ---------------------------------------------------------------------------

def iso_utc_now() -> str:
    return (
        datetime.datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def current_timestamp_compact() -> str:
    # For filenames
    return iso_utc_now().replace(":", "").replace("-", "").replace("Z", "Z")


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def get_node_name() -> str:
    return socket.gethostname()


def is_excluded_path(p: Path, extra_excludes: tuple[str, ...] = ()) -> bool:
    s = str(p)
    prefixes = EXCLUDE_PREFIXES_DEFAULT + extra_excludes
    return any(s == x or s.startswith(x + "/") for x in prefixes)


def safe_read_text(path: Path, limit_bytes: int = 2_000_000) -> str:
    try:
        data = path.read_bytes()
        if len(data) > limit_bytes:
            data = data[:limit_bytes] + b"\n...[TRUNCATED]...\n"
        return data.decode(errors="replace")
    except OSError:
        return ""


def sha256_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def run_cmd(cmd: list[str], timeout: int = 30, max_bytes: int = 2_000_000) -> tuple[str, str, int]:
    """Run a command safely (no shell), return (stdout, stderr, returncode)."""
    env = {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        out = (proc.stdout or "")[:max_bytes]
        err = (proc.stderr or "")[:max_bytes]
        return out, err, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"[timeout after {timeout}s]", 1
    except FileNotFoundError:
        return "", f"[command not found: {cmd[0]}]", 127
    except OSError as e:
        return "", str(e), 1


def dpkg_owner(path: str) -> Optional[str]:
    out, _, rc = run_cmd(["dpkg", "-S", path], timeout=10)
    if rc == 0 and ":" in out:
        return out.split(":", 1)[0].strip()
    return None


# ---------------------------------------------------------------------------
# Node OS checks
# ---------------------------------------------------------------------------

def check_cron(result: TriageResult, quiet: bool) -> None:
    section("Scheduled Tasks — Cron & Systemd Timers")

    cron_paths = [
        Path("/etc/crontab"),
        *Path("/etc/cron.d").glob("*"),
        *Path("/etc/cron.hourly").glob("*"),
        *Path("/etc/cron.daily").glob("*"),
        *Path("/etc/cron.weekly").glob("*"),
        *Path("/etc/cron.monthly").glob("*"),
    ]

    suspicious_kw = (
        "/dev/tcp",
        "ncat",
        "netcat",
        " nc ",
        "bash -i",
        "python",
        "socat",
        "curl",
        "wget",
        "base64",
    )

    for p in cron_paths:
        if not p.is_file():
            continue
        content = safe_read_text(p)
        if not content:
            continue
        result.add_exhibit(f"cron:{p}", content)

        suspicious = [
            ln for ln in content.splitlines()
            if (not ln.strip().startswith("#")) and any(kw in ln for kw in suspicious_kw)
        ]
        if suspicious:
            emit(
                result, "cron", Severity.CRITICAL,
                f"Suspicious cron entry in {p}",
                "Cron entry contains network/shell callback indicators",
                evidence=suspicious,
                mitre="T1053.003",
                recommendation="Remove entry and investigate referenced binaries/scripts",
                quiet=quiet,
            )
        else:
            emit(result, "cron", Severity.INFO, f"Cron file present: {p}", f"{len(content.splitlines())} lines", quiet=quiet)

    # User crontabs (best effort)
    out, _, rc = run_cmd(["ls", "/var/spool/cron/crontabs"], timeout=10)
    if rc == 0:
        for user in out.splitlines():
            user = user.strip()
            if not user:
                continue
            cron_file = Path("/var/spool/cron/crontabs") / user
            if cron_file.exists():
                content = safe_read_text(cron_file)
                if content:
                    result.add_exhibit(f"usercron:{user}", content)
                    emit(result, "cron", Severity.INFO, f"User crontab exists: {user}", str(cron_file), quiet=quiet)

    # Systemd timers
    out, _, rc = run_cmd(["systemctl", "list-timers", "--all", "--no-pager"], timeout=15)
    if rc == 0 and out.strip():
        result.add_exhibit("systemd:timers", out)
        emit(result, "cron", Severity.INFO, "Systemd timers collected", "See exhibit systemd:timers", quiet=quiet)

    # Systemd unit files – flag suspicious ExecStart
    unit_dirs = [Path("/etc/systemd/system"), Path("/lib/systemd/system")]
    for d in unit_dirs:
        if not d.exists():
            continue
        for unit in d.glob("*.service"):
            content = safe_read_text(unit)
            if not content:
                continue
            suspicious_lines = [
                ln for ln in content.splitlines()
                if any(kw in ln for kw in ("/dev/tcp", "ncat", "bash -i", "python -c", "socat", "curl", "wget"))
            ]
            if suspicious_lines:
                emit(
                    result, "cron", Severity.CRITICAL,
                    f"Suspicious systemd unit: {unit.name}",
                    "Unit content contains network/shell callback indicators",
                    evidence=suspicious_lines,
                    mitre="T1543.002",
                    recommendation="Disable unit and investigate referenced binaries/scripts",
                    quiet=quiet,
                )


def check_users(result: TriageResult, quiet: bool) -> None:
    section("User Accounts & Privileges")

    uid0 = [p for p in pwd.getpwall() if p.pw_uid == 0]
    if len(uid0) > 1:
        emit(
            result, "users", Severity.CRITICAL,
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
        try:
            mtime = datetime.datetime.fromtimestamp(passwd_path.stat().st_mtime, tz=timezone.utc)
            age_hours = (datetime.datetime.now(timezone.utc) - mtime).total_seconds() / 3600
        except OSError:
            age_hours = 999999.0

        content = safe_read_text(passwd_path)
        if content:
            result.add_exhibit("users:passwd", content)
        if age_hours < 48:
            emit(
                result, "users", Severity.HIGH,
                f"/etc/passwd modified {age_hours:.1f} hours ago",
                "Recent modification is suspicious on a stable node",
                mitre="T1136.001",
                recommendation="Diff against a known-good baseline (golden AMI/image) and investigate auth logs",
                quiet=quiet,
            )

    # Sudo rules
    sudoers_paths = [Path("/etc/sudoers"), *Path("/etc/sudoers.d").glob("*")]
    for p in sudoers_paths:
        if not p.is_file():
            continue
        content = safe_read_text(p)
        if not content:
            continue
        result.add_exhibit(f"sudo:{p.name}", content)
        nopasswd = [ln for ln in content.splitlines() if "NOPASSWD" in ln and not ln.strip().startswith("#")]
        if nopasswd:
            emit(
                result, "users", Severity.HIGH,
                f"NOPASSWD sudo rules in {p.name}",
                "Passwordless sudo can be used for persistence / privilege escalation",
                evidence=nopasswd,
                mitre="T1548",
                recommendation="Audit and remove unnecessary NOPASSWD rules",
                quiet=quiet,
            )

    # SSH authorized_keys (metadata + content)
    for p in pwd.getpwall():
        home = Path(p.pw_dir)
        if not home.exists():
            continue
        ak_path = home / ".ssh" / "authorized_keys"
        if ak_path.exists():
            content = safe_read_text(ak_path)
            keys = [ln for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
            result.add_exhibit(f"ssh:authorized_keys:{p.pw_name}", content)
            emit(
                result, "users", Severity.MEDIUM,
                f"SSH authorized_keys: {p.pw_name} ({len(keys)} key(s))",
                str(ak_path),
                evidence=keys[:10],
                mitre="T1098.004",
                recommendation="Verify all keys are approved; rotate credentials if suspicious",
                quiet=quiet,
            )


def check_suid(result: TriageResult, quiet: bool) -> None:
    section("SUID / SGID Binaries")

    # Tightened SUID scan:
    #  - avoids container overlays / snapshotters by default
    #  - uses dpkg ownership as a strong signal on Debian/Ubuntu
    #  - only scans common system roots by default (reduces noise)
    found: list[str] = []

    for root in DEFAULT_SUID_ROOTS:
        if not root.exists() or is_excluded_path(root):
            continue
        try:
            for f in root.rglob("*"):
                if is_excluded_path(f):
                    continue
                try:
                    if not f.is_file():
                        continue
                    st = f.stat(follow_symlinks=False)
                    if not (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
                        continue

                    path_s = str(f)
                    found.append(path_s)

                    # classify
                    try:
                        owner = pwd.getpwuid(st.st_uid).pw_name
                    except KeyError:
                        owner = str(st.st_uid)

                    sha = sha256_file(f)
                    pkg = dpkg_owner(path_s)
                    weird_dir = path_s.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/usr/local/"))

                    if pkg is None or weird_dir:
                        why = "unowned by dpkg" if pkg is None else "unexpected location"
                        emit(
                            result, "suid", Severity.HIGH,
                            f"SUID/SGID binary needs review: {f}",
                            f"reason={why} owner={owner} pkg={pkg} sha256={sha}",
                            mitre="T1548.001",
                            recommendation="Confirm provenance; remove/reinstall if unauthorized",
                            quiet=quiet,
                        )
                except OSError:
                    continue
        except OSError:
            continue

    result.add_exhibit("suid:all_found", "\n".join(found))
    emit(
        result, "suid", Severity.INFO,
        f"SUID/SGID scan complete — {len(found)} binaries found",
        "See exhibit suid:all_found for full list",
        quiet=quiet,
    )


def check_shell_rc(result: TriageResult, quiet: bool) -> None:
    section("Shell RC / Profile Backdoors")

    rc_files = [
        ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".zshrc", ".zprofile",
        ".config/fish/config.fish",
    ]
    suspicious_keywords = [
        "/dev/tcp", "ncat", "netcat", " nc ", "bash -i", "socat",
        "curl", "wget", "base64", "python -c", "perl -e", "ruby -e",
        "alias sudo", "LD_PRELOAD",
    ]

    for p in pwd.getpwall():
        home = Path(p.pw_dir)
        if not home.exists():
            continue
        for rc in rc_files:
            rc_path = home / rc
            if not rc_path.exists():
                continue
            content = safe_read_text(rc_path)
            if not content:
                continue
            result.add_exhibit(f"shellrc:{p.pw_name}:{rc}", content)
            hits = [
                ln for ln in content.splitlines()
                if (not ln.strip().startswith("#")) and any(kw in ln for kw in suspicious_keywords)
            ]
            if hits:
                emit(
                    result, "shellrc", Severity.HIGH,
                    f"Suspicious content in ~{p.pw_name}/{rc}",
                    "Shell RC file contains possible persistence indicators",
                    evidence=hits[:20],
                    mitre="T1546.004",
                    recommendation="Review and remove unauthorized commands; rotate creds/tokens if exposed",
                    quiet=quiet,
                )
            else:
                emit(
                    result, "shellrc", Severity.INFO,
                    f"RC file checked: ~{p.pw_name}/{rc}",
                    f"{len(content.splitlines())} lines — no obvious indicators",
                    quiet=quiet,
                )


def check_network(result: TriageResult, quiet: bool) -> None:
    section("Network — Connections & Listeners")

    out, _, rc = run_cmd(["ss", "-tulpn"], timeout=15)
    if rc == 0 and out.strip():
        result.add_exhibit("network:listeners", out)
        emit(result, "network", Severity.INFO, "Active listeners collected", "See exhibit network:listeners", quiet=quiet)

        # Extract proc name from ss line: users:(("proc",pid=...,fd=...))
        proc_re = re.compile(r'users:\(\("([^"]+)"')

        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[4]
            m = proc_re.search(line)
            proc = (m.group(1) if m else "").strip()

            # best-effort port extraction
            port = None
            try:
                port = int(local_addr.split(":")[-1])
            except Exception:
                continue

            if port in COMMON_NODE_PORTS and proc in BENIGN_LISTENER_PROCS:
                continue

            # If listener is loopback-only, reduce severity
            loopback_only = ("127.0.0.1:" in line) or ("[::1]:" in line)

            if port not in {22, 80, 443, 6443, 10250}:
                sev = Severity.MEDIUM
                if proc and proc not in BENIGN_LISTENER_PROCS and (("0.0.0.0:" in line) or (" *:" in line)):
                    sev = Severity.HIGH
                if loopback_only and sev == Severity.MEDIUM:
                    # common local-only services: not usually urgent
                    sev = Severity.LOW

                emit(
                    result, "network", sev,
                    f"Unexpected listener on port {port}",
                    line.strip(),
                    mitre="T1049",
                    recommendation="Identify owning process; confirm service is expected for this node role",
                    quiet=quiet,
                )

    out2, _, _ = run_cmd(["ss", "-tnp", "state", "established"], timeout=15)
    if out2.strip():
        result.add_exhibit("network:established", out2)
        emit(result, "network", Severity.INFO, "Established connections collected", "See exhibit network:established", quiet=quiet)

    hosts_path = Path("/etc/hosts")
    if hosts_path.exists():
        content = safe_read_text(hosts_path)
        if content:
            result.add_exhibit("network:hosts", content)
            non_standard = [
                ln for ln in content.splitlines()
                if ln.strip()
                and not ln.strip().startswith("#")
                and not any(ln.startswith(pfx) for pfx in ("127.", "::1", "fe80", "0.0.0.0"))
            ]
            if non_standard:
                emit(
                    result, "network", Severity.MEDIUM,
                    f"/etc/hosts has {len(non_standard)} non-loopback entries",
                    "Could indicate host redirection / DNS hijacking",
                    evidence=non_standard[:20],
                    mitre="T1565.001",
                    recommendation="Validate entries against baseline; investigate recent changes",
                    quiet=quiet,
                )

    ipt, _, rc = run_cmd(["iptables", "-L", "-n", "-v"], timeout=20)
    if rc == 0 and ipt.strip():
        result.add_exhibit("network:iptables", ipt)


def check_processes(result: TriageResult, quiet: bool) -> None:
    section("Running Processes")

    out, _, rc = run_cmd(["ps", "auxf"], timeout=20)
    if rc == 0 and out.strip():
        result.add_exhibit("processes:ps_auxf", out)

    out2, _, _ = run_cmd(["ps", "-eo", "pid,user,cmd"], timeout=20)
    if not out2.strip():
        return

    # Regex-based to reduce false positives (word boundaries)
    suspicious_res = [
        re.compile(r"\b(ncat|netcat|nc)\b", re.I),
        re.compile(r"\b(socat|chisel|ligolo)\b", re.I),
        re.compile(r"/dev/tcp", re.I),
        re.compile(r"\b(bash\s+-i)\b", re.I),
        re.compile(r"\b(python|perl|ruby)\s+-c\b", re.I),
        re.compile(r"\b(meterpreter|metasploit|cobalt|beacon)\b", re.I),
    ]

    hits: list[str] = []
    for line in out2.splitlines():
        low = line.lower()
        if "kubelet" in low or "containerd" in low or "dockerd" in low:
            continue
        if any(r.search(line) for r in suspicious_res):
            hits.append(line.strip())

    if hits:
        emit(
            result, "processes", Severity.CRITICAL,
            "Suspicious process patterns detected",
            "Process list contains patterns commonly associated with shells/tunnels/C2 tooling",
            evidence=hits[:50],
            mitre="T1059",
            recommendation="Validate commands; contain host if unauthorized; capture full process tree and binaries",
            quiet=quiet,
        )
    else:
        emit(result, "processes", Severity.INFO, "Process scan complete", "No obvious suspicious patterns", quiet=quiet)


def check_motd_and_init(result: TriageResult, quiet: bool) -> None:
    section("MOTD & Init Scripts")

    motd_dir = Path("/etc/update-motd.d")
    if motd_dir.exists():
        for f in sorted(motd_dir.iterdir()):
            if not f.is_file():
                continue
            content = safe_read_text(f)
            if not content:
                continue
            result.add_exhibit(f"motd:{f.name}", content)

            hits = [
                ln for ln in content.splitlines()
                if (not ln.strip().startswith("#")) and any(kw in ln for kw in ("/dev/tcp", "ncat", "bash -i", "curl", "wget"))
            ]
            if hits:
                # Many distros legitimately fetch motd updates/news; reduce severity if loopback
                sev = Severity.HIGH
                if "127.0.0.1" in content or "localhost" in content:
                    sev = Severity.MEDIUM

                emit(
                    result, "motd", sev,
                    f"MOTD script contains network execution: {f.name}",
                    "Review endpoints/commands; some motd scripts legitimately fetch updates/news",
                    evidence=hits[:30],
                    mitre="T1546",
                    recommendation="Confirm expected behavior; remove if unauthorized or contacting external endpoints",
                    quiet=quiet,
                )

    rc_local = Path("/etc/rc.local")
    if rc_local.exists():
        content = safe_read_text(rc_local)
        if content:
            result.add_exhibit("init:rc.local", content)
            emit(result, "init", Severity.INFO, "/etc/rc.local exists", "Review content in exhibit init:rc.local", quiet=quiet)


def check_udev(result: TriageResult, quiet: bool) -> None:
    section("udev Rules")

    rules_dir = Path("/etc/udev/rules.d")
    if not rules_dir.exists():
        return

    for f in sorted(rules_dir.iterdir()):
        if not f.is_file():
            continue
        content = safe_read_text(f)
        if not content:
            continue
        result.add_exhibit(f"udev:{f.name}", content)
        hits = [ln for ln in content.splitlines() if "RUN+=" in ln and not ln.strip().startswith("#")]
        if hits:
            emit(
                result, "udev", Severity.HIGH,
                f"udev rule with RUN+= in {f.name}",
                "udev RUN+= executes commands on device events (possible persistence)",
                evidence=hits[:50],
                mitre="T1546",
                recommendation="Verify RUN+= commands are legitimate",
                quiet=quiet,
            )


def check_ld_preload(result: TriageResult, quiet: bool) -> None:
    section("LD_PRELOAD / Shared Library Hijacking")

    preload_path = Path("/etc/ld.so.preload")
    if preload_path.exists():
        content = safe_read_text(preload_path).strip()
        if content:
            result.add_exhibit("ldpreload:ld.so.preload", content)
            emit(
                result, "ldpreload", Severity.CRITICAL,
                "/etc/ld.so.preload is populated",
                "Preloaded libraries affect ALL dynamic binaries on the system",
                evidence=content.splitlines(),
                mitre="T1574.006",
                recommendation="Verify each listed library is legitimate; investigate timestamps and package ownership",
                quiet=quiet,
            )

    # Recently modified libs in /lib and /usr/lib (best effort, can be noisy)
    recent: list[str] = []
    for d in (Path("/lib"), Path("/usr/lib")):
        if not d.exists() or is_excluded_path(d):
            continue
        try:
            for so in d.rglob("*.so*"):
                try:
                    st = so.stat()
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                    age_days = (datetime.datetime.now(timezone.utc) - mtime).total_seconds() / 86400
                    if age_days < 7:
                        recent.append(f"{so} (mtime={mtime.isoformat()})")
                except OSError:
                    continue
        except OSError:
            continue

    if recent:
        emit(
            result, "ldpreload", Severity.MEDIUM,
            f"{len(recent)} recently modified shared libraries found",
            "Recent .so changes can indicate injection/hijacking (or normal updates)",
            evidence=recent[:50],
            mitre="T1574.006",
            recommendation="Correlate with apt/yum history and file integrity baselines",
            quiet=quiet,
        )


def check_apt_hooks(result: TriageResult, quiet: bool) -> None:
    section("Package Manager Hooks")

    apt_conf_dir = Path("/etc/apt/apt.conf.d")
    if not apt_conf_dir.exists():
        return

    for f in sorted(apt_conf_dir.iterdir()):
        if not f.is_file():
            continue
        content = safe_read_text(f)
        if not content:
            continue
        result.add_exhibit(f"apt:{f.name}", content)
        if "Pre-Invoke" in content or "Post-Invoke" in content or "DPkg::Post-Invoke" in content:
            hits = [ln for ln in content.splitlines() if "Invoke" in ln]
            emit(
                result, "pkgmgr", Severity.HIGH,
                f"APT invoke hook in {f.name}",
                "Hook executes commands during apt operations (can be abused for persistence)",
                evidence=hits[:50],
                mitre="T1554",
                recommendation="Verify hook commands are legitimate and expected",
                quiet=quiet,
            )


def check_git_config(result: TriageResult, quiet: bool) -> None:
    section("Git Backdoors")

    suspicious_git_keys = ("editor", "pager", "sshcommand", "hookspath")
    hits_total: list[str] = []

    for p in pwd.getpwall():
        home = Path(p.pw_dir)
        if not home.exists():
            continue
        gitconfig = home / ".gitconfig"
        if not gitconfig.exists():
            continue
        content = safe_read_text(gitconfig)
        if not content:
            continue
        result.add_exhibit(f"git:config:{p.pw_name}", content)
        hits = [ln for ln in content.splitlines() if any(k in ln.lower() for k in suspicious_git_keys)]
        if hits:
            hits_total.extend([f"{p.pw_name}: {h}" for h in hits[:20]])

    if hits_total:
        emit(
            result, "git", Severity.MEDIUM,
            "Git config contains executable hooks/commands keys",
            "Review for malicious editor/pager/sshCommand/hooksPath",
            evidence=hits_total[:50],
            mitre="T1546",
            recommendation="Audit git config values; remove unexpected commands",
            quiet=quiet,
        )
    else:
        emit(result, "git", Severity.INFO, "Git config scan complete", "No obvious executable-config indicators", quiet=quiet)


def check_kubelet_paths(result: TriageResult, quiet: bool) -> None:
    section("Kubernetes Node Credentials & Kubelet Config")

    paths = [
        Path("/var/lib/kubelet"),
        Path("/etc/kubernetes"),
        Path("/var/lib/rancher/k3s"),
        Path("/etc/rancher/k3s"),
    ]

    present: list[str] = []
    for p in paths:
        if p.exists():
            present.append(str(p))
            # Only list, do not blindly read secrets
            try:
                listing = []
                for item in sorted(p.rglob("*")):
                    if is_excluded_path(item):
                        continue
                    try:
                        st = item.lstat()
                        mode = stat.filemode(st.st_mode)
                        listing.append(f"{mode} {st.st_size:>10} {item}")
                        if len(listing) >= 2000:
                            listing.append("...[TRUNCATED]...")
                            break
                    except OSError:
                        continue
                result.add_exhibit(f"kubelet:listing:{p}", "\n".join(listing))
            except OSError:
                pass

    if present:
        emit(
            result, "kubelet", Severity.INFO,
            "Kubernetes node config paths present",
            "Collected directory listings (metadata only) and key config files when readable",
            evidence=present,
            quiet=quiet,
        )


def check_runtime(result: TriageResult, quiet: bool) -> None:
    section("Container Runtime — Docker / containerd / crictl")

    sockets = [
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
        Path("/run/containerd/containerd.sock"),
        Path("/var/run/containerd/containerd.sock"),
    ]
    present = [str(s) for s in sockets if s.exists()]

    if present:
        emit(
            result, "runtime", Severity.HIGH,
            "Container runtime sockets present on node",
            "If accessible to untrusted processes, sockets can lead to host takeover",
            evidence=present,
            mitre="T1611",
            recommendation="Restrict socket access; use rootless where possible; monitor for socket usage",
            quiet=quiet,
        )

    # Best-effort inventory
    docker, _, drc = run_cmd(["docker", "ps", "-a", "--no-trunc"], timeout=20)
    if drc == 0 and docker.strip():
        result.add_exhibit("runtime:docker_ps", docker)

    ctr, _, crc = run_cmd(["ctr", "-n", "k8s.io", "containers", "list"], timeout=20)
    if crc == 0 and ctr.strip():
        result.add_exhibit("runtime:ctr_containers", ctr)

    crictl, _, crrc = run_cmd(["crictl", "ps", "-a"], timeout=20)
    if crrc == 0 and crictl.strip():
        result.add_exhibit("runtime:crictl_ps", crictl)

    emit(result, "runtime", Severity.INFO, "Runtime checks complete", "Collected what was available", quiet=quiet)


def check_logs(result: TriageResult, quiet: bool) -> None:
    section("Logs — journald / syslog (best effort)")

    # journald
    j, _, rc = run_cmd(["journalctl", "--no-pager", "-n", "2000"], timeout=25)
    if rc == 0 and j.strip():
        result.add_exhibit("logs:journalctl_tail", j)

    # syslog-ish
    for path in (Path("/var/log/syslog"), Path("/var/log/messages"), Path("/var/log/auth.log")):
        if path.exists():
            content = safe_read_text(path, limit_bytes=2_000_000)
            if content:
                result.add_exhibit(f"logs:{path.name}", content)

    emit(result, "logs", Severity.INFO, "Log collection complete", "Best-effort; availability varies by distro", quiet=quiet)


def check_hotspots(result: TriageResult, quiet: bool, recent_hours: int = 72) -> None:
    section("Filesystem Hotspots — tmp, /usr/local/bin, recent executables")

    cutoff = datetime.datetime.now(timezone.utc) - datetime.timedelta(hours=recent_hours)
    hits: list[str] = []

    for d in HOTSPOT_DIRS:
        if not d.exists() or is_excluded_path(d):
            continue
        try:
            for f in d.rglob("*"):
                if is_excluded_path(f):
                    continue
                try:
                    if not f.is_file():
                        continue
                    st = f.stat(follow_symlinks=False)
                    if not (st.st_mode & stat.S_IXUSR):
                        continue
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                    if mtime >= cutoff:
                        sha = sha256_file(f)
                        hits.append(f"{f}\tmtime={mtime.isoformat()}\tsha256={sha}")
                except OSError:
                    continue
        except OSError:
            continue

    if hits:
        result.add_exhibit("hotspots:recent_execs", "\n".join(hits))
        emit(
            result, "hotspots", Severity.HIGH,
            f"{len(hits)} recently modified executables in hotspots",
            "Common persistence drop locations had recent executable changes",
            evidence=hits[:25],
            mitre="T1036",
            recommendation="Validate each binary origin; correlate with package history / deployment activity",
            quiet=quiet,
        )
    else:
        emit(result, "hotspots", Severity.INFO, "Hotspot scan complete", "No recent executables found in common drop locations", quiet=quiet)


# ---------------------------------------------------------------------------
# Kubernetes API checks (optional)
# ---------------------------------------------------------------------------

def k8s_load_client(context: Optional[str]) -> tuple[Any, Any, Any] | None:
    if not K8S_AVAILABLE:
        return None
    try:
        # Try kubeconfig first
        config.load_kube_config(context=context)
    except Exception:
        try:
            # If running in-cluster
            config.load_incluster_config()
        except Exception:
            return None

    v1 = client.CoreV1Api()
    rbac = client.RbacAuthorizationV1Api()
    apps = client.AppsV1Api()
    return v1, rbac, apps


def check_k8s_privileged_pods(result: TriageResult, v1: Any, namespace: str, quiet: bool) -> None:
    section("K8s — Privileged / HostPath Pods")

    try:
        pods = v1.list_namespaced_pod(namespace) if namespace != "all" else v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            ns = pod.metadata.namespace
            name = pod.metadata.name

            # Containers security context
            for c in (pod.spec.containers or []):
                sc = c.security_context
                if not sc:
                    continue
                if getattr(sc, "privileged", False):
                    emit(
                        result, "k8s_pods", Severity.CRITICAL,
                        f"Privileged container: {ns}/{name}/{c.name}",
                        "Privileged containers can escape to the host",
                        mitre="T1611",
                        recommendation="Remove privileged unless absolutely required; enforce PSA/OPA policies",
                        quiet=quiet,
                    )
                if getattr(sc, "run_as_user", None) == 0:
                    emit(result, "k8s_pods", Severity.HIGH, f"Container running as root: {ns}/{name}/{c.name}", "runAsUser: 0", mitre="T1611", quiet=quiet)
                if getattr(sc, "allow_privilege_escalation", False):
                    emit(result, "k8s_pods", Severity.HIGH, f"allowPrivilegeEscalation=true: {ns}/{name}/{c.name}", "Can gain more privileges", mitre="T1548", quiet=quiet)

            # Volumes: hostPath
            for vol in (pod.spec.volumes or []):
                if getattr(vol, "host_path", None):
                    path = vol.host_path.path
                    sev = Severity.CRITICAL if path in ("/", "/etc", "/var/run", "/var/lib/kubelet") else Severity.HIGH
                    emit(
                        result, "k8s_pods", sev,
                        f"HostPath volume in {ns}/{name}: {path}",
                        "HostPath mounts can expose sensitive host files",
                        mitre="T1611",
                        recommendation="Restrict HostPath usage via Pod Security Admission / policy",
                        quiet=quiet,
                    )

            if getattr(pod.spec, "host_network", False):
                emit(result, "k8s_pods", Severity.HIGH, f"hostNetwork=true: {ns}/{name}", "Shares host network namespace", mitre="T1611", quiet=quiet)
            if getattr(pod.spec, "host_pid", False):
                emit(result, "k8s_pods", Severity.CRITICAL, f"hostPID=true: {ns}/{name}", "Can see/signal host processes", mitre="T1611", quiet=quiet)

    except ApiException as e:
        emit(result, "k8s_pods", Severity.INFO, "Could not list pods", str(e), quiet=quiet)


def _rule_is_dangerous(rule: Any) -> bool:
    # rule is V1PolicyRule
    verbs = set(getattr(rule, "verbs", []) or [])
    resources = set(getattr(rule, "resources", []) or [])
    nonres = set(getattr(rule, "non_resource_urls", []) or [])

    dangerous_verbs = {"*", "escalate", "bind", "impersonate"}
    dangerous_resources = {"*", "secrets", "nodes", "pods/exec", "clusterrolebindings", "rolebindings"}

    if verbs & dangerous_verbs:
        return True
    if resources & dangerous_resources:
        return True
    if nonres and "*" in verbs:
        return True
    return False


def check_k8s_rbac(result: TriageResult, rbac: Any, namespace: str, quiet: bool) -> None:
    section("K8s — RBAC: Overprivileged Bindings")

    def fmt_subjects(subs: list[Any]) -> list[str]:
        out: list[str] = []
        for s in subs or []:
            out.append(f"{s.kind}:{s.name} (ns={getattr(s, 'namespace', None)})")
        return out

    try:
        crbs = rbac.list_cluster_role_binding()
        for b in crbs.items:
            role_ref = b.role_ref
            role_name = role_ref.name if role_ref else "?"
            # Fetch clusterrole rules
            try:
                cr = rbac.read_cluster_role(role_name)
                rules = getattr(cr, "rules", []) or []
                if any(_rule_is_dangerous(r) for r in rules):
                    emit(
                        result, "k8s_rbac", Severity.HIGH,
                        f"Potentially dangerous ClusterRoleBinding: {b.metadata.name}",
                        f"roleRef={role_name}",
                        evidence=fmt_subjects(b.subjects or []),
                        mitre="T1068",
                        recommendation="Audit subjects; reduce permissions; avoid binding * verbs/resources to broad subjects",
                        quiet=quiet,
                    )
            except ApiException:
                continue

        # Namespaced rolebindings
        if namespace == "all":
            rbs = rbac.list_role_binding_for_all_namespaces()
        else:
            rbs = rbac.list_namespaced_role_binding(namespace)

        for rb in rbs.items:
            ns = rb.metadata.namespace
            rr = rb.role_ref
            rr_name = rr.name if rr else "?"
            rr_kind = rr.kind if rr else "?"
            # Fetch role rules
            try:
                if rr_kind == "ClusterRole":
                    role_obj = rbac.read_cluster_role(rr_name)
                else:
                    role_obj = rbac.read_namespaced_role(rr_name, ns)
                rules = getattr(role_obj, "rules", []) or []
                if any(_rule_is_dangerous(r) for r in rules):
                    emit(
                        result, "k8s_rbac", Severity.MEDIUM,
                        f"Dangerous RoleBinding: {ns}/{rb.metadata.name}",
                        f"roleRef={rr_kind}:{rr_name}",
                        evidence=fmt_subjects(rb.subjects or []),
                        mitre="T1068",
                        recommendation="Audit binding and reduce privileges",
                        quiet=quiet,
                    )
            except ApiException:
                continue

    except ApiException as e:
        emit(result, "k8s_rbac", Severity.INFO, "Could not list RBAC bindings", str(e), quiet=quiet)


def check_k8s_serviceaccounts(result: TriageResult, v1: Any, namespace: str, quiet: bool) -> None:
    section("K8s — ServiceAccounts & Token Automount")

    try:
        sas = v1.list_namespaced_service_account(namespace) if namespace != "all" else v1.list_service_account_for_all_namespaces()
        for sa in sas.items:
            ns = sa.metadata.namespace
            name = sa.metadata.name
            automount = getattr(sa, "automount_service_account_token", None)
            if automount is True:
                emit(
                    result, "k8s_sa", Severity.MEDIUM,
                    f"ServiceAccount automount enabled: {ns}/{name}",
                    "automountServiceAccountToken=true",
                    mitre="T1552",
                    recommendation="Disable automount where not needed; use projected tokens with audience/expiry",
                    quiet=quiet,
                )
    except ApiException as e:
        emit(result, "k8s_sa", Severity.INFO, "Could not list serviceaccounts", str(e), quiet=quiet)


def check_k8s_secrets(result: TriageResult, v1: Any, namespace: str, include_secret_data: bool, quiet: bool) -> None:
    section("K8s — Secrets Inventory")

    try:
        secrets = v1.list_namespaced_secret(namespace) if namespace != "all" else v1.list_secret_for_all_namespaces()
        for s in secrets.items:
            ns = s.metadata.namespace
            name = s.metadata.name
            typ = s.type
            keys = list((s.data or {}).keys())

            detail = f"type={typ} keys={keys}"
            sev = Severity.MEDIUM if typ and "kubernetes.io/service-account-token" in typ else Severity.LOW
            emit(
                result, "k8s_secrets", sev,
                f"Secret: {ns}/{name}",
                detail,
                mitre="T1552",
                recommendation="Rotate secrets; restrict RBAC; consider external secret managers",
                quiet=quiet,
            )

            if include_secret_data and s.data:
                # Store base64 as returned by API (explicitly opted in)
                result.add_exhibit(f"secretdata:{ns}/{name}", json.dumps(s.data, indent=2))

    except ApiException as e:
        emit(result, "k8s_secrets", Severity.INFO, "Could not list secrets", str(e), quiet=quiet)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_outputs(
    result: TriageResult,
    output_dir: Path,
    make_tar: bool,
    quiet: bool,
) -> tuple[Path, Path, Path, Optional[Path]]:
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_node = re.sub(r"[^A-Za-z0-9_.-]+", "_", result.node)
    base = f"k8s-triage_{safe_node}_{current_timestamp_compact()}"

    json_path = output_dir / f"{base}.json"
    md_path = output_dir / f"{base}.md"
    exhibits_dir = output_dir / f"{base}_exhibits"
    exhibits_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    payload = {
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
        "exhibits_index": sorted(result.exhibits.keys()),
    }
    json_path.write_text(json.dumps(payload, indent=2))

    # Exhibits to files
    for label, content in result.exhibits.items():
        safe_label = re.sub(r"[^A-Za-z0-9_.:-]+", "_", label)
        (exhibits_dir / f"{safe_label}.txt").write_text(content)

    # Markdown report
    lines: list[str] = []
    lines.append(f"# k8s-triage report — `{result.node}`")
    lines.append("")
    lines.append(f"- Timestamp (UTC): `{result.timestamp}`")
    lines.append(f"- Findings: `{len(result.findings)}`")
    lines.append("")

    summ = result.summary()
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {sev.value} | {summ.get(sev.value, 0)} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in sorted(result.findings, key=lambda x: list(Severity).index(x.severity)):
        lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        lines.append(f"- Check: `{f.check}`")
        if f.mitre:
            lines.append(f"- MITRE: `{f.mitre}`")
        if f.detail:
            lines.append(f"- Detail: {f.detail}")
        if f.recommendation:
            lines.append(f"- Recommendation: {f.recommendation}")
        if f.evidence:
            lines.append("")
            lines.append("**Evidence (truncated):**")
            lines.append("")
            lines.append("```")
            for e in f.evidence[:50]:
                lines.append(e.rstrip())
            if len(f.evidence) > 50:
                lines.append(f"... ({len(f.evidence)-50} more omitted; see exhibits)")
            lines.append("```")
        lines.append("")

    lines.append("## Exhibits")
    lines.append("")
    lines.append(f"Exhibits directory: `{exhibits_dir.name}/`")
    lines.append("")
    for label in sorted(result.exhibits.keys()):
        safe_label = re.sub(r"[^A-Za-z0-9_.:-]+", "_", label)
        lines.append(f"- `{safe_label}.txt`  ←  {label}")

    md_path.write_text("\n".join(lines))

    tar_path: Optional[Path] = None
    if make_tar:
        tar_path = output_dir / f"{base}.tar.gz"
        create_safe_tar(tar_path, [json_path, md_path, exhibits_dir])

    if not quiet:
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
        print(f"Wrote {exhibits_dir}")
        if tar_path:
            print(f"Wrote {tar_path}")

    return json_path, md_path, exhibits_dir, tar_path


def create_safe_tar(tar_path: Path, items: list[Path]) -> None:
    """
    Create a tar.gz bundle without following symlinks and with safe arcnames.
    """
    def safe_arcname(p: Path) -> str:
        # store relative names under bundle root
        return p.name

    with tarfile.open(tar_path, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for item in items:
            if item.is_dir():
                for root, dirs, files in os.walk(item, followlinks=False):
                    root_p = Path(root)
                    # Skip excluded paths (defense in depth)
                    if is_excluded_path(root_p):
                        dirs[:] = []
                        continue
                    for fn in files:
                        fp = root_p / fn
                        try:
                            st = fp.lstat()
                            if stat.S_ISLNK(st.st_mode):
                                # Do not include symlinks
                                continue
                            arc = f"{item.name}/{fp.relative_to(item)}"
                            tf.add(fp, arcname=arc, recursive=False)
                        except OSError:
                            continue
            else:
                try:
                    st = item.lstat()
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    tf.add(item, arcname=safe_arcname(item), recursive=False)
                except OSError:
                    continue


# ---------------------------------------------------------------------------
# Runner / dispatch
# ---------------------------------------------------------------------------

NODE_CHECKS: dict[str, Any] = {
    "cron": check_cron,
    "users": check_users,
    "suid": check_suid,
    "shellrc": check_shell_rc,
    "network": check_network,
    "processes": check_processes,
    "motd": check_motd_and_init,
    "udev": check_udev,
    "ldpreload": check_ld_preload,
    "apt_hooks": check_apt_hooks,
    "git": check_git_config,
    "kubelet": check_kubelet_paths,
    "runtime": check_runtime,
    "logs": check_logs,
    "hotspots": check_hotspots,
}

K8S_CHECKS: dict[str, Any] = {
    "k8s_pods": check_k8s_privileged_pods,
    "k8s_rbac": check_k8s_rbac,
    "k8s_sa": check_k8s_serviceaccounts,
    "k8s_secrets": check_k8s_secrets,
}


def run_node_checks(result: TriageResult, checks: list[str], quiet: bool) -> None:
    section("NODE CHECKS")
    for name in checks:
        fn = NODE_CHECKS.get(name)
        if not fn:
            continue
        try:
            if name == "hotspots":
                fn(result, quiet)  # type: ignore[misc]
            else:
                fn(result, quiet)  # type: ignore[misc]
        except Exception as e:
            emit(result, name, Severity.INFO, f"Check failed: {name}", str(e), quiet=quiet)


def run_k8s_checks(
    result: TriageResult,
    namespace: str,
    context: Optional[str],
    include_secret_data: bool,
    checks: list[str],
    quiet: bool,
) -> None:
    section("K8S API CHECKS")
    client_tuple = k8s_load_client(context)
    if not client_tuple:
        emit(
            result, "k8s", Severity.INFO,
            "Kubernetes client not available / config not loaded",
            "Install kubernetes python client and ensure kubeconfig is accessible",
            quiet=quiet,
        )
        return
    v1, rbac, _apps = client_tuple

    for name in checks:
        fn = K8S_CHECKS.get(name)
        if not fn:
            continue
        try:
            if name == "k8s_pods":
                fn(result, v1, namespace, quiet)  # type: ignore[misc]
            elif name == "k8s_rbac":
                fn(result, rbac, namespace, quiet)  # type: ignore[misc]
            elif name == "k8s_sa":
                fn(result, v1, namespace, quiet)  # type: ignore[misc]
            elif name == "k8s_secrets":
                fn(result, v1, namespace, include_secret_data, quiet)  # type: ignore[misc]
        except Exception as e:
            emit(result, name, Severity.INFO, f"Check failed: {name}", str(e), quiet=quiet)


def print_summary(result: TriageResult) -> None:
    if not RICH_AVAILABLE:
        print("\nTriage Summary:", result.summary())
        return

    table = Table(title="Triage Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    summ = result.summary()
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        table.add_row(sev.value, str(summ.get(sev.value, 0)))
    console.print(table)


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

    if not args.quiet:
        print_banner()

    node = get_node_name()
    result = TriageResult(node=node, timestamp=iso_utc_now())

    # Determine check sets
    requested = [c.strip() for c in args.check if c and c.strip()]
    if requested:
        node_checks = [c for c in requested if c in NODE_CHECKS]
        k8s_checks = [c for c in requested if c in K8S_CHECKS]
    else:
        # Default check suites by mode
        node_checks = list(NODE_CHECKS.keys())
        k8s_checks = list(K8S_CHECKS.keys())

    do_node = args.all or args.node_only or (not args.k8s_only)
    do_k8s = args.all or args.k8s_only

    # If user requested only certain checks, obey that
    if requested:
        do_node = any(c in NODE_CHECKS for c in requested)
        do_k8s = any(c in K8S_CHECKS for c in requested)

    if do_node:
        run_node_checks(result, node_checks, quiet=args.quiet)

    if do_k8s:
        run_k8s_checks(
            result,
            namespace=args.namespace,
            context=args.context,
            include_secret_data=args.include_secret_data,
            checks=k8s_checks,
            quiet=args.quiet,
        )

    if not args.quiet:
        print_summary(result)

    outdir = Path(args.output)
    write_outputs(
        result=result,
        output_dir=outdir,
        make_tar=(not args.no_tar),
        quiet=args.quiet,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
