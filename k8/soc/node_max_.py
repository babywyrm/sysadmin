#!/usr/bin/env python3

"""
k8s-triage — Kubernetes Node Persistence & Compromise Triage Tool
=================================================================

Goals:
  - Actionable: prioritize high-signal checks and useful exhibits
  - Quiet-friendly: multiple ways to suppress noise without losing artifacts
  - Safer defaults: no secret content unless explicitly enabled

Install:
  pip install rich kubernetes

Examples:
  python3 max.py --node-only
  python3 max.py --all --min-severity medium
  python3 max.py --all --quiet --no-exhibits
  python3 max.py --node-only --no-section-headers --no-banner
  python3 max.py --node-only --check suid --check network
"""

from __future__ import annotations

import argparse
import datetime as _dt
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import socket
import stat
import subprocess
import sys
import tarfile
from typing import Any, Optional, Iterable

# Optional deps
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Table = None  # type: ignore

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    client = None  # type: ignore
    config = None  # type: ignore
    ApiException = Exception  # type: ignore


# ---------------------------------------------------------------------------
# Models / severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SEVERITY_EMOJI = {
    Severity.INFO: "ℹ️ ",
    Severity.LOW: "🟢",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🔴",
    Severity.CRITICAL: "💀",
}

SEVERITY_RICH_STYLE = {
    Severity.INFO: "cyan",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
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

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def add_exhibit(self, label: str, content: str) -> None:
        self.exhibits[label] = content

    def summary(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out


# ---------------------------------------------------------------------------
# Defaults / noise controls
# ---------------------------------------------------------------------------

EXCLUDE_PREFIXES_DEFAULT: tuple[str, ...] = (
    "/proc",
    "/sys",
    "/run",
    "/dev",
    # container overlays/snapshots: huge noise
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

COMMON_NODE_PORTS: set[int] = {
    22, 53, 68, 80, 443, 179,
    2376, 2377,
    6443, 6444,
    8472,
    10248, 10249, 10250, 10255, 10256, 10257, 10258, 10259,
}

HOSTS_BENIGN_PREFIXES = (
    "127.", "::1", "0.0.0.0",
    "fe00::", "fe80::", "ff00::", "ff02::",
)


# ---------------------------------------------------------------------------
# Console wrapper (supports rich/plain, min severity, quiet, section toggles)
# ---------------------------------------------------------------------------

class UI:
    def __init__(self, use_rich: bool, quiet: bool, min_severity: Severity, show_sections: bool, show_banner: bool):
        self.use_rich = use_rich and RICH_AVAILABLE
        self.quiet = quiet
        self.min_severity = min_severity
        self.show_sections = show_sections
        self.show_banner = show_banner
        self.console = Console() if self.use_rich else None

    def banner(self) -> None:
        if self.quiet or not self.show_banner:
            return
        banner = r"""
██╗  ██╗ █████╗ ███████╗    ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗
██║ ██╔╝██╔══██╗██╔════╝    ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
█████╔╝ ╚█████╔╝███████╗       ██║   ██████╔╝██║███████║██║  ███╗█████╗
██╔═██╗ ██╔══██╗╚════██║       ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝
██║  ██╗╚█████╔╝███████║       ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝ ╚════╝ ╚══════╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

k8s Node Persistence & Compromise Triage Tool
"""
        if self.use_rich:
            self.console.print(Panel(banner, style="bold blue"))
        else:
            print(banner)

    def section(self, title: str) -> None:
        if self.quiet or not self.show_sections:
            return
        if self.use_rich:
            # avoid any fancy formatting that might trigger heavy joins
            self.console.rule(title)
        else:
            print(f"\n{'-'*95}\n{title}\n{'-'*95}")

    def should_print(self, sev: Severity) -> bool:
        if self.quiet:
            return False
        return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[self.min_severity]

    def finding(self, sev: Severity, title: str, detail: str = "", evidence: Optional[list[str]] = None) -> None:
        if not self.should_print(sev):
            return
        ev = evidence or []
        if self.use_rich:
            style = SEVERITY_RICH_STYLE[sev]
            emoji = SEVERITY_EMOJI[sev]
            self.console.print(f"  {emoji}  [{style}][{sev.upper()}][/{style}] {title}")
            if detail:
                self.console.print(f"       [dim]{detail}[/dim]")
            for line in ev[:5]:
                self.console.print(f"       [dim]→ {line.strip()}[/dim]")
            if len(ev) > 5:
                self.console.print(f"       [dim]... and {len(ev)-5} more (see report)[/dim]")
        else:
            print(f"[{sev.upper()}] {title}")
            if detail:
                print(f"  {detail}")
            for line in ev[:5]:
                print(f"  → {line.strip()}")


# ---------------------------------------------------------------------------
# Safe helpers
# ---------------------------------------------------------------------------

def iso_utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ts_compact() -> str:
    return iso_utc_now().replace(":", "").replace("-", "")


def get_node_name() -> str:
    return socket.gethostname()


def is_excluded_path(p: Path, extra_excludes: tuple[str, ...] = ()) -> bool:
    s = str(p)
    prefixes = EXCLUDE_PREFIXES_DEFAULT + extra_excludes
    return any(s == x or s.startswith(x + "/") for x in prefixes)


def safe_read_text(path: Path, limit_bytes: int) -> str:
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


def run_cmd(cmd: list[str], timeout: int, max_bytes: int) -> tuple[str, str, int]:
    env = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        p = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        out = (p.stdout or "")[:max_bytes]
        err = (p.stderr or "")[:max_bytes]
        return out, err, p.returncode
    except subprocess.TimeoutExpired:
        return "", f"[timeout after {timeout}s]", 1
    except FileNotFoundError:
        return "", f"[command not found: {cmd[0]}]", 127
    except OSError as e:
        return "", str(e), 1


def dpkg_owner(path: str) -> Optional[str]:
    """
    dpkg -S can miss paths like /bin/sudo on merged-/usr systems because dpkg
    records /usr/bin/sudo. Resolve realpath to reduce false HIGH spam.
    """
    real = os.path.realpath(path)
    out, _err, rc = run_cmd(["dpkg", "-S", real], timeout=10, max_bytes=200_000)
    if rc == 0 and ":" in out:
        return out.split(":", 1)[0].strip()
    return None


def safe_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "_", label)


# ---------------------------------------------------------------------------
# Emit helper (records always, prints optionally)
# ---------------------------------------------------------------------------

def emit(
    ui: UI,
    result: TriageResult,
    check: str,
    severity: Severity,
    title: str,
    detail: str,
    evidence: Optional[list[str]] = None,
    mitre: Optional[str] = None,
    recommendation: Optional[str] = None,
) -> None:
    f = Finding(
        check=check,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence or [],
        mitre=mitre,
        recommendation=recommendation,
    )
    result.add_finding(f)
    ui.finding(severity, title, detail, evidence)


# ---------------------------------------------------------------------------
# Exhibit policy (silencing/length controls)
# ---------------------------------------------------------------------------

@dataclass
class ExhibitPolicy:
    enabled: bool
    max_bytes: int
    drop_patterns: list[re.Pattern[str]] = field(default_factory=list)

    def allow(self, label: str) -> bool:
        if not self.enabled:
            return False
        for pat in self.drop_patterns:
            if pat.search(label):
                return False
        return True


def add_exhibit(result: TriageResult, policy: ExhibitPolicy, label: str, content: str) -> None:
    if not policy.allow(label):
        return
    if not content:
        return
    # content is already truncated by read/command helpers; keep extra safety cap
    if len(content.encode(errors="ignore")) > policy.max_bytes:
        content = content.encode(errors="ignore")[:policy.max_bytes].decode(errors="replace") + "\n...[TRUNCATED]...\n"
    result.add_exhibit(label, content)


# ---------------------------------------------------------------------------
# Checks: Node OS
# ---------------------------------------------------------------------------

def check_cron(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Scheduled Tasks — Cron & Systemd Timers")

    cron_paths: list[Path] = [Path("/etc/crontab")]
    for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        cron_paths.extend(sorted(Path(d).glob("*")))

    suspicious_kw = ("/dev/tcp", "ncat", "netcat", " nc ", "bash -i", "python", "socat", "curl", "wget", "base64")

    for p in cron_paths:
        if not p.is_file():
            continue
        content = safe_read_text(p, xp.max_bytes)
        add_exhibit(result, xp, f"cron:{p}", content)

        lines = content.splitlines()
        suspicious = [
            ln for ln in lines
            if ln.strip() and not ln.strip().startswith("#") and any(kw in ln for kw in suspicious_kw)
        ]
        if suspicious:
            emit(
                ui, result, "cron", Severity.CRITICAL,
                f"Suspicious cron entry in {p}",
                "Cron entry contains network/shell callback indicators",
                evidence=suspicious[:50],
                mitre="T1053.003",
                recommendation="Remove entry and investigate referenced binaries/scripts",
            )
        else:
            emit(ui, result, "cron", Severity.INFO, f"Cron file present: {p}", f"{len(lines)} lines")

    out, _err, rc = run_cmd(["systemctl", "list-timers", "--all", "--no-pager"], timeout=15, max_bytes=xp.max_bytes)
    if rc == 0 and out.strip():
        add_exhibit(result, xp, "systemd:timers", out)
        emit(ui, result, "cron", Severity.INFO, "Systemd timers collected", "See exhibit systemd:timers")

    # Systemd unit files: ExecStart suspicious patterns
    unit_dirs = [Path("/etc/systemd/system"), Path("/lib/systemd/system")]
    for d in unit_dirs:
        if not d.exists():
            continue
        for unit in d.glob("*.service"):
            content = safe_read_text(unit, xp.max_bytes)
            if not content:
                continue
            # Keep exhibits only for units that match indicators (cuts noise)
            hits = [
                ln for ln in content.splitlines()
                if any(kw in ln for kw in ("/dev/tcp", "ncat", "bash -i", "python -c", "socat", "curl", "wget"))
            ]
            if hits:
                add_exhibit(result, xp, f"systemd:unit:{unit.name}", content)
                emit(
                    ui, result, "cron", Severity.CRITICAL,
                    f"Suspicious systemd unit: {unit.name}",
                    "Unit content contains network/shell callback indicators",
                    evidence=hits[:50],
                    mitre="T1543.002",
                    recommendation="Disable unit and investigate referenced binaries/scripts",
                )


def check_users(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("User Accounts & Privileges")

    uid0 = [p for p in pwd.getpwall() if p.pw_uid == 0]
    if len(uid0) > 1:
        emit(
            ui, result, "users", Severity.CRITICAL,
            f"{len(uid0)} accounts with UID 0 detected",
            "Multiple root-equivalent accounts",
            evidence=[f"{p.pw_name} (shell: {p.pw_shell})" for p in uid0],
            mitre="T1136.001",
            recommendation="Investigate non-root UID 0 accounts immediately",
        )
    else:
        emit(ui, result, "users", Severity.INFO, "UID 0 accounts: only root", "Expected")

    passwd_path = Path("/etc/passwd")
    content = safe_read_text(passwd_path, xp.max_bytes)
    add_exhibit(result, xp, "users:passwd", content)

    # authorized_keys
    for p in pwd.getpwall():
        home = Path(p.pw_dir)
        ak = home / ".ssh" / "authorized_keys"
        if not ak.exists():
            continue
        txt = safe_read_text(ak, xp.max_bytes)
        add_exhibit(result, xp, f"ssh:authorized_keys:{p.pw_name}", txt)
        keys = [ln for ln in txt.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        emit(
            ui, result, "users", Severity.MEDIUM,
            f"SSH authorized_keys: {p.pw_name} ({len(keys)} key(s))",
            str(ak),
            evidence=keys[:10],
            mitre="T1098.004",
            recommendation="Verify all keys are approved; rotate credentials if suspicious",
        )


def check_suid(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("SUID / SGID Binaries")

    found: list[str] = []
    reviews: list[str] = []

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

                    sha = sha256_file(f)
                    pkg = dpkg_owner(path_s)
                    weird = path_s.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/usr/local/"))

                    # Only flag HIGH if genuinely suspicious:
                    # - dpkg unknown after realpath resolution (not just /bin -> /usr/bin mismatch)
                    # - or SUID/SGID in weird dirs
                    if pkg is None or weird:
                        reason = "unowned by dpkg" if pkg is None else "unexpected location"
                        reviews.append(f"{path_s}\treason={reason}\tpkg={pkg}\tsha256={sha}")
                except OSError:
                    continue
        except OSError:
            continue

    add_exhibit(result, xp, "suid:all_found", "\n".join(found))
    if reviews:
        add_exhibit(result, xp, "suid:needs_review", "\n".join(reviews))
        for line in reviews[:20]:
            emit(
                ui, result, "suid", Severity.HIGH,
                f"SUID/SGID binary needs review: {line.split('\\t', 1)[0]}",
                line,
                mitre="T1548.001",
                recommendation="Confirm provenance; reinstall via package manager if unauthorized",
            )
        if len(reviews) > 20:
            emit(ui, result, "suid", Severity.INFO, "More SUID/SGID review items", f"{len(reviews)-20} more in exhibit suid:needs_review")

    emit(ui, result, "suid", Severity.INFO, f"SUID/SGID scan complete — {len(found)} binaries found", "See exhibit suid:all_found")


def check_shell_rc(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Shell RC / Profile Backdoors")

    rc_files = [
        ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".zshrc", ".zprofile", ".config/fish/config.fish",
    ]
    suspicious = ("/dev/tcp", "ncat", "netcat", " nc ", "bash -i", "socat", "curl", "wget", "base64", "python -c", "LD_PRELOAD")

    for p in pwd.getpwall():
        home = Path(p.pw_dir)
        if not home.exists():
            continue
        for rc in rc_files:
            f = home / rc
            if not f.exists():
                continue
            txt = safe_read_text(f, xp.max_bytes)
            if not txt:
                continue
            hits = [ln for ln in txt.splitlines() if ln.strip() and not ln.strip().startswith("#") and any(k in ln for k in suspicious)]
            if hits:
                add_exhibit(result, xp, f"shellrc:{p.pw_name}:{rc}", txt)
                emit(
                    ui, result, "shellrc", Severity.HIGH,
                    f"Suspicious content in ~{p.pw_name}/{rc}",
                    "Shell RC contains possible persistence indicators",
                    evidence=hits[:50],
                    mitre="T1546.004",
                    recommendation="Remove unauthorized lines; investigate who modified the file; rotate exposed creds",
                )
            else:
                emit(ui, result, "shellrc", Severity.INFO, f"RC checked: ~{p.pw_name}/{rc}", f"{len(txt.splitlines())} lines — no obvious indicators")


def _parse_ss_local(local: str) -> tuple[str, Optional[int]]:
    # Examples:
    #   0.0.0.0:8472
    #   127.0.0.1:15000
    #   [::]:15021
    #   [::1]:15000
    #   127.0.0.53%lo:53
    s = local.strip()
    # strip zone suffix
    s = re.sub(r"%[A-Za-z0-9_.-]+:", ":", s)
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
        if not m:
            return s, None
        return m.group(1), int(m.group(2))
    if ":" not in s:
        return s, None
    host, port_s = s.rsplit(":", 1)
    try:
        return host, int(port_s)
    except ValueError:
        return host, None


def check_network(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Network — Connections & Listeners")

    out, _err, rc = run_cmd(["ss", "-tulpn"], timeout=15, max_bytes=xp.max_bytes)
    if rc == 0 and out.strip():
        add_exhibit(result, xp, "network:listeners", out)
        emit(ui, result, "network", Severity.INFO, "Active listeners collected", "See exhibit network:listeners")

        proc_re = re.compile(r'users:\(\("([^"]+)"')
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[4]
            bind_host, port = _parse_ss_local(local)
            if port is None:
                continue

            m = proc_re.search(line)
            proc = (m.group(1) if m else "").strip()

            external_bind = bind_host in ("0.0.0.0", "*", "::")
            loopback = bind_host.startswith("127.") or bind_host == "::1"

            # Ignore common infra if clearly benign
            if port in COMMON_NODE_PORTS and proc in BENIGN_LISTENER_PROCS:
                continue

            sev = Severity.MEDIUM
            if external_bind and proc and proc not in BENIGN_LISTENER_PROCS:
                sev = Severity.HIGH
            if loopback and sev == Severity.MEDIUM:
                sev = Severity.LOW

            emit(
                ui, result, "network", sev,
                f"Unexpected listener on port {port}",
                line.strip(),
                mitre="T1049",
                recommendation="Validate the owning process/service for this node role; close or firewall if unnecessary",
            )

    out2, _err2, _rc2 = run_cmd(["ss", "-tnp", "state", "established"], timeout=15, max_bytes=xp.max_bytes)
    if out2.strip():
        add_exhibit(result, xp, "network:established", out2)
        emit(ui, result, "network", Severity.INFO, "Established connections collected", "See exhibit network:established")

    hosts = Path("/etc/hosts")
    txt = safe_read_text(hosts, xp.max_bytes)
    if txt:
        add_exhibit(result, xp, "network:hosts", txt)
        nonstandard = []
        for ln in txt.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            if any(s.startswith(p) for p in HOSTS_BENIGN_PREFIXES):
                continue
            nonstandard.append(s)
        if nonstandard:
            emit(
                ui, result, "network", Severity.MEDIUM,
                f"/etc/hosts has {len(nonstandard)} non-standard entries",
                "Validate against baseline; could be host redirection",
                evidence=nonstandard[:50],
                mitre="T1565.001",
                recommendation="Confirm entries are expected; investigate recent config changes",
            )


def check_processes(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Running Processes")

    out, _err, rc = run_cmd(["ps", "-eo", "pid,user,cmd"], timeout=20, max_bytes=xp.max_bytes)
    if rc != 0 or not out.strip():
        return
    add_exhibit(result, xp, "processes:ps", out)

    suspicious_res = [
        re.compile(r"\b(ncat|netcat|nc)\b", re.I),
        re.compile(r"\b(socat|chisel|ligolo)\b", re.I),
        re.compile(r"/dev/tcp", re.I),
        re.compile(r"\b(bash\s+-i)\b", re.I),
        re.compile(r"\b(python|perl|ruby)\s+-c\b", re.I),
    ]

    hits = []
    for line in out.splitlines():
        low = line.lower()
        if any(x in low for x in ("kubelet", "containerd", "dockerd", "systemd")):
            continue
        if any(r.search(line) for r in suspicious_res):
            hits.append(line.strip())

    if hits:
        emit(
            ui, result, "processes", Severity.CRITICAL,
            "Suspicious process patterns detected",
            "Patterns commonly associated with shells/tunnels found in process list",
            evidence=hits[:80],
            mitre="T1059",
            recommendation="Confirm legitimacy; capture process tree, binaries, and network connections; contain if unauthorized",
        )
    else:
        emit(ui, result, "processes", Severity.INFO, "Process scan complete", "No obvious suspicious patterns")


def check_motd(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("MOTD & Init Scripts")

    motd_dir = Path("/etc/update-motd.d")
    if motd_dir.exists():
        for f in sorted(motd_dir.iterdir()):
            if not f.is_file():
                continue
            txt = safe_read_text(f, xp.max_bytes)
            if not txt:
                continue
            hits = [
                ln for ln in txt.splitlines()
                if ln.strip() and not ln.strip().startswith("#") and any(kw in ln for kw in ("/dev/tcp", "ncat", "bash -i", "curl", "wget"))
            ]
            if hits:
                add_exhibit(result, xp, f"motd:{f.name}", txt)
                emit(
                    ui, result, "motd", Severity.HIGH,
                    f"MOTD script contains network execution: {f.name}",
                    "May be legitimate on some distros, but verify endpoints/commands",
                    evidence=hits[:50],
                    mitre="T1546",
                    recommendation="Verify intended behavior; remove if unauthorized or contacting unexpected endpoints",
                )


def check_ld_preload(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("LD_PRELOAD / Shared Library Hijacking")

    preload = Path("/etc/ld.so.preload")
    if preload.exists():
        txt = safe_read_text(preload, xp.max_bytes).strip()
        if txt:
            add_exhibit(result, xp, "ldpreload:ld.so.preload", txt)
            emit(
                ui, result, "ldpreload", Severity.CRITICAL,
                "/etc/ld.so.preload is populated",
                "Preloaded libs affect all dynamic binaries",
                evidence=txt.splitlines()[:50],
                mitre="T1574.006",
                recommendation="Validate each path; check timestamps; remove malicious preload entries",
            )


def check_apt_hooks(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Package Manager Hooks")

    d = Path("/etc/apt/apt.conf.d")
    if not d.exists():
        return

    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        txt = safe_read_text(f, xp.max_bytes)
        if not txt:
            continue
        if any(k in txt for k in ("Pre-Invoke", "Post-Invoke", "DPkg::Post-Invoke")):
            add_exhibit(result, xp, f"apt:{f.name}", txt)
            hits = [ln.strip() for ln in txt.splitlines() if "Invoke" in ln]
            emit(
                ui, result, "pkgmgr", Severity.HIGH,
                f"APT invoke hook in {f.name}",
                "Hooks execute during apt operations (can be persistence)",
                evidence=hits[:50],
                mitre="T1554",
                recommendation="Confirm hook is expected (needrestart is common); audit executed script",
            )


def check_kubelet_paths(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Kubernetes Node Credentials & Kubelet Config")

    paths = [Path("/var/lib/kubelet"), Path("/etc/kubernetes"), Path("/var/lib/rancher/k3s"), Path("/etc/rancher/k3s")]
    present = [str(p) for p in paths if p.exists()]
    if present:
        # metadata only listing (capped)
        for p in paths:
            if not p.exists():
                continue
            listing = []
            try:
                for i, item in enumerate(sorted(p.rglob("*"))):
                    if is_excluded_path(item):
                        continue
                    try:
                        st = item.lstat()
                        listing.append(f"{stat.filemode(st.st_mode)} {st.st_size:>10} {item}")
                    except OSError:
                        continue
                    if i >= 1500:
                        listing.append("...[TRUNCATED]...")
                        break
                add_exhibit(result, xp, f"kubelet:listing:{p}", "\n".join(listing))
            except OSError:
                continue

        emit(
            ui, result, "kubelet", Severity.INFO,
            "Kubernetes node config paths present",
            "Collected directory listings (metadata only) where readable",
            evidence=present,
        )


def check_runtime(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Container Runtime — Docker / containerd / crictl")

    sockets = [
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
        Path("/run/containerd/containerd.sock"),
        Path("/var/run/containerd/containerd.sock"),
    ]
    present = [str(s) for s in sockets if s.exists()]
    if present:
        emit(
            ui, result, "runtime", Severity.HIGH,
            "Container runtime sockets present on node",
            "If accessible to untrusted processes, sockets can lead to host takeover",
            evidence=present,
            mitre="T1611",
            recommendation="Restrict group access; monitor for socket usage; avoid exposing sockets into pods",
        )

    # best-effort inventory (exhibits only if commands exist)
    for label, cmd in (
        ("runtime:docker_ps", ["docker", "ps", "-a", "--no-trunc"]),
        ("runtime:ctr_containers", ["ctr", "-n", "k8s.io", "containers", "list"]),
        ("runtime:crictl_ps", ["crictl", "ps", "-a"]),
    ):
        out, _err, rc = run_cmd(cmd, timeout=20, max_bytes=xp.max_bytes)
        if rc == 0 and out.strip():
            add_exhibit(result, xp, label, out)

    emit(ui, result, "runtime", Severity.INFO, "Runtime checks complete", "Collected what was available")


def check_logs(ui: UI, result: TriageResult, xp: ExhibitPolicy) -> None:
    ui.section("Logs — journald / syslog (best effort)")

    out, _err, rc = run_cmd(["journalctl", "--no-pager", "-n", "2000"], timeout=25, max_bytes=xp.max_bytes)
    if rc == 0 and out.strip():
        add_exhibit(result, xp, "logs:journalctl_tail", out)

    for path in (Path("/var/log/syslog"), Path("/var/log/messages"), Path("/var/log/auth.log")):
        if path.exists():
            add_exhibit(result, xp, f"logs:{path.name}", safe_read_text(path, xp.max_bytes))

    emit(ui, result, "logs", Severity.INFO, "Log collection complete", "Best-effort; availability varies by distro")


def check_hotspots(ui: UI, result: TriageResult, xp: ExhibitPolicy, recent_hours: int) -> None:
    ui.section("Filesystem Hotspots — recent executables")

    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=recent_hours)
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
                    mtime = _dt.datetime.fromtimestamp(st.st_mtime, tz=_dt.timezone.utc)
                    if mtime >= cutoff:
                        sha = sha256_file(f)
                        hits.append(f"{f}\tmtime={mtime.isoformat()}\tsha256={sha}")
                except OSError:
                    continue
        except OSError:
            continue

    if hits:
        add_exhibit(result, xp, "hotspots:recent_execs", "\n".join(hits))
        emit(
            ui, result, "hotspots", Severity.HIGH,
            f"{len(hits)} recently modified executables in hotspots",
            "Common persistence drop locations had recent executable changes",
            evidence=hits[:25],
            mitre="T1036",
            recommendation="Validate each binary origin; correlate with deployments/package updates",
        )
    else:
        emit(ui, result, "hotspots", Severity.INFO, "Hotspot scan complete", "No recent executables found")


NODE_CHECKS = {
    "cron": check_cron,
    "users": check_users,
    "suid": check_suid,
    "shellrc": check_shell_rc,
    "network": check_network,
    "processes": check_processes,
    "motd": check_motd,
    "ldpreload": check_ld_preload,
    "apt_hooks": check_apt_hooks,
    "kubelet": check_kubelet_paths,
    "runtime": check_runtime,
    "logs": check_logs,
    "hotspots": check_hotspots,
}


# ---------------------------------------------------------------------------
# Kubernetes checks (optional)
# ---------------------------------------------------------------------------

def k8s_load_client(context: Optional[str]) -> Optional[tuple[Any, Any, Any]]:
    if not K8S_AVAILABLE:
        return None
    try:
        config.load_kube_config(context=context)
    except Exception:
        try:
            config.load_incluster_config()
        except Exception:
            return None
    return client.CoreV1Api(), client.RbacAuthorizationV1Api(), client.AppsV1Api()


def _rule_is_dangerous(rule: Any) -> bool:
    verbs = set(getattr(rule, "verbs", []) or [])
    resources = set(getattr(rule, "resources", []) or [])
    nonres = set(getattr(rule, "non_resource_urls", []) or [])
    if "*" in verbs or {"escalate", "bind", "impersonate"} & verbs:
        return True
    if "*" in resources or {"secrets", "nodes", "pods/exec", "clusterrolebindings", "rolebindings"} & resources:
        return True
    if nonres and "*" in verbs:
        return True
    return False


def check_k8s_pods(ui: UI, result: TriageResult, xp: ExhibitPolicy, v1: Any, namespace: str) -> None:
    ui.section("K8s — Privileged / HostPath Pods")
    try:
        pods = v1.list_namespaced_pod(namespace) if namespace != "all" else v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            ns = pod.metadata.namespace
            name = pod.metadata.name

            for c in (pod.spec.containers or []):
                sc = c.security_context
                if not sc:
                    continue
                if getattr(sc, "privileged", False):
                    emit(ui, result, "k8s_pods", Severity.CRITICAL, f"Privileged container: {ns}/{name}/{c.name}", "privileged=true", mitre="T1611")
                if getattr(sc, "run_as_user", None) == 0:
                    emit(ui, result, "k8s_pods", Severity.HIGH, f"Container running as root: {ns}/{name}/{c.name}", "runAsUser=0")
                if getattr(sc, "allow_privilege_escalation", False):
                    emit(ui, result, "k8s_pods", Severity.HIGH, f"allowPrivilegeEscalation=true: {ns}/{name}/{c.name}", "can gain more privileges")

            for vol in (pod.spec.volumes or []):
                if getattr(vol, "host_path", None):
                    path = vol.host_path.path
                    sev = Severity.CRITICAL if path in ("/", "/etc", "/var/run", "/var/lib/kubelet") else Severity.HIGH
                    emit(ui, result, "k8s_pods", sev, f"HostPath volume in {ns}/{name}: {path}", "hostPath present", mitre="T1611")

            if getattr(pod.spec, "host_network", False):
                emit(ui, result, "k8s_pods", Severity.HIGH, f"hostNetwork=true: {ns}/{name}", "shares host network")
            if getattr(pod.spec, "host_pid", False):
                emit(ui, result, "k8s_pods", Severity.CRITICAL, f"hostPID=true: {ns}/{name}", "can see/signal host processes")

    except ApiException as e:
        emit(ui, result, "k8s_pods", Severity.INFO, "Could not list pods", str(e))


def check_k8s_rbac(ui: UI, result: TriageResult, xp: ExhibitPolicy, rbac: Any, namespace: str) -> None:
    ui.section("K8s — RBAC: Overprivileged Bindings")

    def fmt_subjects(subs: list[Any]) -> list[str]:
        return [f"{s.kind}:{s.name} (ns={getattr(s, 'namespace', None)})" for s in (subs or [])]

    try:
        crbs = rbac.list_cluster_role_binding()
        for b in crbs.items:
            role_name = b.role_ref.name if b.role_ref else "?"
            try:
                cr = rbac.read_cluster_role(role_name)
                rules = getattr(cr, "rules", []) or []
                if any(_rule_is_dangerous(r) for r in rules):
                    emit(
                        ui, result, "k8s_rbac", Severity.HIGH,
                        f"Potentially dangerous ClusterRoleBinding: {b.metadata.name}",
                        f"roleRef={role_name}",
                        evidence=fmt_subjects(b.subjects or [])[:50],
                        recommendation="Audit subjects; reduce permissions; avoid '*' verbs/resources for broad subjects",
                    )
            except ApiException:
                continue

        rbs = rbac.list_role_binding_for_all_namespaces() if namespace == "all" else rbac.list_namespaced_role_binding(namespace)
        for rb in rbs.items:
            ns = rb.metadata.namespace
            rr = rb.role_ref
            rr_name = rr.name if rr else "?"
            rr_kind = rr.kind if rr else "?"
            try:
                role_obj = rbac.read_cluster_role(rr_name) if rr_kind == "ClusterRole" else rbac.read_namespaced_role(rr_name, ns)
                rules = getattr(role_obj, "rules", []) or []
                if any(_rule_is_dangerous(r) for r in rules):
                    emit(
                        ui, result, "k8s_rbac", Severity.MEDIUM,
                        f"Dangerous RoleBinding: {ns}/{rb.metadata.name}",
                        f"roleRef={rr_kind}:{rr_name}",
                        evidence=fmt_subjects(rb.subjects or [])[:50],
                        recommendation="Audit binding and reduce privileges",
                    )
            except ApiException:
                continue

    except ApiException as e:
        emit(ui, result, "k8s_rbac", Severity.INFO, "Could not list RBAC bindings", str(e))


def check_k8s_serviceaccounts(ui: UI, result: TriageResult, xp: ExhibitPolicy, v1: Any, namespace: str) -> None:
    ui.section("K8s — ServiceAccounts & Token Automount")
    try:
        sas = v1.list_namespaced_service_account(namespace) if namespace != "all" else v1.list_service_account_for_all_namespaces()
        for sa in sas.items:
            automount = getattr(sa, "automount_service_account_token", None)
            if automount is True:
                emit(
                    ui, result, "k8s_sa", Severity.MEDIUM,
                    f"ServiceAccount automount enabled: {sa.metadata.namespace}/{sa.metadata.name}",
                    "automountServiceAccountToken=true",
                    recommendation="Disable automount where not needed; use projected tokens with audience/expiry",
                )
    except ApiException as e:
        emit(ui, result, "k8s_sa", Severity.INFO, "Could not list serviceaccounts", str(e))


def check_k8s_secrets(ui: UI, result: TriageResult, xp: ExhibitPolicy, v1: Any, namespace: str, include_secret_data: bool) -> None:
    ui.section("K8s — Secrets Inventory")
    try:
        secrets = v1.list_namespaced_secret(namespace) if namespace != "all" else v1.list_secret_for_all_namespaces()
        for s in secrets.items:
            ns = s.metadata.namespace
            name = s.metadata.name
            typ = s.type
            keys = list((s.data or {}).keys())
            sev = Severity.MEDIUM if typ and "service-account-token" in typ else Severity.LOW
            emit(ui, result, "k8s_secrets", sev, f"Secret: {ns}/{name}", f"type={typ} keys={keys}")
            if include_secret_data and s.data:
                add_exhibit(result, xp, f"secretdata:{ns}/{name}", json.dumps(s.data, indent=2))
    except ApiException as e:
        emit(ui, result, "k8s_secrets", Severity.INFO, "Could not list secrets", str(e))


K8S_CHECKS = {
    "k8s_pods": check_k8s_pods,
    "k8s_rbac": check_k8s_rbac,
    "k8s_sa": check_k8s_serviceaccounts,
    "k8s_secrets": check_k8s_secrets,
}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def create_safe_tar(tar_path: Path, items: list[Path]) -> None:
    with tarfile.open(tar_path, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for item in items:
            if item.is_dir():
                for root, dirs, files in os.walk(item, followlinks=False):
                    root_p = Path(root)
                    if is_excluded_path(root_p):
                        dirs[:] = []
                        continue
                    for fn in files:
                        fp = root_p / fn
                        try:
                            st = fp.lstat()
                            if stat.S_ISLNK(st.st_mode):
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
                    tf.add(item, arcname=item.name, recursive=False)
                except OSError:
                    continue


def write_outputs(ui: UI, result: TriageResult, outdir: Path, make_tar: bool, write_exhibits: bool) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    safe_node = re.sub(r"[^A-Za-z0-9_.-]+", "_", result.node)
    base = f"k8s-triage_{safe_node}_{ts_compact()}"

    json_path = outdir / f"{base}.json"
    md_path = outdir / f"{base}.md"
    exhibits_dir = outdir / f"{base}_exhibits"

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
        "exhibits_index": sorted(result.exhibits.keys()) if write_exhibits else [],
    }
    json_path.write_text(json.dumps(payload, indent=2))

    if write_exhibits and result.exhibits:
        exhibits_dir.mkdir(parents=True, exist_ok=True)
        for label, content in result.exhibits.items():
            (exhibits_dir / f"{safe_label(label)}.txt").write_text(content)

    # Markdown
    lines: list[str] = []
    lines.append(f"# k8s-triage report — `{result.node}`")
    lines.append("")
    lines.append(f"- Timestamp (UTC): `{result.timestamp}`")
    lines.append(f"- Findings: `{len(result.findings)}`")
    lines.append(f"- Exhibits written: `{bool(write_exhibits)}`")
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
    for f in sorted(result.findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.check, x.title)):
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
            for e in f.evidence[:60]:
                lines.append(e.rstrip())
            if len(f.evidence) > 60:
                lines.append(f"... ({len(f.evidence)-60} more omitted; see exhibits)")
            lines.append("```")
        lines.append("")

    if write_exhibits and result.exhibits:
        lines.append("## Exhibits")
        lines.append("")
        lines.append(f"Exhibits directory: `{exhibits_dir.name}/`")
        lines.append("")
        for label in sorted(result.exhibits.keys()):
            lines.append(f"- `{safe_label(label)}.txt`  ←  {label}")

    md_path.write_text("\n".join(lines))

    tar_path: Optional[Path] = None
    if make_tar:
        tar_path = outdir / f"{base}.tar.gz"
        items = [json_path, md_path]
        if write_exhibits and result.exhibits:
            items.append(exhibits_dir)
        create_safe_tar(tar_path, items)

    if not ui.quiet:
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
        if write_exhibits and result.exhibits:
            print(f"Wrote {exhibits_dir}")
        if tar_path:
            print(f"Wrote {tar_path}")


def print_summary(ui: UI, result: TriageResult) -> None:
    if ui.quiet:
        return
    summ = result.summary()
    if ui.use_rich:
        table = Table(title="Triage Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            table.add_row(sev.value, str(summ.get(sev.value, 0)))
        ui.console.print(table)
    else:
        print("Triage Summary:", summ)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="k8s-triage — Kubernetes Node Persistence & Compromise Triage Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="Run all node + k8s checks (best-effort)")
    mode.add_argument("--k8s-only", action="store_true", help="Run Kubernetes API checks only")
    mode.add_argument("--node-only", action="store_true", help="Run node OS checks only")

    p.add_argument("--check", action="append", default=[], help="Run a specific check (repeatable)")
    p.add_argument("--namespace", default="all", help="Namespace for k8s checks (or 'all')")
    p.add_argument("--context", default=None, help="kubeconfig context name (optional)")
    p.add_argument("--output", default="./triage_out", help="Output directory")
    p.add_argument("--no-tar", action="store_true", help="Do not produce a tar.gz bundle")

    # Output silencing / UX
    p.add_argument("--quiet", action="store_true", help="No finding lines; only writes reports")
    p.add_argument("--min-severity", choices=[s.value for s in Severity], default="info", help="Minimum severity to PRINT (reports still contain all findings)")
    p.add_argument("--plain", action="store_true", help="Disable rich output even if installed")
    p.add_argument("--no-section-headers", action="store_true", help="Suppress section header rules")
    p.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")

    # Exhibit controls
    p.add_argument("--no-exhibits", action="store_true", help="Do not write exhibits to disk (findings still written)")
    p.add_argument("--exhibit-max-bytes", type=int, default=2_000_000, help="Max bytes per exhibit")
    p.add_argument("--drop-exhibit", action="append", default=[], help="Regex (repeatable) to skip exhibit labels (e.g. '^logs:' or 'network:established')")

    # Risky / sensitive
    p.add_argument("--include-secret-data", action="store_true", help="Include secret data (base64 as returned by API). DEFAULT OFF for safety.")

    # Usefulness knobs
    p.add_argument("--hotspot-hours", type=int, default=72, help="How far back to look for new executables in hotspots")

    return p.parse_args()


def run_node(ui: UI, result: TriageResult, xp: ExhibitPolicy, checks: list[str], hotspot_hours: int) -> None:
    ui.section("NODE CHECKS")
    for name in checks:
        fn = NODE_CHECKS.get(name)
        if not fn:
            emit(ui, result, name, Severity.INFO, f"Unknown check: {name}", "Skipping")
            continue
        try:
            if name == "hotspots":
                fn(ui, result, xp, hotspot_hours)  # type: ignore[misc]
            else:
                fn(ui, result, xp)  # type: ignore[misc]
        except Exception as e:
            emit(ui, result, name, Severity.INFO, f"Check failed: {name}", str(e))


def run_k8s(ui: UI, result: TriageResult, xp: ExhibitPolicy, checks: list[str], namespace: str, context: Optional[str], include_secret_data: bool) -> None:
    ui.section("K8S API CHECKS")
    tup = k8s_load_client(context)
    if not tup:
        emit(ui, result, "k8s", Severity.INFO, "Kubernetes client not available / config not loaded", "Install kubernetes python client and ensure kubeconfig is accessible")
        return
    v1, rbac, _apps = tup

    for name in checks:
        fn = K8S_CHECKS.get(name)
        if not fn:
            emit(ui, result, name, Severity.INFO, f"Unknown check: {name}", "Skipping")
            continue
        try:
            if name == "k8s_pods":
                fn(ui, result, xp, v1, namespace)  # type: ignore[misc]
            elif name == "k8s_rbac":
                fn(ui, result, xp, rbac, namespace)  # type: ignore[misc]
            elif name == "k8s_sa":
                fn(ui, result, xp, v1, namespace)  # type: ignore[misc]
            elif name == "k8s_secrets":
                fn(ui, result, xp, v1, namespace, include_secret_data)  # type: ignore[misc]
        except Exception as e:
            emit(ui, result, name, Severity.INFO, f"Check failed: {name}", str(e))


def main() -> int:
    args = parse_args()

    ui = UI(
        use_rich=(not args.plain),
        quiet=args.quiet,
        min_severity=Severity(args.min_severity),
        show_sections=(not args.no_section_headers),
        show_banner=(not args.no_banner),
    )
    ui.banner()

    xp = ExhibitPolicy(
        enabled=(not args.no_exhibits),
        max_bytes=int(args.exhibit_max_bytes),
        drop_patterns=[re.compile(p) for p in args.drop_exhibit],
    )

    node = get_node_name()
    result = TriageResult(node=node, timestamp=iso_utc_now())

    requested = [c.strip() for c in (args.check or []) if c and c.strip()]
    if requested:
        node_checks = [c for c in requested if c in NODE_CHECKS]
        k8s_checks = [c for c in requested if c in K8S_CHECKS]
    else:
        node_checks = list(NODE_CHECKS.keys())
        k8s_checks = list(K8S_CHECKS.keys())

    do_node = args.all or args.node_only or (not args.k8s_only)
    do_k8s = args.all or args.k8s_only

    if requested:
        do_node = bool(node_checks)
        do_k8s = bool(k8s_checks)

    if do_node:
        run_node(ui, result, xp, node_checks, hotspot_hours=int(args.hotspot_hours))

    if do_k8s:
        run_k8s(ui, result, xp, k8s_checks, namespace=args.namespace, context=args.context, include_secret_data=args.include_secret_data)

    print_summary(ui, result)

    write_outputs(
        ui=ui,
        result=result,
        outdir=Path(args.output),
        make_tar=(not args.no_tar),
        write_exhibits=(not args.no_exhibits),
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
