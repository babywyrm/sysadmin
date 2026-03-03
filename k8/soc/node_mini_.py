#!/usr/bin/env python3
"""
k8s-triage — Kubernetes Node Persistence & Compromise Triage Tool ..mini..
Refactored for 2026 Standards.. (lol)..
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import pwd
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

# Dependency Handling
try:
    from kubernetes import client, config
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

# --- Data Models ---

class Severity(str, Enum):
    INFO = "info"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    mitre: Optional[str] = None

class TriageResult:
    def __init__(self):
        self.node = socket.gethostname()
        self.timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.findings: list[Finding] = []
        self.exhibits: dict[str, str] = {}

    def add_finding(self, f: Finding): self.findings.append(f)
    def add_exhibit(self, lbl: str, ctx: str): self.exhibits[lbl] = ctx

# --- Utility Helpers ---

def run(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=10)
    except: return ""

def emit(res: TriageResult, check: str, sev: Severity, title: str, detail: str, evidence: list[str] = None, mitre: str = None):
    f = Finding(check, sev, title, detail, evidence or [], mitre)
    res.add_finding(f)
    color = {"info":"blue","low":"green","medium":"yellow","high":"red","critical":"bold red"}.get(sev.value, "white")
    if RICH_AVAILABLE:
        console.print(f"[{color}][{sev.upper()}][/{color}] {title}")
    else:
        print(f"[{sev.upper()}] {title}")

# --- Node OS Forensic Checks ---

def check_cron(res: TriageResult):
    paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
    keywords = ["/dev/tcp", "nc ", "ncat", "bash -i", "python", "curl", "wget"]
    for p in paths:
        path = Path(p)
        if not path.exists(): continue
        for f in ([path] if path.is_file() else path.glob("*")):
            try:
                content = f.read_text()
                res.add_exhibit(f"cron_{f.name}", content)
                hits = [l for l in content.splitlines() if any(k in l for k in keywords)]
                if hits:
                    emit(res, "cron", Severity.CRITICAL, f"Suspicious Cron: {f.name}", "Shell/Network indicators found", hits, "T1053.003")
            except: pass

def check_users(res: TriageResult):
    uids = [u.pw_name for u in pwd.getpwall() if u.pw_uid == 0]
    if len(uids) > 1:
        emit(res, "users", Severity.CRITICAL, "Multiple UID 0 users", f"Found: {uids}", uids, "T1136.001")
    
    for u in pwd.getpwall():
        ak = Path(u.pw_dir) / ".ssh" / "authorized_keys"
        if ak.exists():
            res.add_exhibit(f"ssh_{u.pw_name}", ak.read_text())
            emit(res, "users", Severity.MEDIUM, f"SSH Keys: {u.pw_name}", "Keys found in authorized_keys")

def check_suid(res: TriageResult):
    cmd = ["find", "/", "-xdev", "-perm", "-4000", "-type", "f"]
    found = run(cmd).splitlines()
    known = {"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/chsh"}
    for f in found:
        if f not in known:
            emit(res, "suid", Severity.HIGH, f"Unknown SUID: {f}", "Potential persistence/privesc", [f], "T1548.001")

def check_network(res: TriageResult):
    ss = run(["ss", "-tulpn"])
    res.add_exhibit("net_listeners", ss)
    for line in ss.splitlines():
        if any(p in line for p in [":4444", ":1337", ":8080", ":9001"]):
            emit(res, "net", Severity.HIGH, "Suspicious Listener", line, [line], "T1049")

def check_runtime(res: TriageResult):
    socks = ["/var/run/docker.sock", "/run/containerd/containerd.sock"]
    for s in socks:
        p = Path(s)
        if p.exists():
            mode = stat.S_IMODE(p.stat().st_mode)
            if mode & 0o002: # World writable
                emit(res, "runtime", Severity.CRITICAL, f"Socket World Writable: {s}", "Escape risk", mitre="T1611")

# --- Kubernetes API Checks ---

def check_k8s(res: TriageResult, ns: str):
    if not K8S_AVAILABLE: return
    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces().items if ns == "all" else v1.list_namespaced_pod(ns).items
        for p in pods:
            for c in p.spec.containers:
                if c.security_context and c.security_context.privileged:
                    emit(res, "k8s", Severity.CRITICAL, f"Privileged Pod: {p.metadata.name}", f"NS: {p.metadata.namespace}", mitre="T1611")
    except: pass

# --- Execution & Reporting ---

def main():
    parser = argparse.ArgumentParser(description="k8s-triage 2026")
    parser.add_argument("--ns", default="all", help="K8s Namespace")
    parser.add_argument("--out", default="./triage_results", help="Output Dir")
    args = parser.parse_args()

    if RICH_AVAILABLE:
        console.print(Panel("K8S TRIAGE - INCIDENT RESPONSE EXHIBIT", style="bold blue"))

    res = TriageResult()
    
    # Run Checks
    print("[*] Checking Cron...")
    check_cron(res)
    print("[*] Checking Users...")
    check_users(res)
    print("[*] Checking SUID...")
    check_suid(res)
    print("[*] Checking Network...")
    check_network(res)
    print("[*] Checking Runtime...")
    check_runtime(res)
    print("[*] Checking K8s API...")
    check_k8s(res, args.ns)

    # Save Results
    out = Path(args.out)
    out.mkdir(exist_ok=True)
    
    # JSON Report
    report = {
        "node": res.node, "time": res.timestamp,
        "findings": [f.__dict__ for f in res.findings]
    }
    (out / "report.json").write_text(json.dumps(report, indent=2))
    
    # Exhibits
    with tarfile.open(out / "exhibits.tar.gz", "w:gz") as tar:
        for name, content in res.exhibits.items():
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
                tf.write(content)
                temp_path = tf.name
            tar.add(temp_path, arcname=f"{name}.txt")
            os.unlink(temp_path)

    print(f"\n[+] Triage Complete. Results in: {args.out}")

if __name__ == "__main__":
    main()
