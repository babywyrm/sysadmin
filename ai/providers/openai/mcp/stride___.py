#!/usr/bin/env python3
"""
mcp_stride.py ..testing..

Single-file STRIDE + MITRE ATT&CK analysis tool for
Model Context Protocol (MCP) as a Kubernetes control plane.

Features:
- STRIDE + MITRE mapping
- Architecture linting
- RBAC analysis
- CRD safety checks
- Mermaid diagram generation
- Red/Purple team CTF scaffolding
- JSON output for automation
"""

import argparse
import json
import os
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Any


# ---------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------

@dataclass
class Component:
    name: str
    type: str                 # ai, mcp, controller, api, crd
    trust: str                # trusted | untrusted
    permissions: List[str] = field(default_factory=list)


@dataclass
class Threat:
    stride: str
    title: str
    description: str
    impact: str
    mitigations: List[str]
    mitre: List[str]


# ---------------------------------------------------------------------
# STRIDE + MITRE Knowledge Base
# ---------------------------------------------------------------------

STRIDE_THREATS = [
    Threat("S", "Identity Spoofing",
           "Impersonation of AI, MCP client, or tool identity",
           "Unauthorized actions and policy bypass",
           ["mTLS / SPIFFE identities", "Short-lived tokens", "Explicit identity binding"],
           ["T1078", "T1134"]),

    Threat("T", "State or Policy Tampering",
           "Unauthorized modification of CRDs or MCP policies",
           "Infrastructure mutation or arbitrary execution",
           ["Admission webhooks", "Immutable CRDs", "GitOps policy enforcement"],
           ["T1578", "T1601"]),

    Threat("R", "Repudiation",
           "Lack of attribution or auditability",
           "Incident response and compliance failure",
           ["Correlation IDs", "Immutable audit logs"],
           ["T1070"]),

    Threat("I", "Information Disclosure",
           "Exposure of secrets or sensitive context",
           "Credential theft and lateral movement",
           ["Context redaction", "No secrets in MCP context"],
           ["T1552", "T1041"]),

    Threat("D", "Denial of Service",
           "Reconcile storms or API saturation",
           "Control-plane degradation or outage",
           ["TTL on CRDs", "Retry backoff", "Rate limiting"],
           ["T1499", "T1498"]),

    Threat("E", "Elevation of Privilege",
           "Controllers exceeding intended authority",
           "Full cluster compromise",
           ["Least-privilege RBAC", "Scoped controllers", "Human approval gates"],
           ["T1548", "T1078.004"]),
]


# ---------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------

def load_yaml(path: str) -> Any:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_components(path: str) -> List[Component]:
    data = load_yaml(path)
    comps = []
    for c in data.get("components", []):
        comps.append(Component(
            name=c["name"],
            type=c["type"],
            trust=c.get("trust", "trusted"),
            permissions=c.get("permissions", []),
        ))
    return comps


# ---------------------------------------------------------------------
# Analysis Functions
# ---------------------------------------------------------------------

def analyze_architecture(components: List[Component]) -> List[str]:
    findings = []
    for c in components:
        if c.type == "ai" and c.trust != "untrusted":
            findings.append(f"[WARN] AI '{c.name}' must be treated as untrusted input")

        if c.type == "controller":
            if "*" in c.permissions:
                findings.append(f"[CRITICAL] Controller '{c.name}' has wildcard RBAC")
            if "cluster-admin" in c.permissions:
                findings.append(f"[CRITICAL] Controller '{c.name}' is cluster-admin")

        if c.type == "mcp" and "exec" in c.permissions:
            findings.append(f"[HIGH] MCP '{c.name}' appears to support execution")

    return findings


def analyze_rbac(rbac_yaml: Dict) -> List[str]:
    findings = []
    for rule in rbac_yaml.get("rules", []):
        if "*" in rule.get("verbs", []):
            findings.append("[CRITICAL] Wildcard verb in RBAC rule")
        if "*" in rule.get("resources", []):
            findings.append("[CRITICAL] Wildcard resource in RBAC rule")
    return findings


def analyze_crds(crd_dir: str) -> List[str]:
    findings = []
    for fname in os.listdir(crd_dir):
        if not fname.endswith(".yaml"):
            continue
        crd = load_yaml(os.path.join(crd_dir, fname))
        schema = crd.get("spec", {}).get("versions", [{}])[0].get("schema", {})
        raw = json.dumps(schema)
        if "exec" in raw or "command" in raw:
            findings.append(f"[HIGH] CRD '{fname}' may allow command execution")
        if "immutable" not in raw:
            findings.append(f"[WARN] CRD '{fname}' may be mutable after creation")
    return findings


# ---------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------

def render_stride_table() -> str:
    rows = [
        "| STRIDE | Threat | Impact | MITRE |",
        "|--------|--------|--------|-------|"
    ]
    for t in STRIDE_THREATS:
        rows.append(f"| {t.stride} | {t.title} | {t.impact} | {', '.join(t.mitre)} |")
    return "\n".join(rows)


def render_mermaid() -> str:
    return """```mermaid
flowchart LR
    AI[AI Agent] --> MCP[MCP Server]
    MCP --> CRD[AIAction CRD]
    CRD --> CTRL[Controller]
    CTRL --> KAPI[Kubernetes API]
```"""


def render_ctf() -> str:
    out = ["## Red / Purple Team Exercise Plan\n"]
    for t in STRIDE_THREATS:
        out.append(f"### {t.stride} — {t.title}")
        out.append(f"- Objective: Exploit {t.description.lower()}")
        out.append(f"- MITRE: {', '.join(t.mitre)}\n")
    return "\n".join(out)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MCP STRIDE analysis tool")
    parser.add_argument("--architecture", help="Architecture YAML")
    parser.add_argument("--rbac", help="RBAC YAML")
    parser.add_argument("--crds", help="CRD directory")
    parser.add_argument("--mermaid", action="store_true")
    parser.add_argument("--ctf", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="mcp_stride_report.md")

    args = parser.parse_args()
    findings = []
    report = []

    if args.architecture:
        components = load_components(args.architecture)
        findings += analyze_architecture(components)

    if args.rbac:
        findings += analyze_rbac(load_yaml(args.rbac))

    if args.crds:
        findings += analyze_crds(args.crds)

    report.append("# MCP STRIDE Threat Model\n\n")
    report.append("## STRIDE Overview\n")
    report.append(render_stride_table() + "\n")

    if args.mermaid:
        report.append("## Architecture Diagram\n")
        report.append(render_mermaid() + "\n")

    report.append("## Findings\n")
    report.extend(f"- {f}" for f in findings) if findings else report.append("- No findings")

    if args.ctf:
        report.append("\n" + render_ctf())

    output = "\n".join(report)

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
    else:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[+] Report written to {args.out}")


if __name__ == "__main__":
    main()
