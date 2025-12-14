#!/usr/bin/env python3
"""
mcp_stride.py ..testing..

Single-file STRIDE + MITRE ATT&CK analysis helper for
Model Context Protocol (MCP) used as a Kubernetes control plane.

- Deterministic
- GitHub-friendly Markdown output
- Red / Blue / Purple team usable
"""

import argparse
import yaml
from dataclasses import dataclass, field
from typing import List, Dict


# -----------------------------
# Data Models
# -----------------------------

@dataclass
class Component:
    name: str
    type: str                 # ai, mcp, controller, api, crd, registry
    trust: str                # trusted | untrusted
    permissions: List[str] = field(default_factory=list)


@dataclass
class Threat:
    stride: str               # S, T, R, I, D, E
    title: str
    description: str
    impact: str
    mitigations: List[str]
    mitre: List[str]


# -----------------------------
# STRIDE + MITRE Knowledge Base
# -----------------------------

STRIDE_THREATS: List[Threat] = [
    Threat(
        stride="S",
        title="Identity Spoofing",
        description="Impersonation of AI agent, MCP client, or tool identity",
        impact="Unauthorized actions and policy bypass",
        mitigations=[
            "mTLS or SPIFFE identities",
            "Short-lived service account tokens",
            "Explicit identity binding"
        ],
        mitre=["T1078", "T1134"]
    ),
    Threat(
        stride="T",
        title="State or Policy Tampering",
        description="Unauthorized modification of CRDs or MCP policies",
        impact="Infrastructure mutation or arbitrary execution",
        mitigations=[
            "Admission webhooks",
            "Immutable CRDs after creation",
            "GitOps-managed policies"
        ],
        mitre=["T1578", "T1601"]
    ),
    Threat(
        stride="R",
        title="Repudiation",
        description="Lack of attribution or auditability for actions",
        impact="Incident response and compliance failure",
        mitigations=[
            "Mandatory reason fields",
            "Correlation IDs",
            "Immutable audit logs"
        ],
        mitre=["T1070"]
    ),
    Threat(
        stride="I",
        title="Information Disclosure",
        description="Exposure of secrets or sensitive cluster context",
        impact="Credential theft and lateral movement",
        mitigations=[
            "Read/write separation",
            "Context redaction",
            "No secrets in MCP context"
        ],
        mitre=["T1552", "T1041"]
    ),
    Threat(
        stride="D",
        title="Denial of Service",
        description="Reconcile storms or API saturation",
        impact="Control-plane degradation or outage",
        mitigations=[
            "TTL on AIAction CRDs",
            "Retry caps and backoff",
            "Rate limiting"
        ],
        mitre=["T1499", "T1498"]
    ),
    Threat(
        stride="E",
        title="Elevation of Privilege",
        description="Controllers or tools exceeding intended authority",
        impact="Full cluster compromise",
        mitigations=[
            "Least-privilege RBAC",
            "One-controller-per-action-type",
            "Human approval for high-risk actions"
        ],
        mitre=["T1548", "T1078.004"]
    ),
]


# -----------------------------
# Analysis Logic
# -----------------------------

def analyze_components(components: List[Component]) -> List[str]:
    findings = []

    for c in components:
        if c.type == "ai" and c.trust != "untrusted":
            findings.append(
                f"[WARN] AI component '{c.name}' must be treated as untrusted input"
            )

        if c.type == "controller":
            if "*" in c.permissions:
                findings.append(
                    f"[CRITICAL] Controller '{c.name}' has wildcard permissions"
                )
            if "cluster-admin" in c.permissions:
                findings.append(
                    f"[CRITICAL] Controller '{c.name}' effectively has cluster-admin"
                )

        if c.type == "mcp" and "exec" in c.permissions:
            findings.append(
                f"[HIGH] MCP '{c.name}' appears to have execution capabilities"
            )

    return findings


# -----------------------------
# Rendering
# -----------------------------

def render_stride_table(threats: List[Threat]) -> str:
    lines = [
        "| STRIDE | Threat | Description | Impact | MITRE |",
        "|--------|--------|-------------|--------|-------|"
    ]
    for t in threats:
        lines.append(
            f"| {t.stride} | {t.title} | {t.description} | {t.impact} | {', '.join(t.mitre)} |"
        )
    return "\n".join(lines)


def render_mitigations(threats: List[Threat]) -> str:
    out = []
    for t in threats:
        out.append(f"### {t.stride} — {t.title}")
        for m in t.mitigations:
            out.append(f"- {m}")
        out.append("")
    return "\n".join(out)


# -----------------------------
# Input Loader
# -----------------------------

def load_components(path: str) -> List[Component]:
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    components = []
    for c in data.get("components", []):
        components.append(
            Component(
                name=c["name"],
                type=c["type"],
                trust=c.get("trust", "trusted"),
                permissions=c.get("permissions", []),
            )
        )
    return components


# -----------------------------
# CLI
# -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="MCP STRIDE + MITRE ATT&CK analysis tool"
    )
    parser.add_argument(
        "--architecture",
        required=True,
        help="YAML file describing MCP components"
    )
    parser.add_argument(
        "--out",
        default="mcp_stride_report.md",
        help="Output Markdown file"
    )

    args = parser.parse_args()

    components = load_components(args.architecture)
    findings = analyze_components(components)

    with open(args.out, "w") as f:
        f.write("# MCP STRIDE Threat Model Report\n\n")
        f.write("## STRIDE Overview\n\n")
        f.write(render_stride_table(STRIDE_THREATS))
        f.write("\n\n## Mitigations\n\n")
        f.write(render_mitigations(STRIDE_THREATS))
        f.write("\n\n## Architecture Findings\n\n")

        if findings:
            for finding in findings:
                f.write(f"- {finding}\n")
        else:
            f.write("- No critical findings detected\n")

    print(f"[+] Report written to {args.out}")


if __name__ == "__main__":
    main()
