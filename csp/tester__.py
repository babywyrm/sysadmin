#!/usr/bin/env python3
"""
csp_eval_2026.py

Modern CSP evaluator for 2026-era security posture checks.

Usage:
    python3 csp_eval_2026.py https://example.com
    python3 csp_eval_2026.py https://example.com --json
    python3 csp_eval_2026.py https://example.com --inspect-html

Requirements:
    pip install requests beautifulsoup4
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional

import requests
from bs4 import BeautifulSoup


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    recommendation: str


@dataclass
class EvaluationResult:
    url: str
    status_code: int
    enforced_csp: Optional[str]
    report_only_csp: Optional[str]
    findings: List[Finding]
    summary: Dict[str, int]


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate CSP headers and common 2026-era CSP weaknesses."
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable output",
    )
    parser.add_argument(
        "--inspect-html",
        action="store_true",
        help="Inspect returned HTML for inline script/event-handler usage",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification",
    )
    return parser.parse_args()


def split_csp(policy: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for chunk in policy.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        name = parts[0].strip().lower()
        values = [p.strip() for p in parts[1:]]
        directives[name] = values
    return directives


def has_nonce_or_hash(values: List[str]) -> bool:
    for value in values:
        if value.startswith("'nonce-"):
            return True
        if value.startswith("'sha256-") or value.startswith("'sha384-") or value.startswith("'sha512-"):
            return True
    return False


def count_allowlist_hosts(values: List[str]) -> int:
    count = 0
    for value in values:
        if value.startswith("'"):
            continue
        if value.endswith(":"):
            continue
        count += 1
    return count


def has_keyword(values: List[str], keyword: str) -> bool:
    return keyword in values


def add_finding(
    findings: List[Finding],
    severity: str,
    category: str,
    message: str,
    recommendation: str,
) -> None:
    findings.append(
        Finding(
            severity=severity,
            category=category,
            message=message,
            recommendation=recommendation,
        )
    )


def evaluate_csp(policy: str, findings: List[Finding], source: str = "enforced") -> None:
    directives = split_csp(policy)

    script_src = directives.get("script-src")
    default_src = directives.get("default-src", [])
    object_src = directives.get("object-src")
    base_uri = directives.get("base-uri")
    frame_ancestors = directives.get("frame-ancestors")
    trusted_types = directives.get("require-trusted-types-for")
    style_src = directives.get("style-src", [])
    connect_src = directives.get("connect-src", [])
    img_src = directives.get("img-src", [])
    form_action = directives.get("form-action")

    if not script_src:
        if default_src:
            add_finding(
                findings,
                "MEDIUM",
                "policy-structure",
                f"{source}: script-src is missing; default-src will apply as fallback",
                "Prefer an explicit script-src directive for clarity and safer script control.",
            )
            script_src = default_src
        else:
            add_finding(
                findings,
                "CRITICAL",
                "policy-structure",
                f"{source}: no script-src and no default-src present",
                "Define a deny-by-default policy such as default-src 'none' and an explicit script-src.",
            )
            script_src = []

    # Core modern checks
    if not default_src:
        add_finding(
            findings,
            "LOW",
            "policy-structure",
            f"{source}: default-src is missing",
            "Prefer default-src 'none' as a deny-by-default baseline when practical.",
        )

    if object_src is None:
        add_finding(
            findings,
            "MEDIUM",
            "legacy-surface",
            f"{source}: object-src is missing",
            "Set object-src 'none' to remove legacy plugin/object/embed attack surface.",
        )
    elif object_src != ["'none'"]:
        add_finding(
            findings,
            "MEDIUM",
            "legacy-surface",
            f"{source}: object-src is not locked to 'none'",
            "Use object-src 'none' unless you have a strict and justified requirement.",
        )

    if base_uri is None:
        add_finding(
            findings,
            "MEDIUM",
            "navigation-control",
            f"{source}: base-uri is missing",
            "Set base-uri 'none' or at minimum base-uri 'self'.",
        )

    if frame_ancestors is None:
        add_finding(
            findings,
            "MEDIUM",
            "clickjacking",
            f"{source}: frame-ancestors is missing",
            "Set frame-ancestors 'none' or a minimal allowlist if framing is required.",
        )

    if form_action is None:
        add_finding(
            findings,
            "LOW",
            "navigation-control",
            f"{source}: form-action is missing",
            "Set form-action 'self' or a minimal explicit set of destinations.",
        )

    # Trusted Types
    if trusted_types is None or "'script'" not in trusted_types:
        add_finding(
            findings,
            "MEDIUM",
            "dom-xss",
            f"{source}: Trusted Types enforcement is not enabled",
            "Add require-trusted-types-for 'script' for modern DOM XSS hardening where supported by the application.",
        )

    # script-src analysis
    if has_keyword(script_src, "'unsafe-inline'"):
        add_finding(
            findings,
            "CRITICAL",
            "script-execution",
            f"{source}: script-src contains 'unsafe-inline'",
            "Remove 'unsafe-inline'. Migrate to nonces or hashes.",
        )

    if has_keyword(script_src, "'unsafe-eval'"):
        add_finding(
            findings,
            "HIGH",
            "script-execution",
            f"{source}: script-src contains 'unsafe-eval'",
            "Remove 'unsafe-eval' and eliminate eval-like code paths.",
        )

    if "*" in script_src:
        add_finding(
            findings,
            "CRITICAL",
            "allowlist",
            f"{source}: script-src contains wildcard '*'",
            "Do not use wildcard trust in script-src. Move to nonce/hash-based trust.",
        )

    if "data:" in script_src:
        add_finding(
            findings,
            "CRITICAL",
            "allowlist",
            f"{source}: script-src allows data:",
            "Do not allow data: in script-src.",
        )

    if "blob:" in script_src:
        add_finding(
            findings,
            "MEDIUM",
            "allowlist",
            f"{source}: script-src allows blob:",
            "Only allow blob: if you have a strong and validated requirement.",
        )

    if "http:" in script_src:
        add_finding(
            findings,
            "HIGH",
            "transport",
            f"{source}: script-src allows http:",
            "Do not allow insecure transport for executable content.",
        )

    if "https:" in script_src and not has_nonce_or_hash(script_src) and not has_keyword(script_src, "'strict-dynamic'"):
        add_finding(
            findings,
            "HIGH",
            "allowlist",
            f"{source}: script-src trusts broad https: scheme without nonce/hash/strict-dynamic",
            "Avoid scheme-wide trust. Use nonce/hash-based trust and strict-dynamic where possible.",
        )

    has_nonce_hash = has_nonce_or_hash(script_src)
    has_strict_dynamic = has_keyword(script_src, "'strict-dynamic'")

    if has_nonce_hash and not has_strict_dynamic:
        add_finding(
            findings,
            "LOW",
            "modernization",
            f"{source}: nonce/hash present, but strict-dynamic is absent",
            "Consider adding 'strict-dynamic' for modern script trust propagation if your browser support and app model allow it.",
        )

    if not has_nonce_hash and count_allowlist_hosts(script_src) > 0:
        add_finding(
            findings,
            "MEDIUM",
            "allowlist",
            f"{source}: script-src appears allowlist-heavy without nonce/hash trust",
            "Prefer nonce/hash-based trust over broad host allowlists.",
        )

    if has_nonce_hash:
        add_finding(
            findings,
            "INFO",
            "modernization",
            f"{source}: script-src uses nonce/hash-based trust",
            "Good. Ensure nonces are per-request and not reused across responses.",
        )

    if has_strict_dynamic:
        add_finding(
            findings,
            "INFO",
            "modernization",
            f"{source}: script-src uses strict-dynamic",
            "Good. Validate that trusted loader scripts are tightly controlled.",
        )

    # style-src analysis
    if has_keyword(style_src, "'unsafe-inline'"):
        add_finding(
            findings,
            "LOW",
            "style-policy",
            f"{source}: style-src contains 'unsafe-inline'",
            "Avoid inline styles if possible; consider nonce/hash or a stylesheet-only model.",
        )

    # connect-src analysis
    if connect_src and "*" in connect_src:
        add_finding(
            findings,
            "MEDIUM",
            "exfiltration-surface",
            f"{source}: connect-src contains wildcard '*'",
            "Restrict connect-src to the minimum necessary set of endpoints.",
        )

    # img-src analysis
    if img_src and "*" in img_src:
        add_finding(
            findings,
            "LOW",
            "resource-policy",
            f"{source}: img-src contains wildcard '*'",
            "Reduce broad image trust where practical.",
        )


def inspect_html_for_policy_mismatch(html: str, findings: List[Finding]) -> None:
    soup = BeautifulSoup(html, "html.parser")

    scripts = soup.find_all("script")
    inline_scripts = []
    nonce_scripts = 0

    for script in scripts:
        if script.get("nonce"):
            nonce_scripts += 1
        if not script.get("src") and script.text.strip():
            inline_scripts.append(script.text.strip()[:120])

    if inline_scripts:
        add_finding(
            findings,
            "MEDIUM",
            "html-inline-script",
            f"HTML contains {len(inline_scripts)} inline <script> block(s)",
            "If CSP is intended to be strict, ensure inline scripts use per-request nonces or hashes.",
        )

    event_handler_count = 0
    javascript_url_count = 0

    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if attr.lower().startswith("on"):
                event_handler_count += 1
            if isinstance(value, str) and value.lower().startswith("javascript:"):
                javascript_url_count += 1

    if event_handler_count:
        add_finding(
            findings,
            "HIGH",
            "html-inline-handler",
            f"HTML contains {event_handler_count} inline event handler attribute(s)",
            "Inline event handlers are incompatible with a strong modern CSP unless unsafe-inline/unsafe-hashes patterns are used.",
        )

    if javascript_url_count:
        add_finding(
            findings,
            "HIGH",
            "html-javascript-url",
            f"HTML contains {javascript_url_count} javascript: URL(s)",
            "Remove javascript: URLs; they are risky and incompatible with strong CSP posture.",
        )

    if nonce_scripts:
        add_finding(
            findings,
            "INFO",
            "html-nonce",
            f"HTML contains {nonce_scripts} script tag(s) with nonce attributes",
            "Good sign for nonce-based CSP if the nonce values are per-request and match the CSP header.",
        )


def summarize(findings: List[Finding]) -> Dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)


def fetch(url: str, timeout: int, verify: bool) -> requests.Response:
    headers = {
        "User-Agent": "csp-eval-2026/1.0"
    }
    return requests.get(url, headers=headers, timeout=timeout, verify=verify, allow_redirects=True)


def evaluate_url(url: str, inspect_html: bool, timeout: int, verify: bool) -> EvaluationResult:
    response = fetch(url, timeout=timeout, verify=verify)

    enforced_csp = response.headers.get("Content-Security-Policy")
    report_only_csp = response.headers.get("Content-Security-Policy-Report-Only")

    findings: List[Finding] = []

    if not enforced_csp and not report_only_csp:
        add_finding(
            findings,
            "CRITICAL",
            "missing-csp",
            "No CSP header present (neither enforced nor report-only)",
            "Deploy an enforced CSP. Use report-only only as a migration phase.",
        )

    if enforced_csp:
        evaluate_csp(enforced_csp, findings, source="enforced")

    if report_only_csp:
        evaluate_csp(report_only_csp, findings, source="report-only")
        if not enforced_csp:
            add_finding(
                findings,
                "HIGH",
                "deployment-state",
                "Only Content-Security-Policy-Report-Only is present; no enforced CSP detected",
                "Move to an enforced CSP once violations are understood and remediated.",
            )

    if inspect_html and "text/html" in response.headers.get("Content-Type", ""):
        inspect_html_for_policy_mismatch(response.text, findings)

    findings = sort_findings(findings)
    summary = summarize(findings)

    return EvaluationResult(
        url=response.url,
        status_code=response.status_code,
        enforced_csp=enforced_csp,
        report_only_csp=report_only_csp,
        findings=findings,
        summary=summary,
    )


def print_human(result: EvaluationResult) -> None:
    print("=" * 72)
    print("CSP Evaluation Report")
    print("=" * 72)
    print(f"URL          : {result.url}")
    print(f"Status       : {result.status_code}")
    print(f"Enforced CSP : {'present' if result.enforced_csp else 'absent'}")
    print(f"Report-Only  : {'present' if result.report_only_csp else 'absent'}")
    print()

    print("Summary")
    print("-" * 72)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"{sev:<10} : {result.summary[sev]}")
    print()

    if result.enforced_csp:
        print("Enforced CSP")
        print("-" * 72)
        print(result.enforced_csp)
        print()

    if result.report_only_csp:
        print("Report-Only CSP")
        print("-" * 72)
        print(result.report_only_csp)
        print()

    print("Findings")
    print("-" * 72)
    if not result.findings:
        print("No findings.")
        return

    for idx, finding in enumerate(result.findings, 1):
        print(f"[{idx}] {finding.severity} :: {finding.category}")
        print(f"    Issue : {finding.message}")
        print(f"    Fix   : {finding.recommendation}")
        print()


def print_json(result: EvaluationResult) -> None:
    payload = {
        "url": result.url,
        "status_code": result.status_code,
        "enforced_csp": result.enforced_csp,
        "report_only_csp": result.report_only_csp,
        "summary": result.summary,
        "findings": [asdict(f) for f in result.findings],
    }
    print(json.dumps(payload, indent=2))


def main() -> int:
    args = parse_args()

    try:
        result = evaluate_url(
            url=args.url,
            inspect_html=args.inspect_html,
            timeout=args.timeout,
            verify=not args.insecure,
        )
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print_json(result)
    else:
        print_human(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
