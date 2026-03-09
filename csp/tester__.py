#!/usr/bin/env python3
"""
csp_eval.py

A modern, lightweight Content Security Policy evaluator.

Features:
- Evaluates enforced and report-only CSP headers
- Checks common 2026 CSP weaknesses and anti-patterns
- Optional HTML inspection for:
  - inline <script> blocks
  - inline event handlers
  - javascript: URLs
- Human-readable aligned output
- JSON output for pipelines/CI

Usage:
    python3 csp_eval.py https://example.com
    python3 csp_eval.py https://example.com --inspect-html
    python3 csp_eval.py https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


class Severity(IntEnum):
    """Severity levels for findings."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass(slots=True)
class Finding:
    """A single CSP-related finding."""

    severity: Severity
    category: str
    source: str
    message: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.label,
            "category": self.category,
            "source": self.source,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass(slots=True)
class Result:
    """Full evaluation result for a target URL."""

    url: str
    status_code: int
    content_type: str
    enforced_csp: Optional[str]
    report_only_csp: Optional[str]
    findings: list[Finding]
    score: int
    grade: str

    def summary(self) -> dict[str, int]:
        counts = {sev.label: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "enforced_csp": self.enforced_csp,
            "report_only_csp": self.report_only_csp,
            "score": self.score,
            "grade": self.grade,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }


class Color:
    """Minimal ANSI color helper."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"


class Renderer:
    """Render results as aligned text or JSON."""

    def __init__(self, use_color: bool) -> None:
        self.use_color = use_color and sys.stdout.isatty()

    def colorize(self, text: str, *codes: str) -> str:
        if not self.use_color or not codes:
            return text
        return "".join(codes) + text + Color.RESET

    def severity_text(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: self.colorize("CRITICAL", Color.BOLD, Color.RED),
            Severity.HIGH: self.colorize("HIGH", Color.RED),
            Severity.MEDIUM: self.colorize("MEDIUM", Color.YELLOW),
            Severity.LOW: self.colorize("LOW", Color.BLUE),
            Severity.INFO: self.colorize("INFO", Color.GREEN),
        }
        return mapping[severity]

    def render_json(self, result: Result) -> None:
        print(json.dumps(result.to_dict(), indent=2))

    def render_text(self, result: Result) -> None:
        print("=" * 78)
        print("CSP Evaluation Report")
        print("=" * 78)
        print(f"{'URL':<14}{result.url}")
        print(f"{'Status':<14}{result.status_code}")
        print(f"{'Content-Type':<14}{result.content_type or 'unknown'}")
        print(
            f"{'Enforced CSP':<14}"
            f"{'present' if result.enforced_csp else 'absent'}"
        )
        print(
            f"{'Report-Only':<14}"
            f"{'present' if result.report_only_csp else 'absent'}"
        )
        print(f"{'Score':<14}{result.score}")
        print(f"{'Grade':<14}{result.grade}")
        print()

        print("Summary")
        print("-" * 78)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            print(f"{sev:<14}{result.summary()[sev]}")
        print()

        if result.enforced_csp:
            print("Enforced CSP")
            print("-" * 78)
            print(result.enforced_csp)
            print()

        if result.report_only_csp:
            print("Report-Only CSP")
            print("-" * 78)
            print(result.report_only_csp)
            print()

        print("Findings")
        print("-" * 78)
        if not result.findings:
            print("No findings.")
            return

        for index, finding in enumerate(result.findings, start=1):
            sev = self.severity_text(finding.severity)
            print(
                f"[{index}] {sev:<12} "
                f"{finding.category:<20} "
                f"{finding.source:<12}"
            )
            print(f"     {'Issue':<8}{finding.message}")
            print(f"     {'Fix':<8}{finding.recommendation}")
            print()


class CspEvaluator:
    """Evaluate a target response for CSP posture and common weaknesses."""

    def __init__(
        self,
        timeout: int = 10,
        verify_tls: bool = True,
        inspect_html: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.inspect_html = inspect_html
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "csp-eval/2026"})

    def evaluate(self, url: str) -> Result:
        response = self.session.get(
            url,
            timeout=self.timeout,
            verify=self.verify_tls,
            allow_redirects=True,
        )

        enforced_csp = response.headers.get("Content-Security-Policy")
        report_only_csp = response.headers.get("Content-Security-Policy-Report-Only")
        content_type = response.headers.get("Content-Type", "")

        findings: list[Finding] = []

        if not enforced_csp and not report_only_csp:
            self._add(
                findings,
                Severity.CRITICAL,
                "missing-csp",
                "headers",
                "No CSP header present",
                "Deploy an enforced CSP. Use report-only only during migration.",
            )

        if enforced_csp:
            self._evaluate_policy(enforced_csp, findings, "enforced")

        if report_only_csp:
            self._evaluate_policy(report_only_csp, findings, "report-only")
            if not enforced_csp:
                self._add(
                    findings,
                    Severity.HIGH,
                    "deployment-state",
                    "report-only",
                    "Only Content-Security-Policy-Report-Only is present",
                    "Move to an enforced CSP after validation and rollout testing.",
                )

        if self.inspect_html and "text/html" in content_type:
            self._inspect_html(response.text, findings)

        findings.sort(key=lambda item: int(item.severity), reverse=True)
        score, grade = self._score(findings)

        return Result(
            url=response.url,
            status_code=response.status_code,
            content_type=content_type,
            enforced_csp=enforced_csp,
            report_only_csp=report_only_csp,
            findings=findings,
            score=score,
            grade=grade,
        )

    def _add(
        self,
        findings: list[Finding],
        severity: Severity,
        category: str,
        source: str,
        message: str,
        recommendation: str,
    ) -> None:
        findings.append(
            Finding(
                severity=severity,
                category=category,
                source=source,
                message=message,
                recommendation=recommendation,
            )
        )

    def _parse_policy(self, policy: str) -> dict[str, list[str]]:
        directives: dict[str, list[str]] = {}
        for chunk in policy.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split()
            directives[parts[0].lower()] = [p.strip() for p in parts[1:]]
        return directives

    def _has_nonce_or_hash(self, values: list[str]) -> bool:
        return any(
            value.startswith("'nonce-")
            or value.startswith("'sha256-")
            or value.startswith("'sha384-")
            or value.startswith("'sha512-'")
            for value in values
        )

    def _count_allowlist_hosts(self, values: list[str]) -> int:
        count = 0
        for value in values:
            if value.startswith("'"):
                continue
            if value.endswith(":"):
                continue
            count += 1
        return count

    def _evaluate_policy(
        self,
        policy: str,
        findings: list[Finding],
        source: str,
    ) -> None:
        directives = self._parse_policy(policy)

        script_src = directives.get("script-src")
        default_src = directives.get("default-src", [])
        style_src = directives.get("style-src", [])
        connect_src = directives.get("connect-src", [])
        object_src = directives.get("object-src")
        base_uri = directives.get("base-uri")
        frame_ancestors = directives.get("frame-ancestors")
        trusted_types = directives.get("require-trusted-types-for")
        form_action = directives.get("form-action")

        if not script_src:
            if default_src:
                self._add(
                    findings,
                    Severity.MEDIUM,
                    "policy-structure",
                    source,
                    "script-src is missing; default-src will apply",
                    "Prefer an explicit script-src directive for clarity and safer control.",
                )
                script_src = default_src
            else:
                self._add(
                    findings,
                    Severity.CRITICAL,
                    "policy-structure",
                    source,
                    "No script-src and no default-src present",
                    "Define default-src 'none' and an explicit script-src.",
                )
                script_src = []

        if not default_src:
            self._add(
                findings,
                Severity.LOW,
                "policy-structure",
                source,
                "default-src is missing",
                "Prefer default-src 'none' as a deny-by-default baseline.",
            )

        if object_src is None:
            self._add(
                findings,
                Severity.MEDIUM,
                "legacy-surface",
                source,
                "object-src is missing",
                "Set object-src 'none'.",
            )
        elif object_src != ["'none'"]:
            self._add(
                findings,
                Severity.MEDIUM,
                "legacy-surface",
                source,
                "object-src is not locked to 'none'",
                "Use object-src 'none' unless absolutely required.",
            )

        if base_uri is None:
            self._add(
                findings,
                Severity.MEDIUM,
                "navigation-control",
                source,
                "base-uri is missing",
                "Set base-uri 'none' or base-uri 'self'.",
            )

        if frame_ancestors is None:
            self._add(
                findings,
                Severity.MEDIUM,
                "clickjacking",
                source,
                "frame-ancestors is missing",
                "Set frame-ancestors 'none' or a minimal explicit allowlist.",
            )

        if form_action is None:
            self._add(
                findings,
                Severity.LOW,
                "navigation-control",
                source,
                "form-action is missing",
                "Set form-action 'self' or a minimal explicit list of destinations.",
            )

        if trusted_types is None or "'script'" not in trusted_types:
            self._add(
                findings,
                Severity.MEDIUM,
                "dom-xss",
                source,
                "Trusted Types enforcement is not enabled",
                "Consider require-trusted-types-for 'script' for modern DOM XSS hardening.",
            )

        if "'unsafe-inline'" in script_src:
            self._add(
                findings,
                Severity.CRITICAL,
                "script-execution",
                source,
                "script-src contains 'unsafe-inline'",
                "Remove 'unsafe-inline'. Use nonces or hashes instead.",
            )

        if "'unsafe-eval'" in script_src:
            self._add(
                findings,
                Severity.HIGH,
                "script-execution",
                source,
                "script-src contains 'unsafe-eval'",
                "Remove 'unsafe-eval' and eliminate eval-like code paths.",
            )

        if "*" in script_src:
            self._add(
                findings,
                Severity.CRITICAL,
                "allowlist",
                source,
                "script-src contains wildcard '*'",
                "Do not use wildcard trust in script-src.",
            )

        if "data:" in script_src:
            self._add(
                findings,
                Severity.CRITICAL,
                "allowlist",
                source,
                "script-src allows data:",
                "Do not allow data: in script-src.",
            )

        if "blob:" in script_src:
            self._add(
                findings,
                Severity.MEDIUM,
                "allowlist",
                source,
                "script-src allows blob:",
                "Allow blob: only if you have a strong validated requirement.",
            )

        if "http:" in script_src:
            self._add(
                findings,
                Severity.HIGH,
                "transport",
                source,
                "script-src allows http:",
                "Do not allow insecure transport for executable content.",
            )

        has_nonce_or_hash = self._has_nonce_or_hash(script_src)
        has_strict_dynamic = "'strict-dynamic'" in script_src

        if "https:" in script_src and not has_nonce_or_hash and not has_strict_dynamic:
            self._add(
                findings,
                Severity.HIGH,
                "allowlist",
                source,
                "script-src trusts broad https: scheme without nonce/hash/strict-dynamic",
                "Avoid scheme-wide trust. Prefer nonce/hash-based trust.",
            )

        if not has_nonce_or_hash and self._count_allowlist_hosts(script_src) > 0:
            self._add(
                findings,
                Severity.MEDIUM,
                "allowlist",
                source,
                "script-src is allowlist-heavy without nonce/hash trust",
                "Prefer nonces or hashes over broad host allowlists.",
            )

        if has_nonce_or_hash:
            self._add(
                findings,
                Severity.INFO,
                "modernization",
                source,
                "script-src uses nonce/hash-based trust",
                "Ensure nonces are unpredictable and generated per response.",
            )

        if has_nonce_or_hash and not has_strict_dynamic:
            self._add(
                findings,
                Severity.LOW,
                "modernization",
                source,
                "nonce/hash is present, but strict-dynamic is absent",
                "Consider adding 'strict-dynamic' where compatible.",
            )

        if has_strict_dynamic:
            self._add(
                findings,
                Severity.INFO,
                "modernization",
                source,
                "script-src uses strict-dynamic",
                "Validate that only trusted bootstrap scripts can load descendants.",
            )

        if "'unsafe-inline'" in style_src:
            self._add(
                findings,
                Severity.LOW,
                "style-policy",
                source,
                "style-src contains 'unsafe-inline'",
                "Avoid inline styles where practical.",
            )

        if connect_src and "*" in connect_src:
            self._add(
                findings,
                Severity.MEDIUM,
                "exfiltration-surface",
                source,
                "connect-src contains wildcard '*'",
                "Restrict connect-src to the minimum required endpoints.",
            )

    def _inspect_html(self, html: str, findings: list[Finding]) -> None:
        soup = BeautifulSoup(html, "html.parser")

        inline_scripts = 0
        inline_handlers = 0
        javascript_urls = 0

        for script in soup.find_all("script"):
            if not script.get("src") and script.text.strip():
                inline_scripts += 1

        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.lower().startswith("on"):
                    inline_handlers += 1
                if isinstance(value, str) and value.lower().startswith("javascript:"):
                    javascript_urls += 1

        if inline_scripts:
            self._add(
                findings,
                Severity.MEDIUM,
                "html-inline-script",
                "html",
                f"HTML contains {inline_scripts} inline <script> block(s)",
                "Eliminate inline scripts or protect them with nonces/hashes.",
            )

        if inline_handlers:
            self._add(
                findings,
                Severity.HIGH,
                "html-inline-handler",
                "html",
                f"HTML contains {inline_handlers} inline event handler attribute(s)",
                "Remove inline event handlers and move logic into script files.",
            )

        if javascript_urls:
            self._add(
                findings,
                Severity.HIGH,
                "html-javascript-url",
                "html",
                f"HTML contains {javascript_urls} javascript: URL(s)",
                "Remove javascript: URLs and replace them with safe handlers/navigation.",
            )

    def _score(self, findings: list[Finding]) -> tuple[int, str]:
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        score = 100
        for finding in findings:
            score -= penalties[finding.severity]
        score = max(score, 0)

        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return score, grade


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Professional CSP evaluator for modern web applications."
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument(
        "--inspect-html",
        action="store_true",
        help="Inspect returned HTML for inline script/event-handler issues",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output",
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
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output",
    )
    return parser.parse_args()


def main() -> int:
    """Entrypoint."""
    args = parse_args()

    evaluator = CspEvaluator(
        timeout=args.timeout,
        verify_tls=not args.insecure,
        inspect_html=args.inspect_html,
    )
    renderer = Renderer(use_color=not args.no_color)

    try:
        result = evaluator.evaluate(args.url)
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        renderer.render_json(result)
    else:
        renderer.render_text(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
