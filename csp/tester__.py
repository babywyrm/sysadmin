#!/usr/bin/env python3
"""
csp_eval_pro.py

A professional-grade CSP evaluator for modern web security reviews.

Features:
- Evaluates enforced and report-only CSP headers
- Parses and analyzes CSP directives
- Inspects returned HTML for:
  - inline scripts
  - inline event handlers
  - javascript: URLs
  - external scripts
  - missing SRI on third-party scripts
  - nonce usage
- Optional nonce reuse sampling across multiple requests
- Human-readable colorized output
- JSON output for automation

Example usage:
    python3 csp_eval_pro.py https://example.com
    python3 csp_eval_pro.py https://example.com --inspect-html
    python3 csp_eval_pro.py https://example.com --inspect-html --check-nonce-reuse
    python3 csp_eval_pro.py https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


DirectiveMap = dict[str, list[str]]


class Severity(IntEnum):
    """
    Severity scale for findings.

    Higher values indicate more serious issues.
    """

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
    """
    A single evaluator finding.
    """

    severity: Severity
    category: str
    message: str
    recommendation: str
    source: str = "general"

    def to_json(self) -> dict[str, Any]:
        return {
            "severity": self.severity.label,
            "category": self.category,
            "message": self.message,
            "recommendation": self.recommendation,
            "source": self.source,
        }


@dataclass(slots=True)
class NonceSampleResult:
    """
    Result of nonce sampling across repeated requests.
    """

    sampled_requests: int
    header_nonces: list[str] = field(default_factory=list)
    html_nonces: list[str] = field(default_factory=list)
    reused_header_nonce: bool = False
    reused_html_nonce: bool = False

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExternalScriptRecord:
    """
    Record of an external script reference found in HTML.
    """

    src: str
    integrity: Optional[str]
    nonce: Optional[str]
    crossorigin: Optional[str]

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvaluationResult:
    """
    Full result of a CSP evaluation.
    """

    url: str
    status_code: int
    content_type: str
    enforced_csp: Optional[str]
    report_only_csp: Optional[str]
    findings: list[Finding]
    score: int
    grade: str
    external_scripts: list[ExternalScriptRecord] = field(default_factory=list)
    nonce_sampling: Optional[NonceSampleResult] = None

    def summary(self) -> dict[str, int]:
        counts = {severity.label: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def to_json(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "enforced_csp": self.enforced_csp,
            "report_only_csp": self.report_only_csp,
            "summary": self.summary(),
            "score": self.score,
            "grade": self.grade,
            "external_scripts": [s.to_json() for s in self.external_scripts],
            "nonce_sampling": (
                self.nonce_sampling.to_json() if self.nonce_sampling else None
            ),
            "findings": [f.to_json() for f in self.findings],
        }


class Ansi:
    """
    Small ANSI helper for colorized output.
    """

    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    DIM = "\033[2m"


class Colorizer:
    """
    Color renderer that can be disabled for non-TTY or explicit no-color mode.
    """

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def apply(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + Ansi.RESET

    def severity(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: self.apply("CRITICAL", Ansi.BOLD, Ansi.RED),
            Severity.HIGH: self.apply("HIGH", Ansi.RED),
            Severity.MEDIUM: self.apply("MEDIUM", Ansi.YELLOW),
            Severity.LOW: self.apply("LOW", Ansi.BLUE),
            Severity.INFO: self.apply("INFO", Ansi.GREEN),
        }
        return mapping[severity]


class HttpClient:
    """
    Thin wrapper around requests.Session for consistent fetch behavior.
    """

    def __init__(self, timeout: int = 10, verify: bool = True) -> None:
        self.timeout = timeout
        self.verify = verify
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "csp-eval-pro/2026"})

    def get(self, url: str) -> requests.Response:
        return self.session.get(
            url,
            timeout=self.timeout,
            verify=self.verify,
            allow_redirects=True,
        )


class CspParser:
    """
    Parser and helper utilities for CSP strings.
    """

    NONCE_RE = re.compile(r"'nonce-([^']+)'")
    HASH_RE = re.compile(r"'sha(?:256|384|512)-[^']+'")

    @staticmethod
    def parse(policy: str) -> DirectiveMap:
        directives: DirectiveMap = {}
        for chunk in policy.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split()
            name = parts[0].lower()
            values = [p.strip() for p in parts[1:]]
            directives[name] = values
        return directives

    @classmethod
    def extract_nonces(cls, values: Iterable[str]) -> list[str]:
        nonces: list[str] = []
        for value in values:
            match = cls.NONCE_RE.fullmatch(value)
            if match:
                nonces.append(match.group(1))
        return nonces

    @classmethod
    def has_nonce_or_hash(cls, values: Iterable[str]) -> bool:
        for value in values:
            if value.startswith("'nonce-"):
                return True
            if cls.HASH_RE.fullmatch(value):
                return True
        return False

    @staticmethod
    def has_keyword(values: Iterable[str], keyword: str) -> bool:
        return keyword in values

    @staticmethod
    def count_host_allowlists(values: Iterable[str]) -> int:
        count = 0
        for value in values:
            if value.startswith("'"):
                continue
            if value.endswith(":"):
                continue
            count += 1
        return count


class HtmlInspector:
    """
    Inspects HTML content for CSP-relevant patterns.
    """

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.base_origin = self._origin(base_url)

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def inspect(
        self,
        html: str,
        findings: list[Finding],
    ) -> list[ExternalScriptRecord]:
        soup = BeautifulSoup(html, "html.parser")
        external_scripts: list[ExternalScriptRecord] = []

        self._inspect_inline_scripts(soup, findings)
        self._inspect_inline_handlers(soup, findings)
        self._inspect_javascript_urls(soup, findings)
        external_scripts.extend(self._inspect_external_scripts(soup, findings))

        return external_scripts

    def extract_script_nonces(self, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        nonces: list[str] = []
        for script in soup.find_all("script"):
            nonce = script.get("nonce")
            if isinstance(nonce, str) and nonce.strip():
                nonces.append(nonce.strip())
        return nonces

    def _inspect_inline_scripts(
        self,
        soup: BeautifulSoup,
        findings: list[Finding],
    ) -> None:
        inline_count = 0
        nonce_count = 0

        for script in soup.find_all("script"):
            nonce = script.get("nonce")
            if isinstance(nonce, str) and nonce.strip():
                nonce_count += 1

            if not script.get("src") and script.text.strip():
                inline_count += 1

        if inline_count:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="html-inline-script",
                    message=f"HTML contains {inline_count} inline <script> block(s)",
                    recommendation=(
                        "Ensure inline scripts are eliminated or protected with "
                        "per-request nonces or hashes."
                    ),
                    source="html",
                )
            )

        if nonce_count:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="html-nonce",
                    message=f"HTML contains {nonce_count} script tag(s) with nonce attributes",
                    recommendation=(
                        "Good sign for nonce-based CSP. Ensure nonces are unique "
                        "per response and match the CSP header."
                    ),
                    source="html",
                )
            )

    def _inspect_inline_handlers(
        self,
        soup: BeautifulSoup,
        findings: list[Finding],
    ) -> None:
        count = 0
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.lower().startswith("on"):
                    count += 1

        if count:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="html-inline-handler",
                    message=f"HTML contains {count} inline event handler attribute(s)",
                    recommendation=(
                        "Remove inline event handlers and move behavior into "
                        "script files or nonce/hash-approved script blocks."
                    ),
                    source="html",
                )
            )

    def _inspect_javascript_urls(
        self,
        soup: BeautifulSoup,
        findings: list[Finding],
    ) -> None:
        count = 0
        for tag in soup.find_all(True):
            for _, value in tag.attrs.items():
                if isinstance(value, str) and value.lower().startswith("javascript:"):
                    count += 1

        if count:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="html-javascript-url",
                    message=f"HTML contains {count} javascript: URL(s)",
                    recommendation=(
                        "Remove javascript: URLs and replace them with safe DOM "
                        "event binding and real navigation targets."
                    ),
                    source="html",
                )
            )

    def _inspect_external_scripts(
        self,
        soup: BeautifulSoup,
        findings: list[Finding],
    ) -> list[ExternalScriptRecord]:
        scripts: list[ExternalScriptRecord] = []
        third_party_without_sri = 0

        for script in soup.find_all("script", src=True):
            src = str(script.get("src"))
            integrity = script.get("integrity")
            nonce = script.get("nonce")
            crossorigin = script.get("crossorigin")

            record = ExternalScriptRecord(
                src=src,
                integrity=str(integrity) if integrity else None,
                nonce=str(nonce) if nonce else None,
                crossorigin=str(crossorigin) if crossorigin else None,
            )
            scripts.append(record)

            if self._is_third_party_script(src) and not integrity:
                third_party_without_sri += 1

        if third_party_without_sri:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="sri",
                    message=(
                        f"Found {third_party_without_sri} third-party external script(s) "
                        "without Subresource Integrity"
                    ),
                    recommendation=(
                        "Use SRI for third-party scripts where feasible, especially for "
                        "static CDN-hosted assets."
                    ),
                    source="html",
                )
            )

        return scripts

    def _is_third_party_script(self, src: str) -> bool:
        parsed = urlparse(src)
        if not parsed.scheme or not parsed.netloc:
            return False
        return f"{parsed.scheme}://{parsed.netloc}" != self.base_origin


class CspPolicyAnalyzer:
    """
    Evaluates a CSP policy for modern strengths and weaknesses.
    """

    def evaluate(
        self,
        policy: str,
        findings: list[Finding],
        source: str,
    ) -> None:
        directives = CspParser.parse(policy)

        script_src = directives.get("script-src")
        default_src = directives.get("default-src", [])
        style_src = directives.get("style-src", [])
        connect_src = directives.get("connect-src", [])
        img_src = directives.get("img-src", [])
        object_src = directives.get("object-src")
        base_uri = directives.get("base-uri")
        frame_ancestors = directives.get("frame-ancestors")
        trusted_types = directives.get("require-trusted-types-for")
        form_action = directives.get("form-action")

        if not script_src:
            if default_src:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="policy-structure",
                        message=f"{source}: script-src is missing; default-src will apply",
                        recommendation="Prefer an explicit script-src directive.",
                        source=source,
                    )
                )
                script_src = default_src
            else:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="policy-structure",
                        message=f"{source}: no script-src and no default-src present",
                        recommendation=(
                            "Define a deny-by-default policy such as default-src 'none' "
                            "and an explicit script-src."
                        ),
                        source=source,
                    )
                )
                script_src = []

        if not default_src:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="policy-structure",
                    message=f"{source}: default-src is missing",
                    recommendation="Prefer default-src 'none' as a deny-by-default baseline.",
                    source=source,
                )
            )

        if object_src is None:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="legacy-surface",
                    message=f"{source}: object-src is missing",
                    recommendation="Set object-src 'none'.",
                    source=source,
                )
            )
        elif object_src != ["'none'"]:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="legacy-surface",
                    message=f"{source}: object-src is not locked to 'none'",
                    recommendation="Use object-src 'none' unless absolutely required.",
                    source=source,
                )
            )

        if base_uri is None:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="navigation-control",
                    message=f"{source}: base-uri is missing",
                    recommendation="Set base-uri 'none' or base-uri 'self'.",
                    source=source,
                )
            )

        if frame_ancestors is None:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="clickjacking",
                    message=f"{source}: frame-ancestors is missing",
                    recommendation="Set frame-ancestors 'none' or a minimal explicit allowlist.",
                    source=source,
                )
            )

        if form_action is None:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="navigation-control",
                    message=f"{source}: form-action is missing",
                    recommendation="Set form-action 'self' or a minimal explicit destination list.",
                    source=source,
                )
            )

        if trusted_types is None or "'script'" not in trusted_types:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="dom-xss",
                    message=f"{source}: Trusted Types enforcement is not enabled",
                    recommendation="Consider require-trusted-types-for 'script'.",
                    source=source,
                )
            )

        self._evaluate_script_src(script_src, findings, source)
        self._evaluate_style_src(style_src, findings, source)
        self._evaluate_connect_src(connect_src, findings, source)
        self._evaluate_img_src(img_src, findings, source)

    def _evaluate_script_src(
        self,
        script_src: list[str],
        findings: list[Finding],
        source: str,
    ) -> None:
        if CspParser.has_keyword(script_src, "'unsafe-inline'"):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="script-execution",
                    message=f"{source}: script-src contains 'unsafe-inline'",
                    recommendation="Remove 'unsafe-inline'. Use nonces or hashes instead.",
                    source=source,
                )
            )

        if CspParser.has_keyword(script_src, "'unsafe-eval'"):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="script-execution",
                    message=f"{source}: script-src contains 'unsafe-eval'",
                    recommendation="Remove 'unsafe-eval' and eliminate eval-like execution paths.",
                    source=source,
                )
            )

        if "*" in script_src:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="allowlist",
                    message=f"{source}: script-src contains wildcard '*'",
                    recommendation="Do not use wildcard trust in script-src.",
                    source=source,
                )
            )

        if "data:" in script_src:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="allowlist",
                    message=f"{source}: script-src allows data:",
                    recommendation="Do not allow data: in script-src.",
                    source=source,
                )
            )

        if "blob:" in script_src:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="allowlist",
                    message=f"{source}: script-src allows blob:",
                    recommendation="Allow blob: only if there is a validated application requirement.",
                    source=source,
                )
            )

        if "http:" in script_src:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="transport",
                    message=f"{source}: script-src allows http:",
                    recommendation="Do not allow insecure transport for executable content.",
                    source=source,
                )
            )

        has_nonce_or_hash = CspParser.has_nonce_or_hash(script_src)
        has_strict_dynamic = CspParser.has_keyword(script_src, "'strict-dynamic'")

        if "https:" in script_src and not has_nonce_or_hash and not has_strict_dynamic:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="allowlist",
                    message=(
                        f"{source}: script-src trusts broad https: scheme without "
                        "nonce/hash/strict-dynamic"
                    ),
                    recommendation="Avoid scheme-wide trust. Prefer nonce/hash-based trust.",
                    source=source,
                )
            )

        if not has_nonce_or_hash and CspParser.count_host_allowlists(script_src) > 0:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="allowlist",
                    message=f"{source}: script-src is allowlist-heavy without nonce/hash trust",
                    recommendation="Prefer nonces or hashes over broad host allowlists.",
                    source=source,
                )
            )

        if has_nonce_or_hash:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="modernization",
                    message=f"{source}: script-src uses nonce/hash-based trust",
                    recommendation="Ensure nonces are unpredictable and generated per response.",
                    source=source,
                )
            )

        if has_nonce_or_hash and not has_strict_dynamic:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="modernization",
                    message=f"{source}: nonce/hash present, but strict-dynamic is absent",
                    recommendation="Consider adding 'strict-dynamic' if compatible with your support matrix.",
                    source=source,
                )
            )

        if has_strict_dynamic:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="modernization",
                    message=f"{source}: script-src uses strict-dynamic",
                    recommendation="Validate that only trusted bootstrap scripts can load descendants.",
                    source=source,
                )
            )

    def _evaluate_style_src(
        self,
        style_src: list[str],
        findings: list[Finding],
        source: str,
    ) -> None:
        if CspParser.has_keyword(style_src, "'unsafe-inline'"):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="style-policy",
                    message=f"{source}: style-src contains 'unsafe-inline'",
                    recommendation="Avoid inline styles where practical or move to nonce/hash models.",
                    source=source,
                )
            )

    def _evaluate_connect_src(
        self,
        connect_src: list[str],
        findings: list[Finding],
        source: str,
    ) -> None:
        if connect_src and "*" in connect_src:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="exfiltration-surface",
                    message=f"{source}: connect-src contains wildcard '*'",
                    recommendation="Restrict connect-src to the minimum required endpoints.",
                    source=source,
                )
            )

    def _evaluate_img_src(
        self,
        img_src: list[str],
        findings: list[Finding],
        source: str,
    ) -> None:
        if img_src and "*" in img_src:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="resource-policy",
                    message=f"{source}: img-src contains wildcard '*'",
                    recommendation="Reduce image trust where practical.",
                    source=source,
                )
            )


class ScoreEngine:
    """
    Assigns a simple score and grade based on findings.
    """

    PENALTIES = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    @classmethod
    def score(cls, findings: list[Finding]) -> tuple[int, str]:
        score = 100
        for finding in findings:
            score -= cls.PENALTIES[finding.severity]
        score = max(score, 0)
        return score, cls.grade(score)

    @staticmethod
    def grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"


class NonceReuseChecker:
    """
    Samples the target multiple times to detect nonce reuse patterns.
    """

    def __init__(self, client: HttpClient) -> None:
        self.client = client

    def sample(self, url: str, count: int) -> NonceSampleResult:
        header_nonces: list[str] = []
        html_nonces: list[str] = []

        for _ in range(count):
            response = self.client.get(url)
            csp = response.headers.get("Content-Security-Policy")
            if csp:
                directives = CspParser.parse(csp)
                script_src = directives.get("script-src", [])
                header_nonces.extend(CspParser.extract_nonces(script_src))

            if "text/html" in response.headers.get("Content-Type", ""):
                inspector = HtmlInspector(response.url)
                html_nonces.extend(inspector.extract_script_nonces(response.text))

        reused_header_nonce = len(set(header_nonces)) < len(header_nonces) if header_nonces else False
        reused_html_nonce = len(set(html_nonces)) < len(html_nonces) if html_nonces else False

        return NonceSampleResult(
            sampled_requests=count,
            header_nonces=header_nonces,
            html_nonces=html_nonces,
            reused_header_nonce=reused_header_nonce,
            reused_html_nonce=reused_html_nonce,
        )


class Evaluator:
    """
    Orchestrates the full CSP evaluation workflow.
    """

    def __init__(
        self,
        client: HttpClient,
        inspect_html: bool = False,
        check_nonce_reuse: bool = False,
        nonce_sample_size: int = 3,
    ) -> None:
        self.client = client
        self.inspect_html = inspect_html
        self.check_nonce_reuse = check_nonce_reuse
        self.nonce_sample_size = nonce_sample_size
        self.policy_analyzer = CspPolicyAnalyzer()

    def evaluate(self, url: str) -> EvaluationResult:
        response = self.client.get(url)
        enforced_csp = response.headers.get("Content-Security-Policy")
        report_only_csp = response.headers.get("Content-Security-Policy-Report-Only")
        content_type = response.headers.get("Content-Type", "")

        findings: list[Finding] = []
        external_scripts: list[ExternalScriptRecord] = []
        nonce_sampling: Optional[NonceSampleResult] = None

        if not enforced_csp and not report_only_csp:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="missing-csp",
                    message="No CSP header present",
                    recommendation="Deploy an enforced CSP; use report-only only during migration.",
                    source="headers",
                )
            )

        if enforced_csp:
            self.policy_analyzer.evaluate(enforced_csp, findings, source="enforced")

        if report_only_csp:
            self.policy_analyzer.evaluate(report_only_csp, findings, source="report-only")
            if not enforced_csp:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="deployment-state",
                        message="Only report-only CSP is present; no enforced CSP detected",
                        recommendation="Move to an enforced CSP after validation.",
                        source="report-only",
                    )
                )

        if self.inspect_html and "text/html" in content_type:
            inspector = HtmlInspector(response.url)
            external_scripts = inspector.inspect(response.text, findings)

        if self.check_nonce_reuse and (enforced_csp or report_only_csp):
            checker = NonceReuseChecker(self.client)
            nonce_sampling = checker.sample(response.url, self.nonce_sample_size)

            if nonce_sampling.reused_header_nonce:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="nonce-reuse",
                        message="CSP header nonce appears to be reused across sampled responses",
                        recommendation="Generate a fresh nonce for each response.",
                        source="nonce-sampling",
                    )
                )

            if nonce_sampling.reused_html_nonce:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="nonce-reuse",
                        message="HTML script nonce appears to be reused across sampled responses",
                        recommendation="Generate a fresh nonce for each response and inject it consistently.",
                        source="nonce-sampling",
                    )
                )

        findings.sort(key=lambda f: int(f.severity), reverse=True)
        score, grade = ScoreEngine.score(findings)

        return EvaluationResult(
            url=response.url,
            status_code=response.status_code,
            content_type=content_type,
            enforced_csp=enforced_csp,
            report_only_csp=report_only_csp,
            findings=findings,
            score=score,
            grade=grade,
            external_scripts=external_scripts,
            nonce_sampling=nonce_sampling,
        )


class Renderer:
    """
    Renders results in terminal or JSON form.
    """

    def __init__(self, color: bool = True) -> None:
        self.color = Colorizer(color and sys.stdout.isatty())

    def render_human(self, result: EvaluationResult) -> None:
        print(self._title("CSP Evaluation Report"))
        print(f"URL          : {result.url}")
        print(f"Status       : {result.status_code}")
        print(f"Content-Type : {result.content_type or 'unknown'}")
        print(f"Enforced CSP : {'present' if result.enforced_csp else 'absent'}")
        print(f"Report-Only  : {'present' if result.report_only_csp else 'absent'}")
        print(f"Score / Grade: {result.score} / {result.grade}")
        print()

        print(self._section("Summary"))
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            value = result.summary()[sev]
            sev_enum = Severity[sev]
            label = self.color.severity(sev_enum)
            print(f"{label:<18} {value}")

        if result.enforced_csp:
            print()
            print(self._section("Enforced CSP"))
            print(result.enforced_csp)

        if result.report_only_csp:
            print()
            print(self._section("Report-Only CSP"))
            print(result.report_only_csp)

        if result.external_scripts:
            print()
            print(self._section("External Scripts"))
            for script in result.external_scripts:
                print(f"- src         : {script.src}")
                print(f"  integrity   : {script.integrity or 'absent'}")
                print(f"  nonce       : {script.nonce or 'absent'}")
                print(f"  crossorigin : {script.crossorigin or 'absent'}")

        if result.nonce_sampling:
            print()
            print(self._section("Nonce Sampling"))
            sample = result.nonce_sampling
            print(f"Sample count         : {sample.sampled_requests}")
            print(f"Header nonces        : {sample.header_nonces or []}")
            print(f"HTML nonces          : {sample.html_nonces or []}")
            print(f"Header nonce reused  : {sample.reused_header_nonce}")
            print(f"HTML nonce reused    : {sample.reused_html_nonce}")

        print()
        print(self._section("Findings"))
        if not result.findings:
            print("No findings.")
            return

        for idx, finding in enumerate(result.findings, start=1):
            sev = self.color.severity(finding.severity)
            print(f"[{idx}] {sev}  {finding.category}  ({finding.source})")
            print(f"    Issue : {finding.message}")
            print(f"    Fix   : {finding.recommendation}")
            print()

    def render_json(self, result: EvaluationResult) -> None:
        print(json.dumps(result.to_json(), indent=2))

    def _title(self, text: str) -> str:
        line = "=" * 78
        return f"{line}\n{text}\n{line}"

    def _section(self, text: str) -> str:
        return f"{text}\n{'-' * 78}"


def parse_args() -> argparse.Namespace:
    """
    Parse CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Professional CSP evaluator for modern web applications."
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-readable text",
    )
    parser.add_argument(
        "--inspect-html",
        action="store_true",
        help="Inspect HTML for inline scripts, handlers, and external scripts",
    )
    parser.add_argument(
        "--check-nonce-reuse",
        action="store_true",
        help="Perform repeated fetches to detect nonce reuse",
    )
    parser.add_argument(
        "--nonce-sample-size",
        type=int,
        default=3,
        help="Number of requests for nonce reuse sampling (default: 3)",
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
    """
    Program entrypoint.
    """
    args = parse_args()

    client = HttpClient(timeout=args.timeout, verify=not args.insecure)
    evaluator = Evaluator(
        client=client,
        inspect_html=args.inspect_html,
        check_nonce_reuse=args.check_nonce_reuse,
        nonce_sample_size=args.nonce_sample_size,
    )
    renderer = Renderer(color=not args.no_color)

    try:
        result = evaluator.evaluate(args.url)
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        renderer.render_json(result)
    else:
        renderer.render_human(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
