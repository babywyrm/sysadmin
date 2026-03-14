#!/usr/bin/env python3
"""
csp_eval.py

A modern, lightweight Content Security Policy evaluator.

Features:
  - Evaluates enforced and report-only CSP headers
  - Checks common 2026 CSP weaknesses and anti-patterns
  - Dangerous/attacker-influenced host detection (ngrok, GitHub Pages, …)
  - Known CSP bypass gadget detection (JSONP endpoints, open redirects, …)
  - Wildcard subdomain trust detection
  - Optional HTML inspection:
      · inline <script> blocks
      · inline event handlers
      · javascript: URLs
      · nonce reuse across script tags
  - Paged human-readable output (default pager, disable with --no-pager)
  - Severity filtering (--min-severity)
  - Custom request headers (--header)
  - File output (--output)
  - CI exit-code gating (--exit-code)
  - JSON output for pipelines/CI

Usage:
    python3 csp_eval.py https://example.com
    python3 csp_eval.py https://example.com --inspect-html
    python3 csp_eval.py https://example.com --json
    python3 csp_eval.py https://example.com --min-severity HIGH
    python3 csp_eval.py https://example.com --exit-code HIGH
    python3 csp_eval.py https://example.com --header "Authorization: Bearer TOKEN"
    python3 csp_eval.py https://example.com --output report.json --json
"""

from __future__ import annotations

import argparse
import json
import os
import pydoc
import sys
from dataclasses import dataclass
from enum import IntEnum
from io import StringIO
from typing import Any, Final, Optional

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Dangerous host tables
# ---------------------------------------------------------------------------

# Hosts where any user can publish arbitrary content under a subdomain.
# Allowlisting these in script-src is effectively equivalent to 'unsafe-inline'.
ATTACKER_INFLUENCED_HOSTS: Final[tuple[tuple[str, str], ...]] = (
    ("ngrok.io",           "ngrok tunnels are attacker-controlled"),
    ("ngrok-free.app",     "ngrok tunnels are attacker-controlled"),
    ("ngrok.app",          "ngrok tunnels are attacker-controlled"),
    ("github.io",          "GitHub Pages subdomains are user-controlled"),
    ("vercel.app",         "Vercel deployments are user-controlled"),
    ("netlify.app",        "Netlify deployments are user-controlled"),
    ("pages.dev",          "Cloudflare Pages deployments are user-controlled"),
    ("web.app",            "Firebase Hosting subdomains are user-controlled"),
    ("firebaseapp.com",    "Firebase Hosting subdomains are user-controlled"),
    ("glitch.me",          "Glitch projects are user-controlled"),
    ("repl.co",            "Replit projects are user-controlled"),
    ("replit.dev",         "Replit projects are user-controlled"),
    ("codepen.io",         "CodePen pens are user-controlled"),
    ("jsfiddle.net",       "JSFiddle fiddles are user-controlled"),
    ("stackblitz.io",      "StackBlitz projects are user-controlled"),
    ("render.com",         "Render deployments are user-controlled"),
    ("fly.dev",            "Fly.io deployments are user-controlled"),
    ("railway.app",        "Railway deployments are user-controlled"),
    ("surge.sh",           "Surge.sh deployments are user-controlled"),
    ("onrender.com",       "Render deployments are user-controlled"),
    ("pythonanywhere.com", "PythonAnywhere apps are user-controlled"),
    ("workers.dev",        "Cloudflare Workers deployments are user-controlled"),
)

# Hosts that host known CSP bypass gadgets: JSONP endpoints, open redirects,
# or CDNs wide enough that a single compromised package bypasses the policy.
BYPASS_GADGET_HOSTS: Final[tuple[tuple[str, str], ...]] = (
    ("ajax.googleapis.com",        "hosts Angular/legacy libs with known CSP bypass gadgets"),
    ("www.google.com",             "hosts JSONP endpoints (/jsapi, /uds) usable for bypass"),
    ("accounts.google.com",        "hosts open-redirect endpoints usable for bypass"),
    ("cdn.jsdelivr.net",           "has historically hosted JSONP and open-redirect endpoints"),
    ("cdnjs.cloudflare.com",       "broad CDN; any compromised package bypasses your policy"),
    ("unpkg.com",                  "serves arbitrary npm package files; trivially bypassable"),
    ("rawgit.com",                 "deprecated; domain may be squatted"),
    ("raw.githubusercontent.com",  "serves raw user-supplied content; attacker-writable"),
    ("gist.githubusercontent.com", "serves raw gist content; attacker-writable"),
    ("googleusercontent.com",      "user-writable content (Drive, GCS public buckets)"),
    ("storage.googleapis.com",     "public GCS buckets are attacker-writable"),
    ("s3.amazonaws.com",           "public S3 buckets are attacker-writable"),
    ("blob.core.windows.net",      "public Azure Blob containers are attacker-writable"),
    ("fastly.net",                 "broad CDN origin; trust scope is extremely wide"),
)

# Directives scanned for dangerous / wildcard hosts.
SCANNED_DIRECTIVES: Final[frozenset[str]] = frozenset(
    ("script-src", "style-src", "connect-src", "img-src", "font-src")
)


# ---------------------------------------------------------------------------
# Core data types
# ---------------------------------------------------------------------------


class Severity(IntEnum):
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            raise argparse.ArgumentTypeError(
                f"Invalid severity '{value}'. "
                f"Choose from: {', '.join(s.label for s in cls)}"
            )


@dataclass(slots=True)
class Finding:
    severity:       Severity
    category:       str
    source:         str
    message:        str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity":       self.severity.label,
            "category":       self.category,
            "source":         self.source,
            "message":        self.message,
            "recommendation": self.recommendation,
        }


@dataclass(slots=True)
class Result:
    url:             str
    status_code:     int
    content_type:    str
    enforced_csp:    Optional[str]
    report_only_csp: Optional[str]
    findings:        list[Finding]
    score:           int
    grade:           str

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {sev.label: 0 for sev in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "url":             self.url,
            "status_code":     self.status_code,
            "content_type":    self.content_type,
            "enforced_csp":    self.enforced_csp,
            "report_only_csp": self.report_only_csp,
            "score":           self.score,
            "grade":           self.grade,
            "summary":         self.summary(),
            "findings":        [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------


class Color:
    RESET:  Final = "\033[0m"
    BOLD:   Final = "\033[1m"
    RED:    Final = "\033[31m"
    YELLOW: Final = "\033[33m"
    GREEN:  Final = "\033[32m"
    BLUE:   Final = "\033[34m"
    CYAN:   Final = "\033[36m"
    DIM:    Final = "\033[2m"


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


class Renderer:
    """Render a Result as aligned text (optionally paged) or JSON."""

    _SEVERITY_PAD: Final = 8  # width of the longest label ("CRITICAL")
    _W:            Final = 78  # report width

    def __init__(self, use_color: bool, use_pager: bool) -> None:
        # Colour is suppressed when the caller requests it, or when stdout is
        # not a TTY (piped / redirected).
        self.use_color: bool = use_color and sys.stdout.isatty()
        # Paging is suppressed when the caller requests it, or when stdout is
        # not a TTY — no point paging into a pipe.
        self.use_pager: bool = use_pager and sys.stdout.isatty()

    # ------------------------------------------------------------------
    # Colour helpers
    # ------------------------------------------------------------------

    def _c(self, text: str, *codes: str) -> str:
        """Wrap *text* in ANSI escape codes when colour is enabled."""
        if not self.use_color or not codes:
            return text
        return "".join(codes) + text + Color.RESET

    def _severity_label(self, severity: Severity) -> str:
        label = severity.label.ljust(self._SEVERITY_PAD)
        mapping: dict[Severity, str] = {
            Severity.CRITICAL: self._c(label, Color.BOLD, Color.RED),
            Severity.HIGH:     self._c(label, Color.RED),
            Severity.MEDIUM:   self._c(label, Color.YELLOW),
            Severity.LOW:      self._c(label, Color.BLUE),
            Severity.INFO:     self._c(label, Color.GREEN),
        }
        return mapping[severity]

    def _grade_label(self, grade: str) -> str:
        color = (
            Color.GREEN  if grade == "A"          else
            Color.YELLOW if grade in ("B", "C")   else
            Color.RED
        )
        return self._c(grade, Color.BOLD, color)

    # ------------------------------------------------------------------
    # Public render methods
    # ------------------------------------------------------------------

    def render_json(self, result: Result, out: StringIO) -> None:
        out.write(json.dumps(result.to_dict(), indent=2))
        out.write("\n")

    def render_text(
        self,
        result: Result,
        out: StringIO,
        min_severity: Severity = Severity.INFO,
    ) -> None:
        W = self._W
        sep_heavy = self._c("=" * W, Color.DIM)
        sep_light = self._c("-" * W, Color.DIM)

        def h(label: str) -> str:
            return self._c(label, Color.BOLD)

        def row(key: str, value: str, width: int = 16) -> str:
            return f"  {key:<{width}}{value}"

        out.write(sep_heavy + "\n")
        out.write(h("  CSP Evaluation Report") + "\n")
        out.write(sep_heavy + "\n")
        out.write(row("URL",          result.url)                                   + "\n")
        out.write(row("Status",       str(result.status_code))                      + "\n")
        out.write(row("Content-Type", result.content_type or "unknown")             + "\n")
        out.write(row("Enforced CSP", "present" if result.enforced_csp    else "absent") + "\n")
        out.write(row("Report-Only",  "present" if result.report_only_csp else "absent") + "\n")
        out.write(row("Score",        str(result.score))                            + "\n")
        out.write(row("Grade",        self._grade_label(result.grade))              + "\n")
        out.write("\n")

        out.write(h("  Summary") + "\n")
        out.write(sep_light + "\n")
        for sev in reversed(list(Severity)):
            count = result.summary()[sev.label]
            marker = self._c(str(count), Color.BOLD) if count else self._c("0", Color.DIM)
            out.write(f"  {self._severity_label(sev)}  {marker}\n")
        out.write("\n")

        if result.enforced_csp:
            out.write(h("  Enforced CSP") + "\n")
            out.write(sep_light + "\n")
            out.write(f"  {result.enforced_csp}\n\n")

        if result.report_only_csp:
            out.write(h("  Report-Only CSP") + "\n")
            out.write(sep_light + "\n")
            out.write(f"  {result.report_only_csp}\n\n")

        visible = [f for f in result.findings if f.severity >= min_severity]

        out.write(h("  Findings") + "\n")
        if min_severity > Severity.INFO:
            out.write(
                self._c(
                    f"  (filtered to {min_severity.label} and above"
                    f" — {len(result.findings) - len(visible)} finding(s) hidden)\n",
                    Color.DIM,
                )
            )
        out.write(sep_light + "\n")

        if not visible:
            out.write(self._c("  No findings at this severity level.\n", Color.GREEN))
            return

        for idx, finding in enumerate(visible, start=1):
            sev  = self._severity_label(finding.severity)
            cat  = self._c(finding.category, Color.BOLD)
            src  = self._c(f"[{finding.source}]", Color.CYAN)
            out.write(f"  [{idx:>3}] {sev}  {cat:<30} {src}\n")
            out.write(f"        {'Issue':<6}  {finding.message}\n")
            out.write(
                f"        {self._c('Fix', Color.GREEN):<6}  "
                f"{finding.recommendation}\n"
            )
            out.write("\n")

    # ------------------------------------------------------------------
    # Top-level dispatch (handles paging + file output)
    # ------------------------------------------------------------------

    def emit(
        self,
        result: Result,
        *,
        as_json: bool,
        min_severity: Severity,
        output_path: Optional[str],
    ) -> None:
        buf = StringIO()

        if as_json:
            self.render_json(result, buf)
        else:
            self.render_text(result, buf, min_severity=min_severity)

        text = buf.getvalue()

        # Optional file output — always written without ANSI codes.
        if output_path:
            clean = _strip_ansi(text)
            try:
                with open(output_path, "w", encoding="utf-8") as fh:
                    fh.write(clean)
            except OSError as exc:
                print(f"[!] Could not write output file: {exc}", file=sys.stderr)

        # Terminal output: page or print directly.
        if self.use_pager and not as_json:
            # pydoc.pager respects $PAGER, falls back to 'less' then 'more'.
            pydoc.pager(text)
        else:
            sys.stdout.write(text)


# ---------------------------------------------------------------------------
# ANSI strip helper (for file output)
# ---------------------------------------------------------------------------

import re as _re

_ANSI_ESC: Final = _re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESC.sub("", text)


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class CspEvaluator:
    """Fetch a URL and evaluate its CSP posture."""

    def __init__(
        self,
        timeout:       int  = 10,
        verify_tls:    bool = True,
        inspect_html:  bool = False,
        extra_headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> None:
        self.timeout          = timeout
        self.verify_tls       = verify_tls
        self.inspect_html     = inspect_html
        self.follow_redirects = follow_redirects
        self.session          = requests.Session()
        self.session.headers.update({"User-Agent": "csp-eval/2026"})
        if extra_headers:
            self.session.headers.update(extra_headers)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def evaluate(self, url: str) -> Result:
        response = self.session.get(
            url,
            timeout=self.timeout,
            verify=self.verify_tls,
            allow_redirects=self.follow_redirects,
        )

        enforced_csp  = response.headers.get("Content-Security-Policy")
        report_only   = response.headers.get("Content-Security-Policy-Report-Only")
        content_type  = response.headers.get("Content-Type", "")
        findings: list[Finding] = []

        if not enforced_csp and not report_only:
            self._add(
                findings, Severity.CRITICAL, "missing-csp", "headers",
                "No CSP header present",
                "Deploy an enforced CSP. Use report-only only during migration.",
            )
        else:
            if enforced_csp:
                self._evaluate_policy(enforced_csp, findings, "enforced")
            if report_only:
                self._evaluate_policy(report_only, findings, "report-only")
                if not enforced_csp:
                    self._add(
                        findings, Severity.HIGH, "deployment-state", "report-only",
                        "Only Content-Security-Policy-Report-Only is present",
                        "Migrate to an enforced CSP after validation.",
                    )

        if self.inspect_html and "text/html" in content_type:
            self._inspect_html(response.text, findings)

        findings.sort(key=lambda f: int(f.severity), reverse=True)
        score, grade = self._score(findings)

        return Result(
            url=response.url,
            status_code=response.status_code,
            content_type=content_type,
            enforced_csp=enforced_csp,
            report_only_csp=report_only,
            findings=findings,
            score=score,
            grade=grade,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        findings:       list[Finding],
        severity:       Severity,
        category:       str,
        source:         str,
        message:        str,
        recommendation: str,
    ) -> None:
        findings.append(Finding(severity, category, source, message, recommendation))

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
            v.startswith("'nonce-")
            or v.startswith("'sha256-")
            or v.startswith("'sha384-")
            or v.startswith("'sha512-")
            for v in values
        )

    def _count_allowlist_hosts(self, values: list[str]) -> int:
        return sum(
            1 for v in values
            if not v.startswith("'") and not v.endswith(":")
        )

    @staticmethod
    def _extract_host(value: str) -> Optional[str]:
        """
        Derive a bare hostname from a CSP source expression.

        'https://cdn.example.com/path' -> 'cdn.example.com'
        '*.ngrok.io'                   -> 'ngrok.io'
        'https:'                       -> None
        '*'                            -> None
        """
        v = value.lower()
        if "://" in v:
            v = v.split("://", 1)[1]
        v = v.split("/")[0].split(":")[0]
        if v.startswith("*."):
            v = v[2:]
        if not v or "*" in v:
            return None
        return v

    # ------------------------------------------------------------------
    # Dangerous host checks
    # ------------------------------------------------------------------

    def _check_dangerous_hosts(
        self,
        values:    list[str],
        directive: str,
        source:    str,
        findings:  list[Finding],
    ) -> None:
        for value in values:
            if value.startswith("'"):
                continue
            host = self._extract_host(value)
            if not host:
                continue

            # Attacker-influenced (CRITICAL) takes priority over bypass gadget (HIGH).
            for pattern, reason in ATTACKER_INFLUENCED_HOSTS:
                if host == pattern or host.endswith(f".{pattern}"):
                    self._add(
                        findings,
                        Severity.CRITICAL, "dangerous-allowlist", source,
                        (
                            f"{directive} allowlists '{value}' — {reason}. "
                            "An attacker can host arbitrary content here."
                        ),
                        (
                            f"Remove '{value}' from {directive}. "
                            "Serve the resource yourself or use nonce/hash trust."
                        ),
                    )
                    break
            else:
                for pattern, reason in BYPASS_GADGET_HOSTS:
                    if host == pattern or host.endswith(f".{pattern}"):
                        self._add(
                            findings,
                            Severity.HIGH, "bypass-gadget", source,
                            f"{directive} allowlists '{value}' — {reason}.",
                            (
                                f"Remove '{value}' from {directive}. "
                                "Self-host the resource or switch to nonce/hash trust."
                            ),
                        )
                        break

    def _check_wildcard_subdomain(
        self,
        values:    list[str],
        directive: str,
        source:    str,
        findings:  list[Finding],
    ) -> None:
        for value in values:
            if value.startswith("'"):
                continue
            v = value.lower()
            if "://" in v:
                v = v.split("://", 1)[1]
            host_part = v.split("/")[0].split(":")[0]
            if host_part.startswith("*."):
                apex = host_part[2:]
                if apex and "*" not in apex:
                    self._add(
                        findings,
                        Severity.MEDIUM, "wildcard-subdomain", source,
                        (
                            f"{directive} uses wildcard subdomain trust '{value}'. "
                            "You may not control every subdomain of this domain."
                        ),
                        (
                            "Replace wildcard subdomain entries with explicit "
                            "hostnames or switch to nonce/hash-based trust."
                        ),
                    )

    # ------------------------------------------------------------------
    # Policy-level evaluation
    # ------------------------------------------------------------------

    def _evaluate_policy(
        self,
        policy:   str,
        findings: list[Finding],
        source:   str,
    ) -> None:
        d = self._parse_policy(policy)

        script_src      = d.get("script-src")
        default_src     = d.get("default-src", [])
        style_src       = d.get("style-src", [])
        connect_src     = d.get("connect-src", [])
        img_src         = d.get("img-src", [])
        font_src        = d.get("font-src", [])
        object_src      = d.get("object-src")
        base_uri        = d.get("base-uri")
        frame_ancestors = d.get("frame-ancestors")
        trusted_types   = d.get("require-trusted-types-for")
        form_action     = d.get("form-action")
        report_uri      = d.get("report-uri")
        report_to       = d.get("report-to")

        # ── script-src resolution ──────────────────────────────────────
        if not script_src:
            if default_src:
                self._add(
                    findings, Severity.MEDIUM, "policy-structure", source,
                    "script-src absent; default-src is the effective fallback",
                    "Add an explicit script-src for tighter, clearer control.",
                )
                script_src = default_src
            else:
                self._add(
                    findings, Severity.CRITICAL, "policy-structure", source,
                    "Neither script-src nor default-src is present",
                    "Add default-src 'none' and an explicit script-src.",
                )
                script_src = []

        # ── structural directives ──────────────────────────────────────
        if not default_src:
            self._add(
                findings, Severity.LOW, "policy-structure", source,
                "default-src is absent",
                "Add default-src 'none' as a deny-by-default baseline.",
            )

        if object_src is None:
            self._add(
                findings, Severity.MEDIUM, "legacy-surface", source,
                "object-src is absent",
                "Set object-src 'none'.",
            )
        elif object_src != ["'none'"]:
            self._add(
                findings, Severity.MEDIUM, "legacy-surface", source,
                "object-src is not locked to 'none'",
                "Use object-src 'none' unless absolutely required.",
            )

        if base_uri is None:
            self._add(
                findings, Severity.MEDIUM, "navigation-control", source,
                "base-uri is absent",
                "Set base-uri 'none' or base-uri 'self'.",
            )

        if frame_ancestors is None:
            self._add(
                findings, Severity.MEDIUM, "clickjacking", source,
                "frame-ancestors is absent",
                "Set frame-ancestors 'none' or an explicit minimal allowlist.",
            )

        if form_action is None:
            self._add(
                findings, Severity.LOW, "navigation-control", source,
                "form-action is absent",
                "Set form-action 'self' or a minimal list of destinations.",
            )

        if trusted_types is None or "'script'" not in trusted_types:
            self._add(
                findings, Severity.MEDIUM, "dom-xss", source,
                "Trusted Types enforcement is not enabled",
                "Add require-trusted-types-for 'script' for DOM XSS hardening.",
            )

        # ── reporting ──────────────────────────────────────────────────
        if report_uri is not None and report_to is None:
            self._add(
                findings, Severity.INFO, "reporting", source,
                "report-uri is deprecated",
                "Migrate to the Reporting API: use report-to + a Report-To header.",
            )

        if report_uri is None and report_to is None:
            self._add(
                findings, Severity.LOW, "reporting", source,
                "No CSP reporting endpoint is configured",
                "Add report-to (and a Report-To header) to capture violations.",
            )

        # ── script-src keyword checks ──────────────────────────────────
        if "'unsafe-inline'" in script_src:
            self._add(
                findings, Severity.CRITICAL, "script-execution", source,
                "script-src contains 'unsafe-inline'",
                "Remove 'unsafe-inline'. Use nonces or hashes instead.",
            )

        if "'unsafe-eval'" in script_src:
            self._add(
                findings, Severity.HIGH, "script-execution", source,
                "script-src contains 'unsafe-eval'",
                "Remove 'unsafe-eval'. Eliminate eval() and similar sinks.",
            )

        if "'unsafe-hashes'" in script_src:
            self._add(
                findings, Severity.HIGH, "script-execution", source,
                "script-src contains 'unsafe-hashes'",
                (
                    "Remove 'unsafe-hashes'. It enables hash-matched inline "
                    "event handlers and is a partial bypass foothold."
                ),
            )

        if "*" in script_src:
            self._add(
                findings, Severity.CRITICAL, "allowlist", source,
                "script-src contains wildcard '*'",
                "Never use '*' in script-src.",
            )

        if "data:" in script_src:
            self._add(
                findings, Severity.CRITICAL, "allowlist", source,
                "script-src allows data: URIs",
                "Remove data: from script-src.",
            )

        if "blob:" in script_src:
            self._add(
                findings, Severity.MEDIUM, "allowlist", source,
                "script-src allows blob: URIs",
                "Allow blob: only when strictly required and well-understood.",
            )

        if "http:" in script_src:
            self._add(
                findings, Severity.HIGH, "transport", source,
                "script-src permits http: (plaintext transport)",
                "Remove http: — never allow plaintext transport for scripts.",
            )

        # ── nonce / hash / strict-dynamic ─────────────────────────────
        has_nonce_or_hash  = self._has_nonce_or_hash(script_src)
        has_strict_dynamic = "'strict-dynamic'" in script_src

        if (
            "https:" in script_src
            and not has_nonce_or_hash
            and not has_strict_dynamic
        ):
            self._add(
                findings, Severity.HIGH, "allowlist", source,
                "script-src trusts the broad https: scheme without nonce/hash/strict-dynamic",
                "Replace https: scheme trust with nonce or hash-based trust.",
            )

        if not has_nonce_or_hash and self._count_allowlist_hosts(script_src) > 0:
            self._add(
                findings, Severity.MEDIUM, "allowlist", source,
                "script-src relies on host allowlisting without nonce/hash trust",
                "Prefer nonces or hashes over broad host allowlists.",
            )

        if has_nonce_or_hash:
            self._add(
                findings, Severity.INFO, "modernization", source,
                "script-src uses nonce/hash-based trust",
                "Ensure nonces are cryptographically random and unique per response.",
            )

        if has_nonce_or_hash and not has_strict_dynamic:
            self._add(
                findings, Severity.LOW, "modernization", source,
                "nonce/hash present but 'strict-dynamic' is absent",
                "Consider adding 'strict-dynamic' for dynamically loaded scripts.",
            )

        if has_strict_dynamic:
            self._add(
                findings, Severity.INFO, "modernization", source,
                "script-src uses 'strict-dynamic'",
                "Verify only trusted bootstrap scripts can load further descendants.",
            )

        # ── upgrade-insecure-requests ──────────────────────────────────
        if "upgrade-insecure-requests" not in d:
            self._add(
                findings, Severity.INFO, "transport", source,
                "upgrade-insecure-requests is absent",
                "Add upgrade-insecure-requests to auto-upgrade mixed content.",
            )

        # ── style-src ─────────────────────────────────────────────────
        if "'unsafe-inline'" in style_src:
            self._add(
                findings, Severity.LOW, "style-policy", source,
                "style-src contains 'unsafe-inline'",
                "Avoid inline styles; use external stylesheets or style nonces.",
            )

        # ── connect-src ───────────────────────────────────────────────
        if connect_src and "*" in connect_src:
            self._add(
                findings, Severity.MEDIUM, "exfiltration-surface", source,
                "connect-src contains wildcard '*'",
                "Restrict connect-src to the minimum required endpoints.",
            )

        # ── dangerous host + wildcard subdomain checks ─────────────────
        scanned: dict[str, list[str]] = {
            "script-src":  script_src,
            "style-src":   style_src,
            "connect-src": connect_src,
            "img-src":     img_src,
            "font-src":    font_src,
        }
        for directive, values in scanned.items():
            if values:
                self._check_dangerous_hosts(values, directive, source, findings)
                self._check_wildcard_subdomain(values, directive, source, findings)

    # ------------------------------------------------------------------
    # HTML inspection
    # ------------------------------------------------------------------

    def _inspect_html(self, html: str, findings: list[Finding]) -> None:
        soup = BeautifulSoup(html, "html.parser")

        inline_scripts:  int       = 0
        inline_handlers: int       = 0
        javascript_urls: int       = 0
        nonce_values:    list[str] = []

        for script in soup.find_all("script"):
            if not script.get("src") and script.text.strip():
                inline_scripts += 1
            nonce = script.get("nonce")
            if nonce:
                nonce_values.append(str(nonce))

        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.lower().startswith("on"):
                    inline_handlers += 1
                if isinstance(value, str) and value.lower().startswith("javascript:"):
                    javascript_urls += 1

        if inline_scripts:
            self._add(
                findings, Severity.MEDIUM, "html-inline-script", "html",
                f"{inline_scripts} inline <script> block(s) found",
                "Eliminate inline scripts or protect them with per-response nonces/hashes.",
            )

        if inline_handlers:
            self._add(
                findings, Severity.HIGH, "html-inline-handler", "html",
                f"{inline_handlers} inline event handler attribute(s) found",
                "Remove all inline event handlers and move logic to external scripts.",
            )

        if javascript_urls:
            self._add(
                findings, Severity.HIGH, "html-javascript-url", "html",
                f"{javascript_urls} javascript: URL(s) found",
                "Replace javascript: URLs with safe event listeners or navigation.",
            )

        # Nonce reuse defeats per-response freshness entirely.
        if nonce_values and len(nonce_values) != len(set(nonce_values)):
            seen:   set[str] = set()
            reused: set[str] = set()
            for n in nonce_values:
                (reused if n in seen else seen).add(n)
            self._add(
                findings, Severity.CRITICAL, "nonce-reuse", "html",
                f"Nonce value(s) reused across multiple <script> tags: {sorted(reused)}",
                (
                    "Generate a fresh cryptographically random nonce per response "
                    "and apply it to exactly one script element."
                ),
            )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score(self, findings: list[Finding]) -> tuple[int, str]:
        penalties: dict[Severity, int] = {
            Severity.CRITICAL: 25,
            Severity.HIGH:     15,
            Severity.MEDIUM:   8,
            Severity.LOW:      3,
            Severity.INFO:     0,
        }
        score = max(100 - sum(penalties[f.severity] for f in findings), 0)

        # A completely missing CSP must never earn a passing grade.
        if any(f.category == "missing-csp" for f in findings) and score >= 40:
            score = 39

        grade = (
            "A" if score >= 90 else
            "B" if score >= 75 else
            "C" if score >= 60 else
            "D" if score >= 40 else
            "F"
        )
        return score, grade


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_header(value: str) -> tuple[str, str]:
    """Validate and split a 'Name: Value' header string from the CLI."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"Header must be in 'Name: Value' format, got: {value!r}"
        )
    name, _, val = value.partition(":")
    return name.strip(), val.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Professional CSP evaluator for modern web applications.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s https://example.com\n"
            "  %(prog)s https://example.com --inspect-html --min-severity MEDIUM\n"
            "  %(prog)s https://example.com --json --output report.json\n"
            "  %(prog)s https://example.com --exit-code HIGH\n"
            "  %(prog)s https://example.com --header 'Authorization: Bearer TOKEN'\n"
        ),
    )
    parser.add_argument("url", help="Target URL to evaluate")

    parser.add_argument(
        "--inspect-html", action="store_true",
        help="Inspect returned HTML for inline scripts, handlers, and nonce reuse",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit JSON output",
    )
    parser.add_argument(
        "--no-pager", action="store_true",
        help="Disable paged output (always prints directly to stdout)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output",
    )
    parser.add_argument(
        "--min-severity",
        type=Severity.from_str,
        default=Severity.INFO,
        metavar="LEVEL",
        help=(
            "Only display findings at or above this severity. "
            "Choices: INFO LOW MEDIUM HIGH CRITICAL (default: INFO)"
        ),
    )
    parser.add_argument(
        "--exit-code",
        type=Severity.from_str,
        default=None,
        metavar="LEVEL",
        help=(
            "Exit with code 2 if any finding meets or exceeds this severity. "
            "Useful for CI gating. Choices: INFO LOW MEDIUM HIGH CRITICAL"
        ),
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write results to FILE (plain text or JSON, no ANSI codes)",
    )
    parser.add_argument(
        "--header", dest="headers",
        action="append", type=_parse_header, default=[],
        metavar="'Name: Value'",
        help="Add a custom request header (repeatable)",
    )
    parser.add_argument(
        "--no-follow-redirects", action="store_true",
        help="Do not follow HTTP redirects",
    )
    parser.add_argument(
        "--timeout", type=int, default=10, metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Disable TLS certificate verification",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    extra_headers: dict[str, str] = dict(args.headers)

    evaluator = CspEvaluator(
        timeout=args.timeout,
        verify_tls=not args.insecure,
        inspect_html=args.inspect_html,
        extra_headers=extra_headers or None,
        follow_redirects=not args.no_follow_redirects,
    )
    renderer = Renderer(
        use_color=not args.no_color,
        use_pager=not args.no_pager,
    )

    try:
        result = evaluator.evaluate(args.url)
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}", file=sys.stderr)
        return 1

    renderer.emit(
        result,
        as_json=args.json,
        min_severity=args.min_severity,
        output_path=args.output,
    )

    # CI exit-code gating.
    if args.exit_code is not None:
        if any(f.severity >= args.exit_code for f in result.findings):
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
