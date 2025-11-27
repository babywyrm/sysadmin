#!/usr/bin/env python3
"""
OWASP Top 10 Application Security Tester
----------------------------------------
Performs heuristic checks across web endpoints for common OWASP Top 10 2021 risks:
  A01: Broken Access Control
  A02: Cryptographic Failures
  A03: Injection
  A05: Security Misconfiguration
  A06: Vulnerable/Outdated Components
  A07: Identification & Authentication Failures
  A08: Software/Data Integrity Failures
  A09: Security Logging/Monitoring Failures
  A10: SSRF/Insecure Deserialization indicators

Example:
    python3 owasp_tester.py "sessionid=abc; csrftoken=xyz" https://example.com api_namespaces.txt --json report.json
"""

import asyncio
import aiohttp
import sys
import os
import re
import json
import csv
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Tuple


@dataclass
class Finding:
    """Data structure for a single OWASP finding."""
    owasp_id: str
    severity: str
    message: str
    url: str


def parse_cookies(cookie_string: str) -> Dict[str, str]:
    """Parse cookie string into dictionary."""
    cookies: Dict[str, str] = {}
    for pair in cookie_string.split(';'):
        pair = pair.strip()
        if '=' in pair:
            name, value = pair.split('=', 1)
            cookies[name.strip()] = value.strip()
    return cookies


async def fetch_with_timeout(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    **kwargs: Any
) -> Tuple[Optional[aiohttp.ClientResponse], Optional[str]]:
    """Safely perform an HTTP request with timeout handling."""
    try:
        async with session.request(method, url, **kwargs) as response:
            text = await response.text(errors="ignore")
            return response, text
    except asyncio.TimeoutError:
        return None, "[Timeout]"
    except aiohttp.ClientError as e:
        return None, f"[Client Error: {str(e)}]"
    except Exception as e:
        return None, f"[Unknown Error: {str(e)}]"


async def analyze_endpoint(
    session: aiohttp.ClientSession,
    url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str],
) -> List[Finding]:
    """Perform OWASP Top 10 checks on a given endpoint."""
    findings: List[Finding] = []
    response, body = await fetch_with_timeout(session, "GET", url, headers=headers, cookies=cookies)
    if not response:
        findings.append(Finding("A05", "ERROR", f"Failed to retrieve: {body}", url))
        return findings

    hdrs = {k: v for k, v in response.headers.items()}
    snippet = body[:200].lower()

    def add(owasp_id: str, severity: str, msg: str) -> None:
        findings.append(Finding(owasp_id, severity, msg, url))

    # --- A01: Broken Access Control ---
    if any(x in url.lower() for x in ["admin", "internal", "private"]) and response.status == 200:
        add("A01", "HIGH", "Public access to sensitive endpoint (admin/internal).")

    # --- A02: Cryptographic Failures ---
    if url.startswith("http://"):
        add("A02", "HIGH", "Unencrypted HTTP endpoint detected.")
    if "Strict-Transport-Security" not in hdrs:
        add("A02", "MEDIUM", "Missing HSTS header (Strict-Transport-Security).")

    # --- A03: Injection indicators ---
    if any(k in snippet for k in ["syntax error", "mysql", "sql", "exception", "odbc"]):
        add("A03", "MEDIUM", "Response contains possible error message (may indicate injection).")

    # --- A05: Security Misconfiguration (CORS, headers) ---
    if "Access-Control-Allow-Origin" in hdrs:
        origin = hdrs["Access-Control-Allow-Origin"]
        if origin == "*":
            add("A05", "HIGH", "CORS wildcard origin allows all domains.")
        elif origin == headers.get("Origin"):
            add("A05", "MEDIUM", "CORS reflects request Origin header.")
    else:
        add("A05", "LOW", "No Access-Control-Allow-Origin header (may block some API clients).")

    if hdrs.get("Access-Control-Allow-Credentials", "").lower() == "true":
        add("A05", "MEDIUM", "CORS allows credentials—verify correctness.")

    # --- A06: Vulnerable/Outdated Components ---
    server_str = hdrs.get("Server", "") + hdrs.get("X-Powered-By", "")
    if re.search(r"(apache/2\.2|php/5\.|express/4\.)", server_str.lower()):
        add("A06", "MEDIUM", f"Outdated component/version in header: {server_str}")

    # --- A07: Identification & Authentication Failures ---
    if re.search(r"(login|account|admin|user)", url.lower()) and response.status == 200:
        if not any(h in hdrs for h in ["WWW-Authenticate", "Authorization"]):
            add("A07", "HIGH", "Possible missing authentication controls on sensitive endpoint.")

    # --- A08: Software/Data Integrity Failures ---
    if "cdn" in snippet and "http://" in snippet:
        add("A08", "MEDIUM", "Insecure CDN link (HTTP) found in response snippet.")

    # --- A09: Security Logging & Monitoring Failures ---
    required_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    missing = [h for h in required_headers if h not in hdrs]
    if missing:
        add("A09", "LOW", f"Missing security headers: {', '.join(missing)}")

    # --- A10: SSRF / Deserialization indicators ---
    if re.search(r"http://(127\.0\.0\.1|localhost|\.internal|169\.254)", body):
        add("A10", "HIGH", "Potential SSRF indicator (internal address leakage).")

    return findings


async def process_urls(
    urls: List[str],
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: int = 10,
) -> List[Finding]:
    """Concurrent analyzer for multiple URLs."""
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    conn = aiohttp.TCPConnector(ssl=False)
    results: List[Finding] = []
    async with aiohttp.ClientSession(timeout=timeout_cfg, connector=conn) as session:
        tasks = [analyze_endpoint(session, url, headers, cookies) for url in urls]
        all_results = await asyncio.gather(*tasks)
        for findings in all_results:
            results.extend(findings)
    return results


def export_json(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(fx) for fx in findings], f, indent=2)


def export_csv(findings: List[Finding], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["owasp_id", "severity", "message", "url"])
        writer.writeheader()
        writer.writerows(asdict(fx) for fx in findings)


def print_summary(findings: List[Finding]) -> None:
    print("\n=== OWASP Top 10 Findings Summary ===")
    grouped: Dict[str, List[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.owasp_id, []).append(f)

    for cat in sorted(grouped.keys()):
        print(f"\n{cat}: {len(grouped[cat])} findings")
        for fnd in grouped[cat]:
            print(f"  [{fnd.severity}] {fnd.message} → {fnd.url}")


async def main() -> None:
    if len(sys.argv) < 4:
        print("Usage: python3 owasp_tester.py <cookies> <base_url> <namespaces_file> [--json out.json] [--csv out.csv]")
        sys.exit(1)

    cookie_string = sys.argv[1]
    base_url = sys.argv[2].rstrip('/')
    namespaces_file = sys.argv[3]

    output_json: Optional[str] = None
    output_csv: Optional[str] = None
    if "--json" in sys.argv:
        output_json = sys.argv[sys.argv.index("--json") + 1]
    if "--csv" in sys.argv:
        output_csv = sys.argv[sys.argv.index("--csv") + 1]

    if not os.path.exists(namespaces_file):
        print(f"[ERROR] File not found: {namespaces_file}")
        sys.exit(1)

    with open(namespaces_file, 'r', encoding="utf-8") as f:
        namespaces = [line.strip() for line in f if line.strip()]

    cookies = parse_cookies(cookie_string)
    headers = {
        "Origin": "https://attacker.example",
        "User-Agent": "OWASP-Tester/1.0 (+security-test)",
        "Referer": "https://attacker.example",
    }

    urls = [f"{base_url}/{ns}" for ns in namespaces]
    findings = await process_urls(urls, headers, cookies)
    print_summary(findings)

    if output_json:
        export_json(findings, output_json)
        print(f"\n[INFO] JSON report written to {output_json}")
    if output_csv:
        export_csv(findings, output_csv)
        print(f"[INFO] CSV report written to {output_csv}")


if __name__ == "__main__":
    asyncio.run(main())
