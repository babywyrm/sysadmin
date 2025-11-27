import asyncio
import aiohttp
import sys
import os
import re

def parse_cookies(cookie_string):
    cookies = {}
    cookie_pairs = cookie_string.split(';')
    for pair in cookie_pairs:
        if "=" in pair:
            name, value = pair.strip().split('=', 1)
            cookies[name] = value
    return cookies


async def check_owasp_top10(session, url, headers, cookies):
    """Perform OWASP Top 10-style heuristic inspection."""
    try:
        async with session.get(url, headers=headers, cookies=cookies) as resp:
            print(f"\n=== Analyzing {url} (status {resp.status}) ===")
            r_headers = dict(resp.headers)
            body = await resp.text()
            body_snippet = body[:200]

            # ----------------
            # A01: Broken Access Control
            # ----------------
            if "admin" in url or "internal" in url:
                if resp.status == 200:
                    print(f"[A01 WARNING] {url} may expose admin/internal endpoint without restriction.")

            # ----------------
            # A02: Cryptographic Failures
            # ----------------
            if url.startswith("http://"):
                print(f"[A02 WARNING] Unencrypted HTTP endpoint detected: {url}")

            if "Strict-Transport-Security" not in r_headers:
                print(f"[A02 INFO] Missing HSTS header. Add Strict-Transport-Security.")

            # ----------------
            # A03: Injection indicators
            # ----------------
            if any(x in body_snippet.lower() for x in ["syntax error", "sql", "mysql", "exception"]):
                print(f"[A03 WARNING] Possible reflected backend error—may indicate Injection vulnerability.")

            # ----------------
            # A05: Security Misconfiguration (CORS etc.)
            # ----------------
            if "Access-Control-Allow-Origin" in r_headers:
                origin = r_headers["Access-Control-Allow-Origin"]
                if origin == "*":
                    print(f"[A05 VULNERABLE] CORS wildcard detected on {url}.")
                elif origin == headers["Origin"]:
                    print(f"[A05 POTENTIAL ISSUE] Origin reflection detected.")
            else:
                print(f"[A05 INFO] No Access-Control-Allow-Origin header found.")

            # Check Access-Control-Allow-Credentials
            if "Access-Control-Allow-Credentials" in r_headers:
                if r_headers["Access-Control-Allow-Credentials"].lower() == "true":
                    print(f"[A05 WARNING] Credentials allowed; verify proper configuration.")

            # ----------------
            # A06: Vulnerable/Outdated Components
            # ----------------
            server = r_headers.get("Server", "")
            powered = r_headers.get("X-Powered-By", "")
            if server or powered:
                if re.search(r"(apache/2\.2|php/5\.|express/4\.)", server.lower() + powered.lower()):
                    print(f"[A06 WARNING] Outdated server version detected: {server or powered}")

            # ----------------
            # A07: Identification and Authentication Failures
            # ----------------
            if resp.status == 200 and not any(h in r_headers for h in ["WWW-Authenticate", "Authorization"]):
                # For sensitive paths
                if re.search(r"(login|account|admin|user)", url.lower()):
                    print(f"[A07 WARNING] No authentication headers detected on {url}")

            # ----------------
            # A08: Software and Data Integrity Failures
            # (Simple heuristic - detecting CDN dependencies from insecure sources)
            # ----------------
            if "cdn" in body_snippet and "http://" in body_snippet:
                print(f"[A08 WARNING] Insecure CDN reference (HTTP) found in response snippet.")

            # ----------------
            # A09: Security Logging & Monitoring Failures
            # ----------------
            for header in [
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ]:
                if header not in r_headers:
                    print(f"[A09 INFO] Missing recommended security header: {header}")

            # ----------------
            # A10: SSRF/Insecure Deserialization (heuristic)
            # ----------------
            # Look for endpoints or body references to internal services
            if re.search(r"http://(127\.0\.0\.1|localhost|169\.254|\.internal)", body_snippet):
                print(f"[A10 WARNING] Potential SSRF indicator — internal addresses exposed in response.")

    except Exception as e:
        print(f"[ERROR] {url}: {str(e)}")


async def process_urls(urls, headers, cookies):
    async with aiohttp.ClientSession() as session:
        tasks = [check_owasp_top10(session, url, headers, cookies) for url in urls]
        await asyncio.gather(*tasks)


async def main():
    if len(sys.argv) < 4:
        print("Usage: python3 owasp_tester.py <cookies> <base_url> <namespaces_file>")
        sys.exit(1)

    cookie_string = sys.argv[1]
    base_url = sys.argv[2]
    namespaces_file = sys.argv[3]

    cookies = parse_cookies(cookie_string)
    headers = {
        "Origin": "https://attacker.com",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Referer": "https://attacker.com",
    }

    if not os.path.exists(namespaces_file):
        print(f"[ERROR] File not found: {namespaces_file}")
        sys.exit(1)

    with open(namespaces_file) as f:
        namespaces = [line.strip() for line in f if line.strip()]

    urls = [f"{base_url.rstrip('/')}/{ns}" for ns in namespaces]
    await process_urls(urls, headers, cookies)


if __name__ == "__main__":
    asyncio.run(main())
