#!/usr/bin/env python3
"""
Advanced CORS Tester (2025 Edition) with CLI

- Tests preflight, simple, custom header, credentials, wildcard, reflection, and error scenarios.
- Supports all modern HTTP methods and headers.
- Command-line arguments for endpoint, token, origins, and verbosity.
- Prints detailed, color-coded results for each test.

Requires: requests, colorama
    pip install requests colorama
"""

import requests
from colorama import Fore, Style, init
import json
import argparse
import sys

init(autoreset=True)

class CORSTestCase:
    def __init__(self, name, method, url, headers=None, data=None, expect=None, description=None, verbose=False):
        self.name = name
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.data = data
        self.expect = expect or {}
        self.description = description
        self.verbose = verbose

    def run(self):
        try:
            resp = requests.request(
                self.method,
                self.url,
                headers=self.headers,
                data=self.data,
                allow_redirects=False,
                timeout=10,
            )
            return resp
        except Exception as e:
            print(f"{Fore.RED}[{self.name}] Request failed: {e}{Style.RESET_ALL}")
            return None

    def check(self, resp):
        if not resp:
            return False
        passed = True
        for key, val in self.expect.items():
            if key == "status":
                if resp.status_code != val:
                    print(f"{Fore.RED}  ✗ Expected status {val}, got {resp.status_code}{Style.RESET_ALL}")
                    passed = False
            elif key == "headers":
                for h, v in val.items():
                    actual = resp.headers.get(h)
                    if v == "*":
                        if not actual:
                            print(f"{Fore.RED}  ✗ Expected header {h} to be present{Style.RESET_ALL}")
                            passed = False
                    elif actual != v:
                        print(f"{Fore.RED}  ✗ Expected header {h}: {v}, got: {actual}{Style.RESET_ALL}")
                        passed = False
            elif key == "headers_absent":
                for h in val:
                    if resp.headers.get(h):
                        print(f"{Fore.RED}  ✗ Header {h} should NOT be present{Style.RESET_ALL}")
                        passed = False
        if passed:
            print(f"{Fore.GREEN}  ✓ Passed{Style.RESET_ALL}")
        return passed

    def print_result(self, resp):
        print(f"{Fore.CYAN}=== {self.name} ==={Style.RESET_ALL}")
        if self.description:
            print(f"{self.description}")
        if resp and self.verbose:
            print(f"Status: {resp.status_code}")
            print("Headers:")
            for k, v in resp.headers.items():
                print(f"  {k}: {v}")
            if resp.text and len(resp.text) < 1000:
                print("Body:")
                print(resp.text)
        print("-" * 40)

def build_tests(api_url, token=None, origins=None, verbose=False):
    # Use provided origins or defaults
    trusted_origin = origins[0] if origins else "http://trusted-origin.com"
    test_origin = origins[1] if origins and len(origins) > 1 else "http://test-origin.com"
    untrusted_origin = origins[2] if origins and len(origins) > 2 else "http://untrusted-origin.com"
    wildcard_origin = origins[3] if origins and len(origins) > 3 else "http://wildcard-test.com"

    tests = [
        # 1.1 Preflight Check
        CORSTestCase(
            name="Preflight OPTIONS",
            method="OPTIONS",
            url=api_url,
            headers={
                "Origin": test_origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type"
            },
            expect={
                "status": 200,
                "headers": {
                    "Access-Control-Allow-Origin": test_origin,
                    "Access-Control-Allow-Methods": "*",
                    "Access-Control-Allow-Headers": "*"
                }
            },
            description="Checks if preflight OPTIONS returns correct CORS headers.",
            verbose=verbose
        ),
        # 1.2 Simple Request
        CORSTestCase(
            name="Simple GET with Origin",
            method="GET",
            url=api_url,
            headers={
                "Origin": test_origin
            },
            expect={
                "status": 200,
                "headers": {
                    "Access-Control-Allow-Origin": test_origin
                }
            },
            description="Checks if GET with Origin returns Access-Control-Allow-Origin.",
            verbose=verbose
        ),
        # 2.1 Custom Headers
        CORSTestCase(
            name="POST with Custom Header",
            method="POST",
            url=api_url,
            headers={
                "Origin": test_origin,
                "X-Custom-Header": "custom-value",
                "Content-Type": "application/json"
            },
            data=json.dumps({"key": "value"}),
            expect={
                "status": 200,
                "headers": {
                    "Access-Control-Allow-Headers": "*"
                }
            },
            description="Checks if custom headers are allowed in CORS.",
            verbose=verbose
        ),
        # 2.2 Methods Not Allowed
        CORSTestCase(
            name="DELETE Not Allowed",
            method="DELETE",
            url=api_url,
            headers={
                "Origin": test_origin
            },
            expect={
                "status": 405,
                "headers_absent": ["Access-Control-Allow-Origin"]
            },
            description="Checks if disallowed methods are blocked by CORS.",
            verbose=verbose
        ),
        # 3.1 Origin Reflection
        CORSTestCase(
            name="Origin Reflection (Untrusted)",
            method="GET",
            url=api_url,
            headers={
                "Origin": untrusted_origin
            },
            expect={
                "status": 200,
                "headers_absent": ["Access-Control-Allow-Origin"]
            },
            description="Checks if server reflects untrusted Origin (should not).",
            verbose=verbose
        ),
        # 3.2 Wildcard Matching
        CORSTestCase(
            name="Wildcard Origin",
            method="GET",
            url=api_url,
            headers={
                "Origin": wildcard_origin
            },
            expect={
                "status": 200,
                "headers": {
                    "Access-Control-Allow-Origin": "*"
                }
            },
            description="Checks if server uses wildcard for Access-Control-Allow-Origin.",
            verbose=verbose
        ),
        # 3.3 Credentials Handling
        CORSTestCase(
            name="Credentials Handling",
            method="GET",
            url=api_url,
            headers={
                "Origin": trusted_origin,
                "Authorization": f"Bearer {token or 'YOUR_TOKEN_HERE'}",
                "Cookie": "sessionId=abc123"
            },
            expect={
                "status": 200,
                "headers": {
                    "Access-Control-Allow-Origin": trusted_origin,
                    "Access-Control-Allow-Credentials": "true"
                }
            },
            description="Checks if credentials are allowed and CORS headers are correct.",
            verbose=verbose
        ),
        # 4.1 Invalid Origins
        CORSTestCase(
            name="Invalid Origin",
            method="GET",
            url=api_url,
            headers={
                "Origin": untrusted_origin
            },
            expect={
                "status": 200,
                "headers_absent": ["Access-Control-Allow-Origin"]
            },
            description="Checks if untrusted origins are blocked.",
            verbose=verbose
        ),
        # 4.2 Malformed Preflight
        CORSTestCase(
            name="Malformed Preflight",
            method="OPTIONS",
            url=api_url,
            headers={
                "Origin": "malformed",
                "Access-Control-Request-Method": "PUT"
            },
            expect={
                "status": 400
            },
            description="Checks if malformed preflight is rejected.",
            verbose=verbose
        ),
        # 5.1 Advanced: PATCH, WebDAV, and 2025+ methods
        CORSTestCase(
            name="PATCH with Origin",
            method="PATCH",
            url=api_url,
            headers={
                "Origin": test_origin,
                "Content-Type": "application/json"
            },
            data=json.dumps({"patch": "value"}),
            expect={
                "status": 200,
                "headers": {
                    "Access-Control-Allow-Origin": test_origin
                }
            },
            description="Checks PATCH method CORS handling.",
            verbose=verbose
        ),
        CORSTestCase(
            name="WebDAV PROPFIND",
            method="PROPFIND",
            url=api_url,
            headers={
                "Origin": test_origin
            },
            expect={
                "status": 405
            },
            description="Checks WebDAV method CORS handling (should be blocked unless allowed).",
            verbose=verbose
        ),
    ]
    return tests

def main():
    parser = argparse.ArgumentParser(
        description="Advanced CORS Tester (2025 Edition) with CLI"
    )
    parser.add_argument(
        "--url", "-u", required=True, help="Target API endpoint (e.g., http://localhost:8000/api/resource)"
    )
    parser.add_argument(
        "--token", "-t", help="Bearer token for Authorization header (used in credentials test)"
    )
    parser.add_argument(
        "--origins", "-o", nargs="+", help="List of origins: trusted test untrusted wildcard"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show full response headers and body"
    )
    args = parser.parse_args()

    tests = build_tests(
        api_url=args.url,
        token=args.token,
        origins=args.origins,
        verbose=args.verbose
    )

    print(f"{Fore.YELLOW}Starting Advanced CORS Tests...{Style.RESET_ALL}\n")
    for test in tests:
        resp = test.run()
        test.print_result(resp)
        test.check(resp)
        print("\n")

    print(f"{Fore.GREEN}All tests completed. Review results above.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
