#!/usr/bin/env python3
"""
WordPress leak checker
Usage:
    python3 NEW.py http://getbusy.htb
    python3 NEW.py http://getbusy.htb --json
"""

import argparse
import requests
import sys
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup

TIMEOUT = 10


def check_rest_api(base):
    url = urljoin(base, "/wp-json/wp/v2/users")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code == 200 and '"id":' in r.text and '"name":' in r.text:
            return {"check": "REST API users", "status": "vuln", "details": "Users exposed"}
        return {"check": "REST API users", "status": "safe"}
    except Exception as e:
        return {"check": "REST API users", "status": "error", "details": str(e)}


def check_sitemap(base):
    url = urljoin(base, "/wp-sitemap-users-1.xml")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if "<loc>" in r.text:
            return {"check": "User sitemap", "status": "vuln", "details": "Sitemap leaks users"}
        return {"check": "User sitemap", "status": "safe"}
    except Exception as e:
        return {"check": "User sitemap", "status": "error", "details": str(e)}


def check_author_enum(base):
    url = f"{base}/?author=2"
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        if "Location" in r.headers and "/author/" in r.headers["Location"]:
            return {"check": "Author ID enumeration", "status": "vuln",
                    "details": f"Redirects to {r.headers['Location']}"}
        return {"check": "Author ID enumeration", "status": "safe"}
    except Exception as e:
        return {"check": "Author ID enumeration", "status": "error", "details": str(e)}


def check_login_errors(base):
    url = urljoin(base, "/wp-login.php")
    results = []
    try:
        # Fake user
        r1 = requests.post(url, data={"log": "fakeuser", "pwd": "wrong"}, timeout=TIMEOUT)
        if "not registered" in r1.text.lower():
            results.append({"user": "fakeuser", "status": "vuln", "details": "Reveals non-existent user"})
        else:
            results.append({"user": "fakeuser", "status": "safe"})

        # Real user
        r2 = requests.post(url, data={"log": "admin", "pwd": "wrong"}, timeout=TIMEOUT)
        if "incorrect" in r2.text.lower():
            results.append({"user": "admin", "status": "vuln", "details": "Reveals valid username"})
        else:
            results.append({"user": "admin", "status": "safe"})

        return {"check": "Login error messages", "results": results}
    except Exception as e:
        return {"check": "Login error messages", "status": "error", "details": str(e)}


def check_plugin_listing(base):
    url = urljoin(base, "/wp-content/plugins/")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if "<title>Index of" in r.text or "Directory listing" in r.text:
            return {"check": "Plugin directory listing", "status": "vuln", "details": "Directory browsing enabled"}
        return {"check": "Plugin directory listing", "status": "safe"}
    except Exception as e:
        return {"check": "Plugin directory listing", "status": "error", "details": str(e)}


def check_theme_listing(base):
    url = urljoin(base, "/wp-content/themes/")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if "<title>Index of" in r.text or "Directory listing" in r.text:
            return {"check": "Theme directory listing", "status": "vuln", "details": "Directory browsing enabled"}
        return {"check": "Theme directory listing", "status": "safe"}
    except Exception as e:
        return {"check": "Theme directory listing", "status": "error", "details": str(e)}


def check_wp_readme(base):
    url = urljoin(base, "/readme.html")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if "Welcome to WordPress" in r.text:
            return {"check": "WordPress readme.html", "status": "vuln", "details": "Version info exposed"}
        return {"check": "WordPress readme.html", "status": "safe"}
    except Exception as e:
        return {"check": "WordPress readme.html", "status": "error", "details": str(e)}


def check_meta_generator(base):
    try:
        r = requests.get(base, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and "wordpress" in gen.get("content", "").lower():
            return {"check": "Meta generator tag", "status": "vuln", "details": gen["content"]}
        return {"check": "Meta generator tag", "status": "safe"}
    except Exception as e:
        return {"check": "Meta generator tag", "status": "error", "details": str(e)}


def check_xmlrpc(base):
    url = urljoin(base, "/xmlrpc.php")
    try:
        r = requests.post(url, data="<methodCall><methodName>demo.sayHello</methodName></methodCall>",
                          headers={"Content-Type": "text/xml"}, timeout=TIMEOUT)
        if r.status_code == 200 and "XML-RPC" in r.text:
            return {"check": "XML-RPC enabled", "status": "vuln", "details": "Accessible xmlrpc.php"}
        return {"check": "XML-RPC enabled", "status": "safe"}
    except Exception as e:
        return {"check": "XML-RPC enabled", "status": "error", "details": str(e)}


def check_uploads_listing(base):
    url = urljoin(base, "/wp-content/uploads/")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if "<title>Index of" in r.text or "Directory listing" in r.text:
            return {"check": "Uploads directory listing", "status": "vuln",
                    "details": "Directory browsing enabled"}
        return {"check": "Uploads directory listing", "status": "safe"}
    except Exception as e:
        return {"check": "Uploads directory listing", "status": "error", "details": str(e)}


def run_checks(base):
    return [
        check_rest_api(base),
        check_sitemap(base),
        check_author_enum(base),
        check_login_errors(base),
        check_plugin_listing(base),
        check_theme_listing(base),
        check_wp_readme(base),
        check_meta_generator(base),
        check_xmlrpc(base),
        check_uploads_listing(base),
    ]


def print_results(results, as_json=False):
    if as_json:
        print(json.dumps(results, indent=2))
        return

    leaks = False
    for r in results:
        if r["check"] == "Login error messages":
            print(f"[*] {r['check']}")
            for sub in r["results"]:
                status = "VULN" if sub["status"] == "vuln" else sub["status"].upper()
                details = f" - {sub['details']}" if "details" in sub else ""
                print(f"   {sub['user']}: {status}{details}")
                if sub["status"] == "vuln":
                    leaks = True
        else:
            status = "VULN" if r["status"] == "vuln" else r["status"].upper()
            details = f" - {r['details']}" if "details" in r else ""
            print(f"[*] {r['check']} ... {status}{details}")
            if r["status"] == "vuln":
                leaks = True

    print("\n=== Summary ===")
    print("Leaks detected" if leaks else "All checks safe")


def main():
    parser = argparse.ArgumentParser(description="WordPress leak checker")
    parser.add_argument("target", help="Target URL, e.g. http://getbusy.htb")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    results = run_checks(args.target)
    print_results(results, as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())
