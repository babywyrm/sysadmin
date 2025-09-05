#!/usr/bin/env python3
"""
WordPress leak checker / hardening helper ..beta..
Usage:
    python3 NEW.py http://getbusy.htb
    python3 NEW.py http://getbusy.htb --json
    python3 NEW.py http://getbusy.htb --deep
"""

import argparse
import requests
import sys
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup

TIMEOUT = 10


### === Basic Checks ===

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
        r1 = requests.post(url, data={"log": "fakeuser", "pwd": "wrong"}, timeout=TIMEOUT)
        if "not registered" in r1.text.lower():
            results.append({"user": "fakeuser", "status": "vuln", "details": "Reveals non-existent user"})
        else:
            results.append({"user": "fakeuser", "status": "safe"})

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


### === Deep Checks ===

def check_wp_config(base):
    for path in ["/wp-config.php", "/wp-config.php.bak", "/wp-config.php~", "/wp-config.old"]:
        url = urljoin(base, path)
        try:
            r = requests.get(url, timeout=TIMEOUT)
            if "DB_NAME" in r.text or "define(" in r.text:
                return {"check": "wp-config exposure", "status": "vuln", "details": f"Exposed at {path}"}
        except Exception:
            continue
    return {"check": "wp-config exposure", "status": "safe"}


def check_debug_log(base):
    url = urljoin(base, "/wp-content/debug.log")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if "Fatal" in r.text or "Warning" in r.text:
            return {"check": "Debug log exposed", "status": "vuln"}
        return {"check": "Debug log exposed", "status": "safe"}
    except Exception as e:
        return {"check": "Debug log exposed", "status": "error", "details": str(e)}


def check_backup_archives(base):
    common = ["backup.zip", "site.zip", "wordpress.zip", "db.sql", "db.sql.gz", "backup.tar.gz"]
    for fname in common:
        url = urljoin(base, "/" + fname)
        try:
            r = requests.get(url, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.content) > 1000:
                return {"check": "Backup/archive leak", "status": "vuln", "details": f"Found {fname}"}
        except Exception:
            continue
    return {"check": "Backup/archive leak", "status": "safe"}


def check_git_dir(base):
    url = urljoin(base, "/.git/config")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if "[core]" in r.text and "repositoryformatversion" in r.text:
            return {"check": ".git exposure", "status": "vuln", "details": "Git repo accessible"}
        return {"check": ".git exposure", "status": "safe"}
    except Exception as e:
        return {"check": ".git exposure", "status": "error", "details": str(e)}


def check_headers(base):
    try:
        r = requests.get(base, timeout=TIMEOUT)
        missing = []
        for h in ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
            if h not in r.headers:
                missing.append(h)
        if missing:
            return {"check": "Security headers", "status": "vuln", "details": f"Missing: {', '.join(missing)}"}
        return {"check": "Security headers", "status": "safe"}
    except Exception as e:
        return {"check": "Security headers", "status": "error", "details": str(e)}


def check_well_known(base):
    interesting = ["/.well-known/security.txt", "/.well-known/assetlinks.json",
                   "/.well-known/openid-configuration", "/robots.txt", "/humans.txt"]
    found = []
    for path in interesting:
        url = urljoin(base, path)
        try:
            r = requests.get(url, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text.strip()) > 0:
                found.append(path)
        except Exception:
            continue
    if found:
        return {"check": "Well-known files", "status": "vuln", "details": f"Exposed: {', '.join(found)}"}
    return {"check": "Well-known files", "status": "safe"}


def check_html_leaks(base):
    """Passive: scan HTML for plugin/theme hints or suspicious strings."""
    try:
        r = requests.get(base, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        leaks = []
        for tag in soup.find_all(["link", "script"]):
            src = tag.get("href") or tag.get("src")
            if src and ("wp-content/plugins/" in src or "wp-content/themes/" in src):
                leaks.append(src)
        for c in soup.find_all(string=lambda t: t and any(x in t.lower() for x in ["todo", "apikey", "debug"])):
            leaks.append(f"Comment/inline: {c.strip()[:50]}")
        if leaks:
            return {"check": "HTML leaks", "status": "vuln", "details": ", ".join(leaks[:5])}
        return {"check": "HTML leaks", "status": "safe"}
    except Exception as e:
        return {"check": "HTML leaks", "status": "error", "details": str(e)}


### === Runner ===

def run_checks(base, deep=False):
    checks = [
        check_rest_api,
        check_sitemap,
        check_author_enum,
        check_login_errors,
        check_plugin_listing,
        check_theme_listing,
        check_wp_readme,
        check_meta_generator,
        check_xmlrpc,
        check_uploads_listing,
    ]
    if deep:
        checks.extend([
            check_wp_config,
            check_debug_log,
            check_backup_archives,
            check_git_dir,
            check_headers,
            check_well_known,
            check_html_leaks,
        ])
    return [chk(base) for chk in checks]


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
    parser.add_argument("--deep", action="store_true", help="Run deeper checks (backups, headers, well-known, etc.)")
    args = parser.parse_args()

    results = run_checks(args.target, deep=args.deep)
    print_results(results, as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())
