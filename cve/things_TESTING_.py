#!/usr/bin/env python3
import argparse
import requests
import subprocess
import json
import os,sys,re
from pprint import pprint

# API endpoints for online sources
OSV_API_URL = "https://api.osv.dev/v1/query"
VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"
GITHUB_API_URL = "https://api.github.com/search/issues"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def query_osv(package_name, ecosystem=None):
    headers = {"Content-Type": "application/json"}
    payload = {"package": {"name": package_name}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    response = requests.post(OSV_API_URL, headers=headers, json=payload)
    if response.status_code != 200:
        if ecosystem and response.status_code == 400:
            print(f"OSV API error with ecosystem '{ecosystem}', trying without ecosystem...")
            del payload["package"]["ecosystem"]
            response = requests.post(OSV_API_URL, headers=headers, json=payload)
        else:
            print(f"OSV API error: {response.status_code} - {response.text}")
            return None
    try:
        return response.json()
    except Exception as e:
        print(f"Error parsing OSV response: {e}")
        return None

def query_vulners(query_str):
    params = {"query": query_str, "size": 10}
    try:
        response = requests.get(VULNERS_API_URL, params=params)
        if response.status_code != 200:
            print(f"Vulners API error: {response.status_code} - {response.text}")
            return None
        return response.json()
    except Exception as e:
        print(f"Exception querying Vulners API: {e}")
        return None

def query_github(query_str, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    params = {"q": query_str, "per_page": 10}
    try:
        response = requests.get(GITHUB_API_URL, headers=headers, params=params)
        if response.status_code != 200:
            print(f"GitHub API error: {response.status_code} - {response.text}")
            return None
        return response.json()
    except Exception as e:
        print(f"Exception querying GitHub API: {e}")
        return None

def query_nvd(keyword, api_key=None):
    params = {"keywordSearch": keyword, "resultsPerPage": "10"}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params)
        if response.status_code != 200:
            print(f"NVD API error: {response.status_code} - {response.text}")
            return None
        return response.json()
    except Exception as e:
        print(f"Exception querying NVD API: {e}")
        return None

def query_exploitdb(query_str):
    """
    Query ExploitDB first using the local searchsploit tool.
    If searchsploit is not installed or errors, fall back to ExploitDB’s public API.
    """
    try:
        result = subprocess.run(
            ["searchsploit", "-j", query_str],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            raise Exception(result.stderr.strip())
        data = json.loads(result.stdout)
        if "RESULTS_EXPLOIT" not in data or not data["RESULTS_EXPLOIT"]:
            raise Exception("No exploits in searchsploit output")
        return data
    except Exception as e:
        print(f"searchsploit not available or error: {e}")
        print("Falling back to ExploitDB public API...")
        fallback_url = "https://www.exploit-db.com/search"
        params = {"q": query_str, "format": "json"}
        try:
            response = requests.get(fallback_url, params=params)
            if response.status_code != 200:
                print(f"ExploitDB fallback API error: {response.status_code} - {response.text}")
                return None
            return response.json()
        except Exception as api_e:
            print(f"Exception querying ExploitDB fallback API: {api_e}")
            return None

def fix_typo(tech_str):
    return tech_str.replace("wordpess", "wordpress")

def main():
    parser = argparse.ArgumentParser(
        description="Search for CVEs and exploits for a given technology from multiple sources."
    )
    parser.add_argument("-t", "--tech", required=True,
                        help="Technology/package name (e.g., 'starbox wordpress plugin')")
    parser.add_argument("-e", "--ecosystem",
                        help="Optional ecosystem for OSV (e.g., 'wordpress', 'npm')")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--github-token",
                        help="GitHub Personal Access Token (or set GITHUB_TOKEN env var)",
                        default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--nvd-api-key",
                        help="NVD API Key (or set NVD_API_KEY env var)",
                        default=os.environ.get("NVD_API_KEY"))
    args = parser.parse_args()

    tech = fix_typo(args.tech)
    ecosystem = args.ecosystem
    verbose = args.verbose
    github_token = args.github_token
    nvd_api_key = args.nvd_api_key

    print(f"Querying vulnerabilities for: {tech}")
    if ecosystem:
        print(f"Using ecosystem: {ecosystem}")

    # Prepare query variations
    queries = [
        tech,
        f"{tech} plugin",
        f"{tech} vulnerability"
    ]
    
    #################################
    # 1. OSV API
    #################################
    print("\n--- OSV Results ---")
    found_osv = False
    for q in queries:
        print(f"\n[OSV query]: {q}")
        osv_results = query_osv(q, ecosystem)
        if not osv_results or not osv_results.get("vulns"):
            print("No vulnerabilities found for this query via OSV.")
        else:
            found_osv = True
            for vuln in osv_results["vulns"]:
                if verbose:
                    pprint(vuln)
                else:
                    cve = vuln.get("id", "N/A")
                    summary = vuln.get("summary", "No summary provided")
                    print(f"{cve}: {summary}")
        if found_osv:
            break

    #################################
    # 2. Vulners API
    #################################
    print("\n--- Vulners API Results ---")
    found_vulners = False
    for q in queries:
        print(f"\n[Vulners query]: {q}")
        vulners_results = query_vulners(q)
        if not vulners_results:
            continue
        hits = vulners_results.get("data", {}).get("search", [])
        if not hits:
            print("No results from Vulners API for this query.")
        else:
            found_vulners = True
            for hit in hits:
                vuln_id = hit.get("id", "N/A")
                title = hit.get("title", "No title")
                print(f"{vuln_id}: {title}")
        if found_vulners:
            break

    #################################
    # 3. GitHub Issues API
    #################################
    print("\n--- GitHub Issues Results ---")
    github_query = f'"{tech}" vulnerability'
    github_results = query_github(github_query, token=github_token)
    if not github_results or "items" not in github_results:
        print("No GitHub issues found using query:", github_query)
    else:
        items = github_results["items"]
        if not items:
            print("No matching GitHub issues found.")
        else:
            for item in items:
                title = item.get("title")
                url = item.get("html_url")
                print(f"{title}\n   {url}")
    
    #################################
    # 4. NVD API
    #################################
    print("\n--- NVD API Results ---")
    nvd_results = query_nvd(queries[0], api_key=nvd_api_key)
    if not nvd_results or "vulnerabilities" not in nvd_results:
        print("No vulnerabilities returned from NVD for the keyword.")
    else:
        vulnerabilities = nvd_results.get("vulnerabilities", [])
        if not vulnerabilities:
            print("NVD API returned no vulnerabilities.")
        else:
            for item in vulnerabilities:
                cve_info = item.get("cve", {})
                cve_id = cve_info.get("id", "N/A")
                descriptions = cve_info.get("descriptions", [])
                description = descriptions[0].get("value", "No description available") if descriptions else "No description available"
                print(f"{cve_id}: {description}")

    #################################
    # 5. ExploitDB (searchsploit or fallback)
    #################################
    print("\n--- ExploitDB Results ---")
    found_exploitdb = False
    for q in queries:
        print(f"\n[ExploitDB query]: {q}")
        exploit_data = query_exploitdb(q)
        if not exploit_data or "RESULTS_EXPLOIT" not in exploit_data:
            print("No results from ExploitDB for this query.")
        else:
            results = exploit_data["RESULTS_EXPLOIT"]
            if not results:
                print("No exploits found for this query on ExploitDB.")
            else:
                found_exploitdb = True
                for exp in results:
                    title = exp.get("Title", "No title")
                    exploit_id = exp.get("EDB-ID", "N/A")
                    print(f"EDB-{exploit_id}: {title}")
        if found_exploitdb:
            break


if __name__ == "__main__":
    main()

