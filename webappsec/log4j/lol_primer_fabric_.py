#!/usr/bin/env python3
# coding=utf-8
"""
Modern Log4j Finder Script (Fabric + Remote Scan) ..(updated)..

- Connects to staging/prod servers
- Recursively finds .jar files
- Extracts JAR metadata (version, hash)
- Checks against known vulnerable log4j-core versions
- Saves structured JSON report locally
"""

import os
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from fabric import Connection

# Define your servers
production_servers = ['prod-server-1.example.com', 'prod-server-2.example.com']
staging_servers = ['staging-server-1.example.com', 'staging-server-2.example.com']
local_output_path = '/tmp/log4j_findings.json'

# Known vulnerable ranges (simplified example, extend as needed)
VULNERABLE_VERSIONS = [
    "2.0", "2.0-beta9", "2.1", "2.3", "2.5", "2.8", "2.8.2", "2.9.1",
    "2.12.1", "2.13.0", "2.13.1", "2.14.0", "2.14.1"
]

def sha256sum(local_file):
    """Calculate SHA256 hash of a local file."""
    h = hashlib.sha256()
    with open(local_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def analyze_jar(c, jar_file):
    """
    Inspect a JAR for log4j presence and vulnerable versions.
    """
    findings = []
    try:
        # Look for log4j classes inside the JAR
        result = c.run(f"unzip -l {jar_file} | grep -i 'log4j'", hide=True, warn=True)
        if result.stdout:
            # Try to extract version info
            version_info = c.run(f"unzip -p {jar_file} META-INF/MANIFEST.MF | grep -i 'Implementation-Version'", hide=True, warn=True)
            version = version_info.stdout.strip().split(":")[-1].strip() if version_info.stdout else "unknown"

            vuln_status = "UNKNOWN"
            if version in VULNERABLE_VERSIONS:
                vuln_status = "VULNERABLE"
            elif version != "unknown":
                vuln_status = "SAFE/NEEDS REVIEW"

            findings.append({
                "server": c.host,
                "file": jar_file,
                "log4j_version": version,
                "status": vuln_status
            })
    except Exception as e:
        findings.append({
            "server": c.host,
            "file": jar_file,
            "error": str(e)
        })
    return findings

def check_server(server):
    """
    Connect to a single server and scan for log4j JARs.
    """
    server_findings = []
    with Connection(server) as c:
        print(f"[*] Scanning {server}...")
        jar_files = c.run("find / -type f -name '*.jar' 2>/dev/null", hide=True).stdout.splitlines()
        for jar in jar_files:
            server_findings.extend(analyze_jar(c, jar))
    return server_findings

def check_log4j_vulnerabilities(servers, max_workers=4):
    """
    Run scans in parallel across servers.
    """
    all_findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_server = {executor.submit(check_server, s): s for s in servers}
        for future in as_completed(future_to_server):
            all_findings.extend(future.result())

    # Write results
    with open(local_output_path, "w") as f:
        json.dump(all_findings, f, indent=4)
    print(f"[+] Scan complete. Results saved to {local_output_path}")

if __name__ == "__main__":
    check_log4j_vulnerabilities(production_servers + staging_servers)
##
