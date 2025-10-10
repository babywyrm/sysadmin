#!/usr/bin/env python3
"""
ecr_trivy_orchestrator.py

A unified orchestrator that authenticates to AWS ECR, discovers repositories and images,
runs Trivy vulnerability scans, and produces both JSON and Markdown reports.

───────────────────────────────────────────────────────────────────────────────
Requirements:
  - AWS credentials configured (environment, profile, or EC2/ECS role)
  - aws‑cli v2, docker, and trivy in PATH
  - boto3 (`pip install boto3`)
───────────────────────────────────────────────────────────────────────────────
"""

import argparse
import json
import subprocess
import sys
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
import boto3


# =============================================================================
# Utility and setup helpers
# =============================================================================

def run_command(cmd: List[str], silent: bool = False) -> subprocess.CompletedProcess:
    """Execute a system command with output capture and error surface."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if not silent and result.stdout:
            print(result.stdout.strip())
        return result
    except FileNotFoundError:
        print(f"\nError: Command not found: {cmd[0]}\n")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or e.stdout or ""
        raise RuntimeError(stderr.strip())


def validate_environment() -> None:
    """Ensure required binaries exist."""
    for tool in ("aws", "docker", "trivy"):
        if not shutil.which(tool):
            print(f"Error: '{tool}' not found. Install or add to PATH.")
            sys.exit(1)


def docker_login_ecr(region: str) -> None:
    """Authenticate Docker to ECR for the specified AWS region."""
    print(f"\nAuthenticating to ECR in region {region}...")
    try:
        password_cmd = ["aws", "ecr", "get-login-password", "--region", region]
        password = subprocess.check_output(password_cmd, text=True).strip()
        login_cmd = ["docker", "login", "--username", "AWS",
                     "--password-stdin",
                     f"{boto3.client('sts').get_caller_identity()['Account']}.dkr.ecr.{region}.amazonaws.com"]
        proc = subprocess.run(login_cmd, input=password, text=True,
                              capture_output=True, check=True)
        print("ECR login successful.\n")
    except subprocess.CalledProcessError as e:
        print(f"ECR Docker login failed: {e.stderr or e.stdout}")
        sys.exit(1)


# =============================================================================
# ECR helpers
# =============================================================================

def list_repositories(ecr_client) -> List[Dict[str, Any]]:
    paginator = ecr_client.get_paginator("describe_repositories")
    repos = []
    for page in paginator.paginate():
        repos.extend(page.get("repositories", []))
    return repos


def list_images(ecr_client, repository: str) -> List[Dict[str, Any]]:
    images = []
    paginator = ecr_client.get_paginator("describe_images")
    for page in paginator.paginate(repositoryName=repository):
        images.extend(page.get("imageDetails", []))
    return images


# =============================================================================
# Trivy logic
# =============================================================================

def trivy_scan(image_uri: str) -> Dict[str, Any]:
    """Run a Trivy scan and return parsed JSON output."""
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM",
        "--ignore-unfixed",
        image_uri,
    ]
    try:
        result = run_command(cmd, silent=True)
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON output for {image_uri}")
        return {}
    except RuntimeError as e:
        out = str(e).lower()
        if "unauthorized" in out or "401" in out:
            print(f"Authentication error: {image_uri}. Verify registry login.")
        elif "repository not found" in out:
            print(f"Repository not found error: {image_uri}")
        else:
            print(f"Scan failed for {image_uri}: {e}")
        return {}


def extract_findings(trivy_data: Dict[str, Any],
                     target_cves: List[str] | None = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for res in trivy_data.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            if target_cves and v.get("VulnerabilityID") not in target_cves:
                continue
            findings.append(v)
    return findings


# =============================================================================
# Reporting
# =============================================================================

def write_json(report: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(report, indent=4))
    print(f"JSON report saved -> {path}")


def write_markdown(findings: List[Dict[str, Any]], path: Path) -> None:
    headers = ["Image", "Package", "Installed", "Fixed", "Severity", "CVE", "URL"]
    with path.open("w", encoding="utf-8") as f:
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("|" + "|".join(["---"] * len(headers)) + "|\n")
        for v in findings:
            row = [
                v.get("image_uri", "N/A"),
                v.get("PkgName", "N/A"),
                v.get("InstalledVersion", "N/A"),
                v.get("FixedVersion", "N/A"),
                v.get("Severity", "N/A"),
                v.get("VulnerabilityID", "N/A"),
                v.get("PrimaryURL", "N/A"),
            ]
            f.write("| " + " | ".join(map(str, row)) + " |\n")
    print(f"Markdown summary saved -> {path}")


# =============================================================================
# Main orchestrator
# =============================================================================

def orchestrate(region: str, scan_all: bool,
                repository: str | None, cves: List[str] | None,
                output_dir: Path, skip_login: bool) -> None:
    validate_environment()
    ecr = boto3.client("ecr", region_name=region)
    if not skip_login:
        docker_login_ecr(region)

    output_dir.mkdir(exist_ok=True, parents=True)
    repos = (list_repositories(ecr) if scan_all
             else ecr.describe_repositories(repositoryNames=[repository])["repositories"])
    if not repos:
        print("No repositories found for the specified parameters.")
        return

    all_findings: List[Dict[str, Any]] = []
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "repositories": [],
    }

    for repo in repos:
        name = repo["repositoryName"]
        uri = repo["repositoryUri"]
        print(f"\nRepository: {name}")
        images = list_images(ecr, name)
        if not images:
            print("  - No images found.")
            continue
        for img in images:
            tags = img.get("imageTags", [])
            digest = img["imageDigest"]
            if not tags:
                tags = [f"@{digest}"]
            for tag in tags:
                image_uri = f"{uri}:{tag}" if not tag.startswith("@") else f"{uri}{tag}"
                print(f"  → Scanning image {image_uri}")
                results = trivy_scan(image_uri)
                vulns = extract_findings(results, cves)
                for v in vulns:
                    v["image_uri"] = image_uri
                all_findings.extend(vulns)
                print(f"    Found {len(vulns)} matching vulnerabilities.")
        report["repositories"].append(name)

    report["findings"] = all_findings
    json_path = output_dir / "ecr_trivy_report.json"
    md_path = output_dir / "ecr_trivy_summary.md"
    write_json(report, json_path)
    write_markdown(all_findings, md_path)
    print("\nScan completed successfully.")


# =============================================================================
# Command line interface
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS ECR + Trivy unified vulnerability scanner\n"
                    "Authenticates to ECR, discovers images, scans using Trivy, and reports findings.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true",
                       help="Scan all ECR repositories in the specified region.")
    group.add_argument("--repository", metavar="NAME",
                       help="Scan a single ECR repository by name.")

    parser.add_argument("--region", default="us-east-1",
                        help="AWS region of the ECR repositories (default: us-east-1).")
    parser.add_argument("--cves", nargs="*", metavar="CVE_ID",
                        help="Optional list of CVE IDs to filter results (e.g. CVE-2023-40512 CVE-2023-40513).")
    parser.add_argument("--output-dir", type=Path, default=Path("ecr_trivy_reports"),
                        help="Destination directory for JSON and Markdown reports (default: ./ecr_trivy_reports).")
    parser.add_argument("--skip-login", action="store_true",
                        help="Skip automatic ECR Docker login (use if already logged in).")

    parser.epilog = (
        "Examples:\n"
        "  Scan all repositories in a region:\n"
        "    python ecr_trivy_orchestrator.py --all --region us-east-1\n\n"
        "  Scan a single repository for specific CVEs:\n"
        "    python ecr_trivy_orchestrator.py --repository my-repo "
        "--cves CVE-2023-40512 CVE-2023-40513 --region eu-west-1\n\n"
        "  Skip login when Docker is already authenticated:\n"
        "    python ecr_trivy_orchestrator.py --all --skip-login\n"
    )

    args = parser.parse_args()

    orchestrate(args.region, args.all, args.repository,
                args.cves, args.output_dir, args.skip_login)


if __name__ == "__main__":
    main()
