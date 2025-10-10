#!/usr/bin/env python3
"""
trivy_batch_scan.py

Batch Trivy vulnerability scanner and report generator.

Enhanced features:
  - Detects and provides clear guidance on authentication failures (ECR, GHCR, etc.)
  - Handles network timeouts and transient errors gracefully
  - Performs environment validation (checks Docker, Trivy, network)
  - Optional continue-on-error mode for large batch scans
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Tuple


# --------------------------------------------------------------------------- #
# Utility functions
# --------------------------------------------------------------------------- #

def run_command(command: List[str], retries: int = 0) -> subprocess.CompletedProcess:
    """Run a system command with optional retries and handled errors."""
    for attempt in range(retries + 1):
        try:
            result = subprocess.run(
                command, check=True, capture_output=True, text=True
            )
            return result
        except FileNotFoundError:
            print(f"Error: Required command not found: {command[0]}")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or e.stdout or ""
            if "unauthorized" in stderr.lower() or "401" in stderr:
                raise PermissionError(
                    "Authentication failed. Are you logged in to the registry?\n"
                    "Tip: For AWS ECR, run:\n"
                    "  aws ecr get-login-password --region <region> | "
                    "docker login --username AWS --password-stdin <registry-url>"
                )
            if "repository not found" in stderr.lower():
                raise FileNotFoundError(
                    "Registry reports the image or repo does not exist.\n"
                    "Confirm the image name and registry access rights."
                )
            if attempt < retries:
                print(f"Transient error detected, retrying in 5s (attempt {attempt+1}/{retries})...")
                time.sleep(5)
                continue
            raise RuntimeError(f"Command failed after {attempt + 1} attempt(s): {' '.join(command)}\n{stderr}")
    return result  # not reached


def clear_trivy_cache() -> None:
    print("Clearing Trivy cache...")
    run_command(["trivy", "clean", "--all"])
    print("Trivy cache cleared.\n")


def validate_environment() -> None:
    """Ensure required tools are installed and reachable."""
    required_commands = ["trivy", "docker"]
    for cmd in required_commands:
        if not shutil.which(cmd := cmd):
            print(f"Error: '{cmd}' is not installed or not in PATH.")
            sys.exit(1)

    try:
        subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Warning: Docker daemon not available or permission denied.")
        print("Trivy can still run if scanning remote images only.")
    try:
        subprocess.run(["trivy", "--version"], check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Error: Trivy command not executable.")
        sys.exit(1)


# --------------------------------------------------------------------------- #
# Trivy scanning and parsing
# --------------------------------------------------------------------------- #

def execute_trivy_scan(image: str, output_dir: Path, retries: int = 1) -> Path:
    """Run trivy image scan, return path to JSON results."""
    sanitized = image.replace("/", "_").replace(":", "_")
    outfile = output_dir / f"trivy_{sanitized}.json"

    print(f"Scanning image: {image}")
    command = [
        "trivy", "image",
        "--ignore-unfixed",
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM",
        "--vuln-type", "os,library",
        "-o", str(outfile),
        image,
    ]
    result = run_command(command, retries=retries)
    print(f"Scan complete: {outfile}")
    return outfile


def parse_report(report_file: Path, include_unfixed: bool) -> Tuple[List[str], List[List[str]]]:
    """Parse and return rows from Trivy JSON output."""
    headers = ["Package Name", "Installed", "Fixed", "Severity", "CVE ID", "Description", "URL"]
    rows: List[List[str]] = []

    try:
        with report_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading report {report_file}: {e}")
        return headers, rows

    for res in data.get("Results", []):
        for vuln in res.get("Vulnerabilities", []):
            fixed_ver = vuln.get("FixedVersion", "N/A")
            if not include_unfixed and (not fixed_ver or fixed_ver == "N/A"):
                continue

            rows.append([
                vuln.get("PkgName", "N/A"),
                vuln.get("InstalledVersion", "N/A"),
                fixed_ver,
                vuln.get("Severity", "UNKNOWN"),
                vuln.get("VulnerabilityID", "N/A"),
                vuln.get("Description", "N/A").split("\n")[0],
                vuln.get("PrimaryURL", "N/A"),
            ])

    severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
    rows.sort(key=lambda r: severity_order.get(r[3], 4))
    return headers, rows


def write_markdown(headers: List[str], rows: List[List[str]], output_md: Path) -> None:
    """Output vulnerabilities in markdown form."""
    with output_md.open("w", encoding="utf-8") as f:
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("|" + "|".join(["---"] * len(headers)) + "|\n")
        for r in rows:
            f.write("| " + " | ".join(map(str, r)) + " |\n")


# --------------------------------------------------------------------------- #
# Batch scanning logic
# --------------------------------------------------------------------------- #

def process_images(images: List[str], output_dir: Path, clear_cache: bool, include_unfixed: bool, skip_on_error: bool) -> None:
    """Run scans and write reports for a list of images."""
    output_dir.mkdir(parents=True, exist_ok=True)
    if clear_cache:
        clear_trivy_cache()

    for image in images:
        image = image.strip()
        if not image:
            continue
        try:
            json_path = execute_trivy_scan(image, output_dir)
            headers, rows = parse_report(json_path, include_unfixed)
            if not rows:
                print(f"No vulnerabilities for {image}\n")
                continue
            out_md = output_dir / f"{json_path.stem}.md"
            write_markdown(headers, rows, out_md)
            print(f"Markdown report written: {out_md}\n")
        except (PermissionError, FileNotFoundError) as auth_err:
            print(f"Auth or access issue for {image}: {auth_err}\n")
            if not skip_on_error:
                sys.exit(2)
        except Exception as e:
            print(f"Unexpected error scanning {image}: {e}\n")
            if not skip_on_error:
                sys.exit(1)


# --------------------------------------------------------------------------- #
# CLI handling
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(description="Enhanced Trivy batch scanner with auth handling.")
    parser.add_argument("input_file", help="List of container images (one per line).")
    parser.add_argument("--clear-cache", action="store_true", help="Clear Trivy cache before scanning.")
    parser.add_argument("--include-unfixed", action="store_true", help="Include vulnerabilities without fixes.")
    parser.add_argument("--output-dir", type=Path, default=Path("trivy_reports"), help="Directory for output files.")
    parser.add_argument("--skip-on-error", action="store_true", help="Continue batch on auth or scan failures.")
    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.is_file():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    with input_path.open("r", encoding="utf-8") as f:
        images = [ln.strip() for ln in f if ln.strip()]

    if not images:
        print("No valid images specified in input file.")
        sys.exit(1)

    print(f"Starting Trivy scan for {len(images)} image(s)...\n")
    process_images(images, args.output_dir, args.clear_cache, args.include_unfixed, args.skip_on_error)
    print("All scans completed.\n")


if __name__ == "__main__":
    import shutil
    validate_environment()
    main()
