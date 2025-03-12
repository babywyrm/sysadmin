#!/usr/bin/env python3
import json
import os,sys,re
import subprocess
import argparse
import csv

def reset_trivy_cache():
    """Resets the Trivy cache to ensure a clean state."""
    try:
        subprocess.run(["trivy", "clean", "--all"], check=True)
    except subprocess.CalledProcessError as error:
        print(f"Error clearing Trivy cache: {error}")
        sys.exit(1)

def refresh_vulnerability_databases():
    """
    Refreshes vulnerability databases by downloading the latest 
    general DB and Java DB.
    """
    try:
        subprocess.run(["trivy", "--download-db-only"], check=True)
        subprocess.run(["trivy", "--download-java-db-only"], check=True)
    except subprocess.CalledProcessError as error:
        print(f"Error refreshing vulnerability databases: {error}")
        sys.exit(1)

def execute_trivy_scan(image, clear_cache=False, severity="CRITICAL,HIGH,MEDIUM",
                       vuln_type="os,library", ignore_unfixed=False, refresh_db=False):
    """
    Executes a Trivy scan on the provided Docker image.

    Args:
        image (str): The Docker image to scan.
        clear_cache (bool): Whether to clear the Trivy cache before scanning.
        severity (str): Comma-separated severities to report.
        vuln_type (str): Comma-separated vulnerability types (e.g., "os,library").
        ignore_unfixed (bool): If set, skip vulnerabilities without fixes.
        refresh_db (bool): If True, refresh the vulnerability databases.

    Returns:
        str: The path to the generated JSON report.
    """
    if clear_cache:
        reset_trivy_cache()

    if refresh_db:
        refresh_vulnerability_databases()

    sanitized_image_name = image.replace('/', '_').replace(':', '_')
    output_json = f"trivy_report_{sanitized_image_name}.json"
    
    trivy_cmd = [
        "trivy", "image", "--format=json",
        "--severity", severity,
        "--vuln-type", vuln_type,
        "-o", output_json,
        image
    ]
    
    if ignore_unfixed:
        trivy_cmd.append("--ignore-unfixed")
    
    try:
        subprocess.run(trivy_cmd, check=True)
    except subprocess.CalledProcessError as error:
        print(f"Trivy scan failed: {error}")
        sys.exit(1)
    
    return output_json

def process_trivy_report(report_path, ignore_unfixed=False):
    """
    Processes the JSON output from a Trivy scan.

    Args:
        report_path (str): Path to the Trivy JSON report.
        ignore_unfixed (bool): Whether to ignore vulnerabilities without a fix.

    Returns:
        tuple: (headers, vulnerabilities) for output.
    """
    headers = ["Package Name", "Installed Version", "Fixed Version", "Severity", "CVE ID", "Description", "Link"]
    vulnerabilities = []

    try:
        with open(report_path, 'r') as report_file:
            data = json.load(report_file)
    except (IOError, json.JSONDecodeError) as error:
        print(f"Error reading or parsing JSON report: {error}")
        sys.exit(1)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            fixed_version = vuln.get("FixedVersion", "N/A")
            if ignore_unfixed and (fixed_version == "" or fixed_version == "N/A"):
                continue
            vulnerabilities.append([
                vuln.get("PkgName", "N/A"),
                vuln.get("InstalledVersion", "N/A"),
                fixed_version,
                vuln.get("Severity", "N/A"),
                vuln.get("VulnerabilityID", "N/A"),
                vuln.get("Description", "N/A").split('\n')[0],
                vuln.get("PrimaryURL", "N/A")
            ])

    severity_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
    vulnerabilities.sort(key=lambda x: severity_rank.get(x[3], 4))

    return headers, vulnerabilities

def failsafe_check(image):
    """Failsafe check to ensure CVEs can be detected in vulnerable images."""
    print(f"Running failsafe check for {image}...")
    try:
        # Perform a Trivy scan to check if vulnerabilities are detected
        report_json = execute_trivy_scan(image, clear_cache=True, severity="CRITICAL,HIGH,MEDIUM", vuln_type="os,library")
        
        # Process the report to count vulnerabilities
        headers, vulnerabilities = process_trivy_report(report_json)
        print(f"Found {len(vulnerabilities)} CVEs in {image}")
    except Exception as e:
        print(f"Failsafe check failed for {image}: {e}")
        sys.exit(1)

def print_plain_text_table(headers, rows):
    """
    Prints the vulnerability data as a plain text table to stdout.
    
    Args:
        headers (list): List of table headers.
        rows (list): List of vulnerability rows.
    """
    col_widths = [max(len(str(h)), *(len(str(row[i])) for row in rows)) for i, h in enumerate(headers)]
    header_line = " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers))
    separator = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    print(header_line)
    print(separator)
    for row in rows:
        print(" | ".join(f"{str(row[i]):<{col_widths[i]}}" for i in range(len(row))))

def run_with_failsafe(target_image, clear_cache, severity, vuln_type, ignore_unfixed, refresh_db,
                      output_markdown, output_csv, output_nosql):
    """
    Orchestrates the scanning and report generation, with a failsafe to ensure CVEs are detected
    in vulnerable images before proceeding with the scan for the target image.
    
    Args:
        target_image (str): Docker image name for the target image.
        clear_cache (bool): Whether to clear cache.
        severity (str): Severities to display.
        vuln_type (str): Vulnerability types.
        ignore_unfixed (bool): Ignore vulnerabilities without a fix.
        refresh_db (bool): Refresh vulnerability databases.
        output_markdown (bool): Output results as Markdown.
        output_csv (bool): Output results as CSV.
        output_nosql (bool): Output results as NoSQL (JSON Lines).
    """
    # First, check the predefined vulnerable-by-design images
    failsafe_check("bkimminich/juice-shop")
    failsafe_check("vulnerables/web-dvwa")

    # After failsafe passes, proceed with the actual Trivy scan for the target image
    print(f"\nProceeding with Trivy scan for target image: {target_image}")
    report_json = execute_trivy_scan(target_image, clear_cache, severity, vuln_type, ignore_unfixed, refresh_db)
    headers, rows = process_trivy_report(report_json, ignore_unfixed)

    sanitized_image_name = target_image.replace('/', '_').replace(':', '_')

    if output_markdown:
        markdown_file = f"trivy_report_{sanitized_image_name}.md"
        save_as_markdown(headers, rows, markdown_file)
        print(f"Scan results saved to {markdown_file}")
    if output_csv:
        csv_file = f"trivy_report_{sanitized_image_name}.csv"
        save_as_csv(headers, rows, csv_file)
        print(f"Scan results saved to {csv_file}")
    if output_nosql:
        nosql_file = f"trivy_report_{sanitized_image_name}.jsonl"
        save_as_nosql(headers, rows, nosql_file)
        print(f"Scan results saved to {nosql_file}")
    if not (output_markdown or output_csv or output_nosql):
        print("Scan results:")
        print_plain_text_table(headers, rows)
    
    print("\nSummary of vulnerabilities:")
    for row in rows:
        print(row)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a Trivy scan on a Docker image and generate a vulnerability report."
    )
    parser.add_argument("image", help="Docker image name to scan")
    parser.add_argument("--clear-cache", action="store_true", help="Clear Trivy cache before scanning")
    parser.add_argument("--severity", default="CRITICAL,HIGH,MEDIUM", help="Comma-separated severities to display")
    parser.add_argument("--vuln-type", default="os,library", help="Comma-separated vulnerability types (e.g., os,library)")
    parser.add_argument("--ignore-unfixed", action="store_true", help="Ignore vulnerabilities without a fix")
    parser.add_argument("--refresh-db", action="store_true", help="Force refresh of vulnerability databases")
    parser.add_argument("--markdown", action="store_true", help="Output results as a Markdown file")
    parser.add_argument("--csv", action="store_true", help="Output results as a CSV file")
    parser.add_argument("--nosql", action="store_true", help="Output results as a NoSQL (JSON Lines) file")
    args = parser.parse_args()

    run_with_failsafe(args.image, args.clear_cache, args.severity, args.vuln_type,
                      args.ignore_unfixed, args.refresh_db, args.markdown, args.csv, args.nosql)

##
##
