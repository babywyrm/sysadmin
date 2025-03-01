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

def save_as_markdown(headers, rows, output_path):
    """
    Saves vulnerability data as a Markdown table.

    Args:
        headers (list): List of table headers.
        rows (list): List of vulnerability rows.
        output_path (str): Path to the markdown output file.
    """
    try:
        with open(output_path, 'w') as md_file:
            md_file.write('| ' + ' | '.join(headers) + ' |\n')
            md_file.write('| ' + ' | '.join(['---'] * len(headers)) + ' |\n')
            for row in rows:
                md_file.write('| ' + ' | '.join(map(str, row)) + ' |\n')
    except IOError as error:
        print(f"Error writing to markdown file: {error}")
        sys.exit(1)

def save_as_csv(headers, rows, output_path):
    """
    Saves vulnerability data as a CSV file.

    Args:
        headers (list): List of CSV column headers.
        rows (list): List of vulnerability rows.
        output_path (str): Path to the CSV output file.
    """
    try:
        with open(output_path, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(headers)
            writer.writerows(rows)
    except IOError as error:
        print(f"Error writing to CSV file: {error}")
        sys.exit(1)

def save_as_nosql(headers, rows, output_path):
    """
    Saves vulnerability data in a NoSQL-friendly JSON Lines format.
    Each vulnerability is saved as a JSON object on a separate line.

    Args:
        headers (list): List of field names.
        rows (list): List of vulnerability rows.
        output_path (str): Path to the NoSQL output file.
    """
    try:
        with open(output_path, 'w') as jsonl_file:
            for row in rows:
                record = dict(zip(headers, row))
                jsonl_file.write(json.dumps(record) + "\n")
    except IOError as error:
        print(f"Error writing to NoSQL output file: {error}")
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

def run(image, clear_cache, severity, vuln_type, ignore_unfixed, refresh_db,
        output_markdown, output_csv, output_nosql):
    """
    Orchestrates the scanning and report generation.

    Args:
        image (str): Docker image name.
        clear_cache (bool): Whether to clear cache.
        severity (str): Severities to display.
        vuln_type (str): Vulnerability types.
        ignore_unfixed (bool): Ignore vulnerabilities without a fix.
        refresh_db (bool): Refresh vulnerability databases.
        output_markdown (bool): Output results as Markdown.
        output_csv (bool): Output results as CSV.
        output_nosql (bool): Output results as NoSQL (JSON Lines).
    """
    report_json = execute_trivy_scan(image, clear_cache, severity, vuln_type, ignore_unfixed, refresh_db)
    headers, rows = process_trivy_report(report_json, ignore_unfixed)

    sanitized_image_name = image.replace('/', '_').replace(':', '_')

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

    run(args.image, args.clear_cache, args.severity, args.vuln_type,
        args.ignore_unfixed, args.refresh_db, args.markdown, args.csv, args.nosql)

##
##
