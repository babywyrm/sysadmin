import json
import os,sys,re
import subprocess

##
##

def reset_trivy_cache():
    """Resets the Trivy cache to ensure a clean state."""
    try:
        subprocess.run(["trivy", "clean", "--all"], check=True)
    except subprocess.CalledProcessError as error:
        print(f"Error clearing Trivy cache: {error}")
        sys.exit(1)

def execute_trivy_scan(image, clear_cache=False):
    """
    Executes a Trivy scan on the provided Docker image.

    Args:
        image (str): The name of the Docker image to scan.
        clear_cache (bool): Whether to clear the Trivy cache before scanning.

    Returns:
        str: The path to the generated JSON report.
    """
    if clear_cache:
        reset_trivy_cache()

    # Generate JSON output file name
    sanitized_image_name = image.replace('/', '_').replace(':', '_')
    output_json = f"trivy_report_{sanitized_image_name}.json"
    
    # Prepare Trivy command
    trivy_cmd = [
        "trivy", "image", "--format=json",
        "--severity", "CRITICAL,HIGH,MEDIUM",
        "--vuln-type", "os,library",
        "-o", output_json,
        image
    ]
    
    try:
        subprocess.run(trivy_cmd, check=True)
    except subprocess.CalledProcessError as error:
        print(f"Trivy scan failed: {error}")
        sys.exit(1)
    
    return output_json

def process_trivy_report(report_path):
    """
    Processes the JSON output from a Trivy scan.

    Args:
        report_path (str): Path to the Trivy JSON report.

    Returns:
        tuple: Headers and rows for a markdown table.
    """
    headers = ["Package Name", "Installed Version", "Fixed Version", "Severity", "CVE ID", "Description", "Link"]
    vulnerabilities = []

    # Load the JSON file
    try:
        with open(report_path, 'r') as report_file:
            data = json.load(report_file)
    except (IOError, json.JSONDecodeError) as error:
        print(f"Error reading or parsing JSON report: {error}")
        sys.exit(1)

    # Extract vulnerability information
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulnerabilities.append([
                vuln.get("PkgName", "N/A"),
                vuln.get("InstalledVersion", "N/A"),
                vuln.get("FixedVersion", "N/A"),
                vuln.get("Severity", "N/A"),
                vuln.get("VulnerabilityID", "N/A"),
                vuln.get("Description", "N/A").split('\n')[0],  # Take first line of description
                vuln.get("PrimaryURL", "N/A")
            ])

    # Sort by severity: Critical > High > Medium
    severity_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
    vulnerabilities.sort(key=lambda x: severity_rank.get(x[3], 4))

    return headers, vulnerabilities

def save_as_markdown(headers, rows, output_path):
    """
    Saves the vulnerability data to a markdown file.

    Args:
        headers (list): List of table headers.
        rows (list): List of vulnerability rows.
        output_path (str): Path to the markdown output file.
    """
    try:
        with open(output_path, 'w') as md_file:
            # Write table headers
            md_file.write('| ' + ' | '.join(headers) + ' |\n')
            md_file.write('|---' * len(headers) + '|\n')

            # Write table rows
            for row in rows:
                md_file.write('| ' + ' | '.join(map(str, row)) + ' |\n')
    except IOError as error:
        print(f"Error writing to markdown file: {error}")
        sys.exit(1)

def run(image, clear_cache=False):
    """
    Orchestrates the scanning and report generation.

    Args:
        image (str): Docker image name to scan.
        clear_cache (bool): Whether to clear the cache before scanning.
    """
    report_json = execute_trivy_scan(image, clear_cache)
    sanitized_image_name = image.replace('/', '_').replace(':', '_')
    markdown_file = f"trivy_report_{sanitized_image_name}.md"

    table_headers, table_rows = process_trivy_report(report_json)
    save_as_markdown(table_headers, table_rows, markdown_file)

    print(f"Scan results saved to {markdown_file}\n")
    print("Summary of vulnerabilities:")
    for row in table_rows:
        print(row)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python secure_scan.py <docker_image_name> [--clear-cache]")
        sys.exit(1)

    docker_image = sys.argv[1]
    cache_option = "--clear-cache" in sys.argv
    run(docker_image, cache_option)

##
##

