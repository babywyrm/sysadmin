import json
import os
import sys
import re
import subprocess

# Constants for severity levels
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]
HEADERS = ["Package Name", "Installed Version", "Fixed Version", "Severity", "CVE ID", "Description", "Link"]

def run_trivy_scan(image_name, severity_levels):
    json_output_file = f"trivy_json_{image_name.replace(':', '_')}.json"
    trivy_command = [
        "trivy", "image", "--format=json",
        "--severity", ",".join(severity_levels),
        "--vuln-type", "os,library",
        "-o", json_output_file,
        image_name
    ]
    try:
        subprocess.run(trivy_command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Trivy scan failed: {e}")
        sys.exit(1)

    return json_output_file

def parse_trivy_json(input_file):
    with open(input_file, 'r') as file:
        try:
            trivy_data = json.load(file)
        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON: {e}")
            return [], []

    data = []
    for result in trivy_data.get('Results', []):
        for vulnerability in result.get('Vulnerabilities', []):
            pkg_name = vulnerability.get("PkgName", "N/A")
            installed_version = vulnerability.get("InstalledVersion", "N/A")
            fixed_version = vulnerability.get("FixedVersion", "")
            severity = vulnerability.get("Severity", "N/A")
            cve_id = vulnerability.get("VulnerabilityID", "N/A")
            description = vulnerability.get("Description", "N/A")
            primary_url = vulnerability.get("PrimaryURL", "N/A")

            if fixed_version and severity in SEVERITIES:
                data.append([pkg_name, installed_version, fixed_version, severity, cve_id, description, primary_url])

    # Sort data by severity
    severity_order = {s: i for i, s in enumerate(SEVERITIES)}
    data.sort(key=lambda x: severity_order.get(x[3], len(SEVERITIES)))

    return HEADERS, data

def write_to_markdown(headers, data, output_file):
    with open(output_file, 'w') as file:
        # Write headers
        file.write('| ' + ' | '.join(headers) + ' |\n')
        file.write('|---' * len(headers) + '|\n')

        # Write data
        for row in data:
            file.write('| ' + ' | '.join(map(str, row)) + ' |\n')

def main(image_name, severity_levels):
    json_file = run_trivy_scan(image_name, severity_levels)
    output_file = f"trivy_vulns_{image_name.replace(':', '_')}.md"

    headers, parsed_data = parse_trivy_json(json_file)

    # Output to Markdown
    write_to_markdown(headers, parsed_data, output_file)
    print(f"Data successfully written to {output_file}")

    # Display the data on the screen
    print("\nParsed Data:")
    for row in parsed_data:
        print(row)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <docker_image_name> [<severity_levels>...]")
        sys.exit(1)

    image_name = sys.argv[1]
    severity_levels = sys.argv[2:] if len(sys.argv) > 2 else SEVERITIES
    main(image_name, severity_levels)

##
##

##
##
