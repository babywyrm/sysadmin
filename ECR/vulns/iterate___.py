
import json
import os
import sys
import subprocess

##
##

def clear_trivy_cache():
    """Clears the Trivy cache to ensure fresh vulnerability scans."""
    try:
        subprocess.run(["trivy", "clean", "--all"], check=True)
        print("Trivy cache cleared successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to clean Trivy cache: {e}")
        sys.exit(1)

def execute_trivy_scan(image_name, should_clear_cache=False):
    """Executes a Trivy scan on the specified Docker image and returns the output file name."""
    if should_clear_cache:
        clear_trivy_cache()

    # Generate output file name based on the image name
    json_output_file = f"trivy_json_{image_name.replace('/', '_').replace(':', '_')}.json"
    
    # Construct the Trivy command
    trivy_command = [
        "trivy", "image", "--ignore-unfixed", "--format=json", 
        "--severity", "CRITICAL,HIGH,MEDIUM", 
        "--vuln-type", "os,library", 
        "-o", json_output_file, 
        image_name
    ]
    
    try:
        subprocess.run(trivy_command, check=True)
        print(f"Trivy scan completed for {image_name}. Output saved to {json_output_file}.")
    except subprocess.CalledProcessError as e:
        print(f"Trivy scan failed for {image_name}: {e}")
        return None
    
    return json_output_file

def parse_trivy_report(input_file, include_unfixed=False):
    """Parses the Trivy JSON report and filters vulnerabilities based on the specified criteria."""
    headers = ["Package Name", "Installed Version", "Fixed Version", "Severity", "CVE ID", "Description", "Link"]
    rows = []

    # Load the JSON report
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Parse vulnerabilities from the report
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            pkg_name = vuln.get("PkgName", "N/A")
            installed_version = vuln.get("InstalledVersion", "N/A")
            fixed_version = vuln.get("FixedVersion", "N/A")
            
            # Include or exclude vulnerabilities based on the "fixed_version" field
            if include_unfixed and (fixed_version != "N/A" and fixed_version):
                continue  # Exclude vulnerabilities that are fixed

            severity = vuln.get("Severity", "N/A")
            cve_id = vuln.get("VulnerabilityID", "N/A")
            description = vuln.get("Description", "N/A").split('\n')[0]  # Truncate to the first line
            primary_url = vuln.get("PrimaryURL", "N/A")
            
            # Build a row for the markdown table
            rows.append([pkg_name, installed_version, fixed_version, severity, cve_id, description, primary_url])

    # Sort data by severity: Critical > High > Medium
    severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
    rows.sort(key=lambda x: severity_order.get(x[3], 4))

    return headers, rows

def write_markdown_report(headers, data, output_file):
    """Writes the parsed vulnerability data to a markdown file."""
    with open(output_file, 'w') as file:
        # Write headers
        file.write('| ' + ' | '.join(headers) + ' |\n')
        file.write('|---' * len(headers) + '|\n')

        # Write data rows
        for row in data:
            file.write('| ' + ' | '.join(map(str, row)) + ' |\n')

def main(input_file, should_clear_cache=False, include_unfixed=False):
    """Main function to scan images from an input file and output results."""
    if not os.path.isfile(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        sys.exit(1)

    with open(input_file, 'r') as f:
        images = [line.strip() for line in f if line.strip()]

    if not images:
        print("No images found in the input file.")
        sys.exit(1)

    for image_name in images:
        print(f"Processing image: {image_name}")
        json_file = execute_trivy_scan(image_name, should_clear_cache)
        if json_file:
            output_file = f"trivy_vulns_{image_name.replace('/', '_').replace(':', '_')}.md"

            headers, parsed_data = parse_trivy_report(json_file, include_unfixed)
            
            write_markdown_report(headers, parsed_data, output_file)
            print(f"Data successfully written to {output_file}")

##
##

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <input_file> [--clear-cache] [--include-unfixed]")
        sys.exit(1)

    input_file = sys.argv[1]
    should_clear_cache = "--clear-cache" in sys.argv
    include_unfixed = "--include-unfixed" in sys.argv

    main(input_file, should_clear_cache, include_unfixed)

##
##
