import os,sys,re
import json
import subprocess

##
##

def prune_sbom_cache():
    prune_command = ["docker", "scout", "cache", "prune", "--sboms"]
    try:
        subprocess.run(prune_command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error pruning SBOM cache: {e}")
        sys.exit(1)

def generate_sbom(docker_image):
    sbom_file = f"scout_{docker_image.replace('/', '_').replace(':', '_')}.sbom"
    scout_command = [
        "docker",
        "scout",
        "cves",
        "--format", "sbom",
        "--only-fixed",
        "--only-severity", "medium,high,critical",
        "--output", sbom_file,
        docker_image
    ]
    try:
        subprocess.run(scout_command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error generating SBOM: {e}")
        sys.exit(1)
    return sbom_file

def parse_sbom(sbom_file):
    with open(sbom_file, 'r', encoding='utf-8') as f:
        sbom_data = json.load(f)
    
    vulnerabilities = sbom_data.get('vulnerabilities', [])
    
    markdown_report = "| Package Name | Installed Version | Fixed Version | Severity | CVE ID | Description | Link |\n"
    markdown_report += "|---|---|---|---|---|---|---|\n"
    
    for vulnerability in vulnerabilities:
        purl = vulnerability.get('purl')
        if not purl:
            continue
        
        for v in vulnerability.get('vulnerabilities', []):
            package_name = purl.split('@')[0].replace('pkg:', '')
            installed_version = purl.split('@')[1].split('?')[0] if '?' in purl else ""
            fixed_version = v.get('fixed_by')
            severity = v.get('cvss', {}).get('severity', '').upper()
            cve_id = v.get('source_id')
            description = f"{v.get('cvss', {}).get('score', '')} - {v.get('cvss', {}).get('severity', '')} - {v.get('vulnerable_range', '')}"
            link = v.get('url', '')
            
            markdown_report += f"| {package_name} | {installed_version} | {fixed_version} | {severity} | {cve_id} | {description} | {link} |\n"
    
    return markdown_report

def sort_markdown_report(markdown_report):
    lines = markdown_report.strip().split('\n')
    
    # Extract headers and data rows separately
    headers = lines[0]
    data_rows = lines[2:]  # Skip the header and separator
    
    # Sort data rows based on the numeric severity score (sixth column)
    sorted_rows = sorted(data_rows, key=lambda row: get_severity_score(row), reverse=True)
    
    # Combine headers, separator, and sorted data rows back into a sorted markdown report
    sorted_markdown_report = f"{headers}\n{'|---|---|---|---|---|---|---|'}\n" + '\n'.join(sorted_rows)
    
    return sorted_markdown_report

def get_severity_score(row):
    try:
        return float(row.split('|')[6].strip().split()[0])
    except ValueError:
        # Handle cases where the severity score cannot be converted to float
        return float('-inf')  # Use a very low value for sorting purposes

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sbom_parser.py <docker_image>")
        sys.exit(1)
    
    docker_image = sys.argv[1]
    
    prune_sbom_cache()
    
    sbom_file = generate_sbom(docker_image)
    markdown_report = parse_sbom(sbom_file)
    sorted_markdown_report = sort_markdown_report(markdown_report)
    
    output_md_file = f"scout_{docker_image.replace('/', '_').replace(':', '_')}.md"
    with open(output_md_file, 'w', encoding='utf-8') as f:
        f.write(sorted_markdown_report)
    
    print(f"Markdown report generated: {output_md_file}")

##
##
