import json
import os,sys,re

##
##

# Read the JSON file (replace 'yo.json' with your actual Trivy JSON file)
with open('results.json', 'r') as file:
    trivy_report = json.load(file)

# Prepare the markdown content
markdown_content = """
# CVE Report

## Critical Vulnerabilities
| CVE | CVSS Score | Fixed Version | Impacted Version | Package | Title |
| --- | ---------- | ------------- | ---------------- | ------- | ----- |
"""

# Function to add vulnerabilities to the markdown table
def add_vulnerabilities_to_markdown(vulnerabilities, severity):
    global markdown_content
    for vuln in vulnerabilities:
        markdown_content += """
| {cve} | {cvss} | {fixed_version} | {impacted_version} | {package} | {title} |
""".format(cve=vuln.get("VulnerabilityID", ""),
           cvss=vuln.get("CVSS", ""),
           fixed_version=vuln.get("FixedVersion", ""),
           impacted_version=vuln.get("InstalledVersion", ""),
           package=vuln.get("PkgName", ""),
           title=vuln.get("Title", ""))

# Function to categorize and add vulnerabilities
def categorize_vulnerabilities(vulnerabilities):
    critical_vulnerabilities = []
    high_vulnerabilities = []
    medium_vulnerabilities = []

    for vuln in vulnerabilities:
        severity = vuln.get("Severity", "").upper()
        if severity == "CRITICAL":
            critical_vulnerabilities.append(vuln)
        elif severity == "HIGH":
            high_vulnerabilities.append(vuln)
        elif severity == "MEDIUM":
            medium_vulnerabilities.append(vuln)

    add_vulnerabilities_to_markdown(critical_vulnerabilities, "CRITICAL")
    add_vulnerabilities_to_markdown(high_vulnerabilities, "HIGH")
    add_vulnerabilities_to_markdown(medium_vulnerabilities, "MEDIUM")

# Process each target and extract vulnerabilities
for result in trivy_report.get("Results", []):
    categorize_vulnerabilities(result.get("Vulnerabilities", []))

# Write the markdown content to a file
with open('cve_report.md', 'w') as file:
    file.write(markdown_content)

print("Markdown CVE report generated.")

##
##
