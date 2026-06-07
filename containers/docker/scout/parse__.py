import os,sys,re

##
##

def parse_vulnerability_report(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    # Debug print the content
    print("Content of the file:\n", content)

    # Regex patterns to extract relevant information
    package_pattern = re.compile(r"pkg:(\S+)")
    cve_pattern = re.compile(r"✗ (\w+) (CVE-\d{4}-\d+|GHSA-\w+-\w+-\w+|GMS-\d{4}-\d+) \[(.*?)\]")
    link_pattern = re.compile(r"https://scout.docker.com/v/[\w-]+")
    affected_pattern = re.compile(r"Affected range\s*:\s*<(\S+)")
    fixed_pattern = re.compile(r"Fixed version\s*:\s*([\d.]+)")

    vulnerabilities = []

    packages = re.split(r"\npkg:", content)
    for package_info in packages[1:]:
        package_match = package_pattern.search("pkg:" + package_info)
        if not package_match:
            continue
        package_name = package_match.group(1)

        # Debug print package info
        print("\nPackage Info:\n", package_info)

        cve_matches = cve_pattern.findall(package_info)
        link_matches = link_pattern.findall(package_info)
        affected_matches = affected_pattern.findall(package_info)
        fixed_matches = fixed_pattern.findall(package_info)

        # Debug print matches
        print("\nCVE Matches:", cve_matches)
        print("Link Matches:", link_matches)
        print("Affected Matches:", affected_matches)
        print("Fixed Matches:", fixed_matches)

        for i, cve in enumerate(cve_matches):
            severity, cve_id, description = cve
            affected_version = affected_matches[i] if i < len(affected_matches) else "Unknown"
            fixed_version = fixed_matches[i] if i < len(fixed_matches) else "Unknown"
            link = link_matches[i] if i < len(link_matches) else "Unknown"

            vulnerabilities.append({
                'severity': severity,
                'package': package_name.split('@')[0],
                'current_version': package_name.split('@')[1],
                'affected_version': affected_version,
                'fixed_version': fixed_version,
                'cve_id': cve_id,
                'description': description,
                'link': link
            })

    # Debug print vulnerabilities
    print("\nVulnerabilities:\n", vulnerabilities)

    severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'UNSPECIFIED': 5}
    vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 6))

    return vulnerabilities

def generate_markdown_table(vulnerabilities):
    markdown_table = """
| Severity | Package | Current Version | Affected Version | Fixed Version | CVE ID | Description | Link |
|----------|---------|-----------------|------------------|---------------|--------|-------------|------|
"""

    for vuln in vulnerabilities:
        markdown_table += f"| {vuln['severity']} | {vuln['package']} | {vuln['current_version']} | {vuln['affected_version']} | {vuln['fixed_version']} | {vuln['cve_id']} | {vuln['description']} | [Link]({vuln['link']}) |\n"

    return markdown_table

def main():
    input_file = 'vulns.txt'
    output_file = 'vulns.md'

    vulnerabilities = parse_vulnerability_report(input_file)
    markdown_table = generate_markdown_table(vulnerabilities)

    with open(output_file, 'w') as file:
        file.write(markdown_table)

    print(f"Markdown table generated and saved to {output_file}")

if __name__ == "__main__":
    main()

##
##
