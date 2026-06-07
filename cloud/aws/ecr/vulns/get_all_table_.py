##
##
##

import boto3
from tabulate import tabulate

def get_ecr_vulnerabilities():
    ecr_client = boto3.client('ecr')
    repos = ecr_client.describe_repositories()['repositories']

    all_vulnerabilities = []

    for repo in repos:
        repo_name = repo['repositoryName']
        image_scan_findings = ecr_client.describe_image_scan_findings(
            repositoryName=repo_name
        )['imageScanFindings']['findings']

        for finding in image_scan_findings:
            name = finding['name']
            severity = finding['severity']
            uri = finding['uri']
            vulnerabilities = finding['vulnerabilities']
            
            for vulnerability in vulnerabilities:
                vulnerability_name = vulnerability['name']
                vulnerability_severity = vulnerability['severity']
                description = vulnerability['description']
                all_vulnerabilities.append((repo_name, name, severity, vulnerability_name, vulnerability_severity, description))

    return all_vulnerabilities

def main():
    all_vulnerabilities = get_ecr_vulnerabilities()

    # Organize vulnerabilities based on severity
    vulnerabilities_by_severity = {}
    for repo_name, name, severity, vulnerability_name, vulnerability_severity, description in all_vulnerabilities:
        if severity not in vulnerabilities_by_severity:
            vulnerabilities_by_severity[severity] = []
        vulnerabilities_by_severity[severity].append((repo_name, name, vulnerability_name, description))

    # Create and print a nice table for each severity level
    for severity in sorted(vulnerabilities_by_severity.keys(), reverse=True):
        vulnerabilities_data = vulnerabilities_by_severity[severity]
        table = tabulate(vulnerabilities_data, headers=["Repo", "Image", "Vulnerability", "Description"], tablefmt="grid")
        print(f"Vulnerabilities with severity {severity}:")
        print(table)
        print("\n")

if __name__ == "__main__":
    main()

##
##
##
