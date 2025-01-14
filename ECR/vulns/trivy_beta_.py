#!/usr/bin/env python3

import boto3
import subprocess
import json
import argparse
import os,sys,re
from datetime import datetime, timezone
from typing import List, Dict, Any

##
##

def list_ecr_repositories(ecr_client) -> List[Dict[str, Any]]:
    """
    List all ECR repositories in the specified AWS region.

    Args:
        ecr_client: Boto3 ECR client.

    Returns:
        List[Dict[str, Any]]: List of repositories with their details.
    """
    repositories = []
    paginator = ecr_client.get_paginator('describe_repositories')
    try:
        for page in paginator.paginate():
            repositories.extend(page.get('repositories', []))
    except ecr_client.exceptions.ClientError as e:
        print(f"Error fetching repositories: {e}", file=sys.stderr)
        sys.exit(1)
    return repositories

def list_ecr_images(ecr_client, repository_name: str) -> List[Dict[str, Any]]:
    """
    List all images in a specific ECR repository.

    Args:
        ecr_client: Boto3 ECR client.
        repository_name (str): Name of the ECR repository.

    Returns:
        List[Dict[str, Any]]: List of image details.
    """
    images = []
    paginator = ecr_client.get_paginator('describe_images')
    try:
        for page in paginator.paginate(repositoryName=repository_name):
            images.extend(page.get('imageDetails', []))
    except ecr_client.exceptions.RepositoryNotFoundException:
        print(f"Repository '{repository_name}' not found.", file=sys.stderr)
    except ecr_client.exceptions.ClientError as e:
        print(f"Error fetching images for repository '{repository_name}': {e}", file=sys.stderr)
    return images

def scan_image_with_trivy(image_uri: str) -> Dict:
    """
    Scan a container image using Trivy and return the JSON output.

    Args:
        image_uri (str): The fully qualified URI of the container image to scan.

    Returns:
        Dict: Parsed JSON output from Trivy.
    """
    try:
        # Invoke Trivy with the 'image' subcommand
        result = subprocess.run(
            ["trivy", "image", "--quiet", "--format", "json", image_uri],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        trivy_output = json.loads(result.stdout)
        # Debug: Print the entire Trivy JSON output
        print(f"Debug: Trivy Output for {image_uri}:")
        print(json.dumps(trivy_output, indent=4))
        return trivy_output
    except subprocess.CalledProcessError as e:
        print(f"Trivy scan failed for image {image_uri}: {e.stderr}", file=sys.stderr)
        return {}
    except json.JSONDecodeError:
        print(f"Failed to parse Trivy output for image {image_uri}.", file=sys.stderr)
        return {}

def filter_cves(trivy_output: Dict, target_cves: List[str]) -> List[Dict]:
    """
    Filter the Trivy scan results for specific CVEs.

    Args:
        trivy_output (Dict): The JSON output from Trivy.
        target_cves (List[str]): List of CVE IDs to filter for.

    Returns:
        List[Dict]: List of findings that match the target CVEs.
    """
    matches = []
    vulnerabilities = trivy_output.get('Vulnerabilities', [])
    found_cves = []
    all_cves_found = [vuln.get('VulnerabilityID') for vuln in vulnerabilities]
    print(f"Debug: CVEs found in Trivy scan: {', '.join(all_cves_found)}")
    for vuln in vulnerabilities:
        vuln_id = vuln.get('VulnerabilityID')
        if vuln_id in target_cves:
            matches.append(vuln)
            found_cves.append(vuln_id)
    if found_cves:
        print(f"    * Found CVEs: {', '.join(found_cves)}")
    else:
        print(f"    * No matching CVEs found.")
    return matches

def generate_report(repositories: List[Dict[str, Any]], ecr_client, target_cves: List[str]) -> Dict[str, Any]:
    """
    Generate a vulnerability report for all images in the provided repositories.

    Args:
        repositories (List[Dict[str, Any]]): List of ECR repositories.
        ecr_client: Boto3 ECR client.
        target_cves (List[str]): List of CVE IDs to filter for.

    Returns:
        Dict[str, Any]: Consolidated vulnerability report.
    """
    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "region": ecr_client.meta.region_name,
        "scanned_repositories": [],
        "findings": []
    }

    for repo in repositories:
        repo_name = repo['repositoryName']
        repo_uri = repo['repositoryUri']
        print(f"\nScanning Repository: {repo_name} ({repo_uri})")
        images = list_ecr_images(ecr_client, repo_name)
        if not images:
            print(f"  - No images found in repository '{repo_name}'.")
            continue

        report["scanned_repositories"].append(repo_name)

        for image in images:
            image_digest = image['imageDigest']
            image_tags = image.get('imageTags', [])
            image_pushed_at = image.get('imagePushedAt', None)
            image_size_in_bytes = image.get('imageSizeInBytes', 0)

            # Construct full image URI
            if image_tags:
                for tag in image_tags:
                    image_uri = f"{repo_uri}:{tag}"
                    print(f"  - Scanning Image: {image_uri}")
                    trivy_output = scan_image_with_trivy(image_uri)
                    if not trivy_output:
                        print(f"    * No findings or scan not complete for '{image_uri}'.")
                        continue
                    filtered_findings = filter_cves(trivy_output, target_cves)
                    if filtered_findings:
                        report['findings'].append({
                            "repository": repo_name,
                            "image_uri": image_uri,
                            "image_digest": image_digest,
                            "image_pushed_at": image_pushed_at.isoformat() if image_pushed_at else None,
                            "image_size_in_bytes": image_size_in_bytes,
                            "vulnerabilities": filtered_findings
                        })
                        # Vulnerabilities already printed in filter_cves
                    else:
                        print(f"    * No matching CVEs found in '{image_uri}'.")
            else:
                # Image has no tags, use digest reference
                image_uri = f"{repo_uri}@{image_digest}"
                print(f"  - Scanning Image: {image_uri}")
                trivy_output = scan_image_with_trivy(image_uri)
                if not trivy_output:
                    print(f"    * No findings or scan not complete for '{image_uri}'.")
                    continue
                filtered_findings = filter_cves(trivy_output, target_cves)
                if filtered_findings:
                    report['findings'].append({
                        "repository": repo_name,
                        "image_uri": image_uri,
                        "image_digest": image_digest,
                        "image_pushed_at": image_pushed_at.isoformat() if image_pushed_at else None,
                        "image_size_in_bytes": image_size_in_bytes,
                        "vulnerabilities": filtered_findings
                    })
                    # Vulnerabilities already printed in filter_cves
                else:
                    print(f"    * No matching CVEs found in '{image_uri}'.")
    return report

def save_report(report: Dict[str, Any], report_path: str):
    """
    Save the vulnerability report to a JSON file.

    Args:
        report (Dict[str, Any]): Vulnerability report.
        report_path (str): Path to save the report.
    """
    try:
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\nVulnerability report saved to '{report_path}'.")
    except IOError as e:
        print(f"Error saving report to '{report_path}': {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Scan ECR images for specific CVEs using Trivy.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--repository",
        help="Name of the ECR repository to scan."
    )
    group.add_argument(
        "--all-repositories",
        action='store_true',
        help="Scan all ECR repositories in the AWS account."
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region of the ECR repositories. Default is 'us-east-1'."
    )
    parser.add_argument(
        "--cves",
        nargs='+',
        required=True,
        help="List of CVE IDs to scan for (e.g., CVE-2023-40512 CVE-2023-40513)."
    )
    parser.add_argument(
        "--report",
        default="scan_report.json",
        help="Path to the output report file. Default is 'scan_report.json'."
    )
    args = parser.parse_args()

    # Initialize ECR client
    ecr_client = boto3.client('ecr', region_name=args.region)

    # Determine repositories to scan
    if args.all_repositories:
        print(f"Fetching all ECR repositories in region '{args.region}'...")
        repositories = list_ecr_repositories(ecr_client)
    else:
        try:
            repositories_info = ecr_client.describe_repositories(repositoryNames=[args.repository])
            repositories = [{
                "repositoryName": repo['repositoryName'],
                "repositoryUri": repo['repositoryUri']
            } for repo in repositories_info.get('repositories', [])]
            print(f"Scanning specified ECR repository '{args.repository}' in region '{args.region}'...")
        except ecr_client.exceptions.RepositoryNotFoundException:
            print(f"Repository '{args.repository}' not found.", file=sys.stderr)
            sys.exit(1)
        except ecr_client.exceptions.ClientError as e:
            print(f"Error fetching repository '{args.repository}': {e}", file=sys.stderr)
            sys.exit(1)

    if not repositories:
        print("No repositories found to scan.", file=sys.stderr)
        sys.exit(0)

    print(f"Found {len(repositories)} repository(ies) to scan.")

    # Define target CVEs
    target_cves = args.cves
    print(f"Scanning for CVEs: {', '.join(target_cves)}")

    # Generate vulnerability report
    vulnerability_report = generate_report(repositories, ecr_client, target_cves)

    # Save the report to a JSON file
    save_report(vulnerability_report, args.report)

if __name__ == "__main__":
    main()

##
##
