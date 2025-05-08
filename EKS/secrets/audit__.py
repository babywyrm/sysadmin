#!/usr/bin/env python3
"""
audit_sealed_secrets.py
A utility script to manage, maintain, and audit Bitnami Sealed Secrets.

Features:
  - List and report on Sealed Secret YAML files in a specified directory.
  - Verify required fields in each YAML file.
  - Optionally compare local Sealed Secrets with those deployed on a Kubernetes cluster.

Usage examples:
  # List and audit sealed secrets in the "sealed_secrets" directory.
  ./audit_sealed_secrets.py --dir sealed_secrets --report

  # Compare local sealed secrets with those deployed in Kubernetes.
  ./audit_sealed_secrets.py --dir sealed_secrets --check-cluster --namespace default

  # Output report in JSON format.
  ./audit_sealed_secrets.py --dir sealed_secrets --report --json
"""

import argparse
import os
import sys
import yaml
import json
import subprocess
from typing import List, Dict, Any

def load_yaml_file(path: str) -> Dict[str, Any]:
    """Load YAML file and return its content. On error returns None."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}", file=sys.stderr)
        return None

def find_sealed_secrets(directory: str) -> List[str]:
    """Return a list of YAML file paths in the given directory (recursively) that appear to be Sealed Secrets."""
    yaml_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith((".yaml", ".yml")):
                yaml_files.append(os.path.join(root, f))
    # Filter files that are SealedSecrets (kind == "SealedSecret" or case-insensitive)
    sealed_secret_files = []
    for file in yaml_files:
        data = load_yaml_file(file)
        if data and isinstance(data, dict) and data.get("kind", "").lower() == "sealedsecret":
            sealed_secret_files.append(file)
    return sealed_secret_files

def audit_sealed_secret(file_path: str) -> Dict[str, Any]:
    """
    Perform basic checks on a Sealed Secret YAML file.
    Returns an audit report as a dict.
    """
    data = load_yaml_file(file_path)
    report = {
        "file": file_path,
        "valid": True,
        "issues": [],
        "name": None,
        "namespace": None,
    }
    if not data:
        report["valid"] = False
        report["issues"].append("YAML file could not be loaded.")
        return report

    # Check kind is SealedSecret
    kind = data.get("kind", "")
    if kind.lower() != "sealedsecret":
        report["valid"] = False
        report["issues"].append(f"Kind is not 'SealedSecret': found '{kind}'.")
    # Check metadata.name and namespace exist
    metadata = data.get("metadata", {})
    if not metadata.get("name"):
        report["valid"] = False
        report["issues"].append("Missing metadata.name.")
    else:
        report["name"] = metadata["name"]
    if not metadata.get("namespace"):
        report["issues"].append("Missing metadata.namespace (defaulting to 'default').")
        report["namespace"] = "default"
    else:
        report["namespace"] = metadata["namespace"]

    # You can add additional checks here as needed

    return report

def get_cluster_sealed_secrets(namespace: str) -> List[Dict[str, Any]]:
    """
    Use kubectl to fetch the sealed secrets deployed in the given namespace.
    Returns a list of dictionaries, each representing a SealedSecret.
    """
    try:
        output = subprocess.check_output(
            ["kubectl", "get", "sealedsecret", "-n", namespace, "-o", "json"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        data = json.loads(output)
        return data.get("items", [])
    except subprocess.CalledProcessError as e:
        print(f"Error calling kubectl: {e.output}", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"Error fetching cluster secrets: {exc}", file=sys.stderr)
        return []

def compare_with_cluster(local_reports: List[Dict[str, Any]], namespace: str) -> Dict[str, List[str]]:
    """
    Compare local sealed secret files (by name) with those deployed in the cluster.
    Returns a dictionary containing lists for "missing_locally" and "not_in_cluster".
    """
    local_names = {report.get("name") for report in local_reports if report.get("name")}
    cluster_items = get_cluster_sealed_secrets(namespace)
    cluster_names = {item["metadata"]["name"] for item in cluster_items}

    missing_locally = list(cluster_names - local_names)
    not_in_cluster = list(local_names - cluster_names)

    return {
        "missing_locally": missing_locally,
        "not_in_cluster": not_in_cluster,
    }

def main():
    parser = argparse.ArgumentParser(
        description="Manage, maintain, and audit Bitnami Sealed Secrets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dir", "-d", default=".", help="Directory to search for Sealed Secret YAML files."
    )
    parser.add_argument(
        "--report", "-r", action="store_true", help="Generate an audit report for found Sealed Secrets."
    )
    parser.add_argument(
        "--json", action="store_true", help="Output the report in JSON format."
    )
    parser.add_argument(
        "--check-cluster", action="store_true", help="Compare local Sealed Secrets with those in the cluster."
    )
    parser.add_argument(
        "--namespace", "-n", default="default", help="Kubernetes namespace to check for cluster secrets."
    )

    args = parser.parse_args()

    print(f"Scanning directory: {args.dir}")
    files = find_sealed_secrets(args.dir)
    if not files:
        print("No Sealed Secret YAML files found.")
        sys.exit(0)

    print(f"Found {len(files)} Sealed Secret file(s).\n")

    audit_reports = [audit_sealed_secret(f) for f in files]

    if args.report:
        if args.json:
            print(json.dumps(audit_reports, indent=2))
        else:
            for report in audit_reports:
                print(f"File: {report['file']}")
                print(f" Name: {report['name']}")
                print(f" Namespace: {report['namespace']}")
                print(f" Valid: {report['valid']}")
                if report["issues"]:
                    print(" Issues:")
                    for issue in report["issues"]:
                        print(f"  - {issue}")
                print("")  # Empty line for separation

    if args.check_cluster:
        print(f"Comparing local sealed secrets with those in cluster namespace '{args.namespace}'...")
        comparison = compare_with_cluster(audit_reports, args.namespace)
        print("Secrets found in cluster but missing locally:")
        for name in comparison["missing_locally"]:
            print(f"  - {name}")
        print("\nSecrets found locally but not in cluster:")
        for name in comparison["not_in_cluster"]:
            print(f"  - {name}")

if __name__ == "__main__":
    main()
