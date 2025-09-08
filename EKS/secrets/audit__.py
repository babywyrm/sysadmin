#!/usr/bin/env python3
"""
audit_sealed_secrets.py
A utility script to manage, maintain, and audit Bitnami Sealed Secrets.

Improvements:
  - Logging with verbosity control.
  - Stronger validation (kind, apiVersion, metadata, encryptedData).
  - Optional tabular output with colors.
  - CI/CD friendly (nonzero exit on issues).
  - Supports JSON, table, and plain text output.
"""

import argparse
import os
import sys
import yaml
import json
import subprocess
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None


@dataclass
class AuditReport:
    file: str
    valid: bool = True
    issues: List[str] = None
    name: Optional[str] = None
    namespace: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def load_yaml_file(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Error loading {path}: {e}")
        return None


def find_sealed_secrets(directory: str, workers: int = 4) -> List[str]:
    yaml_files = [
        os.path.join(root, f)
        for root, _, files in os.walk(directory)
        for f in files if f.endswith((".yaml", ".yml"))
    ]

    sealed_secret_files = []

    def check_file(file):
        data = load_yaml_file(file)
        if data and isinstance(data, dict) and str(data.get("kind", "")).lower() == "sealedsecret":
            return file
        return None

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(check_file, f) for f in yaml_files]
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                sealed_secret_files.append(result)

    return sealed_secret_files


def audit_sealed_secret(file_path: str) -> AuditReport:
    data = load_yaml_file(file_path)
    report = AuditReport(file=file_path, issues=[])

    if not data:
        report.valid = False
        report.issues.append("YAML file could not be loaded.")
        return report

    kind = str(data.get("kind", "")).lower()
    if kind != "sealedsecret":
        report.valid = False
        report.issues.append(f"Kind is not 'SealedSecret': found '{kind}'.")

    api_version = data.get("apiVersion")
    if not api_version or not api_version.startswith("bitnami.com/"):
        report.issues.append(f"Unexpected or missing apiVersion: {api_version}")

    metadata = data.get("metadata", {})
    report.name = metadata.get("name")
    report.namespace = metadata.get("namespace", "default")

    if not report.name:
        report.valid = False
        report.issues.append("Missing metadata.name.")

    if "spec" not in data or "encryptedData" not in data.get("spec", {}):
        report.issues.append("Missing spec.encryptedData section.")

    return report


def get_cluster_sealed_secrets(namespace: str) -> List[Dict[str, Any]]:
    try:
        output = subprocess.check_output(
            ["kubectl", "get", "sealedsecret", "-n", namespace, "-o", "json"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        data = json.loads(output)
        return data.get("items", [])
    except FileNotFoundError:
        logging.error("kubectl not found. Please install it or adjust PATH.")
        return []
    except subprocess.CalledProcessError as e:
        logging.error(f"Error calling kubectl: {e.output}")
        return []


def compare_with_cluster(local_reports: List[AuditReport], namespace: str) -> Dict[str, List[str]]:
    local_names = {r.name for r in local_reports if r.name}
    cluster_items = get_cluster_sealed_secrets(namespace)
    cluster_names = {item["metadata"]["name"] for item in cluster_items}

    return {
        "missing_locally": sorted(cluster_names - local_names),
        "not_in_cluster": sorted(local_names - cluster_names),
    }


def print_report(audit_reports: List[AuditReport], fmt: str, json_mode: bool):
    if json_mode:
        print(json.dumps([r.to_dict() for r in audit_reports], indent=2))
        return

    if fmt == "table" and tabulate:
        rows = [
            [r.file, r.name or "-", r.namespace or "-", "OK" if r.valid else "FAIL", "; ".join(r.issues)]
            for r in audit_reports
        ]
        print(tabulate(rows, headers=["File", "Name", "Namespace", "Valid", "Issues"]))
    else:
        for r in audit_reports:
            print(f"File: {r.file}")
            print(f" Name: {r.name}")
            print(f" Namespace: {r.namespace}")
            print(f" Valid: {r.valid}")
            if r.issues:
                print(" Issues:")
                for issue in r.issues:
                    print(f"  - {issue}")
            print("")


def main():
    parser = argparse.ArgumentParser(description="Audit Bitnami Sealed Secrets.")
    parser.add_argument("--dir", "-d", default=".", help="Directory to search for Sealed Secret YAML files.")
    parser.add_argument("--report", "-r", action="store_true", help="Generate an audit report.")
    parser.add_argument("--json", action="store_true", help="Output the report in JSON format.")
    parser.add_argument("--format", choices=["plain", "table"], default="plain", help="Report output format.")
    parser.add_argument("--check-cluster", action="store_true", help="Compare with cluster secrets.")
    parser.add_argument("--namespace", "-n", default="default", help="Kubernetes namespace to check.")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity.")
    parser.add_argument("--exit-nonzero-on-issues", action="store_true", help="Exit with nonzero if issues found.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    logging.info(f"Scanning directory: {args.dir}")
    files = find_sealed_secrets(args.dir)
    if not files:
        logging.warning("No Sealed Secret YAML files found.")
        sys.exit(0)

    logging.info(f"Found {len(files)} Sealed Secret file(s).")
    audit_reports = [audit_sealed_secret(f) for f in files]

    if args.report:
        print_report(audit_reports, args.format, args.json)

    if args.check_cluster:
        comparison = compare_with_cluster(audit_reports, args.namespace)
        print(f"\nCluster comparison (namespace: {args.namespace}):")
        print("  Missing locally:", comparison["missing_locally"])
        print("  Not in cluster:", comparison["not_in_cluster"])

    if args.exit_nonzero_on_issues:
        if any(not r.valid or r.issues for r in audit_reports):
            sys.exit(1)


if __name__ == "__main__":
    main()

##
##
