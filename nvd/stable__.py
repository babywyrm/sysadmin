#!/usr/bin/env python3
"""
CVE comparison tool for container security scanners (Trivy vs Grype).
Provides detailed analysis and reporting of vulnerability findings.
"""

import json
import subprocess
import sys
import argparse
import logging
import re
from pathlib import Path
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Set, Tuple, Optional, Any, List
from tabulate import tabulate
from yaspin import yaspin
from datetime import datetime, timedelta


@dataclass
class CVE:
    """Represents a Common Vulnerabilities and Exposures (CVE) entry."""
    id: str
    severity: str
    cvss: float = 0.0
    vector: str = ""
    source: str = ""
    fixed_version: str = ""
    has_fix: bool = False
    package: str = ""
    installed_version: str = ""


@dataclass
class ScannerVersion:
    """Encapsulates scanner version and database information."""
    name: str
    current_version: str
    is_current: bool = False
    db_version: Optional[str] = None
    db_updated: Optional[datetime] = None


# Type aliases for improved readability
CVEDict = Dict[str, CVE]
CVESet = Set[str]


class ScannerManager:
    """Manages scanner availability, versioning, and vulnerability database updates."""

    _MIN_VERSIONS: Dict[str, str] = {"trivy": "0.45.0", "grype": "0.70.0"}
    _MAX_DB_AGE_DAYS: int = 1

    def __init__(self, logger: logging.Logger) -> None:
        """
        Initializes the ScannerManager.

        Args:
            logger: The logger instance for recording messages.
        """
        self._logger: logging.Logger = logger

    def check_availability(self) -> Tuple[bool, bool]:
        """
        Checks if both Trivy and Grype are installed and accessible in the system's PATH.

        Returns:
            A tuple containing two booleans: (trivy_available, grype_available).
        """
        trivy_available: bool = self._is_available("trivy")
        grype_available: bool = self._is_available("grype")

        if not trivy_available:
            self._logger.error("Trivy not found in PATH")
        if not grype_available:
            self._logger.error("Grype not found in PATH")

        return trivy_available, grype_available

    def _is_available(self, command: str) -> bool:
        """
        Verifies if a given command is executable by checking its version.

        Args:
            command: The command to check (e.g., "trivy", "grype").

        Returns:
            True if the command is available, False otherwise.
        """
        try:
            result: subprocess.CompletedProcess = subprocess.run(
                [command, "--version"],
                capture_output=True,
                timeout=10,
                check=False
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def get_versions(self) -> Tuple[ScannerVersion, ScannerVersion]:
        """
        Retrieves version information for Trivy and Grype.

        Returns:
            A tuple containing ScannerVersion objects for Trivy and Grype.
        """
        return self._get_trivy_info(), self._get_grype_info()

    def _get_trivy_info(self) -> ScannerVersion:
        """
        Fetches Trivy's version details.

        Returns:
            A ScannerVersion object for Trivy.
        """
        try:
            result: subprocess.CompletedProcess = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            match: Optional[re.Match[str]] = re.search(r'Version:\s*(\S+)', result.stdout)
            version: str = match.group(1) if match else "unknown"

            return ScannerVersion(
                name="Trivy",
                current_version=version,
                is_current=self._check_version(version, "trivy")
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self._logger.error(f"Failed to get Trivy version: {e}")
            return ScannerVersion(name="Trivy", current_version="unknown")

    def _get_grype_info(self) -> ScannerVersion:
        """
        Fetches Grype's version and vulnerability database details.

        Returns:
            A ScannerVersion object for Grype.
        """
        try:
            result: subprocess.CompletedProcess = subprocess.run(
                ["grype", "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            match: Optional[re.Match[str]] = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
            version: str = match.group(1) if match else "unknown"

            db_info: Dict[str, Any] = self._get_grype_db()

            return ScannerVersion(
                name="Grype",
                current_version=version,
                is_current=self._check_version(version, "grype"),
                db_version=db_info.get("version"),
                db_updated=db_info.get("updated")
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self._logger.error(f"Failed to get Grype version: {e}")
            return ScannerVersion(name="Grype", current_version="unknown")

    def _get_grype_db(self) -> Dict[str, Any]:
        """
        Retrieves Grype's vulnerability database status information.

        Returns:
            A dictionary containing Grype database version and last updated timestamp.
        """
        info: Dict[str, Any] = {}
        try:
            result: subprocess.CompletedProcess = subprocess.run(
                ["grype", "db", "status"],
                capture_output=True,
                text=True,
                timeout=15,
                check=True
            )
            for line in result.stdout.split('\n'):
                if date_match := re.search(r'(?:Built|Updated):\s*(\d{4}-\d{2}-\d{2})', line):
                    try:
                        info["updated"] = datetime.strptime(date_match.group(1), '%Y-%m-%d')
                    except ValueError:
                        pass  # Ignore malformed date strings
                elif ver_match := re.search(r'(?:Schema|Version):\s*(\S+)', line):
                    info["version"] = ver_match.group(1)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # Return empty dict if command fails
        return info

    def _check_version(self, current: str, scanner: str) -> bool:
        """
        Compares the current scanner version against a minimum required version.

        Args:
            current: The current version string of the scanner.
            scanner: The name of the scanner ("trivy" or "grype").

        Returns:
            True if the current version meets or exceeds the minimum, False otherwise.
        """
        if current == "unknown":
            return False

        try:
            curr_parts: List[int] = [int(x) for x in current.split('.')[:3]]
            min_parts: List[int] = [int(x) for x in self._MIN_VERSIONS[scanner].split('.')[:3]]

            # Pad parts to ensure proper comparison
            while len(curr_parts) < len(min_parts):
                curr_parts.append(0)
            while len(min_parts) < len(curr_parts):
                min_parts.append(0)

            return curr_parts >= min_parts
        except (ValueError, KeyError):
            return False

    def update_databases(self, force: bool = False) -> Tuple[bool, bool]:
        """
        Initiates updates for Trivy and Grype vulnerability databases.

        Args:
            force: If True, force an update even if databases appear fresh.

        Returns:
            A tuple indicating successful update for (Trivy, Grype).
        """
        trivy_updated: bool = self._update_trivy()
        grype_updated: bool = self._update_grype(force)
        return trivy_updated, grype_updated

    def _update_trivy(self) -> bool:
        """
        Cleans and updates the Trivy vulnerability database.

        Returns:
            True if Trivy update was successful, False otherwise.
        """
        try:
            with yaspin(text="Updating Trivy database", color="cyan") as sp:
                subprocess.run(
                    ["trivy", "clean", "--all"],  # 'clean --all' implies a refresh on next scan
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=True
                )
                sp.ok("Done")
                return True
        except subprocess.CalledProcessError as e:
            sp.fail("Failed")
            self._logger.error(f"Trivy update failed: {e}")
            if e.stderr:
                self._logger.error(f"Trivy error output: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            sp.fail("Timeout")
            self._logger.error("Trivy update timed out")
            return False

    def _update_grype(self, force: bool) -> bool:
        """
        Updates the Grype vulnerability database.

        Args:
            force: If True, force an update regardless of current status.

        Returns:
            True if Grype update was successful, False otherwise.
        """
        try:
            with yaspin(text="Updating Grype database", color="cyan") as sp:
                if not force:
                    # Check if update is needed first
                    check_result: subprocess.CompletedProcess = subprocess.run(
                        ["grype", "db", "status"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False
                    )
                    if "No vulnerability database update available" in check_result.stdout:
                        sp.ok("Already up to date")
                        return True

                subprocess.run(
                    ["grype", "db", "update"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=True
                )
                sp.ok("Done")
                return True
        except subprocess.CalledProcessError as e:
            sp.fail("Failed")
            self._logger.error(f"Grype update failed: {e}")
            if e.stderr:
                self._logger.error(f"Grype error output: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            sp.fail("Timeout")
            self._logger.error("Grype update timed out")
            return False

    def check_db_freshness(self, grype_info: ScannerVersion) -> bool:
        """
        Determines if the Grype vulnerability database is considered fresh.

        Args:
            grype_info: The ScannerVersion object containing Grype's DB update info.

        Returns:
            True if the database is fresh, False if it's stale.
        """
        if not grype_info.db_updated:
            return True  # If no update info, assume fresh for now (or no update performed)

        cutoff: datetime = datetime.now() - timedelta(days=self._MAX_DB_AGE_DAYS)
        is_fresh: bool = grype_info.db_updated >= cutoff

        if not is_fresh:
            days_old: int = (datetime.now() - grype_info.db_updated).days
            self._logger.warning(f"Grype database is {days_old} days old. Consider updating.")

        return is_fresh

    def print_status(self, trivy: ScannerVersion, grype: ScannerVersion) -> None:
        """
        Prints a summary of the scanner's current status, versions, and database freshness.

        Args:
            trivy: The ScannerVersion object for Trivy.
            grype: The ScannerVersion object for Grype.
        """
        print(f"\n{'='*60}")
        print("SCANNER STATUS")
        print(f"{'='*60}")

        t_status: str = "OK" if trivy.is_current else "WARNING"
        print(f"[{t_status}] Trivy: {trivy.current_version} (min: {self._MIN_VERSIONS['trivy']})")

        g_status: str = "OK" if grype.is_current else "WARNING"
        print(f"[{g_status}] Grype: {grype.current_version} (min: {self._MIN_VERSIONS['grype']})")

        if grype.db_updated:
            age: int = (datetime.now() - grype.db_updated).days
            db_status: str = "FRESH" if age <= self._MAX_DB_AGE_DAYS else "STALE"
            print(f"   Database: {grype.db_version or 'N/A'} [{db_status} - {age} days old]")

        print(f"{'='*60}")


class SecurityScanner:
    """Abstract base class for container security scanners."""

    def __init__(self, logger: logging.Logger) -> None:
        """
        Initializes the SecurityScanner.

        Args:
            logger: The logger instance for recording messages.
        """
        self._logger: logging.Logger = logger

    def _run_command(self, cmd: List[str], desc: str, timeout: int = 300) -> str:
        """
        Executes an external command safely, with a spinner for user feedback.

        Args:
            cmd: A list of strings representing the command and its arguments.
            desc: A description of the command for the spinner.
            timeout: The maximum time in seconds to wait for the command to complete.

        Returns:
            The standard output of the command.

        Raises:
            subprocess.CalledProcessError: If the command returns a non-zero exit status.
            subprocess.TimeoutExpired: If the command times out.
        """
        with yaspin(text=desc, color="cyan") as spinner:
            try:
                result: subprocess.CompletedProcess = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=True
                )
                spinner.ok("Done")
                return result.stdout
            except subprocess.CalledProcessError as e:
                spinner.fail("Failed")
                self._logger.error(f"Command failed: {' '.join(cmd)}")
                self._logger.error(f"Error: {e.stderr}")
                raise
            except subprocess.TimeoutExpired:
                spinner.fail("Timeout")
                self._logger.error(f"Command timed out: {' '.join(cmd)}")
                raise

    def _load_json(self, path: Path) -> Dict[str, Any]:
        """
        Loads and parses a JSON file.

        Args:
            path: The path to the JSON file.

        Returns:
            A dictionary representing the JSON content.

        Raises:
            json.JSONDecodeError: If the file content is not valid JSON.
            IOError: If there's an issue reading the file.
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self._logger.error(f"Failed to load {path}: {e}")
            raise


class TrivyScanner(SecurityScanner):
    """Specific implementation for scanning with Trivy."""

    def scan(self, image: str, output: Path) -> None:
        """
        Runs a Trivy vulnerability scan on a specified container image.

        Args:
            image: The name or reference of the container image to scan.
            output: The path where the JSON scan results will be saved.
        """
        cmd: List[str] = [
            "trivy", "image",
            "--format", "json",
            "--output", str(output),
            "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
            image
        ]
        self._run_command(cmd, f"Running Trivy scan on {image}")

    def extract_cves(self, json_path: Path) -> CVEDict:
        """
        Parses Trivy's JSON output and extracts CVE data into a structured dictionary.

        Args:
            json_path: The path to Trivy's JSON output file.

        Returns:
            A dictionary where keys are CVE IDs and values are CVE objects.
        """
        data: Dict[str, Any] = self._load_json(json_path)
        cves: CVEDict = {}

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                cve_id: Optional[str] = vuln.get("VulnerabilityID")
                if not cve_id:
                    continue

                cvss: float = 0.0
                vector: str = ""
                nvd: Dict[str, Any] = vuln.get("CVSS", {}).get("nvd", {})

                if nvd:
                    cvss = float(nvd.get("V3Score", 0.0) or 0.0)
                    vector = nvd.get("V3Vector", "")
                else:
                    # Fallback to vendor CVSS if NVD is not available
                    vendor_cvss_list: List[Dict[str, Any]] = list(vuln.get("CVSS", {}).values())
                    if vendor_cvss_list:
                        cvss = float(vendor_cvss_list[0].get("V3Score", 0.0) or 0.0)
                        vector = vendor_cvss_list[0].get("V3Vector", "")

                fixed_version: str = vuln.get("FixedVersion", "")

                cves[cve_id] = CVE(
                    id=cve_id,
                    severity=vuln.get("Severity", "UNKNOWN"),
                    cvss=cvss,
                    vector=vector,
                    source="NVD" if nvd else "Vendor",
                    fixed_version=fixed_version,
                    has_fix=bool(fixed_version),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", "")
                )
        return cves


class GrypeScanner(SecurityScanner):
    """Specific implementation for scanning with Grype."""

    def scan(self, image: str, output: Path) -> None:
        """
        Runs a Grype vulnerability scan on a specified container image.

        Args:
            image: The name or reference of the container image to scan.
            output: The path where the JSON scan results will be saved.
        """
        cmd: List[str] = ["grype", image, "-o", "json", "--file", str(output)]
        self._run_command(cmd, f"Running Grype scan on {image}")

    def extract_cves(self, json_path: Path) -> CVEDict:
        """
        Parses Grype's JSON output and extracts CVE data into a structured dictionary.

        Args:
            json_path: The path to Grype's JSON output file.

        Returns:
            A dictionary where keys are CVE IDs and values are CVE objects.
        """
        data: Dict[str, Any] = self._load_json(json_path)
        cves: CVEDict = {}

        for match in data.get("matches", []):
            vuln: Dict[str, Any] = match.get("vulnerability", {})
            cve_id: Optional[str] = vuln.get("id")
            if not cve_id:
                continue

            cvss: float = 0.0
            vector: str = ""

            # Prefer CVSS v3 metrics
            for entry in vuln.get("cvss", []):
                if entry.get("version") in ["3.1", "3.0"]:
                    cvss = float(entry.get("metrics", {}).get("baseScore", 0.0))
                    vector = entry.get("vector", "")
                    break
            
            # Fallback if no v3 found but other CVSS data exists
            if not cvss and vuln.get("cvss"):
                first_cvss_entry: Dict[str, Any] = vuln["cvss"][0]
                cvss = float(first_cvss_entry.get("metrics", {}).get("baseScore", 0.0))
                vector = first_cvss_entry.get("vector", "")

            artifact: Dict[str, Any] = match.get("artifact", {})
            fixed_versions: List[str] = vuln.get("fix", {}).get("versions", [])
            fixed_version: str = fixed_versions[0] if fixed_versions else ""

            cves[cve_id] = CVE(
                id=cve_id,
                severity=vuln.get("severity", "UNKNOWN"),
                cvss=cvss,
                vector=vector,
                source=vuln.get("dataSource", ""),
                fixed_version=fixed_version,
                has_fix=bool(fixed_version),
                package=artifact.get("name", ""),
                installed_version=artifact.get("version", "")
            )
        return cves


class CVEAnalyzer:
    """Analyzes and compares CVE findings from multiple scanners."""

    def __init__(self, logger: logging.Logger) -> None:
        """
        Initializes the CVEAnalyzer.

        Args:
            logger: The logger instance for recording messages.
        """
        self._logger: logging.Logger = logger

    def filter_with_fixes(self, cves: CVEDict) -> CVEDict:
        """
        Filters a dictionary of CVEs to include only those with known fixes.

        Args:
            cves: A dictionary of CVE objects.

        Returns:
            A new dictionary containing only CVEs with 'has_fix' set to True.
        """
        return {cid: cve for cid, cve in cves.items() if cve.has_fix}

    def find_differences(self, trivy: CVEDict, grype: CVEDict) -> Tuple[CVESet, CVESet, CVESet]:
        """
        Compares CVEs found by Trivy and Grype to identify common and unique findings.

        Args:
            trivy: A dictionary of CVEs found by Trivy.
            grype: A dictionary of CVEs found by Grype.

        Returns:
            A tuple containing three sets: (common_cves, trivy_only_cves, grype_only_cves).
        """
        trivy_ids: CVESet = set(trivy.keys())
        grype_ids: CVESet = set(grype.keys())

        common_cves: CVESet = trivy_ids & grype_ids
        trivy_only_cves: CVESet = trivy_ids - grype_ids
        grype_only_cves: CVESet = grype_ids - trivy_ids

        return common_cves, trivy_only_cves, grype_only_cves

    def get_severity_counts(self, cves: CVEDict) -> Counter:
        """
        Counts the occurrences of CVEs by their severity level.

        Args:
            cves: A dictionary of CVE objects.

        Returns:
            A Counter object mapping severity levels to their counts.
        """
        return Counter(cve.severity.upper() for cve in cves.values())

    def generate_report(
        self,
        path: Path,
        image: str,
        trivy: CVEDict,
        grype: CVEDict,
        common: CVESet,
        unique_trivy: CVESet,
        unique_grype: CVESet,
        fixes_only: bool
    ) -> None:
        """
        Generates a detailed Markdown-formatted report of the CVE comparison.

        Args:
            path: The file path to save the Markdown report.
            image: The name of the scanned container image.
            trivy: CVEs found by Trivy.
            grype: CVEs found by Grype.
            common: CVEs found by both scanners.
            unique_trivy: CVEs found only by Trivy.
            unique_grype: CVEs found only by Grype.
            fixes_only: True if the report only includes CVEs with known fixes.
        """
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# CVE Comparison Report\n\n")
            f.write(f"**Image:** `{image}`\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Filter:** {'Fixes Only' if fixes_only else 'All CVEs'}\n\n")

            f.write("## Summary\n\n")
            f.write(f"- **Trivy Total:** {len(trivy)}\n")
            f.write(f"- **Grype Total:** {len(grype)}\n")
            f.write(f"- **Common:** {len(common)}\n")
            f.write(f"- **Trivy Only:** {len(unique_trivy)}\n")
            f.write(f"- **Grype Only:** {len(unique_grype)}\n\n")

            f.write("## Severity Breakdown\n\n")
            f.write("### Trivy\n\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count: int = self.get_severity_counts(trivy)[sev]
                if count:
                    f.write(f"- **{sev}:** {count}\n")

            f.write("\n### Grype\n\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count: int = self.get_severity_counts(grype)[sev]
                if count:
                    f.write(f"- **{sev}:** {count}\n")
            f.write("\n")

            if common:
                f.write("## Common CVEs (Found by Both)\n\n")
                self._write_table(f, common, trivy)

            if unique_trivy:
                f.write("## Trivy-Only CVEs\n\n")
                self._write_table(f, unique_trivy, trivy)

            if unique_grype:
                f.write("## Grype-Only CVEs\n\n")
                self._write_table(f, unique_grype, grype)

    def _write_table(self, file: Any, cve_ids: CVESet, cves: CVEDict) -> None:
        """
        Writes a Markdown table of CVE details to a file-like object.

        Args:
            file: The file-like object to write to.
            cve_ids: A set of CVE IDs to include in the table.
            cves: The full dictionary of CVE objects to draw data from.
        """
        file.write("| CVE ID | Severity | CVSS | Package | Installed | Fixed | Fix |\n")
        file.write("|--------|----------|------|---------|-----------|-------|-----|\n")

        sorted_cves: List[CVE] = sorted(
            [cves[cid] for cid in cve_ids],
            key=lambda x: (x.cvss, x.id),
            reverse=True
        )

        for cve in sorted_cves:
            fix_icon: str = "✅" if cve.has_fix else "❌"
            fixed_version: str = cve.fixed_version or "N/A"
            file.write(
                f"| {cve.id} | {cve.severity} | {cve.cvss:.1f} | "
                f"{cve.package} | {cve.installed_version} | {fixed_version} | {fix_icon} |\n"
            )
        file.write("\n")

    def print_summary(
        self,
        trivy: CVEDict,
        grype: CVEDict,
        common: CVESet,
        unique_trivy: CVESet,
        unique_grype: CVESet,
        fixes_only: bool,
        verbose: bool
    ) -> None:
        """
        Prints a summary of the CVE comparison to the console.

        Args:
            trivy: CVEs found by Trivy.
            grype: CVEs found by Grype.
            common: CVEs found by both scanners.
            unique_trivy: CVEs found only by Trivy.
            unique_grype: CVEs found only by Grype.
            fixes_only: True if the summary is based on CVEs with fixes.
            verbose: If True, prints detailed CVE lists for common and unique findings.
        """
        print(f"\n{'='*60}")
        print("CVE COMPARISON SUMMARY")
        print(f"{'='*60}")
        print(f"Filter: {'Fixes Only' if fixes_only else 'All CVEs'}\n")

        summary_data: List[List[Any]] = [
            ["Trivy Total", len(trivy)],
            ["Grype Total", len(grype)],
            ["Common", len(common)],
            ["Trivy Only", len(unique_trivy)],
            ["Grype Only", len(unique_grype)]
        ]
        print(tabulate(summary_data, headers=["Category", "Count"], tablefmt="grid"))

        print(f"\n{'='*60}")
        print("SEVERITY BREAKDOWN")
        print(f"{'='*60}\n")

        trivy_sev_counts: Counter = self.get_severity_counts(trivy)
        grype_sev_counts: Counter = self.get_severity_counts(grype)

        severity_data: List[List[Any]] = [
            [sev, trivy_sev_counts[sev], grype_sev_counts[sev]]
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        ]
        print(tabulate(severity_data, headers=["Severity", "Trivy", "Grype"], tablefmt="grid"))

        if verbose:
            if common:
                print(f"\n{'='*60}")
                print(f"COMMON CVEs - Top 10 by CVSS")
                print(f"{'='*60}")
                self._print_details(common, trivy, 10)

            if unique_trivy:
                print(f"\n{'='*60}")
                print(f"TRIVY-ONLY CVEs (All {len(unique_trivy)})")
                print(f"{'='*60}")
                self._print_details(unique_trivy, trivy)

            if unique_grype:
                print(f"\n{'='*60}")
                print(f"GRYPE-ONLY CVEs (All {len(unique_grype)})")
                print(f"{'='*60}")
                self._print_details(unique_grype, grype)

    def _print_details(self, ids: CVESet, cves: CVEDict, limit: Optional[int] = None) -> None:
        """
        Prints a formatted table of CVE details to the console.

        Args:
            ids: A set of CVE IDs to display.
            cves: The full dictionary of CVE objects.
            limit: An optional integer to limit the number of CVEs displayed.
        """
        sorted_cves: List[CVE] = sorted(
            [cves[cid] for cid in ids],
            key=lambda x: (x.cvss, x.id),
            reverse=True
        )

        if limit:
            sorted_cves = sorted_cves[:limit]

        detail_data: List[List[Any]] = [
            [
                cve.id,
                cve.severity,
                f"{cve.cvss:.1f}",
                cve.package[:30] + "..." if len(cve.package) > 30 else cve.package,
                "✅" if cve.has_fix else "❌"
            ]
            for cve in sorted_cves
        ]

        print(tabulate(detail_data, headers=["CVE ID", "Severity", "CVSS", "Package", "Fix"], tablefmt="grid"))


def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configures and returns a logger instance.

    Args:
        verbose: If True, sets log level to DEBUG; otherwise, INFO.

    Returns:
        A configured logging.Logger instance.
    """
    level: int = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def validate_image(image: str) -> str:
    """
    Validates the format of a container image name.

    Args:
        image: The container image name string.

    Returns:
        The validated image name string.

    Raises:
        ValueError: If the image name is invalid.
    """
    if not image or len(image) > 512:
        raise ValueError("Invalid image name length")

    # Basic regex to match common image name formats (e.g., registry/repo:tag or repo:tag)
    # This is a basic validation; comprehensive validation would be more complex.
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9._-]+$', image) and \
       not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._/-]+$', image):
        raise ValueError("Invalid image name format. Expected format like 'repo:tag' or 'registry/repo:tag'.")

    return image


def main() -> None:
    """
    Main execution function of the CVE comparison tool.
    Handles argument parsing, scanner execution, analysis, and reporting.
    """
    parser = argparse.ArgumentParser(
        description="Compare CVE findings between Trivy and Grype"
    )
    parser.add_argument("image", help="Container image to scan (e.g., nginx:latest)")
    parser.add_argument("--fixes-only", action="store_true", help="Only show CVEs with fixes")
    parser.add_argument("--output-dir", type=Path, default=Path("."), help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed CVE info")
    parser.add_argument("--force-update", action="store_true", help="Force update databases")
    parser.add_argument("--skip-update-check", action="store_true", help="Skip version checks")
    parser.add_argument("--auto-update", action="store_true", help="Auto-update stale databases")

    args: argparse.Namespace = parser.parse_args()
    logger: logging.Logger = setup_logging(args.verbose)

    try:
        mgr: ScannerManager = ScannerManager(logger)

        # Check scanner availability
        trivy_ok, grype_ok = mgr.check_availability()
        if not (trivy_ok and grype_ok):
            logger.error("Both Trivy and Grype must be installed and in PATH.")
            sys.exit(1)

        # Perform version checks and handle database updates if not skipped
        if not args.skip_update_check:
            trivy_info, grype_info = mgr.get_versions()
            mgr.print_status(trivy_info, grype_info)

            if not trivy_info.is_current:
                logger.warning(f"Trivy {trivy_info.current_version} may be outdated. Minimum required: {mgr._MIN_VERSIONS['trivy']}")
            if not grype_info.is_current:
                logger.warning(f"Grype {grype_info.current_version} may be outdated. Minimum required: {mgr._MIN_VERSIONS['grype']}")

            db_fresh: bool = mgr.check_db_freshness(grype_info)

            if args.force_update or (args.auto_update and not db_fresh):
                logger.info("Updating vulnerability databases...")
                trivy_update_success, grype_update_success = mgr.update_databases(args.force_update)

                if not (trivy_update_success and grype_update_success):
                    logger.error("One or more vulnerability database updates failed.")
                    if not args.force_update:
                        if input("Continue with potentially stale databases anyway? (y/N): ").strip().lower() != 'y':
                            sys.exit(1)
            elif not db_fresh:
                logger.warning("Vulnerability databases may be stale.")
                logger.info("Use --auto-update or --force-update to refresh databases.")
                if input("Continue with stale databases? (y/N): ").strip().lower() != 'y':
                    sys.exit(1)

        # Validate image name and prepare output directory
        image: str = validate_image(args.image)
        args.output_dir.mkdir(exist_ok=True, parents=True)

        # Initialize scanner and analyzer components
        trivy_scanner: TrivyScanner = TrivyScanner(logger)
        grype_scanner: GrypeScanner = GrypeScanner(logger)
        analyzer: CVEAnalyzer = CVEAnalyzer(logger)

        # Generate unique filenames for scan outputs and report
        safe_name: str = re.sub(r'[^a-zA-Z0-9._-]', '_', image)
        suffix: str = "_fixes" if args.fixes_only else ""

        trivy_json_path: Path = args.output_dir / f"trivy_{safe_name}{suffix}.json"
        grype_json_path: Path = args.output_dir / f"grype_{safe_name}{suffix}.json"
        report_md_path: Path = args.output_dir / f"report_{safe_name}{suffix}.md"

        # Execute scans for both Trivy and Grype
        logger.info(f"Starting vulnerability scan for image: {image}")
        trivy_scanner.scan(image, trivy_json_path)
        grype_scanner.scan(image, grype_json_path)

        # Extract and optionally filter CVE data
        trivy_cves: CVEDict = trivy_scanner.extract_cves(trivy_json_path)
        grype_cves: CVEDict = grype_scanner.extract_cves(grype_json_path)

        if args.fixes_only:
            trivy_cves = analyzer.filter_with_fixes(trivy_cves)
            grype_cves = analyzer.filter_with_fixes(grype_cves)

        # Analyze differences between scanner findings
        common_cves, unique_trivy_cves, unique_grype_cves = analyzer.find_differences(trivy_cves, grype_cves)

        # Generate and print reports
        analyzer.generate_report(
            report_md_path, image, trivy_cves, grype_cves,
            common_cves, unique_trivy_cves, unique_grype_cves, args.fixes_only
        )

        analyzer.print_summary(
            trivy_cves, grype_cves, common_cves, unique_trivy_cves,
            unique_grype_cves, args.fixes_only, args.verbose
        )

        logger.info(f"\nAnalysis complete.")
        logger.info(f"Markdown report saved: {report_md_path}")
        logger.info(f"Trivy JSON output: {trivy_json_path}")
        logger.info(f"Grype JSON output: {grype_json_path}")

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user.")
        sys.exit(130)
    except ValueError as e:
        logger.error(f"Input validation error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"An unexpected error occurred during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
