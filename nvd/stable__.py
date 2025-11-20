#!/usr/bin/env python3
"""
CVE comparison tool for container security scanners (Trivy vs Grype).. (beta)..
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
from typing import Dict, Set, Tuple, Optional, Any
from tabulate import tabulate
from yaspin import yaspin
from datetime import datetime, timedelta


@dataclass
class CVE:
    """CVE data representation."""
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
    """Scanner version information."""
    name: str
    current_version: str
    is_current: bool = False
    db_version: Optional[str] = None
    db_updated: Optional[datetime] = None


CVEDict = Dict[str, CVE]
CVESet = Set[str]


class ScannerManager:
    """Manages scanner installations and updates."""

    MIN_VERSIONS = {"trivy": "0.45.0", "grype": "0.70.0"}
    MAX_DB_AGE_DAYS = 1

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def check_availability(self) -> Tuple[bool, bool]:
        """Check if both scanners are installed."""
        trivy = self._is_available("trivy")
        grype = self._is_available("grype")

        if not trivy:
            self.logger.error("Trivy not found in PATH")
        if not grype:
            self.logger.error("Grype not found in PATH")

        return trivy, grype

    def _is_available(self, command: str) -> bool:
        """Check if command is available."""
        try:
            result = subprocess.run(
                [command, "--version"],
                capture_output=True,
                timeout=10,
                check=False
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def get_versions(self) -> Tuple[ScannerVersion, ScannerVersion]:
        """Get version info for both scanners."""
        return self._get_trivy_info(), self._get_grype_info()

    def _get_trivy_info(self) -> ScannerVersion:
        """Get Trivy version."""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            match = re.search(r'Version:\s*(\S+)', result.stdout)
            version = match.group(1) if match else "unknown"

            return ScannerVersion(
                name="Trivy",
                current_version=version,
                is_current=self._check_version(version, "trivy")
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.logger.error(f"Failed to get Trivy version: {e}")
            return ScannerVersion(name="Trivy", current_version="unknown")

    def _get_grype_info(self) -> ScannerVersion:
        """Get Grype version and DB info."""
        try:
            result = subprocess.run(
                ["grype", "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True
            )
            match = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
            version = match.group(1) if match else "unknown"

            db_info = self._get_grype_db()

            return ScannerVersion(
                name="Grype",
                current_version=version,
                is_current=self._check_version(version, "grype"),
                db_version=db_info.get("version"),
                db_updated=db_info.get("updated")
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.logger.error(f"Failed to get Grype version: {e}")
            return ScannerVersion(name="Grype", current_version="unknown")

    def _get_grype_db(self) -> Dict[str, Any]:
        """Get Grype database info."""
        try:
            result = subprocess.run(
                ["grype", "db", "status"],
                capture_output=True,
                text=True,
                timeout=15,
                check=True
            )

            info = {}
            for line in result.stdout.split('\n'):
                if date_match := re.search(r'(?:Built|Updated):\s*(\d{4}-\d{2}-\d{2})', line):
                    try:
                        info["updated"] = datetime.strptime(date_match.group(1), '%Y-%m-%d')
                    except ValueError:
                        pass
                elif ver_match := re.search(r'(?:Schema|Version):\s*(\S+)', line):
                    info["version"] = ver_match.group(1)

            return info
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return {}

    def _check_version(self, current: str, scanner: str) -> bool:
        """Check if version meets minimum."""
        if current == "unknown":
            return False

        try:
            curr_parts = [int(x) for x in current.split('.')[:3]]
            min_parts = [int(x) for x in self.MIN_VERSIONS[scanner].split('.')[:3]]

            while len(curr_parts) < len(min_parts):
                curr_parts.append(0)
            while len(min_parts) < len(curr_parts):
                min_parts.append(0)

            return curr_parts >= min_parts
        except (ValueError, KeyError):
            return False

    def update_databases(self, force: bool = False) -> Tuple[bool, bool]:
        """Update vulnerability databases."""
        trivy = self._update_trivy(force)
        grype = self._update_grype(force)
        return trivy, grype

    def _update_trivy(self, force: bool) -> bool:
        """Update Trivy database."""
        try:
            with yaspin(text="Updating Trivy database", color="cyan") as sp:
                result = subprocess.run(
                    ["trivy", "clean", "--all"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=True
                )
                sp.ok("Done")
                return True
        except subprocess.CalledProcessError as e:
            sp.fail("Failed")
            self.logger.error(f"Trivy update failed: {e}")
            if e.stderr:
                self.logger.error(f"Trivy error output: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            sp.fail("Timeout")
            self.logger.error("Trivy update timed out")
            return False

    def _update_grype(self, force: bool) -> bool:
        """Update Grype database."""
        try:
            with yaspin(text="Updating Grype database", color="cyan") as sp:
                # Check if update is needed first
                if not force:
                    check_result = subprocess.run(
                        ["grype", "db", "status"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False
                    )
                    if "No vulnerability database update available" in check_result.stdout:
                        sp.ok("Already up to date")
                        return True

                result = subprocess.run(
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
            self.logger.error(f"Grype update failed: {e}")
            if e.stderr:
                self.logger.error(f"Grype error output: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            sp.fail("Timeout")
            self.logger.error("Grype update timed out")
            return False

    def check_db_freshness(self, grype_info: ScannerVersion) -> bool:
        """Check if database is fresh."""
        if not grype_info.db_updated:
            return True

        cutoff = datetime.now() - timedelta(days=self.MAX_DB_AGE_DAYS)
        is_fresh = grype_info.db_updated >= cutoff

        if not is_fresh:
            days = (datetime.now() - grype_info.db_updated).days
            self.logger.warning(f"Grype database is {days} days old")

        return is_fresh

    def print_status(self, trivy: ScannerVersion, grype: ScannerVersion) -> None:
        """Print scanner status."""
        print(f"\n{'='*60}")
        print("SCANNER STATUS")
        print(f"{'='*60}")

        t_status = "OK" if trivy.is_current else "WARNING"
        print(f"[{t_status}] Trivy: {trivy.current_version} (min: {self.MIN_VERSIONS['trivy']})")

        g_status = "OK" if grype.is_current else "WARNING"
        print(f"[{g_status}] Grype: {grype.current_version} (min: {self.MIN_VERSIONS['grype']})")

        if grype.db_updated:
            age = (datetime.now() - grype.db_updated).days
            db_status = "FRESH" if age <= 1 else "STALE"
            print(f"   Database: {grype.db_version or 'N/A'} [{db_status} - {age} days old]")

        print(f"{'='*60}")


class SecurityScanner:
    """Base scanner operations."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def _run_command(self, cmd: list[str], desc: str, timeout: int = 300) -> str:
        """Execute command safely."""
        with yaspin(text=desc, color="cyan") as spinner:
            try:
                result = subprocess.run(
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
                self.logger.error(f"Command failed: {' '.join(cmd)}")
                self.logger.error(f"Error: {e.stderr}")
                raise
            except subprocess.TimeoutExpired:
                spinner.fail("Timeout")
                self.logger.error(f"Command timed out: {' '.join(cmd)}")
                raise

    def _load_json(self, path: Path) -> Dict[str, Any]:
        """Load and parse JSON file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.error(f"Failed to load {path}: {e}")
            raise


class TrivyScanner(SecurityScanner):
    """Trivy scanner wrapper."""

    def scan(self, image: str, output: Path) -> None:
        """Run Trivy scan."""
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--output", str(output),
            "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
            image
        ]
        self._run_command(cmd, f"Running Trivy scan on {image}")

    def extract_cves(self, json_path: Path) -> CVEDict:
        """Extract CVE data from Trivy output."""
        data = self._load_json(json_path)
        cves = {}

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                cve_id = vuln.get("VulnerabilityID")
                if not cve_id:
                    continue

                # Prefer NVD CVSS
                cvss = 0.0
                vector = ""
                nvd = vuln.get("CVSS", {}).get("nvd", {})

                if nvd:
                    cvss = float(nvd.get("V3Score", 0.0) or 0.0)
                    vector = nvd.get("V3Vector", "")
                else:
                    # Fallback to vendor
                    vendor = list(vuln.get("CVSS", {}).values())
                    if vendor:
                        cvss = float(vendor[0].get("V3Score", 0.0) or 0.0)
                        vector = vendor[0].get("V3Vector", "")

                fixed = vuln.get("FixedVersion", "")

                cves[cve_id] = CVE(
                    id=cve_id,
                    severity=vuln.get("Severity", "UNKNOWN"),
                    cvss=cvss,
                    vector=vector,
                    source="NVD" if nvd else "Vendor",
                    fixed_version=fixed,
                    has_fix=bool(fixed),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", "")
                )

        return cves


class GrypeScanner(SecurityScanner):
    """Grype scanner wrapper."""

    def scan(self, image: str, output: Path) -> None:
        """Run Grype scan."""
        cmd = ["grype", image, "-o", "json", "--file", str(output)]
        self._run_command(cmd, f"Running Grype scan on {image}")

    def extract_cves(self, json_path: Path) -> CVEDict:
        """Extract CVE data from Grype output."""
        data = self._load_json(json_path)
        cves = {}

        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            cve_id = vuln.get("id")
            if not cve_id:
                continue

            # Extract CVSS (prefer v3)
            cvss = 0.0
            vector = ""

            for entry in vuln.get("cvss", []):
                if entry.get("version") in ["3.1", "3.0"]:
                    cvss = float(entry.get("metrics", {}).get("baseScore", 0.0))
                    vector = entry.get("vector", "")
                    break

            # Fallback
            if not cvss and vuln.get("cvss"):
                first = vuln["cvss"][0]
                cvss = float(first.get("metrics", {}).get("baseScore", 0.0))
                vector = first.get("vector", "")

            artifact = match.get("artifact", {})
            versions = vuln.get("fix", {}).get("versions", [])
            fixed = versions[0] if versions else ""

            cves[cve_id] = CVE(
                id=cve_id,
                severity=vuln.get("severity", "UNKNOWN"),
                cvss=cvss,
                vector=vector,
                source=vuln.get("dataSource", ""),
                fixed_version=fixed,
                has_fix=bool(fixed),
                package=artifact.get("name", ""),
                installed_version=artifact.get("version", "")
            )

        return cves


class CVEAnalyzer:
    """Analyzes and compares CVE findings."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def filter_with_fixes(self, cves: CVEDict) -> CVEDict:
        """Filter to CVEs with fixes."""
        return {cid: cve for cid, cve in cves.items() if cve.has_fix}

    def find_differences(self, trivy: CVEDict, grype: CVEDict) -> Tuple[CVESet, CVESet, CVESet]:
        """Find common and unique CVEs."""
        trivy_ids = set(trivy.keys())
        grype_ids = set(grype.keys())

        return (
            trivy_ids & grype_ids,  # common
            trivy_ids - grype_ids,  # trivy only
            grype_ids - trivy_ids   # grype only
        )

    def get_severity_counts(self, cves: CVEDict) -> Counter:
        """Count CVEs by severity."""
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
        """Generate markdown report."""
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

            # Severity breakdown
            f.write("## Severity Breakdown\n\n")
            f.write("### Trivy\n\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = self.get_severity_counts(trivy)[sev]
                if count:
                    f.write(f"- **{sev}:** {count}\n")

            f.write("\n### Grype\n\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = self.get_severity_counts(grype)[sev]
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

    def _write_table(self, file, cve_ids: CVESet, cves: CVEDict) -> None:
        """Write CVE table to file."""
        file.write("| CVE ID | Severity | CVSS | Package | Installed | Fixed | Fix |\n")
        file.write("|--------|----------|------|---------|-----------|-------|-----|\n")

        sorted_cves = sorted(
            [cves[cid] for cid in cve_ids],
            key=lambda x: (x.cvss, x.id),
            reverse=True
        )

        for cve in sorted_cves:
            fix_icon = "✅" if cve.has_fix else "❌"
            fixed = cve.fixed_version or "N/A"
            file.write(
                f"| {cve.id} | {cve.severity} | {cve.cvss:.1f} | "
                f"{cve.package} | {cve.installed_version} | {fixed} | {fix_icon} |\n"
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
        """Print console summary."""
        print(f"\n{'='*60}")
        print("CVE COMPARISON SUMMARY")
        print(f"{'='*60}")
        print(f"Filter: {'Fixes Only' if fixes_only else 'All CVEs'}\n")

        summary = [
            ["Trivy Total", len(trivy)],
            ["Grype Total", len(grype)],
            ["Common", len(common)],
            ["Trivy Only", len(unique_trivy)],
            ["Grype Only", len(unique_grype)]
        ]
        print(tabulate(summary, headers=["Category", "Count"], tablefmt="grid"))

        # Severity breakdown
        print(f"\n{'='*60}")
        print("SEVERITY BREAKDOWN")
        print(f"{'='*60}\n")

        trivy_sev = self.get_severity_counts(trivy)
        grype_sev = self.get_severity_counts(grype)

        sev_data = [
            [sev, trivy_sev[sev], grype_sev[sev]]
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        ]
        print(tabulate(sev_data, headers=["Severity", "Trivy", "Grype"], tablefmt="grid"))

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
        """Print CVE details."""
        sorted_cves = sorted(
            [cves[cid] for cid in ids],
            key=lambda x: (x.cvss, x.id),
            reverse=True
        )

        if limit:
            sorted_cves = sorted_cves[:limit]

        data = [
            [
                cve.id,
                cve.severity,
                f"{cve.cvss:.1f}",
                cve.package[:30] + "..." if len(cve.package) > 30 else cve.package,
                "✅" if cve.has_fix else "❌"
            ]
            for cve in sorted_cves
        ]

        print(tabulate(data, headers=["CVE ID", "Severity", "CVSS", "Package", "Fix"], tablefmt="grid"))


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def validate_image(image: str) -> str:
    """Validate container image name."""
    if not image or len(image) > 512:
        raise ValueError("Invalid image name length")

    # Match registry/repo:tag or repo:tag
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9._-]+$', image):
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._/-]+$', image):
            raise ValueError("Invalid image name format")

    return image


def main() -> None:
    """Main execution."""
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

    args = parser.parse_args()
    logger = setup_logging(args.verbose)

    try:
        mgr = ScannerManager(logger)

        # Check availability
        trivy_ok, grype_ok = mgr.check_availability()
        if not (trivy_ok and grype_ok):
            logger.error("Both Trivy and Grype must be installed")
            sys.exit(1)

        # Version checks
        if not args.skip_update_check:
            trivy_info, grype_info = mgr.get_versions()
            mgr.print_status(trivy_info, grype_info)

            if not trivy_info.is_current:
                logger.warning(f"Trivy {trivy_info.current_version} may be outdated")
            if not grype_info.is_current:
                logger.warning(f"Grype {grype_info.current_version} may be outdated")

            db_fresh = mgr.check_db_freshness(grype_info)

            # Handle updates
            if args.force_update or (args.auto_update and not db_fresh):
                logger.info("Updating vulnerability databases...")
                trivy_ok, grype_ok = mgr.update_databases(args.force_update)

                if not (trivy_ok and grype_ok):
                    logger.error("Failed to update databases")
                    if not args.force_update:
                        if input("Continue anyway? (y/N): ").strip().lower() != 'y':
                            sys.exit(1)

            elif not db_fresh:
                logger.warning("Vulnerability databases may be stale")
                logger.info("Use --auto-update or --force-update to refresh")
                if input("Continue? (y/N): ").strip().lower() != 'y':
                    sys.exit(1)

        # Validate and setup
        image = validate_image(args.image)
        args.output_dir.mkdir(exist_ok=True, parents=True)

        # Initialize components
        trivy = TrivyScanner(logger)
        grype = GrypeScanner(logger)
        analyzer = CVEAnalyzer(logger)

        # Generate filenames
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', image)
        suffix = "_fixes" if args.fixes_only else ""

        trivy_json = args.output_dir / f"trivy_{safe_name}{suffix}.json"
        grype_json = args.output_dir / f"grype_{safe_name}{suffix}.json"
        report_md = args.output_dir / f"report_{safe_name}{suffix}.md"

        # Execute scans
        logger.info(f"Starting scan for: {image}")
        trivy.scan(image, trivy_json)
        grype.scan(image, grype_json)

        # Extract data
        trivy_cves = trivy.extract_cves(trivy_json)
        grype_cves = grype.extract_cves(grype_json)

        # Filter if requested
        if args.fixes_only:
            trivy_cves = analyzer.filter_with_fixes(trivy_cves)
            grype_cves = analyzer.filter_with_fixes(grype_cves)

        # Analyze
        common, unique_trivy, unique_grype = analyzer.find_differences(trivy_cves, grype_cves)

        # Generate reports
        analyzer.generate_report(
            report_md, image, trivy_cves, grype_cves,
            common, unique_trivy, unique_grype, args.fixes_only
        )

        analyzer.print_summary(
            trivy_cves, grype_cves, common, unique_trivy,
            unique_grype, args.fixes_only, args.verbose
        )

        logger.info(f"\nReport saved: {report_md}")
        logger.info(f"Trivy JSON: {trivy_json}")
        logger.info(f"Grype JSON: {grype_json}")

    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        sys.exit(130)
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
