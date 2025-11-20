#!/usr/bin/env python3
"""
CVE comparison tool for container security scanners (Trivy vs Grype) - Enhanced Edition
Provides detailed analysis and reporting of vulnerability findings with parallel scanning,
caching, and multiple output formats.
"""

import json
import subprocess
import sys
import argparse
import logging
import re
import hashlib
import yaml
import csv
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Dict, Set, Tuple, Optional, Any, List
from tabulate import tabulate
from yaspin import yaspin
from datetime import datetime, timedelta
import concurrent.futures
import threading


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


@dataclass
class ScanConfig:
    """Scan configuration."""
    min_cvss: float = 0.0
    max_cvss: float = 10.0
    severities: List[str] = None
    fixes_only: bool = False
    parallel_scan: bool = True
    cache_enabled: bool = True
    cache_max_age_hours: int = 24
    output_formats: List[str] = None
    package_summary: bool = False
    
    def __post_init__(self):
        if self.severities is None:
            self.severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if self.output_formats is None:
            self.output_formats = ['markdown']


CVEDict = Dict[str, CVE]
CVESet = Set[str]


class CacheManager:
    """Manages scan result caching."""
    
    def __init__(self, cache_dir: Path = None, logger: logging.Logger = None):
        self.cache_dir = cache_dir or Path.home() / ".cve_scanner_cache"
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.logger = logger or logging.getLogger(__name__)
    
    def get_cache_key(self, image: str, scanner: str) -> str:
        """Generate cache key for image+scanner combo."""
        return hashlib.md5(f"{image}:{scanner}".encode()).hexdigest()
    
    def is_cached(self, image: str, scanner: str, max_age_hours: int = 24) -> bool:
        """Check if recent scan results exist."""
        cache_file = self.cache_dir / f"{self.get_cache_key(image, scanner)}.json"
        if not cache_file.exists():
            return False
        
        age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
        return age.total_seconds() < (max_age_hours * 3600)
    
    def get_cached_result(self, image: str, scanner: str) -> Optional[Path]:
        """Get cached result file path if valid."""
        cache_file = self.cache_dir / f"{self.get_cache_key(image, scanner)}.json"
        if cache_file.exists():
            return cache_file
        return None
    
    def save_to_cache(self, image: str, scanner: str, result_file: Path) -> None:
        """Save scan result to cache."""
        try:
            cache_file = self.cache_dir / f"{self.get_cache_key(image, scanner)}.json"
            if result_file.exists():
                import shutil
                shutil.copy2(result_file, cache_file)
                self.logger.debug(f"Cached {scanner} result for {image}")
        except Exception as e:
            self.logger.warning(f"Failed to cache result: {e}")


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

    def __init__(self, logger: logging.Logger, cache_manager: Optional[CacheManager] = None):
        self.logger = logger
        self.cache = cache_manager

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

    def scan(self, image: str, output: Path, use_cache: bool = False) -> None:
        """Run Trivy scan with optional caching."""
        if use_cache and self.cache:
            if self.cache.is_cached(image, "trivy"):
                cached_file = self.cache.get_cached_result(image, "trivy")
                if cached_file:
                    import shutil
                    shutil.copy2(cached_file, output)
                    self.logger.info(f"Using cached Trivy result for {image}")
                    return

        cmd = [
            "trivy", "image",
            "--format", "json",
            "--output", str(output),
            "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
            image
        ]
        self._run_command(cmd, f"Running Trivy scan on {image}")
        
        if use_cache and self.cache:
            self.cache.save_to_cache(image, "trivy", output)

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

    def scan(self, image: str, output: Path, use_cache: bool = False) -> None:
        """Run Grype scan with optional caching."""
        if use_cache and self.cache:
            if self.cache.is_cached(image, "grype"):
                cached_file = self.cache.get_cached_result(image, "grype")
                if cached_file:
                    import shutil
                    shutil.copy2(cached_file, output)
                    self.logger.info(f"Using cached Grype result for {image}")
                    return

        cmd = ["grype", image, "-o", "json", "--file", str(output)]
        self._run_command(cmd, f"Running Grype scan on {image}")
        
        if use_cache and self.cache:
            self.cache.save_to_cache(image, "grype", output)

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


class ParallelScanner:
    """Manages parallel scanning operations."""
    
    def __init__(self, trivy: TrivyScanner, grype: GrypeScanner, logger: logging.Logger):
        self.trivy = trivy
        self.grype = grype
        self.logger = logger
        
    def scan_parallel(self, image: str, trivy_output: Path, grype_output: Path, 
                     use_cache: bool = False) -> Tuple[bool, bool]:
        """Run both scanners in parallel."""
        success = {"trivy": False, "grype": False}
        
        def run_trivy():
            try:
                self.trivy.scan(image, trivy_output, use_cache)
                success["trivy"] = True
            except Exception as e:
                self.logger.error(f"Trivy scan failed: {e}")
        
        def run_grype():
            try:
                self.grype.scan(image, grype_output, use_cache)
                success["grype"] = True  
            except Exception as e:
                self.logger.error(f"Grype scan failed: {e}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(run_trivy),
                executor.submit(run_grype)
            ]
            concurrent.futures.wait(futures)
        
        return success["trivy"], success["grype"]


class EnhancedAnalyzer:
    """Enhanced CVE analysis with filtering and metrics."""

    def __init__(self, logger: logging.Logger, config: ScanConfig):
        self.logger = logger
        self.config = config

    def filter_cves(self, cves: CVEDict) -> CVEDict:
        """Apply all configured filters."""
        filtered = cves
        
        # Filter by fixes
        if self.config.fixes_only:
            filtered = {cid: cve for cid, cve in filtered.items() if cve.has_fix}
        
        # Filter by CVSS range
        filtered = {
            cid: cve for cid, cve in filtered.items()
            if self.config.min_cvss <= cve.cvss <= self.config.max_cvss
        }
        
        # Filter by severity
        filtered = {
            cid: cve for cid, cve in filtered.items()
            if cve.severity.upper() in [s.upper() for s in self.config.severities]
        }
        
        return filtered

    def get_overlap_percentage(self, trivy: CVEDict, grype: CVEDict) -> float:
        """Calculate CVE overlap percentage."""
        if not trivy and not grype:
            return 100.0
        total_unique = len(set(trivy.keys()) | set(grype.keys()))
        common = len(set(trivy.keys()) & set(grype.keys()))
        return (common / total_unique) * 100 if total_unique > 0 else 0.0

    def get_package_risk_summary(self, cves: CVEDict) -> Dict[str, Dict]:
        """Summarize risk by package."""
        package_summary = {}
        for cve in cves.values():
            if cve.package not in package_summary:
                package_summary[cve.package] = {
                    'total_cves': 0,
                    'max_cvss': 0.0,
                    'has_fixes': 0,
                    'severities': Counter()
                }
            
            pkg = package_summary[cve.package]
            pkg['total_cves'] += 1
            pkg['max_cvss'] = max(pkg['max_cvss'], cve.cvss)
            if cve.has_fix:
                pkg['has_fixes'] += 1
            pkg['severities'][cve.severity] += 1
        
        return package_summary

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


class MultiFormatReporter:
    """Generates reports in multiple formats."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def generate_markdown_report(self, path: Path, image: str, trivy: CVEDict, grype: CVEDict,
                                common: CVESet, unique_trivy: CVESet, unique_grype: CVESet,
                                config: ScanConfig, analyzer: EnhancedAnalyzer) -> None:
        """Generate markdown report with enhanced information."""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# Enhanced CVE Comparison Report\n\n")
            f.write(f"**Image:** `{image}`\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Filters Applied:**\n")
            f.write(f"- Fixes Only: {config.fixes_only}\n")
            f.write(f"- CVSS Range: {config.min_cvss} - {config.max_cvss}\n")
            f.write(f"- Severities: {', '.join(config.severities)}\n\n")

            # Summary with overlap
            overlap = analyzer.get_overlap_percentage(trivy, grype)
            f.write("## Summary\n\n")
            f.write(f"- **Trivy Total:** {len(trivy)}\n")
            f.write(f"- **Grype Total:** {len(grype)}\n")
            f.write(f"- **Common:** {len(common)}\n")
            f.write(f"- **Trivy Only:** {len(unique_trivy)}\n")
            f.write(f"- **Grype Only:** {len(unique_grype)}\n")
            f.write(f"- **Coverage Overlap:** {overlap:.1f}%\n\n")

            # Severity breakdown
            f.write("## Severity Breakdown\n\n")
            f.write("### Trivy\n\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = analyzer.get_severity_counts(trivy)[sev]
                if count:
                    f.write(f"- **{sev}:** {count}\n")

            f.write("\n### Grype\n\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = analyzer.get_severity_counts(grype)[sev]
                if count:
                    f.write(f"- **{sev}:** {count}\n")
            f.write("\n")

            # Package risk summary
            if config.package_summary:
                f.write("## Package Risk Summary\n\n")
                self._write_package_summary(f, analyzer.get_package_risk_summary(trivy), "Trivy")
                self._write_package_summary(f, analyzer.get_package_risk_summary(grype), "Grype")

            # CVE tables
            if common:
                f.write("## Common CVEs (Found by Both)\n\n")
                self._write_table(f, common, trivy)

            if unique_trivy:
                f.write("## Trivy-Only CVEs\n\n")
                self._write_table(f, unique_trivy, trivy)

            if unique_grype:
                f.write("## Grype-Only CVEs\n\n")
                self._write_table(f, unique_grype, grype)

    def _write_package_summary(self, file, pkg_summary: Dict, scanner_name: str) -> None:
        """Write package risk summary table."""
        if not pkg_summary:
            return
            
        file.write(f"### {scanner_name} Package Summary\n\n")
        file.write("| Package | CVEs | Max CVSS | Fixes Available | Risk Level |\n")
        file.write("|---------|------|----------|-----------------|------------|\n")
        
        # Sort by risk (max CVSS then CVE count)
        sorted_packages = sorted(
            pkg_summary.items(),
            key=lambda x: (x[1]['max_cvss'], x[1]['total_cves']),
            reverse=True
        )
        
        for pkg_name, info in sorted_packages[:20]:  # Top 20 packages
            risk_level = "🔴 Critical" if info['max_cvss'] >= 9.0 else \
                        "🟡 High" if info['max_cvss'] >= 7.0 else \
                        "🟢 Medium" if info['max_cvss'] >= 4.0 else "⚪ Low"
            
            file.write(
                f"| {pkg_name} | {info['total_cves']} | {info['max_cvss']:.1f} | "
                f"{info['has_fixes']}/{info['total_cves']} | {risk_level} |\n"
            )
        file.write("\n")

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

    def generate_csv_report(self, path: Path, trivy: CVEDict, grype: CVEDict) -> None:
        """Generate CSV report."""
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'CVE_ID', 'Scanner', 'Severity', 'CVSS', 'Package', 
                'Installed_Version', 'Fixed_Version', 'Has_Fix', 'Vector', 'Source'
            ])
            
            for cve in trivy.values():
                writer.writerow([
                    cve.id, 'Trivy', cve.severity, cve.cvss, cve.package,
                    cve.installed_version, cve.fixed_version, cve.has_fix,
                    cve.vector, cve.source
                ])
            
            for cve in grype.values():
                writer.writerow([
                    cve.id, 'Grype', cve.severity, cve.cvss, cve.package,
                    cve.installed_version, cve.fixed_version, cve.has_fix,
                    cve.vector, cve.source
                ])

    def generate_json_report(self, path: Path, image: str, trivy: CVEDict, grype: CVEDict,
                           common: CVESet, unique_trivy: CVESet, unique_grype: CVESet,
                           config: ScanConfig, analyzer: EnhancedAnalyzer) -> None:
        """Generate JSON report."""
        report = {
            "metadata": {
                "image": image,
                "generated": datetime.now().isoformat(),
                "config": asdict(config)
            },
            "summary": {
                "trivy_total": len(trivy),
                "grype_total": len(grype),
                "common": len(common),
                "trivy_only": len(unique_trivy),
                "grype_only": len(unique_grype),
                "overlap_percentage": analyzer.get_overlap_percentage(trivy, grype)
            },
            "severity_breakdown": {
                "trivy": dict(analyzer.get_severity_counts(trivy)),
                "grype": dict(analyzer.get_severity_counts(grype))
            },
            "cves": {
                "trivy": {cid: asdict(cve) for cid, cve in trivy.items()},
                "grype": {cid: asdict(cve) for cid, cve in grype.items()}
            },
            "differences": {
                "common": list(common),
                "trivy_only": list(unique_trivy),
                "grype_only": list(unique_grype)
            }
        }
        
        if config.package_summary:
            report["package_summary"] = {
                "trivy": analyzer.get_package_risk_summary(trivy),
                "grype": analyzer.get_package_risk_summary(grype)
            }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

    def print_enhanced_summary(self, trivy: CVEDict, grype: CVEDict, common: CVESet,
                             unique_trivy: CVESet, unique_grype: CVESet, 
                             config: ScanConfig, analyzer: EnhancedAnalyzer, verbose: bool) -> None:
        """Print enhanced console summary."""
        print(f"\n{'='*70}")
        print("ENHANCED CVE COMPARISON SUMMARY")
        print(f"{'='*70}")
        
        # Show applied filters
        filters = []
        if config.fixes_only:
            filters.append("Fixes Only")
        if config.min_cvss > 0.0 or config.max_cvss < 10.0:
            filters.append(f"CVSS: {config.min_cvss}-{config.max_cvss}")
        if set(config.severities) != {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
            filters.append(f"Severities: {', '.join(config.severities)}")
        
        if filters:
            print(f"Filters: {' | '.join(filters)}")
        else:
            print("Filters: None")
        print()

        overlap = analyzer.get_overlap_percentage(trivy, grype)
        summary = [
            ["Trivy Total", len(trivy)],
            ["Grype Total", len(grype)],
            ["Common", len(common)],
            ["Trivy Only", len(unique_trivy)],
            ["Grype Only", len(unique_grype)],
            ["Coverage Overlap", f"{overlap:.1f}%"]
        ]
        print(tabulate(summary, headers=["Category", "Count"], tablefmt="grid"))

        # Severity breakdown
        print(f"\n{'='*70}")
        print("SEVERITY BREAKDOWN")
        print(f"{'='*70}\n")

        trivy_sev = analyzer.get_severity_counts(trivy)
        grype_sev = analyzer.get_severity_counts(grype)

        sev_data = [
            [sev, trivy_sev[sev], grype_sev[sev]]
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        ]
        print(tabulate(sev_data, headers=["Severity", "Trivy", "Grype"], tablefmt="grid"))

        # Package summary
        if config.package_summary:
            print(f"\n{'='*70}")
            print("TOP RISK PACKAGES")
            print(f"{'='*70}")
            self._print_package_summary(analyzer.get_package_risk_summary(trivy), "Trivy", 5)
            self._print_package_summary(analyzer.get_package_risk_summary(grype), "Grype", 5)

        if verbose:
            if common:
                print(f"\n{'='*70}")
                print(f"COMMON CVEs - Top 10 by CVSS")
                print(f"{'='*70}")
                self._print_details(common, trivy, 10)

            if unique_trivy:
                print(f"\n{'='*70}")
                print(f"TRIVY-ONLY CVEs (All {len(unique_trivy)})")
                print(f"{'='*70}")
                self._print_details(unique_trivy, trivy)

            if unique_grype:
                print(f"\n{'='*70}")
                print(f"GRYPE-ONLY CVEs (All {len(unique_grype)})")
                print(f"{'='*70}")
                self._print_details(unique_grype, grype)

    def _print_package_summary(self, pkg_summary: Dict, scanner_name: str, limit: int = 10) -> None:
        """Print package risk summary."""
        if not pkg_summary:
            return
            
        print(f"\n{scanner_name} Top {limit} Risk Packages:")
        sorted_packages = sorted(
            pkg_summary.items(),
            key=lambda x: (x[1]['max_cvss'], x[1]['total_cves']),
            reverse=True
        )[:limit]
        
        data = [
            [
                pkg_name[:40] + "..." if len(pkg_name) > 40 else pkg_name,
                info['total_cves'],
                f"{info['max_cvss']:.1f}",
                f"{info['has_fixes']}/{info['total_cves']}"
            ]
            for pkg_name, info in sorted_packages
        ]
        
        print(tabulate(data, headers=["Package", "CVEs", "Max CVSS", "Fixes"], tablefmt="grid"))

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


def load_config(config_path: Path) -> ScanConfig:
    """Load configuration from YAML file."""
    if config_path and config_path.exists():
        try:
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
            return ScanConfig(**data)
        except Exception as e:
            logging.warning(f"Failed to load config from {config_path}: {e}")
    return ScanConfig()


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
        description="Enhanced CVE comparison tool for Trivy and Grype with parallel scanning, caching, and multiple output formats"
    )
    parser.add_argument("image", help="Container image to scan (e.g., nginx:latest)")
    parser.add_argument("--config", type=Path, help="Configuration file path")
    parser.add_argument("--fixes-only", action="store_true", help="Only show CVEs with fixes")
    parser.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS score")
    parser.add_argument("--max-cvss", type=float, default=10.0, help="Maximum CVSS score")
    parser.add_argument("--severity", action="append", help="Filter by severity (can be used multiple times)")
    parser.add_argument("--output-dir", type=Path, default=Path("."), help="Output directory")
    parser.add_argument("--format", choices=['markdown', 'json', 'csv'], 
                       action='append', help="Output formats (can be used multiple times)")
    parser.add_argument("--cache", action="store_true", help="Enable result caching")
    parser.add_argument("--no-parallel", action="store_true", help="Disable parallel scanning")
    parser.add_argument("--package-summary", action="store_true", help="Include package risk summary")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed CVE info")
    parser.add_argument("--force-update", action="store_true", help="Force update databases")
    parser.add_argument("--skip-update-check", action="store_true", help="Skip version checks")
    parser.add_argument("--auto-update", action="store_true", help="Auto-update stale databases")

    args = parser.parse_args()
    logger = setup_logging(args.verbose)

    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override config with CLI args
        if args.fixes_only:
            config.fixes_only = True
        if args.min_cvss != 0.0:
            config.min_cvss = args.min_cvss
        if args.max_cvss != 10.0:
            config.max_cvss = args.max_cvss
        if args.severity:
            config.severities = [s.upper() for s in args.severity]
        if args.format:
            config.output_formats = args.format
        if args.cache:
            config.cache_enabled = True
        if args.no_parallel:
            config.parallel_scan = False
        if args.package_summary:
            config.package_summary = True

        # Initialize managers
        mgr = ScannerManager(logger)
        cache_manager = CacheManager(logger=logger) if config.cache_enabled else None

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
        trivy = TrivyScanner(logger, cache_manager)
        grype = GrypeScanner(logger, cache_manager)
        analyzer = EnhancedAnalyzer(logger, config)
        reporter = MultiFormatReporter(logger)

        # Generate filenames
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', image)
        filter_suffix = ""
        if config.fixes_only:
            filter_suffix += "_fixes"
        if config.min_cvss > 0.0 or config.max_cvss < 10.0:
            filter_suffix += f"_cvss{config.min_cvss}-{config.max_cvss}"

        trivy_json = args.output_dir / f"trivy_{safe_name}{filter_suffix}.json"
        grype_json = args.output_dir / f"grype_{safe_name}{filter_suffix}.json"

        # Execute scans
        logger.info(f"Starting {'parallel ' if config.parallel_scan else ''}scan for: {image}")
        
        if config.parallel_scan:
            parallel_scanner = ParallelScanner(trivy, grype, logger)
            trivy_ok, grype_ok = parallel_scanner.scan_parallel(
                image, trivy_json, grype_json, config.cache_enabled
            )
            if not (trivy_ok and grype_ok):
                logger.error("One or both scans failed")
                sys.exit(1)
        else:
            trivy.scan(image, trivy_json, config.cache_enabled)
            grype.scan(image, grype_json, config.cache_enabled)

        # Extract and filter data
        trivy_cves = analyzer.filter_cves(trivy.extract_cves(trivy_json))
        grype_cves = analyzer.filter_cves(grype.extract_cves(grype_json))

        # Analyze
        common, unique_trivy, unique_grype = analyzer.find_differences(trivy_cves, grype_cves)

        # Generate reports
        for format_type in config.output_formats:
            if format_type == 'markdown':
                report_path = args.output_dir / f"report_{safe_name}{filter_suffix}.md"
                reporter.generate_markdown_report(
                    report_path, image, trivy_cves, grype_cves,
                    common, unique_trivy, unique_grype, config, analyzer
                )
                logger.info(f"Markdown report saved: {report_path}")
            
            elif format_type == 'json':
                json_path = args.output_dir / f"report_{safe_name}{filter_suffix}.json"
                reporter.generate_json_report(
                    json_path, image, trivy_cves, grype_cves,
                    common, unique_trivy, unique_grype, config, analyzer
                )
                logger.info(f"JSON report saved: {json_path}")
            
            elif format_type == 'csv':
                csv_path = args.output_dir / f"report_{safe_name}{filter_suffix}.csv"
                reporter.generate_csv_report(csv_path, trivy_cves, grype_cves)
                logger.info(f"CSV report saved: {csv_path}")

        # Print summary
        reporter.print_enhanced_summary(
            trivy_cves, grype_cves, common, unique_trivy, unique_grype,
            config, analyzer, args.verbose
        )

        logger.info(f"\nScan results: {trivy_json}, {grype_json}")

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
