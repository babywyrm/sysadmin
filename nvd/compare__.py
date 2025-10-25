#!/usr/bin/env python3
"""
NVD Vulnerability Scanner v2.4.0
Enhanced validation of Trivy CVE detection against NVD data with date range filtering.
"""
import requests
import json
import csv
import sys
import argparse
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, asdict, field
from pathlib import Path
from time import sleep
import os
import subprocess
import threading
import queue
from dotenv import load_dotenv
from dateutil import parser as date_parser

load_dotenv()

VERSION = "2.4.0"
SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class NVDConfig:
    api_key: Optional[str] = os.getenv("NVD_API_KEY")
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    rate_limit_delay: float = 0.6
    timeout: int = 30
    max_retries: int = 3


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published: str
    last_modified: str
    affected_packages: List[Dict[str, str]] = field(default_factory=list)
    found_by_trivy: bool = True
    nvd_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationReport:
    trivy_found_count: int
    nvd_verified_count: int
    trivy_only_cves: List[str]
    nvd_only_cves: List[str]
    date_range_matches: int
    total_packages_scanned: int


class NVDAPIError(Exception):
    pass


def test_trivy_installation() -> bool:
    """Test if Trivy is installed and working."""
    try:
        result = subprocess.run(
            ["trivy", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        if result.returncode == 0:
            version_info = result.stdout.strip()
            print(f"✓ Trivy found: {version_info}")
            return True
        else:
            print(f"✗ Trivy error: {result.stderr}")
            return False
    except FileNotFoundError:
        print("✗ Trivy not found. Please install Trivy:")
        print("  brew install trivy  # macOS")
        print("  # or visit: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
        return False
    except subprocess.TimeoutExpired:
        print("✗ Trivy command timed out")
        return False


class DockerImageScanner:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def scan_with_trivy(self, image_name: str, tag: str) -> Tuple[Dict[str, List[Dict]], Set[str]]:
        full_image = f"{image_name}:{tag}"
        self.logger.info(f"Scanning {full_image} with Trivy...")
        
        # First, try to pull the image if it doesn't exist locally
        self.logger.info("Checking if image exists locally...")
        check_cmd = ["docker", "images", "-q", full_image]
        try:
            result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)
            if not result.stdout.strip():
                self.logger.info(f"Image not found locally, pulling {full_image}...")
                pull_cmd = ["docker", "pull", full_image]
                pull_result = subprocess.run(pull_cmd, capture_output=True, text=True, timeout=300)
                if pull_result.returncode != 0:
                    raise RuntimeError(f"Failed to pull image: {pull_result.stderr}")
        except subprocess.TimeoutExpired:
            self.logger.warning("Docker pull timed out, continuing with Trivy scan...")
        except FileNotFoundError:
            self.logger.warning("Docker not found, continuing with Trivy scan...")

        # Prepare Trivy command with better options
        command = [
            "trivy", "image",
            "--format", "json",
            "--no-progress",  # Disable progress bar
            "--timeout", "5m",  # Set Trivy's own timeout
            full_image
        ]
        
        self.logger.info(f"Running: {' '.join(command)}")
        
        def run_trivy(cmd, result_queue):
            try:
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=360,  # 6 minutes total timeout
                    env={**os.environ, "TRIVY_QUIET": "true"}
                )
                result_queue.put(('success', result))
            except subprocess.TimeoutExpired as e:
                result_queue.put(('timeout', e))
            except Exception as e:
                result_queue.put(('error', e))

        # Run Trivy in a separate thread so we can monitor progress
        result_queue = queue.Queue()
        trivy_thread = threading.Thread(target=run_trivy, args=(command, result_queue))
        trivy_thread.daemon = True
        trivy_thread.start()
        
        # Monitor progress
        start_time = datetime.now()
        while trivy_thread.is_alive():
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > 0 and elapsed % 30 == 0:  # Log every 30 seconds
                self.logger.info(f"Trivy scan still running... ({elapsed:.0f}s elapsed)")
            
            try:
                # Check if we have a result
                status, result = result_queue.get(timeout=1)
                break
            except queue.Empty:
                continue
        else:
            # Thread finished, get the result
            status, result = result_queue.get()
        
        # Handle results
        if status == 'timeout':
            raise RuntimeError("Trivy scan timed out after 6 minutes")
        elif status == 'error':
            raise RuntimeError(f"Trivy scan failed: {result}")
        elif result.returncode != 0:
            # Try to get more details about the error
            error_msg = result.stderr or result.stdout or "Unknown error"
            if "TOOMANYREQUESTS" in error_msg:
                raise RuntimeError("Trivy hit rate limits. Try again later or use --offline mode")
            elif "no such image" in error_msg.lower():
                raise RuntimeError(f"Image {full_image} not found. Check the image name and tag")
            else:
                raise RuntimeError(f"Trivy scan failed (exit code {result.returncode}): {error_msg}")

        # Parse results
        try:
            trivy_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Trivy output: {e}")
            self.logger.error(f"Raw output: {result.stdout[:500]}...")
            raise RuntimeError("Trivy returned invalid JSON")
        
        vulns_map: Dict[str, List[Dict]] = {}
        all_packages: Set[str] = set()
        
        for res in trivy_data.get("Results", []):
            target = res.get("Target", "")
            self.logger.debug(f"Processing target: {target}")
            
            for vuln in res.get("Vulnerabilities", []):
                cve_id = vuln.get("VulnerabilityID")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue
                
                pkg_name = vuln.get("PkgName")
                all_packages.add(pkg_name)
                
                pkg_info = {
                    "package": pkg_name,
                    "version": vuln.get("InstalledVersion"),
                    "fix": vuln.get("FixedVersion", "N/A"),
                    "target": target,
                    "severity": vuln.get("Severity", "UNKNOWN")
                }
                
                if cve_id not in vulns_map:
                    vulns_map[cve_id] = []
                vulns_map[cve_id].append(pkg_info)
        
        self.logger.info(
            f"✓ Trivy scan completed: {len(vulns_map)} unique CVEs across {len(all_packages)} packages"
        )
        return vulns_map, all_packages


class NVDVulnerabilityEngine:
    def __init__(self, config: NVDConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.session = self._setup_session()
        self._log_api_status()

    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        if self.config.api_key:
            session.headers.update({"apiKey": self.config.api_key})
        session.headers.update({"User-Agent": f"NVD-Scanner/{VERSION}"})
        return session

    def _log_api_status(self) -> None:
        if self.config.api_key and len(self.config.api_key) > 20:
            self.logger.info("✓ NVD API Key active (50 req/30s)")
        else:
            self.logger.warning("⚠ No NVD API Key (5 req/30s) - Consider getting one for better performance")
            self.config.rate_limit_delay = 6.0

    def validate_trivy_against_nvd(
        self,
        image_name: str,
        tag: str,
        min_severity: Optional[str],
        start_date: Optional[datetime],
        end_date: Optional[datetime],
        validate_date_range: bool = True
    ) -> Tuple[List[Vulnerability], ValidationReport]:
        """
        Comprehensive validation of Trivy results against NVD data.
        """
        scanner = DockerImageScanner(self.logger)
        trivy_vulns_map, scanned_packages = scanner.scan_with_trivy(image_name, tag)
        trivy_cve_ids = set(trivy_vulns_map.keys())
        
        if not trivy_cve_ids:
            return [], ValidationReport(0, 0, [], [], 0, len(scanned_packages))

        self.logger.info(f"Validating {len(trivy_cve_ids)} Trivy-found CVEs against NVD...")
        
        # Get NVD data for Trivy-found CVEs
        nvd_results = self.query_by_cve_ids(list(trivy_cve_ids))
        nvd_cve_ids = {vuln["cve"]["id"] for vuln in nvd_results}
        
        # Optional: Also query NVD for the date range to find what we might have missed
        nvd_date_range_cves = set()
        if validate_date_range and start_date and end_date:
            self.logger.info("Querying NVD for all CVEs in the specified date range...")
            nvd_date_range_results = self.query_by_date_range(start_date, end_date)
            nvd_date_range_cves = {vuln["cve"]["id"] for vuln in nvd_date_range_results}
            self.logger.info(f"NVD has {len(nvd_date_range_cves)} CVEs published in date range")

        # Create vulnerability objects
        enriched_vulns = []
        for nvd_vuln in nvd_results:
            formatted_vuln = self.format_vulnerability(nvd_vuln)
            formatted_vuln.affected_packages = trivy_vulns_map.get(formatted_vuln.cve_id, [])
            formatted_vuln.found_by_trivy = True
            formatted_vuln.nvd_verified = True
            enriched_vulns.append(formatted_vuln)

        # Apply filters and show publication date details
        filtered_vulns = self._filter_results_with_dates(enriched_vulns, min_severity, start_date, end_date)
        
        # Generate validation report
        trivy_only = trivy_cve_ids - nvd_cve_ids
        nvd_only = nvd_date_range_cves - trivy_cve_ids if validate_date_range else set()
        
        date_range_matches = len([v for v in filtered_vulns if self._is_in_date_range(v, start_date, end_date)])
        
        report = ValidationReport(
            trivy_found_count=len(trivy_cve_ids),
            nvd_verified_count=len(nvd_cve_ids),
            trivy_only_cves=list(trivy_only),
            nvd_only_cves=list(nvd_only),
            date_range_matches=date_range_matches,
            total_packages_scanned=len(scanned_packages)
        )

        # Sort results
        filtered_vulns.sort(
            key=lambda v: (SEVERITY_LEVELS.get(v.severity, 0), v.cvss_score),
            reverse=True,
        )
        
        return filtered_vulns, report

    def query_by_date_range(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        Query NVD for all CVEs published within a date range.
        Note: This can return a large number of results, use carefully.
        """
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "resultsPerPage": 2000  # Max allowed by NVD API
        }
        
        all_vulns = []
        start_index = 0
        
        while True:
            params["startIndex"] = start_index
            try:
                sleep(self.config.rate_limit_delay)
                data = self._api_request(params)
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    break
                    
                all_vulns.extend(vulnerabilities)
                
                total_results = data.get("totalResults", 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                    
                start_index += len(vulnerabilities)
                self.logger.debug(f"Fetched {len(all_vulns)}/{total_results} CVEs from date range")
                
            except NVDAPIError as e:
                self.logger.warning(f"Error fetching date range data at index {start_index}: {e}")
                break
        
        self.logger.info(f"Retrieved {len(all_vulns)} CVEs from NVD for date range")
        return all_vulns

    def query_by_cve_ids(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Query NVD for specific CVE IDs with batching for efficiency.
        """
        all_vulns = []
        batch_size = 10  # Process in smaller batches to avoid timeouts
        
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            self.logger.debug(f"Processing CVE batch {i//batch_size + 1}: {len(batch)} CVEs")
            
            for cve_id in batch:
                params = {"cveId": cve_id}
                try:
                    if len(all_vulns) > 0:  # Rate limiting
                        sleep(self.config.rate_limit_delay)
                    
                    data = self._api_request(params)
                    all_vulns.extend(data.get("vulnerabilities", []))
                    
                except NVDAPIError as e:
                    self.logger.warning(f"Could not fetch data for {cve_id}: {e}")
                    
        return all_vulns

    def _is_in_date_range(self, vuln: Vulnerability, start_date: Optional[datetime], end_date: Optional[datetime]) -> bool:
        if not start_date or not end_date:
            return True
        try:
            pub_date = date_parser.isoparse(vuln.published)
            return start_date <= pub_date <= end_date
        except:
            return False

    def _filter_results_with_dates(
        self,
        vulns: List[Vulnerability],
        min_severity: Optional[str],
        start_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> List[Vulnerability]:
        filtered = list(vulns)
        
        # Show publication dates for debugging
        if start_date and end_date and vulns:
            self.logger.info(f"\n📅 CVE PUBLICATION DATE ANALYSIS:")
            self.logger.info(f"Requested date range: {start_date.date()} to {end_date.date()}")
            
            # Sample of publication dates
            pub_dates = []
            for v in vulns[:10]:  # Show first 10
                try:
                    pub_date = date_parser.isoparse(v.published)
                    pub_dates.append((v.cve_id, pub_date.date()))
                    in_range = "✓" if self._is_in_date_range(v, start_date, end_date) else "✗"
                    self.logger.info(f"  {in_range} {v.cve_id}: Published {pub_date.date()}")
                except:
                    self.logger.info(f"  ? {v.cve_id}: Invalid date format")
            
            if len(vulns) > 10:
                self.logger.info(f"  ... and {len(vulns) - 10} more CVEs")
        
        if min_severity:
            min_level = SEVERITY_LEVELS.get(min_severity.upper(), 0)
            self.logger.info(f"Filtering for severity {min_severity} and higher")
            filtered = [v for v in filtered if SEVERITY_LEVELS.get(v.severity, 0) >= min_level]
        
        if start_date and end_date:
            pre_filter_count = len(filtered)
            self.logger.info(f"Filtering for publication date between {start_date.date()} and {end_date.date()}")
            filtered = [v for v in filtered if self._is_in_date_range(v, start_date, end_date)]
            self.logger.info(f"Date filter result: {len(filtered)}/{pre_filter_count} CVEs match the date range")
        
        return filtered

    def _filter_results(
        self,
        vulns: List[Vulnerability],
        min_severity: Optional[str],
        start_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> List[Vulnerability]:
        return self._filter_results_with_dates(vulns, min_severity, start_date, end_date)

    def _api_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        for attempt in range(self.config.max_retries):
            try:
                resp = self.session.get(
                    self.config.base_url, params=params, timeout=self.config.timeout
                )
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.HTTPError) and e.response.status_code == 404:
                    raise NVDAPIError(f"CVE not found ({e.response.status_code})")
                self.logger.error(f"API request failed on attempt {attempt+1}: {e}")
                if attempt < self.config.max_retries - 1:
                    sleep(2 ** attempt)  # Exponential backoff
        raise NVDAPIError(f"Failed after {self.config.max_retries} retries")

    def format_vulnerability(self, vuln: Dict[str, Any]) -> Vulnerability:
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_score, severity = 0.0, "N/A"
        
        # Try different CVSS versions
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                data = metrics[version][0].get("cvssData", {})
                cvss_score = float(data.get("baseScore", 0.0))
                if version == "cvssMetricV2":
                    severity = ("HIGH" if cvss_score >= 7.0 else 
                               "MEDIUM" if cvss_score >= 4.0 else "LOW")
                else:
                    severity = data.get("baseSeverity", "N/A")
                break
        
        return Vulnerability(
            cve_id=cve.get("id", "N/A"),
            description=next((d["value"] for d in cve.get("descriptions", []) 
                            if d["lang"] == "en"), "No description"),
            severity=severity,
            cvss_score=cvss_score,
            published=cve.get("published", "N/A"),
            last_modified=cve.get("lastModified", "N/A"),
        )

    def print_validation_report(self, report: ValidationReport, vulns: List[Vulnerability]) -> None:
        print("\n" + "=" * 80)
        print("TRIVY vs NVD VALIDATION REPORT")
        print("=" * 80)
        print(f"Total Packages Scanned: {report.total_packages_scanned}")
        print(f"CVEs Found by Trivy: {report.trivy_found_count}")
        print(f"CVEs Verified in NVD: {report.nvd_verified_count}")
        print(f"Date Range Matches: {report.date_range_matches}")
        
        if report.trivy_only_cves:
            print(f"\n⚠ CVEs found by Trivy but not in NVD ({len(report.trivy_only_cves)}):")
            for cve in sorted(report.trivy_only_cves)[:10]:  # Show first 10
                print(f"  - {cve}")
            if len(report.trivy_only_cves) > 10:
                print(f"  ... and {len(report.trivy_only_cves) - 10} more")
        
        if report.nvd_only_cves:
            print(f"\n📋 CVEs in NVD date range but not found by Trivy ({len(report.nvd_only_cves)}):")
            for cve in sorted(report.nvd_only_cves)[:10]:
                print(f"  - {cve}")
            if len(report.nvd_only_cves) > 10:
                print(f"  ... and {len(report.nvd_only_cves) - 10} more")
        
        accuracy = (report.nvd_verified_count / max(report.trivy_found_count, 1)) * 100
        print(f"\n✓ Trivy-NVD Accuracy: {accuracy:.1f}%")
        print("=" * 80)

    def print_summary(self, vulns: List[Vulnerability]) -> None:
        if not vulns:
            self.logger.info("No vulnerabilities found meeting the criteria.")
            return
        
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        scores = [v.cvss_score for v in vulns if v.cvss_score > 0]
        
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        
        avg = sum(scores) / len(scores) if scores else 0.0
        
        print(f"\nTotal Vulnerabilities: {len(vulns)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts.get(sev, 0) > 0:
                print(f"  {sev}: {counts[sev]}")
        print(f"Average CVSS Score: {avg:.2f}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enhanced NVD Vulnerability Scanner with Trivy validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--docker", type=str, required=True, help="Docker image to scan (e.g., nginx:latest)")
    parser.add_argument("--days", type=int, help="Filter by NVD publish date: last N days")
    parser.add_argument("--start", type=str, help="Start date for NVD filtering (YYYY-MM-DD)")
    parser.add_argument("--end", type=str, help="End date for NVD filtering (YYYY-MM-DD)")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], 
                       help="Minimum severity to report")
    parser.add_argument("--limit", type=int, default=20, help="Number of vulnerabilities to display")
    parser.add_argument("--validate-date-range", action="store_true", 
                       help="Also check NVD for CVEs in date range that Trivy might have missed")
    parser.add_argument("--test-trivy", action="store_true", 
                       help="Test Trivy connection and exit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"v{VERSION}")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logger = logging.getLogger()
    
    # Test Trivy installation
    if args.test_trivy or not test_trivy_installation():
        return 1 if not test_trivy_installation() else 0
    
    try:
        config = NVDConfig()
        engine = NVDVulnerabilityEngine(config, logger)
        
        # Parse Docker image
        image_parts = args.docker.split(":")
        image_name = image_parts[0]
        tag = image_parts[1] if len(image_parts) > 1 else "latest"

        # Handle date ranges with timezone awareness
        start_date, end_date = None, None
        if args.days:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=args.days)
        elif args.start:
            start_date = datetime.strptime(args.start, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if args.end:
                end_date = datetime.strptime(args.end, "%Y-%m-%d").replace(
                    hour=23, minute=59, second=59, tzinfo=timezone.utc
                )
            else:
                end_date = datetime.now(timezone.utc)

        print(f"\n{'=' * 80}")
        print(f"SCANNING DOCKER IMAGE: {image_name}:{tag}")
        print(f"{'=' * 80}")
        
        if start_date and end_date:
            print(f"Date Range: {start_date.date()} to {end_date.date()}")
        if args.min_severity:
            print(f"Minimum Severity: {args.min_severity}")
        print()

        # Perform validation scan
        vulns, report = engine.validate_trivy_against_nvd(
            image_name, tag, args.min_severity, start_date, end_date, args.validate_date_range
        )
        
        # Print reports
        engine.print_validation_report(report, vulns)
        engine.print_summary(vulns)
        
        # Display detailed vulnerabilities with publication dates
        if vulns:
            print(f"\nTop {min(args.limit, len(vulns))} Vulnerabilities:")
            print("-" * 80)
            for i, v in enumerate(vulns[:args.limit], 1):
                try:
                    pub_date = date_parser.isoparse(v.published).strftime("%Y-%m-%d")
                    mod_date = date_parser.isoparse(v.last_modified).strftime("%Y-%m-%d")
                except:
                    pub_date = v.published
                    mod_date = v.last_modified
                    
                print(f"\n{i}. {v.cve_id} | {v.severity} (CVSS: {v.cvss_score})")
                print(f"   📅 Published: {pub_date} | Last Modified: {mod_date}")
                print(f"   📝 {v.description[:120]}...")
                
                # Show affected packages
                pkg_names = list(set(pkg['package'] for pkg in v.affected_packages))
                if pkg_names:
                    print(f"   📦 Affected: {', '.join(pkg_names[:3])}")
                    if len(pkg_names) > 3:
                        print(f"       ... and {len(pkg_names) - 3} more packages")
        else:
            # If no vulnerabilities match filters, show ALL publication dates for debugging
            print("\n" + "=" * 80)
            print("🔍 DEBUGGING: ALL CVE PUBLICATION DATES FOUND")
            print("=" * 80)
            print("Since no CVEs matched your filters, here are ALL CVEs found by Trivy")
            print("with their actual NVD publication dates:")
            print("-" * 80)
            
            # Re-run without filters to show all dates
            all_vulns, _ = engine.validate_trivy_against_nvd(
                image_name, tag, None, None, None, False
            )
            
            for i, v in enumerate(all_vulns[:20], 1):  # Show first 20
                try:
                    pub_date = date_parser.isoparse(v.published).strftime("%Y-%m-%d")
                except:
                    pub_date = v.published
                print(f"{i:2d}. {v.cve_id} | {v.severity:8s} | Published: {pub_date}")
            
            if len(all_vulns) > 20:
                print(f"    ... and {len(all_vulns) - 20} more CVEs")
                
            if start_date and end_date:
                print(f"\n❌ None of these CVEs were published between {start_date.date()} and {end_date.date()}")
                print(f"💡 Try a wider date range like: --start 2020-01-01")
        
        return 0
        
    except (ValueError, NVDAPIError, RuntimeError) as e:
        logger.error(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("\nCancelled by user.")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())
    
