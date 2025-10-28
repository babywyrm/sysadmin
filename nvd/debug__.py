#!/usr/bin/env python3
"""
CVE comparison tool for container security scanners (Trivy vs Grype)... (beta,debug)...
Provides detailed analysis and reporting of vulnerability findings.
Explicitly prioritizes NVD as the primary data source for CVSS scores.
"""

import json
import subprocess
import sys
import argparse
import logging
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any
from tabulate import tabulate
from yaspin import yaspin


@dataclass
class CVE:
    """Structured CVE data representation."""
    id: str
    severity: str
    cvss: str
    vector: str
    source: str
    fixed_version: str
    has_fix: bool


class SecurityScanner:
    """Base class for security scanner operations."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal attacks."""
        return "".join(c for c in filename if c.isalnum() or c in "._-")[:100]
    
    def _run_command(self, cmd: List[str], description: str) -> str:
        """Execute command safely without shell injection."""
        with yaspin(text=description, color="cyan") as spinner:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=True
                )
                spinner.ok("DONE")
                return result.stdout
            except subprocess.CalledProcessError as e:
                spinner.fail("FAILED")
                self.logger.error(f"Command failed: {' '.join(cmd)}")
                self.logger.error(f"Error: {e.stderr}")
                sys.exit(1)
            except subprocess.TimeoutExpired:
                spinner.fail("TIMEOUT")
                self.logger.error(f"Command timed out: {' '.join(cmd)}")
                sys.exit(1)
    
    def _load_json_safe(self, path: Path) -> Dict[str, Any]:
        """Safely load and parse JSON file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.error(f"Failed to load JSON from {path}: {e}")
            sys.exit(1)


class TrivyScanner(SecurityScanner):
    """Trivy security scanner handler."""
    
    def scan(self, image: str, output_path: Path) -> None:
        """Execute Trivy scan."""
        cmd = [
            "trivy", "image", 
            "--quiet", 
            "--format", "json", 
            "-o", str(output_path),
            image
        ]
        self._run_command(cmd, f"Scanning {image} with Trivy")
    
    def extract_cves(self, json_path: Path, debug: bool = False) -> List[CVE]:
        """Extract CVE data from Trivy JSON output. PRIORITIZES NVD DATA."""
        data = self._load_json_safe(json_path)
        cves = []
        
        if debug:
            self.logger.info(f"\n{'='*60}")
            self.logger.info("TRIVY DEBUG: Examining fix information")
            self.logger.info(f"{'='*60}")
        
        fix_count = 0
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                fixed_version = vuln.get("FixedVersion", "").strip()
                
                # More robust fix detection
                no_fix_indicators = ["", "none", "not-fixed", "unfixed", "n/a"]
                has_fix = (
                    fixed_version and 
                    fixed_version.lower() not in no_fix_indicators
                )
                
                if debug and has_fix:
                    fix_count += 1
                    if fix_count <= 5:  # Show first 5 examples
                        self.logger.info(f"  {vuln.get('VulnerabilityID')}: FixedVersion='{fixed_version}'")
                
                # EXPLICIT NVD PRIORITIZATION
                cvss_data = vuln.get("CVSS", {})
                if not isinstance(cvss_data, dict):
                    cvss_data = {}
                
                nvd_data = cvss_data.get("nvd", {})
                if not isinstance(nvd_data, dict):
                    nvd_data = {}
                
                cvss_score = "N/A"
                cvss_vector = "N/A"
                source = "trivy"  # default
                
                if nvd_data:
                    # NVD data available - prioritize V3 over V2
                    cvss_score = str(nvd_data.get("V3Score") or nvd_data.get("V2Score") or "N/A")
                    cvss_vector = nvd_data.get("Vectors", "N/A")
                    source = "nvd"
                else:
                    # Fallback to other CVSS sources if available
                    for source_name, source_data in cvss_data.items():
                        if isinstance(source_data, dict) and source_data:
                            cvss_score = str(source_data.get("V3Score") or source_data.get("V2Score") or "N/A")
                            cvss_vector = source_data.get("Vectors", "N/A")
                            source = source_name
                            break
                
                cves.append(CVE(
                    id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    severity=vuln.get("Severity", "UNKNOWN").upper(),
                    cvss=cvss_score,
                    vector=cvss_vector,
                    source=source,
                    fixed_version=fixed_version if has_fix else "N/A",
                    has_fix=has_fix
                ))
        
        if debug:
            self.logger.info(f"Total CVEs with fixes: {fix_count}/{len(cves)}")
            self.logger.info(f"{'='*60}\n")
        
        return cves


class GrypeScanner(SecurityScanner):
    """Grype security scanner handler."""
    
    def scan(self, image: str, output_path: Path) -> None:
        """Execute Grype scan."""
        cmd = ["grype", image, "-o", "json"]
        output = self._run_command(cmd, f"Scanning {image} with Grype")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(output)
    
    def extract_cves(self, json_path: Path, debug: bool = False) -> List[CVE]:
        """Extract CVE data from Grype JSON output. PRIORITIZES NVD DATA."""
        data = self._load_json_safe(json_path)
        cves = []
        
        if debug:
            self.logger.info(f"\n{'='*60}")
            self.logger.info("GRYPE DEBUG: Examining fix information")
            self.logger.info(f"{'='*60}")
        
        fix_count = 0
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            
            # Extract fix information - more robust approach
            fixed_version = ""
            has_fix = False
            no_fix_indicators = ["unknown", "not-fixed", "none", "unfixed", "n/a", ""]
            
            if "fix" in vuln:
                fix_info = vuln["fix"]
                
                if debug and fix_count < 5:  # Show first 5 examples
                    self.logger.info(f"  {vuln.get('id')}: fix={fix_info}")
                
                if isinstance(fix_info, dict):
                    versions = fix_info.get("versions", [])
                    state = fix_info.get("state", "").lower()
                    
                    # Check if explicitly marked as fixed
                    if state == "fixed" and versions:
                        fixed_version = str(versions[0]) if versions else ""
                    elif versions:
                        # Has version info - check if valid
                        version_str = str(versions[0])
                        if version_str.lower() not in no_fix_indicators:
                            fixed_version = version_str
                            
                elif isinstance(fix_info, list) and fix_info:
                    version_str = str(fix_info[0])
                    if version_str.lower() not in no_fix_indicators:
                        fixed_version = version_str
            
            # Final check for has_fix
            has_fix = bool(fixed_version and fixed_version.lower() not in no_fix_indicators)
            
            if has_fix:
                fix_count += 1
            
            # EXPLICIT NVD PRIORITIZATION FOR CVSS
            cvss_score = "N/A"
            cvss_vector = "N/A"
            nvd_source = False
            
            cvss_list = vuln.get("cvss", [])
            if cvss_list and isinstance(cvss_list, list):
                # First, try to find NVD source
                nvd_cvss = None
                other_cvss = None
                
                for cvss_entry in cvss_list:
                    # Type check - skip if not a dict
                    if not isinstance(cvss_entry, dict):
                        continue
                        
                    source_info = cvss_entry.get("source", {})
                    if not isinstance(source_info, dict):
                        continue
                        
                    source_name = source_info.get("name", "").lower()
                    if "nvd" in source_name:
                        nvd_cvss = cvss_entry
                        nvd_source = True
                        break
                    elif other_cvss is None:  # Keep first non-NVD as fallback
                        other_cvss = cvss_entry
                
                # Use NVD if available, otherwise fallback to other source
                selected_cvss = nvd_cvss if nvd_cvss else other_cvss
                
                if selected_cvss and isinstance(selected_cvss, dict):
                    metrics = selected_cvss.get("metrics", {})
                    if isinstance(metrics, dict):
                        cvss_score = str(metrics.get("baseScore", "N/A"))
                    cvss_vector = selected_cvss.get("vectorString", "N/A")
            
            # Determine source - prioritize NVD detection
            data_source = vuln.get("dataSource", "")
            if nvd_source or "nvd" in data_source.lower():
                source = "nvd"
            elif data_source:
                source = "grype"
            else:
                source = "vendor"
            
            cves.append(CVE(
                id=vuln.get("id", "UNKNOWN"),
                severity=vuln.get("severity", "UNKNOWN").upper(),
                cvss=cvss_score,
                vector=cvss_vector,
                source=source,
                fixed_version=fixed_version if has_fix else "N/A",
                has_fix=has_fix
            ))
        
        if debug:
            self.logger.info(f"Total CVEs with fixes: {fix_count}/{len(cves)}")
            self.logger.info(f"{'='*60}\n")
        
        return cves


class CVEAnalyzer:
    """CVE analysis and reporting functionality."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def filter_with_fixes(self, cves: List[CVE]) -> List[CVE]:
        """Filter CVEs to only those with available fixes."""
        return [cve for cve in cves if cve.has_fix]
    
    def calculate_summary(self, cves: List[CVE]) -> Dict[str, int]:
        """Calculate severity summary statistics."""
        summary = defaultdict(int)
        for cve in cves:
            summary[cve.severity] += 1
        
        # Ensure all severity levels are represented
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]:
            summary.setdefault(severity, 0)
        
        return dict(summary)
    
    def find_common_and_unique(self, trivy_cves: List[CVE], grype_cves: List[CVE]) -> tuple:
        """Find common and unique CVEs between scanners."""
        trivy_ids = {cve.id for cve in trivy_cves}
        grype_ids = {cve.id for cve in grype_cves}
        
        # Create lookup dictionaries for detailed comparison
        trivy_lookup = {cve.id: cve for cve in trivy_cves}
        grype_lookup = {cve.id: cve for cve in grype_cves}
        
        common = [trivy_lookup[cve_id] for cve_id in trivy_ids & grype_ids]
        unique_trivy = [cve for cve in trivy_cves if cve.id not in grype_ids]
        unique_grype = [cve for cve in grype_cves if cve.id not in trivy_ids]
        
        return common, unique_trivy, unique_grype
    
    def generate_markdown_report(
        self,
        output_path: Path,
        image: str,
        trivy_cves: List[CVE],
        grype_cves: List[CVE],
        common: List[CVE],
        unique_trivy: List[CVE],
        unique_grype: List[CVE],
        fixes_only: bool = False
    ) -> None:
        """Generate comprehensive markdown report."""
        trivy_summary = self.calculate_summary(trivy_cves)
        grype_summary = self.calculate_summary(grype_cves)
        
        filter_text = " (with vendor fixes only)" if fixes_only else ""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# CVE Comparison Report: {image}{filter_text}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(f"- **Trivy Total**: {len(trivy_cves)} CVEs\n")
            f.write(f"- **Grype Total**: {len(grype_cves)} CVEs\n")
            f.write(f"- **Common**: {len(common)} CVEs\n")
            f.write(f"- **Trivy Unique**: {len(unique_trivy)} CVEs\n")
            f.write(f"- **Grype Unique**: {len(unique_grype)} CVEs\n\n")
            
            # Severity breakdown
            f.write("## Severity Distribution\n\n")
            severity_table = []
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]:
                if trivy_summary[severity] > 0 or grype_summary[severity] > 0:
                    severity_table.append([severity, trivy_summary[severity], grype_summary[severity]])
            
            f.write(tabulate(severity_table, headers=["Severity", "Trivy", "Grype"], tablefmt="github"))
            f.write("\n\n")
            
            # Detailed sections
            self._write_cve_section(f, "Common CVEs", common, fixes_only)
            self._write_cve_section(f, "Trivy Unique CVEs", unique_trivy, fixes_only)
            self._write_cve_section(f, "Grype Unique CVEs", unique_grype, fixes_only)
    
    def _write_cve_section(self, f, title: str, cves: List[CVE], show_fixes: bool) -> None:
        """Write a CVE section to the markdown file."""
        f.write(f"## {title} ({len(cves)} total)\n\n")
        
        if not cves:
            f.write("No CVEs found.\n\n")
            return
        
        headers = ["Severity", "CVE ID", "CVSS Score", "Vector", "Source"]
        if show_fixes:
            headers.append("Fixed Version")
        
        rows = []
        for cve in sorted(cves, key=lambda x: (x.severity, x.id)):
            row = [cve.severity, cve.id, cve.cvss, cve.vector, cve.source]
            if show_fixes:
                row.append(cve.fixed_version)
            rows.append(row)
        
        f.write(tabulate(rows, headers=headers, tablefmt="github"))
        f.write("\n\n")
    
    def print_unified_comparison_table(
        self,
        trivy_cves: List[CVE],
        grype_cves: List[CVE],
        fixes_only: bool = False
    ) -> None:
        """Print a unified comparison table showing all CVEs with scanner detection status."""
        print(f"\n{'-'*80}")
        print("UNIFIED CVE COMPARISON TABLE")
        print(f"{'-'*80}")
        
        # Create a unified dataset
        all_cve_ids = set()
        trivy_lookup = {}
        grype_lookup = {}
        
        for cve in trivy_cves:
            all_cve_ids.add(cve.id)
            trivy_lookup[cve.id] = cve
        
        for cve in grype_cves:
            all_cve_ids.add(cve.id)
            grype_lookup[cve.id] = cve
        
        # Build unified rows
        unified_rows = []
        for cve_id in sorted(all_cve_ids):
            trivy_cve = trivy_lookup.get(cve_id)
            grype_cve = grype_lookup.get(cve_id)
            
            # Use the CVE data from whichever scanner found it (prefer NVD source)
            primary_cve = None
            if trivy_cve and grype_cve:
                # Both found it - prefer NVD source
                primary_cve = trivy_cve if trivy_cve.source == "nvd" else grype_cve
            elif trivy_cve:
                primary_cve = trivy_cve
            else:
                primary_cve = grype_cve
            
            # Scanner detection status
            trivy_status = "✓" if trivy_cve else "✗"
            grype_status = "✓" if grype_cve else "✗"
            
            # Get source information
            trivy_source = trivy_cve.source if trivy_cve else "-"
            grype_source = grype_cve.source if grype_cve else "-"
            
            # Fixed version (prefer the one with actual version info)
            fixed_version = "N/A"
            if trivy_cve and trivy_cve.fixed_version != "N/A":
                fixed_version = trivy_cve.fixed_version
            elif grype_cve and grype_cve.fixed_version != "N/A":
                fixed_version = grype_cve.fixed_version
            
            row = [
                primary_cve.severity,
                cve_id,
                primary_cve.cvss,
                f"{trivy_status} ({trivy_source})",
                f"{grype_status} ({grype_source})"
            ]
            
            if fixes_only:
                row.append(fixed_version)
            
            unified_rows.append(row)
        
        # Sort by severity then CVE ID
        severity_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4, "UNKNOWN": 5}
        unified_rows.sort(key=lambda x: (severity_priority.get(x[0], 6), x[1]))
        
        # Headers
        headers = ["Severity", "CVE ID", "CVSS", "Trivy", "Grype"]
        if fixes_only:
            headers.append("Fixed Version")
            
        # Group rows by severity before printing
        grouped_by_severity = defaultdict(list)
        for row in unified_rows:
            grouped_by_severity[row[0]].append(row)
            
        # Get the sorted list of severities present in the results
        sorted_severities = sorted(grouped_by_severity.keys(), key=lambda sev: severity_priority.get(sev, 6))

        for severity in sorted_severities:
            rows_for_severity = grouped_by_severity[severity]
            print(f"\n{severity} ({len(rows_for_severity)} CVEs):")
            print("-" * (len(headers) * 15))
            # Print the entire group at once for proper alignment
            print(tabulate(rows_for_severity, headers=headers, tablefmt="simple"))

        print(f"\n{'-'*80}")
        print("Legend: ✓ = Found, ✗ = Not Found, (source) = Data Source")
        print(f"{'-'*80}")
    
    def print_console_summary(
        self,
        trivy_cves: List[CVE],
        grype_cves: List[CVE],
        common: List[CVE],
        unique_trivy: List[CVE],
        unique_grype: List[CVE],
        fixes_only: bool = False,
        verbose: bool = False
    ) -> None:
        """Print summary to console."""
        filter_text = " (fixes only)" if fixes_only else ""
        
        print(f"\n{'='*60}")
        print(f"CVE COMPARISON SUMMARY{filter_text}")
        print(f"{'='*60}")
        print(f"Trivy CVEs:      {len(trivy_cves):>6}")
        print(f"Grype CVEs:      {len(grype_cves):>6}")
        print(f"Common:          {len(common):>6}")
        print(f"Trivy Unique:    {len(unique_trivy):>6}")
        print(f"Grype Unique:    {len(unique_grype):>6}")
        
        if fixes_only:
            trivy_fixes = sum(1 for cve in trivy_cves if cve.has_fix)
            grype_fixes = sum(1 for cve in grype_cves if cve.has_fix)
            print(f"Trivy w/ Fixes:  {trivy_fixes:>6}")
            print(f"Grype w/ Fixes:  {grype_fixes:>6}")
        
        print(f"\nSeverity Breakdown:")
        trivy_summary = self.calculate_summary(trivy_cves)
        grype_summary = self.calculate_summary(grype_cves)
        
        severity_table = []
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]:
            if trivy_summary[severity] > 0 or grype_summary[severity] > 0:
                severity_table.append([severity, trivy_summary[severity], grype_summary[severity]])
        
        print(tabulate(severity_table, headers=["Severity", "Trivy", "Grype"], tablefmt="simple"))
        print(f"{'='*60}")
        
        # Verbose output - use unified table instead of separate sections
        if verbose:
            self.print_unified_comparison_table(trivy_cves, grype_cves, fixes_only)


def setup_logging() -> logging.Logger:
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def validate_image_name(image: str) -> str:
    """Validate and sanitize container image name."""
    if not image or len(image) > 255:
        raise ValueError("Invalid image name length")
    
    # Basic validation for container image format
    if not any(c.isalnum() for c in image):
        raise ValueError("Invalid image name format")
    
    return image


def main() -> None:
    """Main execution function."""
    logger = setup_logging()
    
    parser = argparse.ArgumentParser(
        description="Compare CVE findings between Trivy and Grype security scanners",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "image",
        help="Container image to scan (e.g., nginx:latest)"
    )
    parser.add_argument(
        "--fixes-only",
        action="store_true",
        help="Only analyze CVEs that have vendor fixes available"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Output directory for reports and scan results"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed CVE information in console output"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show debug information about fix detection"
    )
    
    args = parser.parse_args()
    
    try:
        # Validate inputs
        image = validate_image_name(args.image)
        output_dir = args.output_dir
        output_dir.mkdir(exist_ok=True, parents=True)
        
        # Initialize components
        trivy = TrivyScanner(logger)
        grype = GrypeScanner(logger)
        analyzer = CVEAnalyzer(logger)
        
        # Generate safe filenames
        safe_image_name = trivy._sanitize_filename(
            image.replace("/", "_").replace(":", "_").replace(".", "_")
        )
        
        suffix = "_fixes" if args.fixes_only else ""
        trivy_json = output_dir / f"trivy_{safe_image_name}{suffix}.json"
        grype_json = output_dir / f"grype_{safe_image_name}{suffix}.json"
        report_md = output_dir / f"report_{safe_image_name}{suffix}.md"
        
        # Execute scans
        logger.info(f"Starting security scan comparison for: {image}")
        trivy.scan(image, trivy_json)
        grype.scan(image, grype_json)
        
        # Extract and process CVE data
        trivy_cves = trivy.extract_cves(trivy_json, debug=args.debug)
        grype_cves = grype.extract_cves(grype_json, debug=args.debug)
        
        if args.fixes_only:
            trivy_cves = analyzer.filter_with_fixes(trivy_cves)
            grype_cves = analyzer.filter_with_fixes(grype_cves)
        
        # Analyze differences
        common, unique_trivy, unique_grype = analyzer.find_common_and_unique(trivy_cves, grype_cves)
        
        # Generate reports
        analyzer.generate_markdown_report(
            report_md, image, trivy_cves, grype_cves,
            common, unique_trivy, unique_grype, args.fixes_only
        )
        
        analyzer.print_console_summary(
            trivy_cves, grype_cves, common, unique_trivy, unique_grype, 
            args.fixes_only, args.verbose
        )
        
        logger.info(f"Analysis complete. Report saved to: {report_md}")
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
