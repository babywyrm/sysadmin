#!/usr/bin/env python3
"""
NVD Vulnerability Scanner v2.0.0
Query the National Vulnerability Database with advanced filtering and export.. (beta)..
"""

import requests
import json
import csv
import sys
import argparse
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from time import sleep
import os
from dotenv import load_dotenv

load_dotenv()

VERSION = "2.0.0"
SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class NVDConfig:
    """Configuration for NVD API"""

    api_key: Optional[str] = None
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page: int = 2000
    rate_limit_delay: float = 0.6
    timeout: int = 30
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "NVDConfig":
        return cls(api_key=os.getenv("NVD_API_KEY"))


@dataclass
class Vulnerability:
    """Structured vulnerability data"""

    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published: str
    last_modified: str
    references: List[str]
    cwe_ids: List[str]
    affected_products: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NVDAPIError(Exception):
    """NVD API errors"""

    pass


class NVDVulnerabilityEngine:
    """Engine to query NVD database with severity hierarchy filtering"""

    def __init__(self, config: Optional[NVDConfig] = None):
        self.config = config or NVDConfig.from_env()
        self.logger = self._setup_logger()
        self.session = self._setup_session()
        self._log_api_status()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("NVDScanner")
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        if self.config.api_key:
            session.headers.update({"apiKey": self.config.api_key})
        session.headers.update(
            {"User-Agent": f"NVD-Scanner/{VERSION}", "Accept": "application/json"}
        )
        return session

    def _log_api_status(self) -> None:
        if self.config.api_key and len(self.config.api_key) > 20:
            self.logger.info("✓ API Key active (50 req/30s)")
        else:
            self.logger.warning("⚠ No API Key (5 req/30s)")
            self.config.rate_limit_delay = 6.0

    def query_vulnerabilities(
        self,
        start_date: datetime,
        end_date: datetime,
        min_severity: Optional[str] = None,
        keyword: Optional[str] = None,
        cwe_id: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query NVD with severity hierarchy (min_severity includes all higher severities)
        e.g., min_severity="HIGH" returns HIGH and CRITICAL
        """
        if start_date > end_date or end_date > datetime.now():
            raise ValueError("Invalid date range")

        all_vulns: List[Dict[str, Any]] = []
        start_index = 0
        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        self.logger.info(f"Querying {pub_start} to {pub_end}")
        if min_severity:
            self.logger.info(
                f"Min severity: {min_severity} "
                f"(includes {self._get_severity_range(min_severity)})"
            )
        if keyword:
            self.logger.info(f"Keyword: {keyword}")
        if cwe_id:
            self.logger.info(f"CWE: {cwe_id}")

        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": self.config.results_per_page,
                "startIndex": start_index,
            }
            if keyword:
                params["keywordSearch"] = keyword
            if cwe_id:
                params["cweId"] = cwe_id

            try:
                data = self._api_request(params)
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                filtered = self._filter_by_min_severity(vulns, min_severity)
                all_vulns.extend(filtered)

                total = data.get("totalResults", 0)
                self.logger.info(f"Retrieved {len(all_vulns)}/{total}")

                if max_results and len(all_vulns) >= max_results:
                    all_vulns = all_vulns[:max_results]
                    break

                if start_index + len(vulns) >= total:
                    break

                start_index += self.config.results_per_page
                sleep(self.config.rate_limit_delay)

            except NVDAPIError as e:
                self.logger.error(f"API Error: {e}")
                break

        return all_vulns

    def _get_severity_range(self, min_severity: str) -> str:
        """Get human-readable severity range"""
        if not min_severity:
            return "ALL"
        min_level = SEVERITY_LEVELS.get(min_severity.upper(), 1)
        included = [s for s, l in SEVERITY_LEVELS.items() if l >= min_level]
        return ", ".join(sorted(included, key=lambda x: SEVERITY_LEVELS[x]))

    def _filter_by_min_severity(
        self, vulns: List[Dict[str, Any]], min_severity: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Filter by minimum severity level (includes all higher levels)"""
        if not min_severity:
            return vulns

        min_level = SEVERITY_LEVELS.get(min_severity.upper(), 0)
        filtered = []

        for vuln in vulns:
            severity = self._extract_severity(vuln.get("cve", {}).get("metrics", {}))
            if severity:
                vuln_level = SEVERITY_LEVELS.get(severity.upper(), 0)
                if vuln_level >= min_level:
                    filtered.append(vuln)

        return filtered

    def _extract_severity(self, metrics: Dict[str, Any]) -> Optional[str]:
        """Extract severity from metrics"""
        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics:
                return metrics[version][0].get("cvssData", {}).get("baseSeverity")
        if "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0)
            return "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
        return None

    def _api_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make API request with retry logic"""
        for attempt in range(self.config.max_retries):
            try:
                resp = self.session.get(
                    self.config.base_url, params=params, timeout=self.config.timeout
                )
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.HTTPError as e:
                if resp.status_code == 403:
                    raise NVDAPIError("API Key invalid or rate limit exceeded")
                elif resp.status_code == 503 and attempt < self.config.max_retries - 1:
                    self.logger.warning(f"Service unavailable, retry {attempt + 1}")
                    sleep(5)
                else:
                    raise NVDAPIError(f"HTTP {resp.status_code}: {e}")
            except requests.exceptions.Timeout:
                if attempt < self.config.max_retries - 1:
                    self.logger.warning(f"Timeout, retry {attempt + 1}")
                    sleep(2)
            except requests.exceptions.RequestException as e:
                raise NVDAPIError(f"Request failed: {e}")
        raise NVDAPIError(f"Failed after {self.config.max_retries} retries")

    def format_vulnerability(self, vuln: Dict[str, Any]) -> Vulnerability:
        """Format vulnerability into structured object"""
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})

        # Extract CVSS data
        cvss_score, severity, vector = 0.0, "N/A", "N/A"
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                data = metrics[version][0].get("cvssData", {})
                cvss_score = float(data.get("baseScore", 0.0))
                if version == "cvssMetricV2":
                    severity = "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
                else:
                    severity = data.get("baseSeverity", "N/A")
                vector = data.get("vectorString", "N/A")
                break

        # Extract description
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description",
        )

        # Extract references and CWEs
        refs = [r.get("url", "") for r in cve.get("references", [])[:5]]
        cwes = [
            d.get("value", "")
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("lang") == "en"
        ]

        # Extract affected products
        products = [
            m.get("criteria", "")
            for c in cve.get("configurations", [])
            for n in c.get("nodes", [])
            for m in n.get("cpeMatch", [])[:3]
        ]

        return Vulnerability(
            cve_id=cve.get("id", "N/A"),
            description=desc,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=vector,
            published=cve.get("published", "N/A"),
            last_modified=cve.get("lastModified", "N/A"),
            references=refs,
            cwe_ids=cwes,
            affected_products=products,
        )

    def export(
        self, vulns: List[Dict[str, Any]], format: str, filename: Optional[str] = None
    ) -> str:
        """Export vulnerabilities to specified format"""
        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{ts}.{format}"

        formatted = [self.format_vulnerability(v) for v in vulns]
        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with output_path.open("w", encoding="utf-8") as f:
                json.dump([v.to_dict() for v in formatted], f, indent=2)

        elif format == "csv":
            with output_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "cve_id",
                        "severity",
                        "cvss_score",
                        "published",
                        "description",
                        "cvss_vector",
                        "cwe_ids",
                    ],
                )
                writer.writeheader()
                for v in formatted:
                    writer.writerow(
                        {
                            "cve_id": v.cve_id,
                            "severity": v.severity,
                            "cvss_score": v.cvss_score,
                            "published": v.published,
                            "description": v.description[:500],
                            "cvss_vector": v.cvss_vector,
                            "cwe_ids": ", ".join(v.cwe_ids),
                        }
                    )

        elif format == "md":
            with output_path.open("w", encoding="utf-8") as f:
                f.write(
                    f"# NVD Vulnerability Report\n\n"
                    f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"**Total:** {len(formatted)}\n\n---\n\n"
                )
                for v in formatted:
                    f.write(
                        f"## {v.cve_id}\n\n"
                        f"**Severity:** {v.severity} (CVSS: {v.cvss_score})\n"
                        f"**Published:** {v.published}\n\n"
                        f"**Description:** {v.description}\n\n"
                    )
                    if v.cwe_ids:
                        f.write(f"**CWE:** {', '.join(v.cwe_ids)}\n\n")
                    if v.references:
                        f.write("**References:**\n")
                        for ref in v.references:
                            f.write(f"- {ref}\n")
                        f.write("\n")
                    f.write("---\n\n")

        elif format == "html":
            with output_path.open("w", encoding="utf-8") as f:
                f.write(
                    f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>NVD Report</title>
<style>
body{{font-family:system-ui;max-width:1200px;margin:0 auto;padding:20px;background:#f5f5f5}}
.header{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:30px;border-radius:10px;margin-bottom:30px}}
.card{{background:white;padding:20px;margin-bottom:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}}
.severity{{display:inline-block;padding:5px 15px;border-radius:20px;font-weight:bold;font-size:12px}}
.CRITICAL{{background:#dc3545;color:white}}.HIGH{{background:#fd7e14;color:white}}
.MEDIUM{{background:#ffc107;color:black}}.LOW{{background:#28a745;color:white}}
.cve{{font-size:20px;font-weight:bold}}.desc{{margin:15px 0;color:#666}}
.meta{{font-size:14px;color:#888}}.refs a{{color:#667eea;text-decoration:none}}
</style></head><body>
<div class="header"><h1>NVD Vulnerability Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total: {len(formatted)}</p></div>
"""
                )
                for v in formatted:
                    f.write(
                        f'<div class="card"><div class="cve">{v.cve_id}</div>\n'
                        f'<span class="severity {v.severity}">{v.severity}</span> '
                        f'<span class="meta">CVSS: {v.cvss_score}</span>\n'
                        f'<div class="desc">{v.description}</div>\n'
                        f'<div class="meta">Published: {v.published}</div>\n'
                    )
                    if v.cwe_ids:
                        f.write(f'<div class="meta">CWE: {", ".join(v.cwe_ids)}</div>\n')
                    if v.references:
                        f.write('<div class="refs"><strong>References:</strong><br>')
                        for ref in v.references[:3]:
                            f.write(f'<a href="{ref}" target="_blank">{ref}</a><br>')
                        f.write("</div>")
                    f.write("</div>\n")
                f.write("</body></html>")

        self.logger.info(f"✓ Exported {len(formatted)} vulnerabilities to {filename}")
        return str(output_path)

    def print_summary(self, vulns: List[Dict[str, Any]]) -> None:
        """Print summary statistics"""
        if not vulns:
            self.logger.info("No vulnerabilities found")
            return

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        scores = []

        for v in vulns:
            f = self.format_vulnerability(v)
            counts[f.severity] = counts.get(f.severity, 0) + 1
            if f.cvss_score > 0:
                scores.append(f.cvss_score)

        avg = sum(scores) / len(scores) if scores else 0.0

        print("\n" + "=" * 80)
        print("VULNERABILITY SUMMARY")
        print("=" * 80)
        print(f"Total: {len(vulns)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts.get(sev, 0) > 0:
                print(f"  {sev}: {counts[sev]}")
        print(f"\nAverage CVSS: {avg:.2f}")
        print("=" * 80)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="NVD Vulnerability Scanner - Query CVE data with severity hierarchy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Last 7 days, HIGH+ (includes HIGH and CRITICAL)
  python nvd_scanner.py --days 7 --min-severity HIGH

  # Specific range, MEDIUM+ (includes MEDIUM, HIGH, CRITICAL)
  python nvd_scanner.py --start 2024-10-01 --end 2024-10-23 --min-severity MEDIUM

  # Export multiple formats
  python nvd_scanner.py --days 30 --min-severity CRITICAL --export json csv html

  # Search with keyword
  python nvd_scanner.py --days 14 --keyword "apache" --min-severity HIGH

Environment: Set NVD_API_KEY in .env file for higher rate limits
        """,
    )

    date_group = parser.add_mutually_exclusive_group(required=True)
    date_group.add_argument("--days", type=int, help="Days to look back")
    date_group.add_argument("--start", type=str, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end", type=str, help="End date (YYYY-MM-DD)")
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity (includes higher levels)",
    )
    parser.add_argument("--keyword", type=str, help="Keyword search")
    parser.add_argument("--cwe", type=str, help="CWE ID (e.g., CWE-79)")
    parser.add_argument("--max-results", type=int, help="Max results")
    parser.add_argument(
        "--export", nargs="+", choices=["json", "csv", "md", "html"], help="Export formats"
    )
    parser.add_argument("--output", type=str, help="Output filename (no extension)")
    parser.add_argument("--output-dir", type=str, default=".", help="Output directory")
    parser.add_argument("--limit", type=int, default=10, help="Display limit")
    parser.add_argument("--no-summary", action="store_true", help="Skip summary")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"v{VERSION}")

    return parser.parse_args()


def main() -> int:
    """Main entry point"""
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        engine = NVDVulnerabilityEngine()

        # Parse dates
        end_date = datetime.now()
        if args.days:
            start_date = end_date - timedelta(days=args.days)
        else:
            start_date = datetime.strptime(args.start, "%Y-%m-%d")
            if args.end:
                end_date = datetime.strptime(args.end, "%Y-%m-%d")

        # Query
        vulns = engine.query_vulnerabilities(
            start_date=start_date,
            end_date=end_date,
            min_severity=args.min_severity,
            keyword=args.keyword,
            cwe_id=args.cwe,
            max_results=args.max_results,
        )

        # Summary
        if not args.no_summary:
            engine.print_summary(vulns)

        # Display
        if vulns:
            print(f"\nTop {min(args.limit, len(vulns))} vulnerabilities:")
            print("-" * 80)
            for v in vulns[: args.limit]:
                f = engine.format_vulnerability(v)
                print(
                    f"\n{f.cve_id} | {f.severity} (CVSS: {f.cvss_score})\n"
                    f"Published: {f.published}\n"
                    f"{f.description[:200]}..."
                )

        # Export
        if args.export and vulns:
            output_dir = Path(args.output_dir)
            for fmt in args.export:
                filename = (
                    str(output_dir / f"{args.output}.{fmt}") if args.output else None
                )
                engine.export(vulns, fmt, filename)

        return 0

    except (ValueError, NVDAPIError) as e:
        logging.error(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        logging.info("\nCancelled")
        return 130
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())
