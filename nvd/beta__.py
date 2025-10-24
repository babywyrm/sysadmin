#!/usr/bin/env python3
"""
NVD Vulnerability Scanner
A comprehensive tool for querying the National Vulnerability Database (NVD)
with advanced filtering, export capabilities, and security features.

Author: T3 Security Team, lol
Version: 2.0.0
License: MIT
"""

import requests
import json
import csv
import sys
import argparse
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from time import sleep
from enum import Enum
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants
VERSION = "2.0.0"
DEFAULT_RESULTS_PER_PAGE = 2000
MAX_RESULTS_PER_PAGE = 2000
API_KEY_ENV_VAR = "NVD_API_KEY"
DEFAULT_TIMEOUT = 30


class Severity(Enum):
    """CVSS Severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ExportFormat(Enum):
    """Available export formats"""

    JSON = "json"
    CSV = "csv"
    MARKDOWN = "md"
    HTML = "html"


@dataclass
class NVDConfig:
    """Configuration for NVD API with validation"""

    api_key: Optional[str] = None
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page: int = DEFAULT_RESULTS_PER_PAGE
    rate_limit_delay: float = 0.6
    timeout: int = DEFAULT_TIMEOUT
    max_retries: int = 3
    verify_ssl: bool = True

    def __post_init__(self):
        """Validate configuration after initialization"""
        if self.results_per_page > MAX_RESULTS_PER_PAGE:
            raise ValueError(
                f"results_per_page cannot exceed {MAX_RESULTS_PER_PAGE}"
            )
        if self.rate_limit_delay < 0:
            raise ValueError("rate_limit_delay must be positive")
        if self.timeout < 1:
            raise ValueError("timeout must be at least 1 second")

    @classmethod
    def from_env(cls) -> "NVDConfig":
        """Create configuration from environment variables"""
        api_key = os.getenv(API_KEY_ENV_VAR)
        return cls(api_key=api_key)


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
        """Convert to dictionary"""
        return asdict(self)


class NVDAPIError(Exception):
    """Custom exception for NVD API errors"""

    pass


class NVDVulnerabilityEngine:
    """
    Enhanced engine to query NVD database for vulnerabilities
    with improved security, typing, and error handling
    """

    def __init__(
        self, config: Optional[NVDConfig] = None, logger: Optional[Any] = None
    ):
        """
        Initialize the vulnerability engine

        Args:
            config: Configuration object for NVD API
            logger: Logger instance for output
        """
        self.config = config or NVDConfig.from_env()
        self.logger = logger or self._setup_logger()
        self.session = self._setup_session()
        self._validate_api_key()

    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger("NVDScanner")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _setup_session(self) -> requests.Session:
        """Setup requests session with proper headers"""
        session = requests.Session()

        if self.config.api_key:
            session.headers.update({"apiKey": self.config.api_key})

        session.headers.update(
            {
                "User-Agent": f"NVD-Scanner/{VERSION}",
                "Accept": "application/json",
            }
        )

        return session

    def _validate_api_key(self) -> None:
        """Validate API key and log status"""
        if self.config.api_key:
            if len(self.config.api_key) < 20:
                self.logger.warning("API key appears to be invalid (too short)")
            else:
                self.logger.info("✓ API Key loaded successfully")
                self.logger.info(
                    "Rate limit: 50 requests per 30 seconds"
                )
        else:
            self.logger.warning(
                "⚠ No API Key found. Using public rate limits "
                "(5 requests/30s)"
            )
            self.config.rate_limit_delay = 6.0

    def query_vulnerabilities(
        self,
        start_date: datetime,
        end_date: datetime,
        severities: Optional[List[str]] = None,
        keyword: Optional[str] = None,
        cwe_id: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query NVD for vulnerabilities with comprehensive filtering

        Args:
            start_date: Start of date range
            end_date: End of date range
            severities: List of severity levels to filter
            keyword: Keyword to search for in CVE descriptions
            cwe_id: Common Weakness Enumeration ID
            max_results: Maximum number of results to return

        Returns:
            List of vulnerability dictionaries

        Raises:
            NVDAPIError: If API request fails
            ValueError: If date range is invalid
        """
        self._validate_date_range(start_date, end_date)

        all_vulnerabilities: List[Dict[str, Any]] = []
        start_index = 0

        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        self.logger.info(f"Querying NVD from {pub_start} to {pub_end}")
        if severities:
            self.logger.info(f"Severity filter: {', '.join(severities)}")
        if keyword:
            self.logger.info(f"Keyword filter: {keyword}")
        if cwe_id:
            self.logger.info(f"CWE ID filter: {cwe_id}")

        while True:
            params = self._build_query_params(
                pub_start, pub_end, start_index, keyword, cwe_id
            )

            try:
                data = self._make_api_request(params)
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                filtered = self._filter_by_severity(
                    vulnerabilities, severities
                )
                all_vulnerabilities.extend(filtered)

                total_results = data.get("totalResults", 0)
                self.logger.info(
                    f"Retrieved {len(all_vulnerabilities)} of "
                    f"{total_results} total vulnerabilities"
                )

                if max_results and len(all_vulnerabilities) >= max_results:
                    all_vulnerabilities = all_vulnerabilities[:max_results]
                    self.logger.info(f"Reached max results limit: {max_results}")
                    break

                if start_index + len(vulnerabilities) >= total_results:
                    break

                start_index += self.config.results_per_page
                sleep(self.config.rate_limit_delay)

            except NVDAPIError as e:
                self.logger.error(f"API Error: {e}")
                break

        return all_vulnerabilities

    def _validate_date_range(
        self, start_date: datetime, end_date: datetime
    ) -> None:
        """Validate date range"""
        if start_date > end_date:
            raise ValueError("start_date must be before end_date")
        if end_date > datetime.now():
            raise ValueError("end_date cannot be in the future")

    def _build_query_params(
        self,
        pub_start: str,
        pub_end: str,
        start_index: int,
        keyword: Optional[str],
        cwe_id: Optional[str],
    ) -> Dict[str, Any]:
        """Build query parameters for API request"""
        params: Dict[str, Any] = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": self.config.results_per_page,
            "startIndex": start_index,
        }

        if keyword:
            params["keywordSearch"] = keyword
        if cwe_id:
            params["cweId"] = cwe_id

        return params

    def _make_api_request(
        self, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Make API request with retry logic

        Raises:
            NVDAPIError: If all retry attempts fail
        """
        for attempt in range(self.config.max_retries):
            try:
                response = self.session.get(
                    self.config.base_url,
                    params=params,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                )
                response.raise_for_status()
                return response.json()

            except requests.exceptions.HTTPError as e:
                if response.status_code == 403:
                    raise NVDAPIError(
                        "API Key invalid or rate limit exceeded"
                    )
                elif response.status_code == 503:
                    self.logger.warning(
                        f"Service unavailable, retry {attempt + 1}/"
                        f"{self.config.max_retries}"
                    )
                    sleep(5)
                else:
                    raise NVDAPIError(f"HTTP Error {response.status_code}: {e}")

            except requests.exceptions.Timeout:
                self.logger.warning(
                    f"Request timeout, retry {attempt + 1}/"
                    f"{self.config.max_retries}"
                )
                sleep(2)

            except requests.exceptions.RequestException as e:
                raise NVDAPIError(f"Request failed: {e}")

        raise NVDAPIError(
            f"Failed after {self.config.max_retries} retry attempts"
        )

    def _filter_by_severity(
        self,
        vulnerabilities: List[Dict[str, Any]],
        severities: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        """Filter vulnerabilities by CVSS severity"""
        if not severities:
            return vulnerabilities

        filtered: List[Dict[str, Any]] = []
        severities_upper = [s.upper() for s in severities]

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})

            severity = self._extract_severity(metrics)

            if severity and severity.upper() in severities_upper:
                filtered.append(vuln)

        return filtered

    def _extract_severity(self, metrics: Dict[str, Any]) -> Optional[str]:
        """Extract severity from metrics"""
        if "cvssMetricV31" in metrics:
            return (
                metrics["cvssMetricV31"][0]
                .get("cvssData", {})
                .get("baseSeverity")
            )
        elif "cvssMetricV30" in metrics:
            return (
                metrics["cvssMetricV30"][0]
                .get("cvssData", {})
                .get("baseSeverity")
            )
        elif "cvssMetricV2" in metrics:
            base_score = (
                metrics["cvssMetricV2"][0]
                .get("cvssData", {})
                .get("baseScore", 0)
            )
            return self._map_v2_severity(base_score)
        return None

    @staticmethod
    def _map_v2_severity(score: float) -> str:
        """Map CVSS v2 score to severity level"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def format_vulnerability(
        self, vuln: Dict[str, Any]
    ) -> Vulnerability:
        """Format vulnerability data into structured object"""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # Extract description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available",
        )

        # Extract CVSS data
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        severity = "N/A"
        vector = "N/A"

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = float(cvss_data.get("baseScore", 0.0))
            severity = cvss_data.get("baseSeverity", "N/A")
            vector = cvss_data.get("vectorString", "N/A")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = float(cvss_data.get("baseScore", 0.0))
            severity = cvss_data.get("baseSeverity", "N/A")
            vector = cvss_data.get("vectorString", "N/A")
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = float(cvss_data.get("baseScore", 0.0))
            severity = self._map_v2_severity(cvss_score)
            vector = cvss_data.get("vectorString", "N/A")

        # Extract dates
        published = cve.get("published", "N/A")
        last_modified = cve.get("lastModified", "N/A")

        # Extract references
        references = cve.get("references", [])
        ref_urls = [ref.get("url", "") for ref in references[:5]]

        # Extract CWE IDs
        weaknesses = cve.get("weaknesses", [])
        cwe_ids: List[str] = []
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    cwe_ids.append(desc.get("value", ""))

        # Extract affected products
        configurations = cve.get("configurations", [])
        affected_products: List[str] = []
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches[:3]:
                    criteria = match.get("criteria", "")
                    if criteria:
                        affected_products.append(criteria)

        return Vulnerability(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=vector,
            published=published,
            last_modified=last_modified,
            references=ref_urls,
            cwe_ids=cwe_ids,
            affected_products=affected_products,
        )

    def export_to_json(
        self,
        vulnerabilities: List[Dict[str, Any]],
        filename: Optional[str] = None,
    ) -> str:
        """Export vulnerabilities to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{timestamp}.json"

        formatted = [
            self.format_vulnerability(v).to_dict()
            for v in vulnerabilities
        ]

        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(formatted, f, indent=2, ensure_ascii=False)

        self.logger.info(
            f"✓ Exported {len(formatted)} vulnerabilities to {filename}"
        )
        return str(output_path)

    def export_to_csv(
        self,
        vulnerabilities: List[Dict[str, Any]],
        filename: Optional[str] = None,
    ) -> str:
        """Export vulnerabilities to CSV file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{timestamp}.csv"

        formatted = [
            self.format_vulnerability(v) for v in vulnerabilities
        ]

        if not formatted:
            self.logger.warning("No vulnerabilities to export")
            return ""

        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "cve_id",
                "severity",
                "cvss_score",
                "published",
                "description",
                "cvss_vector",
                "cwe_ids",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for vuln in formatted:
                writer.writerow(
                    {
                        "cve_id": vuln.cve_id,
                        "severity": vuln.severity,
                        "cvss_score": vuln.cvss_score,
                        "published": vuln.published,
                        "description": vuln.description[:500],
                        "cvss_vector": vuln.cvss_vector,
                        "cwe_ids": ", ".join(vuln.cwe_ids),
                    }
                )

        self.logger.info(
            f"✓ Exported {len(formatted)} vulnerabilities to {filename}"
        )
        return str(output_path)

    def export_to_markdown(
        self,
        vulnerabilities: List[Dict[str, Any]],
        filename: Optional[str] = None,
    ) -> str:
        """Export vulnerabilities to Markdown file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{timestamp}.md"

        formatted = [
            self.format_vulnerability(v) for v in vulnerabilities
        ]

        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            f.write("# NVD Vulnerability Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Vulnerabilities:** {len(formatted)}\n\n")
            f.write("---\n\n")

            for vuln in formatted:
                f.write(f"## {vuln.cve_id}\n\n")
                f.write(
                    f"**Severity:** {vuln.severity} "
                    f"(CVSS: {vuln.cvss_score})\n\n"
                )
                f.write(f"**Published:** {vuln.published}\n\n")
                f.write(f"**Description:** {vuln.description}\n\n")
                if vuln.cwe_ids:
                    f.write(f"**CWE IDs:** {', '.join(vuln.cwe_ids)}\n\n")
                if vuln.references:
                    f.write("**References:**\n")
                    for ref in vuln.references:
                        f.write(f"- {ref}\n")
                    f.write("\n")
                f.write("---\n\n")

        self.logger.info(
            f"✓ Exported {len(formatted)} vulnerabilities to {filename}"
        )
        return str(output_path)

    def export_to_html(
        self,
        vulnerabilities: List[Dict[str, Any]],
        filename: Optional[str] = None,
    ) -> str:
        """Export vulnerabilities to HTML file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{timestamp}.html"

        formatted = [
            self.format_vulnerability(v) for v in vulnerabilities
        ]

        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            f.write(self._generate_html_report(formatted))

        self.logger.info(
            f"✓ Exported {len(formatted)} vulnerabilities to {filename}"
        )
        return str(output_path)

    def _generate_html_report(
        self, vulnerabilities: List[Vulnerability]
    ) -> str:
        """Generate HTML report"""
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NVD Vulnerability Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .vuln-card {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .severity {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 12px;
        }
        .severity.CRITICAL { background: #dc3545; color: white; }
        .severity.HIGH { background: #fd7e14; color: white; }
        .severity.MEDIUM { background: #ffc107; color: black; }
        .severity.LOW { background: #28a745; color: white; }
        .cve-id { font-size: 20px; font-weight: bold; color: #333; }
        .description { margin: 15px 0; color: #666; }
        .meta { font-size: 14px; color: #888; }
        .references { margin-top: 10px; }
        .references a { color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>NVD Vulnerability Report</h1>
        <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        <p>Total Vulnerabilities: """ + str(len(vulnerabilities)) + """</p>
    </div>
"""

        for vuln in vulnerabilities:
            html += f"""
    <div class="vuln-card">
        <div class="cve-id">{vuln.cve_id}</div>
        <span class="severity {vuln.severity}">{vuln.severity}</span>
        <span class="meta">CVSS: {vuln.cvss_score}</span>
        <div class="description">{vuln.description}</div>
        <div class="meta">Published: {vuln.published}</div>
"""
            if vuln.cwe_ids:
                html += f"""
        <div class="meta">CWE: {', '.join(vuln.cwe_ids)}</div>
"""
            if vuln.references:
                html += """
        <div class="references">
            <strong>References:</strong><br>
"""
                for ref in vuln.references[:3]:
                    html += f'            <a href="{ref}" target="_blank">{ref}</a><br>\n'
                html += """
        </div>
"""
            html += """
    </div>
"""

        html += """
</body>
</html>
"""
        return html

    def print_summary(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> None:
        """Print detailed summary statistics"""
        if not vulnerabilities:
            self.logger.info("No vulnerabilities found.")
            return

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "N/A": 0,
        }

        cvss_scores: List[float] = []

        for vuln in vulnerabilities:
            formatted = self.format_vulnerability(vuln)
            severity = formatted.severity
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["N/A"] += 1

            if formatted.cvss_score > 0:
                cvss_scores.append(formatted.cvss_score)

        avg_cvss = (
            sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        )

        print("\n" + "=" * 80)
        print("VULNERABILITY SUMMARY")
        print("=" * 80)
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        print(f"  CRITICAL: {severity_counts['CRITICAL']}")
        print(f"  HIGH:     {severity_counts['HIGH']}")
        print(f"  MEDIUM:   {severity_counts['MEDIUM']}")
        print(f"  LOW:      {severity_counts['LOW']}")
        if severity_counts["N/A"] > 0:
            print(f"  N/A:      {severity_counts['N/A']}")
        print(f"\nAverage CVSS Score: {avg_cvss:.2f}")
        print("=" * 80)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="NVD Vulnerability Scanner - Query and analyze CVE data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Last 7 days, HIGH and CRITICAL only
  python nvd_scanner.py --days 7 --severity HIGH CRITICAL

  # Specific date range with keyword
  python nvd_scanner.py --start 2024-10-01 --end 2024-10-23 --keyword "apache"

  # Export to multiple formats
  python nvd_scanner.py --days 30 --severity CRITICAL --export json csv html

  # Search by CWE ID
  python nvd_scanner.py --days 14 --cwe CWE-79 --severity HIGH CRITICAL

Environment Variables:
  NVD_API_KEY    Your NVD API key (recommended)

Configuration:
  Create a .env file with: NVD_API_KEY=your_api_key_here
        """,
    )

    # Date range options
    date_group = parser.add_mutually_exclusive_group(required=True)
    date_group.add_argument(
        "--days",
        type=int,
        help="Number of days to look back from today",
    )
    date_group.add_argument(
        "--start",
        type=str,
        help="Start date (YYYY-MM-DD)",
    )

    parser.add_argument(
        "--end",
        type=str,
        help="End date (YYYY-MM-DD), defaults to today",
    )

    # Filtering options
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter by severity level(s)",
    )

    parser.add_argument(
        "--keyword",
        type=str,
        help="Keyword to search in CVE descriptions",
    )

    parser.add_argument(
        "--cwe",
        type=str,
        help="Common Weakness Enumeration ID (e.g., CWE-79)",
    )

    parser.add_argument(
        "--max-results",
        type=int,
        help="Maximum number of results to return",
    )

    # Export options
    parser.add_argument(
        "--export",
        nargs="+",
        choices=["json", "csv", "md", "html"],
        help="Export format(s)",
    )

    parser.add_argument(
        "--output",
        type=str,
        help="Output filename (without extension)",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="Output directory for exports",
    )

    # Display options
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of vulnerabilities to display (default: 10)",
    )

    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Don't print summary statistics",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"NVD Scanner v{VERSION}",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point"""
    args = parse_arguments()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        # Initialize engine
        config = NVDConfig.from_env()
        engine = NVDVulnerabilityEngine(config)

        # Parse dates
        if args.days:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=args.days)
        else:
            start_date = datetime.strptime(args.start, "%Y-%m-%d")
            if args.end:
                end_date = datetime.strptime(args.end, "%Y-%m-%d")
            else:
                end_date = datetime.now()

        # Query vulnerabilities
        vulnerabilities = engine.query_vulnerabilities(
            start_date=start_date,
            end_date=end_date,
            severities=args.severity,
            keyword=args.keyword,
            cwe_id=args.cwe,
            max_results=args.max_results,
        )

        # Print summary
        if not args.no_summary:
            engine.print_summary(vulnerabilities)

        # Display vulnerabilities
        if vulnerabilities:
            print(f"\nShowing top {min(args.limit, len(vulnerabilities))} vulnerabilities:")
            print("-" * 80)
            for vuln in vulnerabilities[: args.limit]:
                formatted = engine.format_vulnerability(vuln)
                print(f"\n{formatted.cve_id}")
                print(
                    f"Severity: {formatted.severity} "
                    f"(CVSS: {formatted.cvss_score})"
                )
                print(f"Published: {formatted.published}")
                print(f"Description: {formatted.description[:200]}...")

        # Export if requested
        if args.export and vulnerabilities:
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            for fmt in args.export:
                if args.output:
                    filename = str(output_dir / f"{args.output}.{fmt}")
                else:
                    filename = None

                if fmt == "json":
                    engine.export_to_json(vulnerabilities, filename)
                elif fmt == "csv":
                    engine.export_to_csv(vulnerabilities, filename)
                elif fmt == "md":
                    engine.export_to_markdown(vulnerabilities, filename)
                elif fmt == "html":
                    engine.export_to_html(vulnerabilities, filename)

        return 0

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return 1
    except NVDAPIError as e:
        logging.error(f"API Error: {e}")
        return 1
    except KeyboardInterrupt:
        logging.info("\nOperation cancelled by user")
        return 130
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())
