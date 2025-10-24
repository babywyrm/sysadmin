import requests
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from dataclasses import dataclass
from time import sleep
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


@dataclass
class NVDConfig:
    """Configuration for NVD API"""

    api_key: Optional[str] = os.getenv("NVD_API_KEY")
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page: int = 2000  # Max allowed by NVD
    rate_limit_delay: float = 0.6  # 0.6s with API key (50 req/30s)


class NVDVulnerabilityEngine:
    """Engine to query NVD database for vulnerabilities"""

    def __init__(self, config: NVDConfig = None):
        self.config = config or NVDConfig()
        self.session = requests.Session()
        if self.config.api_key:
            self.session.headers.update({"apiKey": self.config.api_key})
            print("✓ API Key loaded successfully")
        else:
            print(
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
    ) -> List[Dict]:
        """
        Query NVD for vulnerabilities within date range and severity filters

        Args:
            start_date: Start of date range
            end_date: End of date range
            severities: List of severity levels (LOW, MEDIUM, HIGH, CRITICAL)
            keyword: Optional keyword to filter CVEs

        Returns:
            List of vulnerability dictionaries
        """
        all_vulnerabilities = []
        start_index = 0

        # Format dates for API
        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        print(f"\nQuerying NVD from {pub_start} to {pub_end}...")
        if severities:
            print(f"Severity filter: {', '.join(severities)}")
        if keyword:
            print(f"Keyword filter: {keyword}")

        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": self.config.results_per_page,
                "startIndex": start_index,
            }

            if keyword:
                params["keywordSearch"] = keyword

            try:
                response = self.session.get(
                    self.config.base_url, params=params, timeout=30
                )
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                # Filter by severity if specified
                filtered = self._filter_by_severity(
                    vulnerabilities, severities
                )
                all_vulnerabilities.extend(filtered)

                total_results = data.get("totalResults", 0)
                print(
                    f"Retrieved {len(all_vulnerabilities)} of "
                    f"{total_results} total vulnerabilities..."
                )

                # Check if we've retrieved all results
                if start_index + len(vulnerabilities) >= total_results:
                    break

                start_index += self.config.results_per_page
                sleep(self.config.rate_limit_delay)

            except requests.exceptions.RequestException as e:
                print(f"Error querying NVD: {e}")
                break

        return all_vulnerabilities

    def _filter_by_severity(
        self, vulnerabilities: List[Dict], severities: Optional[List[str]]
    ) -> List[Dict]:
        """Filter vulnerabilities by CVSS severity"""
        if not severities:
            return vulnerabilities

        filtered = []
        severities_upper = [s.upper() for s in severities]

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})

            # Check CVSS v3.x first
            severity = None
            if "cvssMetricV31" in metrics:
                severity = (
                    metrics["cvssMetricV31"][0]
                    .get("cvssData", {})
                    .get("baseSeverity")
                )
            elif "cvssMetricV30" in metrics:
                severity = (
                    metrics["cvssMetricV30"][0]
                    .get("cvssData", {})
                    .get("baseSeverity")
                )
            elif "cvssMetricV2" in metrics:
                # Map V2 severity
                base_score = (
                    metrics["cvssMetricV2"][0]
                    .get("cvssData", {})
                    .get("baseScore", 0)
                )
                severity = self._map_v2_severity(base_score)

            if severity and severity.upper() in severities_upper:
                filtered.append(vuln)

        return filtered

    @staticmethod
    def _map_v2_severity(score: float) -> str:
        """Map CVSS v2 score to severity level"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def format_vulnerability(self, vuln: Dict) -> Dict:
        """Format vulnerability data for display"""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # Extract description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available",
        )

        # Extract CVSS score and severity
        metrics = cve.get("metrics", {})
        cvss_score = "N/A"
        severity = "N/A"
        vector = "N/A"

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", "N/A")
            severity = cvss_data.get("baseSeverity", "N/A")
            vector = cvss_data.get("vectorString", "N/A")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", "N/A")
            severity = cvss_data.get("baseSeverity", "N/A")
            vector = cvss_data.get("vectorString", "N/A")
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", "N/A")
            severity = self._map_v2_severity(cvss_score)
            vector = cvss_data.get("vectorString", "N/A")

        # Published date
        published = cve.get("published", "N/A")

        # Extract references
        references = cve.get("references", [])
        ref_urls = [ref.get("url") for ref in references[:3]]

        return {
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": vector,
            "published": published,
            "references": ref_urls,
        }

    def export_to_json(
        self, vulnerabilities: List[Dict], filename: str = None
    ):
        """Export vulnerabilities to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{timestamp}.json"

        formatted = [
            self.format_vulnerability(v) for v in vulnerabilities
        ]

        with open(filename, "w") as f:
            json.dump(formatted, f, indent=2)

        print(f"\n✓ Exported {len(formatted)} vulnerabilities to {filename}")
        return filename

    def export_to_csv(
        self, vulnerabilities: List[Dict], filename: str = None
    ):
        """Export vulnerabilities to CSV file"""
        import csv

        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{timestamp}.csv"

        formatted = [
            self.format_vulnerability(v) for v in vulnerabilities
        ]

        if not formatted:
            print("No vulnerabilities to export")
            return

        with open(filename, "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "cve_id",
                "severity",
                "cvss_score",
                "published",
                "description",
                "cvss_vector",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for vuln in formatted:
                writer.writerow(
                    {
                        "cve_id": vuln["cve_id"],
                        "severity": vuln["severity"],
                        "cvss_score": vuln["cvss_score"],
                        "published": vuln["published"],
                        "description": vuln["description"][:500],
                        "cvss_vector": vuln["cvss_vector"],
                    }
                )

        print(f"\n✓ Exported {len(formatted)} vulnerabilities to {filename}")
        return filename

    def print_summary(self, vulnerabilities: List[Dict]):
        """Print summary statistics of vulnerabilities"""
        if not vulnerabilities:
            print("\nNo vulnerabilities found.")
            return

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for vuln in vulnerabilities:
            formatted = self.format_vulnerability(vuln)
            severity = formatted["severity"]
            if severity in severity_counts:
                severity_counts[severity] += 1

        print("\n" + "=" * 80)
        print("VULNERABILITY SUMMARY")
        print("=" * 80)
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        print(f"  CRITICAL: {severity_counts['CRITICAL']}")
        print(f"  HIGH:     {severity_counts['HIGH']}")
        print(f"  MEDIUM:   {severity_counts['MEDIUM']}")
        print(f"  LOW:      {severity_counts['LOW']}")
        print("=" * 80)


# Example usage
if __name__ == "__main__":
    print("=" * 80)
    print("NVD VULNERABILITY SCANNER")
    print("=" * 80)

    # Initialize engine
    engine = NVDVulnerabilityEngine()

    # Example 1: Last 7 days - HIGH and CRITICAL
    print("\n[EXAMPLE 1] Last 7 days - HIGH/CRITICAL vulnerabilities")
    print("-" * 80)

    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)

    vulns = engine.query_vulnerabilities(
        start_date=start_date,
        end_date=end_date,
        severities=["HIGH", "CRITICAL"],
    )

    engine.print_summary(vulns)

    # Display first 5 vulnerabilities
    print("\nTop 5 vulnerabilities:")
    print("-" * 80)
    for vuln in vulns[:5]:
        formatted = engine.format_vulnerability(vuln)
        print(f"\nCVE: {formatted['cve_id']}")
        print(
            f"Severity: {formatted['severity']} "
            f"(Score: {formatted['cvss_score']})"
        )
        print(f"Published: {formatted['published']}")
        print(f"Description: {formatted['description'][:200]}...")

    # Export results
    engine.export_to_json(vulns)
    engine.export_to_csv(vulns)

    # Example 2: Last 30 days - CRITICAL only with keyword
    print("\n\n[EXAMPLE 2] Last 30 days - CRITICAL with keyword 'remote'")
    print("-" * 80)

    start_date = datetime.now() - timedelta(days=30)
    end_date = datetime.now()

    critical_vulns = engine.query_vulnerabilities(
        start_date=start_date,
        end_date=end_date,
        severities=["CRITICAL"],
        keyword="remote",
    )

    engine.print_summary(critical_vulns)

    print("\n" + "=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)
