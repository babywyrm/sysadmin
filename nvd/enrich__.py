#!/usr/bin/env python3
"""
NVD Vulnerability Scanner v2.2.2
Query CVE data and scan Docker images, enriching Trivy results with NVD data.. (beta)..
"""
import requests
import json
import csv
import sys
import argparse
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict, field
from pathlib import Path
from time import sleep
import os
from dotenv import load_dotenv
import re

load_dotenv()

VERSION = "2.2.2"
SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class NVDConfig:
    api_key: Optional[str] = os.getenv("NVD_API_KEY")
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page: int = 2000
    rate_limit_delay: float = 0.6
    timeout: int = 30
    max_retries: int = 3


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published: str
    last_modified: str
    references: List[str]
    cwe_ids: List[str]
    affected_packages: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NVDAPIError(Exception):
    pass


class DockerImageScanner:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def scan_with_trivy(self, image_name: str, tag: str) -> Dict[str, List[Dict]]:
        import subprocess

        self.logger.info(f"Scanning {image_name}:{tag} with Trivy for all vulnerabilities...")
        command = [
            "trivy", "image", "--format", "json", "--quiet", f"{image_name}:{tag}"
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                raise RuntimeError(f"Trivy scan failed: {result.stderr}")
            trivy_data = json.loads(result.stdout)
            vulns_map: Dict[str, List[Dict]] = {}
            for res in trivy_data.get("Results", []):
                for vuln in res.get("Vulnerabilities", []):
                    cve_id = vuln.get("VulnerabilityID")
                    if not cve_id or not cve_id.startswith("CVE-"):
                        continue
                    pkg_info = {
                        "package": vuln.get("PkgName"),
                        "version": vuln.get("InstalledVersion"),
                        "fix": vuln.get("FixedVersion", "N/A"),
                    }
                    if cve_id not in vulns_map:
                        vulns_map[cve_id] = []
                    vulns_map[cve_id].append(pkg_info)
            self.logger.info(
                f"Trivy found {len(vulns_map)} unique potential CVEs to check against NVD."
            )
            return vulns_map
        except FileNotFoundError:
            self.logger.error("Trivy not found. Please install Trivy to use this feature.")
            return {}
        except Exception as e:
            self.logger.error(f"Trivy scan error: {e}")
            return {}


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
            self.logger.info("✓ API Key active (50 req/30s)")
        else:
            self.logger.warning("⚠ No API Key (5 req/30s)")
            self.config.rate_limit_delay = 6.0

    def scan_docker_image_with_trivy(
        self, image_name: str, tag: str, min_severity: Optional[str]
    ) -> List[Vulnerability]:
        scanner = DockerImageScanner(self.logger)
        trivy_vulns_map = scanner.scan_with_trivy(image_name, tag)
        unique_cve_ids = list(trivy_vulns_map.keys())
        if not unique_cve_ids:
            return []

        self.logger.info(f"Enriching {len(unique_cve_ids)} CVEs with NVD data...")
        nvd_results = self.query_by_cve_ids(unique_cve_ids)
        enriched_vulns = []
        for nvd_vuln in nvd_results:
            formatted_vuln = self.format_vulnerability(nvd_vuln)
            formatted_vuln.affected_packages = trivy_vulns_map.get(
                formatted_vuln.cve_id, []
            )
            enriched_vulns.append(formatted_vuln)

        if min_severity:
            min_level = SEVERITY_LEVELS.get(min_severity.upper(), 0)
            self.logger.info(
                f"Filtering results for NVD severity of {min_severity} and higher."
            )
            final_vulns = [
                v for v in enriched_vulns if SEVERITY_LEVELS.get(v.severity, 0) >= min_level
            ]
        else:
            final_vulns = enriched_vulns

        final_vulns.sort(
            key=lambda v: (SEVERITY_LEVELS.get(v.severity, 0), v.cvss_score),
            reverse=True,
        )
        return final_vulns

    def query_by_cve_ids(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        """
        THE FIX IS HERE: Query NVD for each CVE ID one by one,
        which is the correct method for the API.
        """
        all_vulns = []
        for cve_id in cve_ids:
            params = {"cveId": cve_id}
            try:
                # Add a small delay between each request to respect rate limits
                sleep(self.config.rate_limit_delay)
                data = self._api_request(params)
                all_vulns.extend(data.get("vulnerabilities", []))
            except NVDAPIError as e:
                # A 404 for a single CVE is not a fatal error, it might be a new CVE
                # not yet in the main database, or a false positive from Trivy.
                self.logger.warning(f"Could not fetch data for {cve_id}: {e}")
        return all_vulns

    def _api_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        for attempt in range(self.config.max_retries):
            try:
                resp = self.session.get(
                    self.config.base_url, params=params, timeout=self.config.timeout
                )
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.RequestException as e:
                # We handle the 404 specifically in the calling function now
                if isinstance(e, requests.HTTPError) and e.response.status_code == 404:
                    raise NVDAPIError(f"CVE not found ({e.response.status_code})")

                self.logger.error(f"API request failed: {e}")
                if attempt < self.config.max_retries - 1:
                    sleep(2)
        raise NVDAPIError(f"Failed after {self.config.max_retries} retries")

    def format_vulnerability(self, vuln: Dict[str, Any]) -> Vulnerability:
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_score, severity, vector = 0.0, "N/A", "N/A"
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                data = metrics[version][0].get("cvssData", {})
                cvss_score = float(data.get("baseScore", 0.0))
                if version == "cvssMetricV2":
                    severity = "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
                else:
                    severity = data.get("baseSeverity", "N/A")
                vector = data.get("vectorString", "N/A")
                break
        return Vulnerability(
            cve_id=cve.get("id", "N/A"),
            description=next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description"),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=vector,
            published=cve.get("published", "N/A"),
            last_modified=cve.get("lastModified", "N/A"),
            references=[r.get("url", "") for r in cve.get("references", [])[:5]],
            cwe_ids=[d.get("value", "") for w in cve.get("weaknesses", []) for d in w.get("description", []) if d.get("lang") == "en"],
        )

    def print_summary(self, vulns: List[Vulnerability]) -> None:
        if not vulns:
            self.logger.info("No vulnerabilities found meeting the criteria.")
            return
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        scores = [v.cvss_score for v in vulns if v.cvss_score > 0]
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        avg = sum(scores) / len(scores) if scores else 0.0
        print("\n" + "=" * 80)
        print("VULNERABILITY SUMMARY")
        print("=" * 80)
        print(f"Total Unique Vulnerabilities Found: {len(vulns)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts.get(sev, 0) > 0:
                print(f"  {sev}: {counts[sev]}")
        print(f"\nAverage CVSS Score: {avg:.2f}")
        print("=" * 80)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NVD Vulnerability Scanner - Scan Docker images and enrich with NVD.", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--docker", type=str, required=True, help="Docker image to scan (e.g., nginx, nginx:1.21)")
    parser.add_argument("--trivy", action="store_true", help="Use Trivy for scanning (currently required for docker mode)")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Minimum NVD severity to report")
    parser.add_argument("--limit", type=int, default=10, help="Display limit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"v{VERSION}")
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger()
    try:
        if not args.trivy:
            logger.error("--trivy flag is required for Docker scanning in this version.")
            return 1
        config = NVDConfig()
        engine = NVDVulnerabilityEngine(config, logger)
        image_parts = args.docker.split(":")
        image_name = image_parts[0]
        tag = image_parts[1] if len(image_parts) > 1 else "latest"
        print(f"\n{'=' * 80}\nSCANNING DOCKER IMAGE: {image_name}:{tag}\n{'=' * 80}\n")
        vulns = engine.scan_docker_image_with_trivy(image_name, tag, args.min_severity)
        engine.print_summary(vulns)
        if vulns:
            print(f"\nDisplaying top {min(args.limit, len(vulns))} vulnerabilities:")
            print("-" * 80)
            for v in vulns[: args.limit]:
                print(f"\n{v.cve_id} | {v.severity} (CVSS: {v.cvss_score})")
                print(f"Description: {v.description[:150]}...")
                for pkg in v.affected_packages:
                    print(f"  - Package: {pkg['package']}@{pkg['version']} (Fix: {pkg['fix']})")
        return 0
    except (ValueError, NVDAPIError) as e:
        logger.error(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("\nCancelled by user.")
        return 130
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=args.verbose)
        return 1

if __name__ == "__main__":
    sys.exit(main())
