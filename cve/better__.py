#!/usr/bin/env python3
"""
Advanced vulnerability scanner with intelligence consolidation and validation ..beta..

"""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityResult:
    """Enhanced vulnerability result with intelligence data."""
    id: str
    title: str
    description: str
    source: str
    url: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    published: Optional[str] = None
    affected_versions: Optional[List[str]] = None
    exploit_available: bool = False
    actively_exploited: bool = False
    patch_available: bool = False
    related_cves: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    confidence: float = 1.0

    def get_hash(self) -> str:
        """Generate a stable hash for deduplication."""
        content = f"{self.title.lower()}{(self.description or '')[:200].lower()}"
        return hashlib.md5(content.encode()).hexdigest()


@dataclass
class ConsolidatedVulnerability:
    """Consolidated vulnerability from multiple sources."""
    primary_cve: str
    all_ids: List[str]
    title: str
    description: str
    sources: List[str]
    severity: Optional[str]
    max_score: Optional[float]
    earliest_published: Optional[str]
    affected_versions: List[str]
    urls: List[str]
    exploit_available: bool
    actively_exploited: bool
    patch_available: bool
    related_cves: List[str]
    tags: List[str]
    risk_score: float
    confidence: float


class VulnerabilityIntelligence:
    """Intelligence engine for vulnerability analysis."""

    def __init__(self, cache_dir: str = ".vuln_cache") -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.exploit_signatures = [
            "remote code execution", "rce", "arbitrary code", "buffer overflow",
            "stack overflow", "heap overflow", "sql injection", "sqli",
            "command injection", "privilege escalation", "priv esc",
            "authentication bypass", "auth bypass", "unauthenticated",
            "directory traversal", "path traversal", "file inclusion",
            "cross-site scripting", "xss", "csrf"
        ]

    def analyze_relevance(self, vuln: VulnerabilityResult, target_tech: str) -> float:
        """Analyze vulnerability relevance to a target technology."""
        confidence = 1.0
        tech_lower = (target_tech or "").lower()
        title_lower = (vuln.title or "").lower()
        desc_lower = (vuln.description or "").lower()

        if not tech_lower:
            return max(min(confidence, 2.0), 0.1)

        # Exact name match boosts confidence
        if tech_lower in title_lower:
            confidence += 0.3
        elif any(word in title_lower for word in tech_lower.split()):
            confidence += 0.1

        if tech_lower in desc_lower:
            confidence += 0.2
        elif any(word in desc_lower for word in tech_lower.split()):
            confidence += 0.05

        # Penalize overly generic titles
        if "vulnerability" in title_lower and "security" in title_lower:
            confidence -= 0.2

        # Boost when CVE is explicitly mentioned
        if re.search(r"CVE-\d{4}-\d+", vuln.title or ""):
            confidence += 0.2

        return max(min(confidence, 2.0), 0.1)

    def detect_exploits(self, vuln: VulnerabilityResult) -> bool:
        """Detect whether an exploit/PoC likely exists."""
        text = f"{vuln.title or ''} {vuln.description or ''}".lower()
        exploit_indicators = ["exploit", "poc", "proof of concept", "metasploit", "nuclei", "payload", "shell"]
        return any(ind in text for ind in exploit_indicators)

    def detect_active_exploitation(self, vuln: VulnerabilityResult) -> bool:
        """Detect signs of active exploitation from description/title."""
        text = f"{vuln.title or ''} {vuln.description or ''}".lower()
        active_indicators = ["in the wild", "actively exploited", "zero-day", "0day", "ransomware", "apt", "threat actor", "malware"]
        return any(ind in text for ind in active_indicators)

    def calculate_risk_score(self, vuln: ConsolidatedVulnerability) -> float:
        """Calculate a bounded risk score from 0-10."""
        base_score = vuln.max_score or 5.0
        severity_multipliers = {"CRITICAL": 1.5, "HIGH": 1.3, "MEDIUM": 1.0, "LOW": 0.7}
        risk_score = base_score * severity_multipliers.get((vuln.severity or "MEDIUM").upper(), 1.0)

        if vuln.actively_exploited:
            risk_score *= 1.8
        if vuln.exploit_available:
            risk_score *= 1.4
        if not vuln.patch_available:
            risk_score *= 1.2
        if vuln.related_cves:
            risk_score *= 1.1

        adjusted = min(risk_score * max(vuln.confidence, 0.1), 10.0)
        return round(adjusted, 2)


class AdvancedVulnerabilityScanner:
    """Advanced vulnerability scanner with intelligence consolidation."""

    NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_RETRIES = 3
    RETRY_BACKOFF = 1.0  # seconds

    def __init__(self, github_token: Optional[str] = None, nvd_api_key: Optional[str] = None) -> None:
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self.intelligence = VulnerabilityIntelligence()
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "AdvancedVulnerabilityScanner":
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=10)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.session:
            await self.session.close()

    def generate_search_terms(self, tech: str) -> List[str]:
        """Generate comprehensive search terms for queries."""
        terms = {tech.strip()}
        if " " in tech:
            terms.update({tech.replace(" ", "-"), tech.replace(" ", "_"), tech.replace(" ", "")})
        context_suffixes = ["plugin", "extension", "module", "library", "framework", "vulnerability", "exploit", "CVE"]
        terms.update({f"{tech} {s}" for s in context_suffixes})
        return [t for t in sorted(terms) if t]

    def extract_severity_info(self, vuln_data: Dict) -> Tuple[Optional[str], Optional[float]]:
        """Extract severity and score from NVD CVE structure, defensively."""
        metrics = vuln_data.get("metrics", {}) or {}

        # try v3.1 -> v3.0 -> v2
        for key in ("cvssMetricV31", "cvssMetricV30"):
            arr = metrics.get(key)
            if arr and isinstance(arr, list) and arr:
                cvss = arr[0].get("cvssData") or {}
                severity = cvss.get("baseSeverity") or cvss.get("severity")
                score = cvss.get("baseScore") or cvss.get("score")
                try:
                    if score is not None:
                        score = float(score)
                except Exception:
                    score = None
                return (severity.upper() if isinstance(severity, str) else severity, score)

        # fallback to v2
        arr_v2 = metrics.get("cvssMetricV2")
        if arr_v2 and isinstance(arr_v2, list) and arr_v2:
            cvss = arr_v2[0].get("cvssData") or {}
            score = cvss.get("baseScore")
            try:
                score = float(score) if score is not None else None
            except Exception:
                score = None
            severity = None
            if score is not None:
                severity = "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
            return severity, score

        return None, None

    async def _http_get_with_retries(self, url: str, headers: Dict = None, params: Dict = None) -> Optional[Dict]:
        """Perform GET with simple retry/backoff and JSON decode."""
        if not self.session:
            return None
        headers = headers or {}
        retries = 0
        while retries < self.MAX_RETRIES:
            try:
                async with self.session.get(url, headers=headers, params=params) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif 400 <= resp.status < 500:
                        # client errors are unlikely to be fixed by retrying
                        logger.warning("NVD request returned HTTP %s", resp.status)
                        return None
                    else:
                        logger.debug("NVD returned %s, retrying", resp.status)
            except asyncio.TimeoutError:
                logger.debug("Timeout when requesting NVD (attempt %s)", retries + 1)
            except aiohttp.ClientError as exc:
                logger.debug("HTTP error when querying NVD: %s", exc)
            retries += 1
            await asyncio.sleep(self.RETRY_BACKOFF * retries)
        logger.warning("NVD request failed after %s attempts", self.MAX_RETRIES)
        return None

    async def query_nvd_single(self, keyword: str) -> List[VulnerabilityResult]:
        """Query NVD API for a single keyword (safe, no exploit code)."""
        if not self.session:
            return []

        params = {"keywordSearch": keyword, "resultsPerPage": "20"}
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}

        try:
            data = await self._http_get_with_retries(self.NVD_ENDPOINT, headers=headers, params=params)
            if not data:
                return []

            results: List[VulnerabilityResult] = []
            for item in data.get("vulnerabilities", []):
                cve_info = item.get("cve", {}) or {}
                cve_id = cve_info.get("id") or "N/A"

                descriptions = cve_info.get("descriptions") or []
                description = ""
                if descriptions:
                    # prefer english
                    for d in descriptions:
                        if d.get("lang") in (None, "", "en") and d.get("value"):
                            description = d.get("value")
                            break
                    if not description:
                        description = descriptions[0].get("value", "")

                severity, score = self.extract_severity_info(cve_info)

                published = cve_info.get("published")
                if published:
                    try:
                        published = datetime.fromisoformat(published.replace("Z", "+00:00")).strftime("%Y-%m-%d")
                    except Exception:
                        # leave raw if parse fails
                        pass

                vuln = VulnerabilityResult(
                    id=cve_id,
                    title=cve_id,
                    description=description,
                    source="NVD",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    severity=severity,
                    score=score,
                    published=published
                )

                # Intelligence
                vuln.confidence = self.intelligence.analyze_relevance(vuln, keyword)
                vuln.exploit_available = self.intelligence.detect_exploits(vuln)
                vuln.actively_exploited = self.intelligence.detect_active_exploitation(vuln)

                # Keep only reasonably relevant results
                if vuln.confidence > 0.3:
                    results.append(vuln)

            # sort by confidence, then score
            results.sort(key=lambda r: ((r.confidence or 0.0), (r.score or 0.0)), reverse=True)
            return results

        except Exception as e:
            logger.warning("NVD query failed for keyword '%s': %s", keyword, e)
            return []

    async def query_multiple_nvd_terms(self, terms: List[str]) -> List[VulnerabilityResult]:
        """Query NVD with multiple search terms, with lightweight rate control."""
        all_results: List[VulnerabilityResult] = []
        seen_ids = set()

        # Limit number of terms to avoid aggressive request patterns
        for term in terms[:5]:
            await asyncio.sleep(0.5)
            try:
                results = await self.query_nvd_single(term)
            except Exception as exc:
                logger.debug("Error querying term '%s': %s", term, exc)
                results = []

            for res in results:
                if res.id not in seen_ids:
                    seen_ids.add(res.id)
                    all_results.append(res)

        return all_results

    def merge_vulnerability_group(self, vulns: List[VulnerabilityResult], primary_id: str) -> ConsolidatedVulnerability:
        """Merge a group of related vulnerabilities into a consolidated record."""
        best_vuln = max(vulns, key=lambda v: len(v.description or ""))

        all_ids = sorted({v.id for v in vulns})
        sources = sorted({v.source for v in vulns})
        urls = [v.url for v in vulns if v.url]

        scores = [v.score for v in vulns if v.score is not None]
        max_score = max(scores) if scores else None

        severities = [ (v.severity or "").upper() for v in vulns if v.severity ]
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        best_severity = next((s for s in severity_order if s in severities), None)

        dates = [v.published for v in vulns if v.published]
        earliest_date = min(dates) if dates else None

        versions = []
        for v in vulns:
            if v.affected_versions:
                versions.extend(v.affected_versions)

        consolidated = ConsolidatedVulnerability(
            primary_cve=primary_id,
            all_ids=all_ids,
            title=best_vuln.title,
            description=best_vuln.description,
            sources=sources,
            severity=best_severity,
            max_score=max_score,
            earliest_published=earliest_date,
            affected_versions=sorted(set(versions)),
            urls=urls,
            exploit_available=any(v.exploit_available for v in vulns),
            actively_exploited=any(v.actively_exploited for v in vulns),
            patch_available=any(v.patch_available for v in vulns),
            related_cves=[],
            tags=[],
            risk_score=0.0,
            confidence=(sum(v.confidence for v in vulns) / len(vulns)) if vulns else 1.0
        )
        return consolidated

    def consolidate_vulnerabilities(self, all_vulns: List[VulnerabilityResult]) -> List[ConsolidatedVulnerability]:
        """Consolidate duplicate vulnerabilities from multiple sources."""
        cve_groups: Dict[str, List[VulnerabilityResult]] = {}
        hash_groups: Dict[str, List[VulnerabilityResult]] = {}

        for vuln in all_vulns:
            if vuln.id and vuln.id.startswith("CVE-"):
                cve_groups.setdefault(vuln.id, []).append(vuln)
            else:
                hash_groups.setdefault(vuln.get_hash(), []).append(vuln)

        consolidated: List[ConsolidatedVulnerability] = []

        for cve_id, vulns in cve_groups.items():
            consolidated.append(self.merge_vulnerability_group(vulns, cve_id))

        for hash_key, vulns in hash_groups.items():
            if len(vulns) > 1:
                consolidated.append(self.merge_vulnerability_group(vulns, vulns[0].id))
            else:
                v = vulns[0]
                consolidated.append(ConsolidatedVulnerability(
                    primary_cve=v.id,
                    all_ids=[v.id],
                    title=v.title,
                    description=v.description,
                    sources=[v.source],
                    severity=v.severity,
                    max_score=v.score,
                    earliest_published=v.published,
                    affected_versions=v.affected_versions or [],
                    urls=[v.url] if v.url else [],
                    exploit_available=v.exploit_available,
                    actively_exploited=v.actively_exploited,
                    patch_available=v.patch_available,
                    related_cves=v.related_cves or [],
                    tags=v.tags or [],
                    risk_score=0.0,
                    confidence=v.confidence
                ))

        for vuln in consolidated:
            vuln.risk_score = self.intelligence.calculate_risk_score(vuln)

        consolidated.sort(key=lambda x: x.risk_score, reverse=True)
        return consolidated

    async def comprehensive_scan(self, tech: str, ecosystem: Optional[str] = None) -> List[ConsolidatedVulnerability]:
        """Perform comprehensive vulnerability scan with intelligence."""
        logger.info("Starting comprehensive scan for: %s", tech)
        search_terms = self.generate_search_terms(tech)
        logger.info("Generated %d search terms", len(search_terms))

        logger.info("Querying NVD with multiple terms...")
        all_vulns = await self.query_multiple_nvd_terms(search_terms)
        logger.info("Found %d raw vulnerability entries", len(all_vulns))

        consolidated = self.consolidate_vulnerabilities(all_vulns)
        logger.info("Consolidated to %d unique vulnerabilities", len(consolidated))
        return consolidated

    def export_results(self, results: List[ConsolidatedVulnerability], format_type: str = "json", filename: Optional[str] = None) -> str:
        """Export results to a file and return the filename used."""
        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"vuln_scan_{timestamp}.{format_type}"

        path = Path(filename)
        if format_type == "json":
            with path.open("w", encoding="utf-8") as fh:
                json.dump([asdict(r) for r in results], fh, indent=2, ensure_ascii=False)
        elif format_type == "csv":
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["CVE", "Title", "Severity", "Score", "Risk Score", "Published", "Sources", "Exploit Available", "URLs"])
                for r in results:
                    writer.writerow([
                        r.primary_cve,
                        r.title,
                        r.severity or "Unknown",
                        r.max_score or "N/A",
                        f"{r.risk_score:.2f}",
                        r.earliest_published or "Unknown",
                        "; ".join(r.sources),
                        "Yes" if r.exploit_available else "No",
                        "; ".join(r.urls)
                    ])
        logger.info("Results exported to %s", path.resolve())
        return str(path.resolve())

    def print_enhanced_results(self, results: List[ConsolidatedVulnerability], verbose: bool = False, limit: Optional[int] = None) -> None:
        """Print consolidated results in a human-friendly, emoji-free format."""
        if not results:
            print("\nNo vulnerabilities found.")
            return

        display = results[:limit] if limit else results

        print("\nCONSOLIDATED VULNERABILITY REPORT")
        print(f"Total unique vulnerabilities: {len(results)}")
        print(f"Critical/High: {sum(1 for r in results if (r.severity or '').upper() in ['CRITICAL','HIGH'])}")
        print(f"Exploits observed: {sum(1 for r in results if r.exploit_available)}")
        print(f"Actively exploited: {sum(1 for r in results if r.actively_exploited)}")
        print("=" * 88)

        for i, r in enumerate(display, start=1):
            level = "LOW"
            if r.risk_score >= 8:
                level = "CRITICAL"
            elif r.risk_score >= 6:
                level = "HIGH"
            elif r.risk_score >= 4:
                level = "MEDIUM"

            print(f"\n{i}. [{level}] {r.primary_cve} - {r.title}")
            print(f"   Risk Score: {r.risk_score:.2f}/10 | Severity: {r.severity or 'Unknown'}")
            if r.max_score is not None:
                print(f"   CVSS Score: {r.max_score}")
            if r.earliest_published:
                print(f"   Published: {r.earliest_published}")
            if r.sources:
                print(f"   Sources: {', '.join(r.sources)}")
            indicators = []
            if r.exploit_available:
                indicators.append("Exploit available")
            if r.actively_exploited:
                indicators.append("Actively exploited")
            if r.patch_available:
                indicators.append("Patch available")
            if indicators:
                print(f"   Indicators: {' | '.join(indicators)}")
            if verbose and r.description:
                desc = (r.description[:400] + "...") if len(r.description) > 400 else r.description
                print(f"   Description: {desc}")
            if r.urls:
                print(f"   Primary URL: {r.urls[0]}")

async def main() -> None:
    """Main entrypoint for the scanner CLI."""
    parser = argparse.ArgumentParser(
        description="Advanced Vulnerability Scanner with Intelligence Consolidation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t wordpress
  python3 scanner.py -t "apache httpd" -v --limit 10
  python3 scanner.py -t nginx --export csv --export-file nginx_vulns.csv
"""
    )

    parser.add_argument("-t", "--tech", required=True, help="Technology to scan for vulnerabilities")
    parser.add_argument("-e", "--ecosystem", help="Ecosystem context (npm, PyPI, Go, etc.)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full vulnerability descriptions")
    parser.add_argument("--limit", type=int, help="Limit number of results displayed")
    parser.add_argument("--export", choices=["json", "csv"], help="Export results to file")
    parser.add_argument("--export-file", help="Custom export filename")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub API token for higher limits")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"), help="NVD API key for better access")

    args = parser.parse_args()

    logger.info("Advanced Vulnerability Scanner v3.0 (emoji-free)")
    async with AdvancedVulnerabilityScanner(github_token=args.github_token, nvd_api_key=args.nvd_api_key) as scanner:
        try:
            results = await scanner.comprehensive_scan(args.tech, args.ecosystem)
            scanner.print_enhanced_results(results, verbose=args.verbose, limit=args.limit)

            if args.export:
                filename = args.export_file or None
                outpath = scanner.export_results(results, args.export, filename)
                logger.info("Exported results to: %s", outpath)

        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            sys.exit(1)
        except Exception as e:
            logger.exception("Scan failed: %s", e)
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
##
##
