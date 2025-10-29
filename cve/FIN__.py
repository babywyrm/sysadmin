#!/usr/bin/env python3
"""
FIN — Advanced Vulnerability Scanner with Intelligence Consolidation and Validation.. (beta)..

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
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityResult:
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
        content = f"{self.title.lower()}{(self.description or '')[:200].lower()}"
        return hashlib.md5(content.encode()).hexdigest()


@dataclass
class ConsolidatedVulnerability:
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


# ---------------------------------------------------------------------------
# Intelligence Engine
# ---------------------------------------------------------------------------

class VulnerabilityIntelligence:
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
        confidence = 1.0
        tech_lower = target_tech.lower()
        title_lower = vuln.title.lower()
        desc_lower = (vuln.description or "").lower()

        if tech_lower in title_lower:
            confidence += 0.3
        elif any(word in title_lower for word in tech_lower.split()):
            confidence += 0.1
        if tech_lower in desc_lower:
            confidence += 0.2
        elif any(word in desc_lower for word in tech_lower.split()):
            confidence += 0.05
        if "vulnerability" in title_lower and "security" in title_lower:
            confidence -= 0.2
        if re.search(r"CVE-\d{4}-\d+", vuln.title):
            confidence += 0.2
        return max(min(confidence, 2.0), 0.1)

    def detect_exploits(self, vuln: VulnerabilityResult) -> bool:
        text = f"{vuln.title} {vuln.description or ''}".lower()
        return any(x in text for x in ["exploit", "poc", "proof of concept", "metasploit", "nuclei", "payload", "shell"])

    def detect_active_exploitation(self, vuln: VulnerabilityResult) -> bool:
        text = f"{vuln.title} {vuln.description or ''}".lower()
        return any(x in text for x in ["in the wild", "actively exploited", "zero-day", "0day", "ransomware", "apt", "threat actor", "malware"])

    def calculate_risk_score(self, vuln: ConsolidatedVulnerability) -> float:
        base = vuln.max_score or 5.0
        mult = {"CRITICAL": 1.5, "HIGH": 1.3, "MEDIUM": 1.0, "LOW": 0.7}
        score = base * mult.get((vuln.severity or "MEDIUM").upper(), 1.0)
        if vuln.actively_exploited:
            score *= 1.8
        if vuln.exploit_available:
            score *= 1.4
        if not vuln.patch_available:
            score *= 1.2
        if vuln.related_cves:
            score *= 1.1
        return round(min(score * max(vuln.confidence, 0.1), 10.0), 2)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class AdvancedVulnerabilityScanner:
    NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"
    MAX_RETRIES = 3
    RETRY_BACKOFF = 1.0

    def __init__(self, github_token: Optional[str] = None, nvd_api_key: Optional[str] = None) -> None:
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self.intelligence = VulnerabilityIntelligence()
        self.session: Optional[aiohttp.ClientSession] = None
        self.trace_dir: Optional[Path] = None

    async def __aenter__(self) -> AdvancedVulnerabilityScanner:
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=10)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.session:
            await self.session.close()

    # -----------------------------------------------------------------------
    # HTTP helper with retries and trace saving
    # -----------------------------------------------------------------------
    async def _http_get_with_retries(
        self, url: str, headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None, payload: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        if not self.session:
            return None
        headers = headers or {}

        for attempt in range(self.MAX_RETRIES):
            try:
                method = "POST" if payload else "GET"
                logger.debug("Attempt %d %s %s params=%s payload=%s",
                             attempt + 1, method, url, params, payload)
                if payload:
                    async with self.session.post(url, headers=headers, json=payload) as resp:
                        logger.debug("HTTP status: %s", resp.status)
                        if resp.status == 200:
                            data = await resp.json()
                            if self.trace_dir:
                                fname = f"{Path(url).stem}_{int(time.time())}.json"
                                (self.trace_dir / fname).write_text(json.dumps(data, indent=2))
                            return data
                else:
                    async with self.session.get(url, headers=headers, params=params) as resp:
                        logger.debug("HTTP status: %s", resp.status)
                        if resp.status == 200:
                            data = await resp.json()
                            if self.trace_dir:
                                fname = f"{Path(url).stem}_{int(time.time())}.json"
                                (self.trace_dir / fname).write_text(json.dumps(data, indent=2))
                            return data
                if 400 <= resp.status < 500:
                    logger.warning("Client error %s from %s", resp.status, url)
                    return None
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug("Attempt %d failed: %s", attempt + 1, e)
            await asyncio.sleep(self.RETRY_BACKOFF * (attempt + 1))
        logger.warning("All retries failed for %s", url)
        return None

    # -----------------------------------------------------------------------
    # NVD Query
    # -----------------------------------------------------------------------
    async def query_nvd(self, keyword: str) -> List[VulnerabilityResult]:
        params = {"keywordSearch": keyword, "resultsPerPage": "20"}
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        data = await self._http_get_with_retries(self.NVD_ENDPOINT, headers=headers, params=params)
        if not data:
            return []
        results: List[VulnerabilityResult] = []
        for item in data.get("vulnerabilities", []):
            cve_info = item.get("cve") or {}
            cve_id = cve_info.get("id") or "N/A"
            descs = cve_info.get("descriptions") or []
            description = next((d.get("value") for d in descs if d.get("lang") in (None, "", "en")), "") or ""
            vuln = VulnerabilityResult(
                id=cve_id, title=cve_id, description=description,
                source="NVD", url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
            vuln.confidence = self.intelligence.analyze_relevance(vuln, keyword)
            results.append(vuln)
        return results

    # -----------------------------------------------------------------------
    # Vulners Query
    # -----------------------------------------------------------------------
    async def query_vulners(self, keyword: str) -> List[VulnerabilityResult]:
        """Query the Vulners API for matching vulnerabilities."""
        params = {"query": keyword, "size": 20}
        data = await self._http_get_with_retries(self.VULNERS_API_URL, params=params)
        if not data:
            return []

        results: List[VulnerabilityResult] = []
        try:
            hits = data.get("data", {}).get("search", [])
            for hit in hits:
                vuln_id = hit.get("id") or "N/A"
                title = hit.get("title") or vuln_id
                description = hit.get("description") or hit.get("snippet", "")
                vuln = VulnerabilityResult(
                    id=vuln_id,
                    title=title,
                    description=description,
                    source="Vulners",
                    url=f"https://vulners.com/{vuln_id}"
                )
                vuln.confidence = self.intelligence.analyze_relevance(vuln, keyword)
                vuln.exploit_available = self.intelligence.detect_exploits(vuln)
                vuln.actively_exploited = self.intelligence.detect_active_exploitation(vuln)
                results.append(vuln)
        except Exception as e:
            logger.warning("Failed to parse Vulners response: %s", e)
        return results

    # -----------------------------------------------------------------------
    # Consolidation + full scan
    # -----------------------------------------------------------------------
    def merge_vulnerability_group(self, vulns: List[VulnerabilityResult], primary_id: str) -> ConsolidatedVulnerability:
        best = max(vulns, key=lambda v: len(v.description or ""))
        ids = sorted({v.id for v in vulns})
        srcs = sorted({v.source for v in vulns})
        urls = [v.url for v in vulns if v.url]
        consolidated = ConsolidatedVulnerability(
            primary_cve=primary_id, all_ids=ids, title=best.title, description=best.description,
            sources=srcs, severity=None, max_score=None, earliest_published=None,
            affected_versions=[], urls=urls, exploit_available=False, actively_exploited=False,
            patch_available=False, related_cves=[], tags=[], risk_score=0, confidence=1.0
        )
        consolidated.risk_score = self.intelligence.calculate_risk_score(consolidated)
        return consolidated

    def consolidate_vulnerabilities(self, vulns: List[VulnerabilityResult]) -> List[ConsolidatedVulnerability]:
        grouped: Dict[str, List[VulnerabilityResult]] = {}
        for v in vulns:
            grouped.setdefault(v.id, []).append(v)
        merged = [self.merge_vulnerability_group(vs, k) for k, vs in grouped.items()]
        merged.sort(key=lambda x: x.risk_score, reverse=True)
        return merged

    async def comprehensive_scan(self, tech: str, ecosystem: Optional[str] = None) -> List[ConsolidatedVulnerability]:
        logger.info("Starting comprehensive scan for technology: %s", tech)

        nvd_results = await self.query_nvd(tech)
        logger.info("Retrieved %d NVD vulnerabilities", len(nvd_results))

        vulners_results = await self.query_vulners(tech)
        logger.info("Retrieved %d Vulners vulnerabilities", len(vulners_results))

        all_results = nvd_results + vulners_results
        consolidated = self.consolidate_vulnerabilities(all_results)
        logger.info("Consolidated into %d unique vulnerabilities", len(consolidated))
        return consolidated

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    def print_enhanced_results(self, results: List[ConsolidatedVulnerability], verbose: bool = False, limit: Optional[int] = None) -> None:
        if not results:
            print("\nNo vulnerabilities found.")
            return
        display = results[:limit] if limit else results
        print("\nCONSOLIDATED VULNERABILITY REPORT")
        print(f"Total unique vulnerabilities: {len(results)}")
        print("=" * 80)
        for i, r in enumerate(display, start=1):
            print(f"\n{i}. [{r.primary_cve}] {r.title}")
            print(f"   Risk Score: {r.risk_score}/10 | Severity: {r.severity or 'Unknown'}")
            if verbose and r.description:
                desc = (r.description[:400] + "...") if len(r.description) > 400 else r.description
                print(f"   Description: {desc}")
            if r.urls:
                print(f"   URL: {r.urls[0]}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def main() -> None:
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner (FIN)")
    parser.add_argument("-t", "--tech", required=True, help="Technology to scan for vulnerabilities")
    parser.add_argument("-e", "--ecosystem", help="Ecosystem context (npm, PyPI, Go, etc.)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full descriptions")
    parser.add_argument("--limit", type=int, help="Limit number of results displayed")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug logging and trace saving")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        Path(".vuln_trace").mkdir(exist_ok=True)
        logger.debug("Trace directory created at %s", Path(".vuln_trace").resolve())

    async with AdvancedVulnerabilityScanner() as scanner:
        if args.debug:
            scanner.trace_dir = Path(".vuln_trace")
        try:
            results = await scanner.comprehensive_scan(args.tech, args.ecosystem)
            scanner.print_enhanced_results(results, verbose=args.verbose, limit=args.limit)
        except Exception as e:
            logger.exception("Scan failed: %s", e)
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
