#!/usr/bin/env python3
"""
Advanced vulnerability scanner with intelligence consolidation & validation.. (testing..)
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set
import logging
from datetime import datetime, timedelta
import hashlib
import re
from pathlib import Path
import csv

import aiohttp


# Configure logging..
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
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
    confidence: float = 1.0  # How confident we are this is relevant
    
    def get_hash(self) -> str:
        """Generate hash for deduplication."""
        content = f"{self.title.lower()}{self.description.lower()[:100]}"
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
    
    def __init__(self, cache_dir: str = ".vuln_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.known_exploits = set()
        self.load_exploit_signatures()
        
    def load_exploit_signatures(self):
        """Load known exploit signatures and IOCs."""
        exploit_patterns = [
            "remote code execution", "rce", "arbitrary code",
            "buffer overflow", "stack overflow", "heap overflow",
            "sql injection", "sqli", "command injection",
            "privilege escalation", "priv esc", "local privilege",
            "authentication bypass", "auth bypass", "unauthenticated",
            "directory traversal", "path traversal", "file inclusion",
            "cross-site scripting", "xss", "csrf", "cross-site request"
        ]
        self.exploit_signatures = exploit_patterns
        
    def analyze_relevance(self, vuln: VulnerabilityResult, target_tech: str) -> float:
        """Analyze how relevant a vulnerability is to the target technology."""
        confidence = 1.0
        
        # Check if tech name appears in title/description
        tech_lower = target_tech.lower()
        title_lower = vuln.title.lower()
        desc_lower = vuln.description.lower()
        
        if tech_lower in title_lower:
            confidence += 0.3
        elif any(word in title_lower for word in tech_lower.split()):
            confidence += 0.1
            
        if tech_lower in desc_lower:
            confidence += 0.2
        elif any(word in desc_lower for word in tech_lower.split()):
            confidence += 0.05
            
        # Penalize generic results
        generic_terms = ["vulnerability", "security", "issue", "bug", "flaw"]
        if all(term in title_lower for term in generic_terms[:2]):
            confidence -= 0.2
            
        # Boost for specific CVE mentions
        if re.search(r'CVE-\d{4}-\d+', vuln.title):
            confidence += 0.2
            
        return min(max(confidence, 0.1), 2.0)
    
    def detect_exploits(self, vuln: VulnerabilityResult) -> bool:
        """Detect if vulnerability likely has exploits available."""
        text = f"{vuln.title} {vuln.description}".lower()
        
        # Check for explicit exploit mentions
        exploit_indicators = [
            "exploit", "poc", "proof of concept", "metasploit",
            "nuclei", "payload", "shell", "reverse shell"
        ]
        
        return any(indicator in text for indicator in exploit_indicators)
    
    def detect_active_exploitation(self, vuln: VulnerabilityResult) -> bool:
        """Detect signs of active exploitation."""
        text = f"{vuln.title} {vuln.description}".lower()
        
        active_indicators = [
            "in the wild", "actively exploited", "zero-day", "0day",
            "ransomware", "apt", "threat actor", "malware"
        ]
        
        return any(indicator in text for indicator in active_indicators)
    
    def calculate_risk_score(self, vuln: ConsolidatedVulnerability) -> float:
        """Calculate comprehensive risk score."""
        base_score = vuln.max_score or 5.0
        
        # Severity multiplier
        severity_multipliers = {
            "CRITICAL": 1.5,
            "HIGH": 1.3,
            "MEDIUM": 1.0,
            "LOW": 0.7
        }
        
        multiplier = severity_multipliers.get(vuln.severity or "MEDIUM", 1.0)
        risk_score = base_score * multiplier
        
        # Additional risk factors
        if vuln.actively_exploited:
            risk_score *= 1.8
        if vuln.exploit_available:
            risk_score *= 1.4
        if not vuln.patch_available:
            risk_score *= 1.2
        if vuln.related_cves:
            risk_score *= 1.1
        
        # Confidence factor
        risk_score *= vuln.confidence
        
        return min(risk_score, 10.0)


class AdvancedVulnerabilityScanner:
    """Advanced vulnerability scanner with intelligence consolidation."""
    
    def __init__(self, github_token: Optional[str] = None, nvd_api_key: Optional[str] = None):
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self.intelligence = VulnerabilityIntelligence()
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=10)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def generate_search_terms(self, tech: str) -> List[str]:
        """Generate comprehensive search terms."""
        terms = [tech]
        
        # Add common variations
        if " " in tech:
            terms.extend([
                tech.replace(" ", "-"),
                tech.replace(" ", "_"),
                tech.replace(" ", "")
            ])
        
        # Add prefixes/suffixes
        terms.extend([
            f"{tech} plugin",
            f"{tech} extension",
            f"{tech} module",
            f"{tech} library",
            f"{tech} framework",
            f"{tech} vulnerability",
            f"{tech} exploit",
            f"{tech} CVE"
        ])
        
        return list(set(terms))  # Remove duplicates
    
    async def query_multiple_nvd_terms(self, terms: List[str]) -> List[VulnerabilityResult]:
        """Query NVD with multiple search terms."""
        all_results = []
        seen_cves = set()
        
        for term in terms[:5]:  # Limit to avoid rate limiting
            await asyncio.sleep(0.5)  # Rate limiting
            results = await self.query_nvd_single(term)
            
            for result in results:
                if result.id not in seen_cves:
                    seen_cves.add(result.id)
                    all_results.append(result)
                    
        return all_results
    
    async def query_nvd_single(self, keyword: str) -> List[VulnerabilityResult]:
        """Query NVD API for a single keyword."""
        params = {"keywordSearch": keyword, "resultsPerPage": "20"}
        headers = {}
        
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
            
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status != 200:
                    return []
                    
                data = await response.json()
                results = []
                
                for item in data.get("vulnerabilities", []):
                    cve_info = item.get("cve", {})
                    cve_id = cve_info.get("id", "N/A")
                    
                    # Get description
                    descriptions = cve_info.get("descriptions", [])
                    description = descriptions[0].get("value", "") if descriptions else ""
                    
                    # Extract severity and score
                    severity, score = self.extract_severity_info(cve_info)
                    
                    # Get published date
                    published = cve_info.get("published", "")
                    if published:
                        try:
                            published = datetime.fromisoformat(published.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                        except:
                            pass
                    
                    vuln = VulnerabilityResult(
                        id=cve_id,
                        title=f"{cve_id}",
                        description=description,
                        source="NVD",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        severity=severity,
                        score=score,
                        published=published
                    )
                    
                    # Add intelligence analysis
                    vuln.confidence = self.intelligence.analyze_relevance(vuln, keyword)
                    vuln.exploit_available = self.intelligence.detect_exploits(vuln)
                    vuln.actively_exploited = self.intelligence.detect_active_exploitation(vuln)
                    
                    # Only include if confidence is reasonable
                    if vuln.confidence > 0.3:
                        results.append(vuln)
                        
                return sorted(results, key=lambda x: x.confidence, reverse=True)
                
        except Exception as e:
            logger.warning(f"NVD query failed: {e}")
            return []
    
    def extract_severity_info(self, vuln_data: dict) -> tuple[Optional[str], Optional[float]]:
        """Extract severity and score from CVE data."""
        severity = None
        score = None
        
        metrics = vuln_data.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity")
            score = cvss.get("baseScore")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss.get("baseSeverity")
            score = cvss.get("baseScore")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            score = cvss.get("baseScore")
            if score:
                if score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                    
        return severity, score
    
    def consolidate_vulnerabilities(self, all_vulns: List[VulnerabilityResult]) -> List[ConsolidatedVulnerability]:
        """Consolidate duplicate vulnerabilities from multiple sources."""
        # Group by CVE ID first
        cve_groups = {}
        hash_groups = {}
        
        for vuln in all_vulns:
            # Group exact CVE matches
            if vuln.id.startswith("CVE-"):
                if vuln.id not in cve_groups:
                    cve_groups[vuln.id] = []
                cve_groups[vuln.id].append(vuln)
            else:
                # Group similar vulnerabilities by content hash
                hash_key = vuln.get_hash()
                if hash_key not in hash_groups:
                    hash_groups[hash_key] = []
                hash_groups[hash_key].append(vuln)
        
        consolidated = []
        
        # Process CVE groups
        for cve_id, vulns in cve_groups.items():
            consolidated.append(self.merge_vulnerability_group(vulns, cve_id))
        
        # Process hash groups (non-CVE vulnerabilities)
        for hash_key, vulns in hash_groups.items():
            if len(vulns) > 1:  # Only consolidate if multiple sources
                primary_id = vulns[0].id
                consolidated.append(self.merge_vulnerability_group(vulns, primary_id))
            else:
                # Convert single vulnerability to consolidated format
                vuln = vulns[0]
                consolidated.append(ConsolidatedVulnerability(
                    primary_cve=vuln.id,
                    all_ids=[vuln.id],
                    title=vuln.title,
                    description=vuln.description,
                    sources=[vuln.source],
                    severity=vuln.severity,
                    max_score=vuln.score,
                    earliest_published=vuln.published,
                    affected_versions=vuln.affected_versions or [],
                    urls=[vuln.url] if vuln.url else [],
                    exploit_available=vuln.exploit_available,
                    actively_exploited=vuln.actively_exploited,
                    patch_available=vuln.patch_available,
                    related_cves=vuln.related_cves or [],
                    tags=vuln.tags or [],
                    risk_score=0,
                    confidence=vuln.confidence
                ))
        
        # Calculate risk scores
        for vuln in consolidated:
            vuln.risk_score = self.intelligence.calculate_risk_score(vuln)
        
        # Sort by risk score
        return sorted(consolidated, key=lambda x: x.risk_score, reverse=True)
    
    def merge_vulnerability_group(self, vulns: List[VulnerabilityResult], primary_id: str) -> ConsolidatedVulnerability:
        """Merge a group of similar vulnerabilities."""
        # Choose best title and description
        best_vuln = max(vulns, key=lambda v: len(v.description))
        
        # Collect all unique data
        all_ids = list(set(v.id for v in vulns))
        sources = list(set(v.source for v in vulns))
        urls = [v.url for v in vulns if v.url]
        
        # Get best severity and score
        scores = [v.score for v in vulns if v.score]
        max_score = max(scores) if scores else None
        
        severities = [v.severity for v in vulns if v.severity]
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        best_severity = None
        for sev in severity_order:
            if sev in severities:
                best_severity = sev
                break
        
        # Get earliest published date
        dates = [v.published for v in vulns if v.published]
        earliest_date = min(dates) if dates else None
        
        # Merge affected versions
        all_versions = []
        for v in vulns:
            if v.affected_versions:
                all_versions.extend(v.affected_versions)
        unique_versions = list(set(all_versions))
        
        # Aggregate boolean flags
        exploit_available = any(v.exploit_available for v in vulns)
        actively_exploited = any(v.actively_exploited for v in vulns)
        patch_available = any(v.patch_available for v in vulns)
        
        # Average confidence
        avg_confidence = sum(v.confidence for v in vulns) / len(vulns)
        
        return ConsolidatedVulnerability(
            primary_cve=primary_id,
            all_ids=all_ids,
            title=best_vuln.title,
            description=best_vuln.description,
            sources=sources,
            severity=best_severity,
            max_score=max_score,
            earliest_published=earliest_date,
            affected_versions=unique_versions,
            urls=urls,
            exploit_available=exploit_available,
            actively_exploited=actively_exploited,
            patch_available=patch_available,
            related_cves=[],
            tags=[],
            risk_score=0,
            confidence=avg_confidence
        )
    
    async def comprehensive_scan(self, tech: str, ecosystem: Optional[str] = None) -> List[ConsolidatedVulnerability]:
        """Perform comprehensive vulnerability scan with intelligence."""
        logger.info(f"🔍 Starting comprehensive scan for: {tech}")
        
        # Generate search terms
        search_terms = self.generate_search_terms(tech)
        logger.info(f"📋 Generated {len(search_terms)} search terms")
        
        # Collect all vulnerabilities
        all_vulns = []
        
        # Enhanced NVD search
        logger.info("🔍 Querying NVD with multiple terms...")
        nvd_results = await self.query_multiple_nvd_terms(search_terms)
        all_vulns.extend(nvd_results)
        
        # TODO: Add other sources here (OSV, GitHub, etc.)
        
        logger.info(f"📊 Found {len(all_vulns)} raw vulnerabilities")
        
        # Consolidate and analyze
        consolidated = self.consolidate_vulnerabilities(all_vulns)
        logger.info(f"🎯 Consolidated to {len(consolidated)} unique vulnerabilities")
        
        return consolidated
    
    def export_results(self, results: List[ConsolidatedVulnerability], format: str = "json", filename: Optional[str] = None):
        """Export results to various formats."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vuln_scan_{timestamp}.{format}"
        
        if format == "json":
            with open(filename, 'w') as f:
                json.dump([asdict(result) for result in results], f, indent=2)
        
        elif format == "csv":
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "CVE", "Title", "Severity", "Score", "Risk Score", 
                    "Published", "Sources", "Exploit Available", "URLs"
                ])
                
                for result in results:
                    writer.writerow([
                        result.primary_cve,
                        result.title,
                        result.severity or "Unknown",
                        result.max_score or "N/A",
                        f"{result.risk_score:.2f}",
                        result.earliest_published or "Unknown",
                        ", ".join(result.sources),
                        "Yes" if result.exploit_available else "No",
                        "; ".join(result.urls)
                    ])
        
        logger.info(f"📄 Results exported to {filename}")
    
    def print_enhanced_results(self, results: List[ConsolidatedVulnerability], verbose: bool = False, limit: Optional[int] = None):
        """Print enhanced consolidated results."""
        if not results:
            print("\n❌ No vulnerabilities found")
            return
        
        display_results = results[:limit] if limit else results
        
        print(f"\n🎯 CONSOLIDATED VULNERABILITY REPORT")
        print(f"📊 Total: {len(results)} unique vulnerabilities")
        print(f"🔴 Critical/High: {sum(1 for r in results if r.severity in ['CRITICAL', 'HIGH'])}")
        print(f"💥 With Exploits: {sum(1 for r in results if r.exploit_available)}")
        print(f"⚡ Actively Exploited: {sum(1 for r in results if r.actively_exploited)}")
        print("="*100)
        
        for i, vuln in enumerate(display_results, 1):
            # Risk emoji
            if vuln.risk_score >= 8:
                risk_emoji = "🔥"
            elif vuln.risk_score >= 6:
                risk_emoji = "🔴"
            elif vuln.risk_score >= 4:
                risk_emoji = "🟡"
            else:
                risk_emoji = "🟢"
            
            print(f"\n{i}. {risk_emoji} {vuln.primary_cve}: {vuln.title}")
            print(f"   📈 Risk Score: {vuln.risk_score:.1f}/10 | Severity: {vuln.severity or 'Unknown'}")
            
            if vuln.max_score:
                print(f"   📊 CVSS Score: {vuln.max_score}")
            
            if vuln.earliest_published:
                print(f"   📅 Published: {vuln.earliest_published}")
            
            print(f"   🔍 Sources: {', '.join(vuln.sources)}")
            
            # Threat indicators
            indicators = []
            if vuln.exploit_available:
                indicators.append("💣 Exploit Available")
            if vuln.actively_exploited:
                indicators.append("⚡ Actively Exploited")
            if vuln.patch_available:
                indicators.append("🛠️ Patch Available")
            
            if indicators:
                print(f"   🚨 {' | '.join(indicators)}")
            
            if verbose and vuln.description:
                desc = vuln.description
                if len(desc) > 300:
                    desc = desc[:300] + "..."
                print(f"   📝 {desc}")
            
            if vuln.urls:
                print(f"   🔗 {vuln.urls[0]}")


async def main():
    """Enhanced main function with new features."""
    parser = argparse.ArgumentParser(
        description="Advanced Vulnerability Scanner with Intelligence Consolidation",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-t", "--tech", required=True, help="Technology to scan")
    parser.add_argument("-e", "--ecosystem", help="Ecosystem (npm, PyPI, etc.)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--limit", type=int, help="Limit number of results shown")
    parser.add_argument("--export", choices=["json", "csv"], help="Export format")
    parser.add_argument("--export-file", help="Export filename")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    
    args = parser.parse_args()
    
    print("🚀 Advanced Vulnerability Scanner v3.0")
    print("=" * 60)
    
    async with AdvancedVulnerabilityScanner(
        github_token=args.github_token,
        nvd_api_key=args.nvd_api_key
    ) as scanner:
        
        try:
            results = await scanner.comprehensive_scan(args.tech, args.ecosystem)
            
            scanner.print_enhanced_results(
                results, 
                verbose=args.verbose, 
                limit=args.limit
            )
            
            if args.export:
                scanner.export_results(results, args.export, args.export_file)
                
        except KeyboardInterrupt:
            print("\n❌ Scan interrupted")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
##
##
