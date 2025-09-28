#!/usr/bin/env python3
"""
Modern vulnerability scanner that queries multiple sources for CVEs and exploits.. (beta)..
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import logging
from datetime import datetime

import aiohttp


# Configure logging..
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityResult:
    """Structured vulnerability result."""
    id: str
    title: str
    description: str
    source: str
    url: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    published: Optional[str] = None
    affected_versions: Optional[List[str]] = None


@dataclass
class APIEndpoints:
    """API endpoint configuration."""
    OSV = "https://api.osv.dev/v1/query"
    GITHUB = "https://api.github.com/search/issues"
    NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EXPLOITDB = "https://www.exploit-db.com/search"


class VulnerabilityScanner:
    """Modern vulnerability scanner with async support."""
    
    def __init__(self, github_token: Optional[str] = None, nvd_api_key: Optional[str] = None):
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self.endpoints = APIEndpoints()
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=10)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.session.close()
        
    def _fix_typos(self, tech: str) -> str:
        """Fix common typos in technology names."""
        return tech.replace("wordpess", "wordpress")
    
    def _generate_query_variations(self, tech: str) -> List[str]:
        """Generate different query variations for better coverage."""
        return [
            tech,
            f"{tech} plugin",
            f"{tech} vulnerability"
        ]
    
    def _extract_severity_info(self, vuln_data: dict) -> tuple[Optional[str], Optional[float]]:
        """Extract severity and score from vulnerability data."""
        severity = None
        score = None
        
        # Check for CVSS v3 metrics
        metrics = vuln_data.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "Unknown")
            score = cvss.get("baseScore")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "Unknown")
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
    
    async def query_osv(self, package_name: str, ecosystem: Optional[str] = None) -> List[VulnerabilityResult]:
        """Query OSV API for vulnerabilities."""
        headers = {"Content-Type": "application/json"}
        payload = {"package": {"name": package_name}}
        
        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem
            
        try:
            async with self.session.post(self.endpoints.OSV, headers=headers, json=payload) as response:
                if response.status == 400 and ecosystem:
                    logger.warning(f"OSV API error with ecosystem '{ecosystem}', retrying without")
                    del payload["package"]["ecosystem"]
                    async with self.session.post(self.endpoints.OSV, headers=headers, json=payload) as retry_response:
                        if retry_response.status == 200:
                            data = await retry_response.json()
                        else:
                            return []
                elif response.status == 200:
                    data = await response.json()
                else:
                    return []
                    
            results = []
            for vuln in data.get("vulns", []):
                # Extract affected versions
                affected_versions = []
                for affected in vuln.get("affected", []):
                    if "ranges" in affected:
                        for range_info in affected["ranges"]:
                            for event in range_info.get("events", []):
                                if "introduced" in event:
                                    affected_versions.append(f"≥{event['introduced']}")
                                if "fixed" in event:
                                    affected_versions.append(f"<{event['fixed']}")
                
                # Get severity from database_specific if available
                severity = None
                db_specific = vuln.get("database_specific", {})
                if "severity" in db_specific:
                    severity = db_specific["severity"]
                
                published = vuln.get("published", "")
                if published:
                    try:
                        published = datetime.fromisoformat(published.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                    except:
                        pass
                
                results.append(VulnerabilityResult(
                    id=vuln.get("id", "N/A"),
                    title=vuln.get("summary", "No summary"),
                    description=vuln.get("details", "No details available"),
                    source="OSV",
                    url=f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                    severity=severity,
                    published=published,
                    affected_versions=affected_versions[:3] if affected_versions else None  # Limit to 3
                ))
            return results
            
        except Exception as e:
            logger.warning(f"OSV query failed for '{package_name}': {e}")
            return []
    
    async def query_github(self, query_str: str) -> List[VulnerabilityResult]:
        """Query GitHub Issues API."""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
            
        params = {"q": f'"{query_str}" vulnerability OR CVE', "per_page": 10}
        
        try:
            async with self.session.get(self.endpoints.GITHUB, headers=headers, params=params) as response:
                if response.status == 403:
                    logger.warning("GitHub API rate limited. Consider using --github-token")
                    return []
                elif response.status != 200:
                    return []
                    
                data = await response.json()
                results = []
                
                for item in data.get("items", []):
                    body = item.get("body", "") or ""
                    description = (body[:400] + "...") if len(body) > 400 else body
                    
                    # Try to extract CVE from title or body
                    title = item.get("title", "No title")
                    severity = None
                    if any(word in title.lower() for word in ["critical", "high", "severe"]):
                        severity = "HIGH"
                    elif any(word in title.lower() for word in ["medium", "moderate"]):
                        severity = "MEDIUM"
                    elif any(word in title.lower() for word in ["low", "minor"]):
                        severity = "LOW"
                    
                    created_at = item.get("created_at", "")
                    if created_at:
                        try:
                            created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                        except:
                            created_at = ""
                    
                    results.append(VulnerabilityResult(
                        id=f"#{item.get('number', 'N/A')}",
                        title=title,
                        description=description or "No description",
                        source="GitHub",
                        url=item.get("html_url"),
                        severity=severity,
                        published=created_at
                    ))
                return results
                
        except Exception as e:
            logger.warning(f"GitHub query failed: {e}")
            return []
    
    async def query_nvd(self, keyword: str) -> List[VulnerabilityResult]:
        """Query NVD API for CVEs with detailed information."""
        params = {"keywordSearch": keyword, "resultsPerPage": "10"}
        headers = {}
        
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        else:
            # Add delay to respect rate limits without API key
            await asyncio.sleep(1)
            
        try:
            async with self.session.get(self.endpoints.NVD, headers=headers, params=params) as response:
                if response.status == 403:
                    logger.warning("NVD API rate limited. Consider using --nvd-api-key")
                    return []
                elif response.status != 200:
                    return []
                    
                data = await response.json()
                results = []
                
                for item in data.get("vulnerabilities", []):
                    cve_info = item.get("cve", {})
                    cve_id = cve_info.get("id", "N/A")
                    
                    # Get description
                    descriptions = cve_info.get("descriptions", [])
                    description = descriptions[0].get("value", "No description available") if descriptions else "No description available"
                    
                    # Extract severity and score
                    severity, score = self._extract_severity_info(cve_info)
                    
                    # Get published date
                    published = cve_info.get("published", "")
                    if published:
                        try:
                            published = datetime.fromisoformat(published.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                        except:
                            pass
                    
                    # Get affected versions/configurations
                    affected_versions = []
                    configurations = cve_info.get("configurations", {})
                    if "nodes" in configurations:
                        for node in configurations["nodes"][:2]:  # Limit to 2 nodes
                            for cpe_match in node.get("cpeMatch", []):
                                if cpe_match.get("vulnerable", False):
                                    criteria = cpe_match.get("criteria", "")
                                    if criteria:
                                        # Extract version from CPE
                                        parts = criteria.split(":")
                                        if len(parts) >= 6:
                                            version = parts[5]
                                            if version and version != "*":
                                                affected_versions.append(version)
                    
                    results.append(VulnerabilityResult(
                        id=cve_id,
                        title=f"{cve_id}",
                        description=description,
                        source="NVD",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        severity=severity,
                        score=score,
                        published=published,
                        affected_versions=affected_versions[:3] if affected_versions else None
                    ))
                return results
                
        except Exception as e:
            logger.warning(f"NVD query failed: {e}")
            return []
    
    def query_exploitdb_local(self, query_str: str) -> List[VulnerabilityResult]:
        """Query local searchsploit tool."""
        try:
            result = subprocess.run(
                ["searchsploit", "-j", query_str],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return []
                
            data = json.loads(result.stdout)
            results = []
            
            for exploit in data.get("RESULTS_EXPLOIT", []):
                edb_id = exploit.get("EDB-ID", "N/A")
                title = exploit.get("Title", "No title")
                
                # Determine severity based on exploit type
                severity = None
                if any(word in title.lower() for word in ["remote", "rce", "code execution"]):
                    severity = "HIGH"
                elif any(word in title.lower() for word in ["privilege", "escalation", "bypass"]):
                    severity = "MEDIUM"
                elif any(word in title.lower() for word in ["dos", "denial"]):
                    severity = "MEDIUM"
                
                results.append(VulnerabilityResult(
                    id=f"EDB-{edb_id}",
                    title=title,
                    description=exploit.get("Path", "No description"),
                    source="ExploitDB",
                    url=f"https://www.exploit-db.com/exploits/{edb_id}",
                    severity=severity
                ))
            return results
            
        except Exception:
            return []
    
    async def scan_technology(self, tech: str, ecosystem: Optional[str] = None, verbose: bool = False) -> Dict[str, List[VulnerabilityResult]]:
        """Scan a technology across all sources."""
        tech = self._fix_typos(tech)
        queries = self._generate_query_variations(tech)
        
        logger.info(f"Scanning vulnerabilities for: {tech}")
        if ecosystem:
            logger.info(f"Using ecosystem: {ecosystem}")
        
        all_results = {}
        
        # OSV - try main query first, then variations if no results
        logger.info("🔍 Querying OSV...")
        osv_results = await self.query_osv(tech, ecosystem)
        if not osv_results:
            for query in queries[1:]:  # Try other variations
                osv_results = await self.query_osv(query, ecosystem)
                if osv_results:
                    break
        
        if osv_results:
            all_results["OSV"] = osv_results
        
        # GitHub
        logger.info("🔍 Querying GitHub...")
        github_results = await self.query_github(tech)
        if github_results:
            all_results["GitHub"] = github_results
        
        # NVD  
        logger.info("🔍 Querying NVD...")
        nvd_results = await self.query_nvd(tech)
        if nvd_results:
            all_results["NVD"] = nvd_results
        
        # ExploitDB - try local first
        logger.info("🔍 Querying ExploitDB...")
        exploitdb_results = []
        for query in queries:
            local_results = self.query_exploitdb_local(query)
            if local_results:
                exploitdb_results.extend(local_results)
                break
        
        if exploitdb_results:
            all_results["ExploitDB"] = exploitdb_results
        
        return all_results
    
    def _get_severity_emoji(self, severity: Optional[str]) -> str:
        """Get emoji for severity level."""
        if not severity:
            return "ℹ️"
        severity_upper = severity.upper()
        if severity_upper in ["CRITICAL", "HIGH"]:
            return "🔴"
        elif severity_upper == "MEDIUM":
            return "🟡"
        elif severity_upper == "LOW":
            return "🟢"
        else:
            return "ℹ️"
    
    def print_results(self, results: Dict[str, List[VulnerabilityResult]], verbose: bool = False, show_summary: bool = False):
        """Print scan results in a formatted way."""
        total_found = sum(len(vulns) for vulns in results.values())
        
        if total_found == 0:
            print("\n❌ No vulnerabilities found across all sources.")
            print("\nTips:")
            print("• Try different search terms or add ecosystem (-e)")
            print("• Use --github-token for higher GitHub rate limits") 
            print("• Use --nvd-api-key for better NVD access")
            return
        
        print(f"\n🎯 Found {total_found} total vulnerabilities across {len(results)} sources\n")
        
        for source, vulns in results.items():
            if not vulns:
                continue
                
            print(f"{'='*80}")
            print(f"🔍 {source.upper()} - {len(vulns)} vulnerabilities found")
            print('='*80)
            
            for i, vuln in enumerate(vulns, 1):
                severity_emoji = self._get_severity_emoji(vuln.severity)
                severity_text = f" [{vuln.severity}]" if vuln.severity else ""
                score_text = f" (Score: {vuln.score})" if vuln.score else ""
                
                print(f"\n{i}. {severity_emoji} {vuln.id}: {vuln.title}{severity_text}{score_text}")
                
                if vuln.published:
                    print(f"   📅 Published: {vuln.published}")
                
                if vuln.affected_versions:
                    versions = ", ".join(vuln.affected_versions)
                    print(f"   📦 Affected: {versions}")
                
                # Show description (truncated or full based on verbose mode)
                if vuln.description and vuln.description != "No description":
                    desc = vuln.description
                    if not verbose and len(desc) > 200:
                        desc = desc[:200] + "..."
                    print(f"   📝 {desc}")
                
                if vuln.url:
                    print(f"   🔗 {vuln.url}")
                    
                if show_summary and i <= 3:  # Show summary for first 3
                    print(f"   💡 Summary: {self._generate_summary(vuln)}")
    
    def _generate_summary(self, vuln: VulnerabilityResult) -> str:
        """Generate a brief summary of the vulnerability."""
        desc = vuln.description.lower()
        
        if "code execution" in desc or "rce" in desc:
            return "Remote code execution vulnerability - allows attackers to run arbitrary code"
        elif "sql injection" in desc:
            return "SQL injection vulnerability - allows database manipulation"
        elif "cross-site scripting" in desc or "xss" in desc:
            return "Cross-site scripting vulnerability - enables client-side attacks"
        elif "privilege escalation" in desc:
            return "Privilege escalation - allows gaining higher system privileges"
        elif "denial of service" in desc or "dos" in desc:
            return "Denial of service - can cause service disruption"
        elif "authentication bypass" in desc:
            return "Authentication bypass - allows unauthorized access"
        elif "buffer overflow" in desc:
            return "Buffer overflow - memory corruption that can lead to code execution"
        elif "path traversal" in desc or "directory traversal" in desc:
            return "Path traversal - allows access to unauthorized files"
        else:
            return "Security vulnerability - check details for impact assessment"


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Modern vulnerability scanner with detailed CVE information.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 yo.py -t wordpress -v
  python3 yo.py -t "nginx" --summary  
  python3 yo.py -t "react" -e npm --github-token YOUR_TOKEN
        """
    )
    parser.add_argument(
        "-t", "--tech", 
        required=True,
        help="Technology/package name (e.g., 'wordpress', 'nginx', 'react')"
    )
    parser.add_argument(
        "-e", "--ecosystem",
        help="Optional ecosystem for OSV (e.g., 'npm', 'PyPI', 'Go')"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Show full vulnerability descriptions"
    )
    parser.add_argument(
        "--summary", 
        action="store_true",
        help="Show AI-generated summaries for top vulnerabilities"
    )
    parser.add_argument(
        "--github-token",
        help="GitHub Personal Access Token for higher rate limits",
        default=os.environ.get("GITHUB_TOKEN")
    )
    parser.add_argument(
        "--nvd-api-key",
        help="NVD API Key for better access",
        default=os.environ.get("NVD_API_KEY")
    )
    
    args = parser.parse_args()
    
    print("🚀 Modern Vulnerability Scanner v2.0")
    print("=" * 50)
    
    # Initialize scanner
    async with VulnerabilityScanner(
        github_token=args.github_token,
        nvd_api_key=args.nvd_api_key
    ) as scanner:
        
        try:
            results = await scanner.scan_technology(
                tech=args.tech,
                ecosystem=args.ecosystem,
                verbose=args.verbose
            )
            
            scanner.print_results(results, verbose=args.verbose, show_summary=args.summary)
            
        except KeyboardInterrupt:
            print("\n❌ Scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
##
