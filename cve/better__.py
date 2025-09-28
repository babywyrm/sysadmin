#!/usr/bin/env python3
"""
Modern vulnerability scanner that queries multiple sources for CVEs and exploits.. (testing)..
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

import aiohttp


# Configure logging
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
    
    async def query_osv(self, package_name: str, ecosystem: Optional[str] = None) -> List[VulnerabilityResult]:
        """Query OSV API for vulnerabilities."""
        headers = {"Content-Type": "application/json"}
        payload = {"package": {"name": package_name}}
        
        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem
            
        try:
            async with self.session.post(self.endpoints.OSV, headers=headers, json=payload) as response:
                response_text = await response.text()
                
                if response.status == 400 and ecosystem:
                    logger.warning(f"OSV API error with ecosystem '{ecosystem}', retrying without")
                    del payload["package"]["ecosystem"]
                    async with self.session.post(self.endpoints.OSV, headers=headers, json=payload) as retry_response:
                        if retry_response.status == 200:
                            data = await retry_response.json()
                        else:
                            logger.warning(f"OSV API still failing: {retry_response.status}")
                            return []
                elif response.status == 200:
                    data = await response.json()
                else:
                    logger.warning(f"OSV API returned {response.status} for '{package_name}'")
                    return []
                    
            results = []
            for vuln in data.get("vulns", []):
                results.append(VulnerabilityResult(
                    id=vuln.get("id", "N/A"),
                    title=vuln.get("summary", "No summary"),
                    description=vuln.get("details", "No details"),
                    source="OSV",
                    url=f"https://osv.dev/vulnerability/{vuln.get('id', '')}"
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
                    logger.warning(f"GitHub API error: {response.status}")
                    return []
                    
                data = await response.json()
                results = []
                
                for item in data.get("items", []):
                    body = item.get("body", "") or ""
                    description = (body[:200] + "...") if len(body) > 200 else body
                    
                    results.append(VulnerabilityResult(
                        id=f"#{item.get('number', 'N/A')}",
                        title=item.get("title", "No title"),
                        description=description or "No description",
                        source="GitHub",
                        url=item.get("html_url")
                    ))
                return results
                
        except Exception as e:
            logger.warning(f"GitHub query failed: {e}")
            return []
    
    async def query_nvd(self, keyword: str) -> List[VulnerabilityResult]:
        """Query NVD API for CVEs."""
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
                    logger.warning(f"NVD API error: {response.status}")
                    return []
                    
                data = await response.json()
                results = []
                
                for item in data.get("vulnerabilities", []):
                    cve_info = item.get("cve", {})
                    descriptions = cve_info.get("descriptions", [])
                    description = descriptions[0].get("value", "No description") if descriptions else "No description"
                    
                    cve_id = cve_info.get("id", "N/A")
                    results.append(VulnerabilityResult(
                        id=cve_id,
                        title=f"CVE: {cve_id}",
                        description=description,
                        source="NVD",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
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
                results.append(VulnerabilityResult(
                    id=f"EDB-{edb_id}",
                    title=exploit.get("Title", "No title"),
                    description=exploit.get("Path", "No description"),
                    source="ExploitDB (Local)",
                    url=f"https://www.exploit-db.com/exploits/{edb_id}"
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
    
    def print_results(self, results: Dict[str, List[VulnerabilityResult]], verbose: bool = False):
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
                
            print(f"{'='*60}")
            print(f"🔍 {source.upper()} - {len(vulns)} vulnerabilities found")
            print('='*60)
            
            for i, vuln in enumerate(vulns, 1):
                print(f"\n{i}. 🚨 {vuln.id}: {vuln.title}")
                
                if verbose and vuln.description != "No description":
                    # Truncate long descriptions
                    desc = vuln.description
                    if len(desc) > 300:
                        desc = desc[:300] + "..."
                    print(f"   📝 {desc}")
                
                if vuln.url:
                    print(f"   🔗 {vuln.url}")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Modern vulnerability scanner for technologies across multiple sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 yo.py -t wordpress
  python3 yo.py -t "nginx" -v
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
        help="Show detailed vulnerability descriptions"
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
    
    print("🚀 Modern Vulnerability Scanner")
    print("=" * 40)
    
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
            
            scanner.print_results(results, verbose=args.verbose)
            
        except KeyboardInterrupt:
            print("\n❌ Scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())


