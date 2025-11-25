"""Security scanning utilities."""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Security scanner for secrets and C2 detection."""

    def __init__(self, vt_api_key: Optional[str] = None) -> None:
        self.vt_api_key = vt_api_key
        self.signatures: Dict[str, str] = {}
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Load secret detection signatures."""
        # Default signatures (would load from sigs.json)
        self.signatures = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{32,})",
            "jwt": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "private_key": r"-----BEGIN PRIVATE KEY-----",
            "slack_token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
            "github_token": r"ghp_[a-zA-Z0-9]{36}",
        }

    async def scan_secrets(self, strings: List[str]) -> List[Dict[str, str]]:
        """Scan strings for secrets."""
        findings = []

        for string in strings:
            for secret_type, pattern in self.signatures.items():
                matches = re.findall(pattern, string, re.IGNORECASE)
                if matches:
                    for match in matches:
                        findings.append({
                            "type": secret_type,
                            "value": match if isinstance(match, str) else match[0],
                            "context": string[:100],
                        })

        return findings

    async def scan_c2(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Scan for C2 addresses using VirusTotal."""
        if not self.vt_api_key:
            logger.warning("No VirusTotal API key provided")
            return []

        # Extract URLs
        urls = []
        for string in strings:
            if self._is_valid_url(string):
                urls.append(string)

        # Check with VT
        findings = []
        async with httpx.AsyncClient() as client:
            for url in urls:
                domain = urlparse(url).netloc
                if domain:
                    result = await self._check_virustotal(client, domain)
                    if result:
                        findings.append(result)

        return findings

    async def _check_virustotal(
        self, client: httpx.AsyncClient, domain: str
    ) -> Optional[Dict[str, Any]]:
        """Check domain with VirusTotal."""
        if not self.vt_api_key:
            return None

        try:
            headers = {"x-apikey": self.vt_api_key}
            response = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
            )

            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)

                if malicious > 0:
                    return {
                        "domain": domain,
                        "malicious_count": malicious,
                        "stats": stats,
                    }

        except Exception as e:
            logger.error(f"VT check failed for {domain}: {e}")

        return None

    def _is_valid_url(self, string: str) -> bool:
        """Check if string is a valid URL."""
        try:
            result = urlparse(string)
            return all([result.scheme, result.netloc])
        except:
            return False

    async def scan_nuclei_template(
        self, strings: List[str], template_path: Path
    ) -> List[Dict[str, str]]:
        """Scan using Nuclei template."""
        findings = []

        try:
            import yaml

            with open(template_path) as f:
                template = yaml.safe_load(f)

            template_id = template.get("id", "unknown")
            severity = template.get("info", {}).get("severity", "info")

            # Extract regex patterns
            regexes = []
            for extractor in template.get("file", [{}])[0].get("extractors", []):
                regexes.extend(extractor.get("regex", []))

            # Scan strings
            for regex_pattern in regexes:
                for string in strings:
                    matches = re.findall(regex_pattern, string)
                    if matches:
                        for match in matches:
                            findings.append({
                                "template_id": template_id,
                                "severity": severity,
                                "match": match,
                                "context": string[:100],
                            })

        except Exception as e:
            logger.error(f"Failed to scan with template {template_path}: {e}")

        return findings
