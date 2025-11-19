#!/usr/bin/env python3
"""
pentest_tool.py — Enhanced concurrent GraphQL & Cypher injection pentester ..beta..
"""

import argparse
import csv
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterator
from urllib.parse import urlparse
import threading

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ─── Configuration & Data Models ───────────────────────────────────────────────
@dataclass
class TestResult:
    """Structured test result"""
    mode: str
    payload: str
    status_code: int
    response_time: float
    response_snippet: str
    error: Optional[str] = None
    
    @property
    def success(self) -> bool:
        return 200 <= self.status_code < 300
    
    @property
    def suspicious(self) -> bool:
        """Identify potentially interesting responses"""
        indicators = ["error", "exception", "sql", "database", "schema", "syntax"]
        return any(ind in self.response_snippet.lower() for ind in indicators)


@dataclass
class TestConfig:
    """Test configuration"""
    mode: str
    url: str
    headers: Dict[str, str]
    timeout: int
    workers: int
    rate_limit: float = 0.1  # Minimum delay between requests
    auth: Optional[Tuple[str, str]] = None
    
    def __post_init__(self):
        """Validate configuration"""
        if not self.url.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        
        parsed = urlparse(self.url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")


# ─── Enhanced Utilities ────────────────────────────────────────────────────────
class Logger:
    """Thread-safe logger with sanitized output"""
    
    def __init__(self, name: str = "pentest_tool", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self._lock = threading.Lock()
    
    def sanitize_message(self, msg: str) -> str:
        """Remove potentially sensitive information from logs"""
        sensitive_patterns = ["password", "token", "auth", "key"]
        for pattern in sensitive_patterns:
            if pattern in msg.lower():
                # Redact sensitive values
                words = msg.split()
                for i, word in enumerate(words):
                    if pattern in word.lower() and "=" in word:
                        key, _ = word.split("=", 1)
                        words[i] = f"{key}=***"
                msg = " ".join(words)
        return msg
    
    def info(self, msg: str, *args) -> None:
        with self._lock:
            self.logger.info(self.sanitize_message(msg), *args)
    
    def debug(self, msg: str, *args) -> None:
        with self._lock:
            self.logger.debug(self.sanitize_message(msg), *args)
    
    def error(self, msg: str, *args) -> None:
        with self._lock:
            self.logger.error(self.sanitize_message(msg), *args)


def load_payloads(path: Path) -> List[str]:
    """Load and validate payload strings from file"""
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {path}")
    
    try:
        content = path.read_text(encoding='utf-8')
        
        if path.suffix.lower() == ".json":
            payloads = json.loads(content)
            if not isinstance(payloads, list):
                raise ValueError("JSON payload file must contain a list")
        else:
            payloads = [line.strip() for line in content.splitlines() if line.strip()]
        
        # Basic payload validation
        validated_payloads = []
        for payload in payloads:
            if isinstance(payload, str) and payload.strip():
                validated_payloads.append(payload.strip())
        
        if not validated_payloads:
            raise ValueError("No valid payloads found in file")
        
        return validated_payloads
    
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Error reading payload file: {e}")


def create_session(timeout: int) -> requests.Session:
    """Create a configured requests session with retry strategy"""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Set default timeout
    session.timeout = timeout
    
    return session


# ─── Enhanced Pentesters ───────────────────────────────────────────────────────
class BasePentester:
    """Base class for pentesters with common functionality"""
    
    def __init__(self, config: TestConfig, logger: Logger):
        self.config = config
        self.logger = logger
        self.session = create_session(config.timeout)
        self._last_request_time = 0.0
        self._request_lock = threading.Lock()
    
    def _rate_limit(self) -> None:
        """Implement rate limiting"""
        with self._request_lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.config.rate_limit:
                time.sleep(self.config.rate_limit - elapsed)
            self._last_request_time = time.time()
    
    def close(self) -> None:
        """Cleanup resources"""
        self.session.close()


class GraphQLPentester(BasePentester):
    """Enhanced GraphQL penetration tester"""
    
    def introspect(self) -> Optional[Dict[str, Any]]:
        """Perform GraphQL introspection"""
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    types {
                        name
                        kind
                        fields {
                            name
                            type {
                                name
                                kind
                            }
                        }
                    }
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                }
            }
            """
        }
        
        try:
            self._rate_limit()
            response = self.session.post(
                self.config.url,
                json=introspection_query,
                headers=self.config.headers,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                if "data" in result and "__schema" in result["data"]:
                    return result
            
            self.logger.debug(f"Introspection failed: {response.status_code}")
            return None
            
        except Exception as e:
            self.logger.error(f"Introspection error: {e}")
            return None
    
    def test_payload(self, payload: str) -> TestResult:
        """Test a single GraphQL payload"""
        start_time = time.time()
        
        try:
            self._rate_limit()
            response = self.session.post(
                self.config.url,
                json={"query": payload},
                headers=self.config.headers,
                timeout=self.config.timeout
            )
            
            elapsed = time.time() - start_time
            snippet = self._extract_snippet(response.text)
            
            return TestResult(
                mode="graphql",
                payload=payload,
                status_code=response.status_code,
                response_time=elapsed,
                response_snippet=snippet
            )
            
        except Exception as e:
            elapsed = time.time() - start_time
            return TestResult(
                mode="graphql",
                payload=payload,
                status_code=-1,
                response_time=elapsed,
                response_snippet="",
                error=str(e)
            )
    
    def _extract_snippet(self, text: str) -> str:
        """Extract relevant snippet from response"""
        return text[:300].replace("\n", " ").replace("\r", "")


class CypherPentester(BasePentester):
    """Enhanced Cypher penetration tester"""
    
    def __init__(self, config: TestConfig, logger: Logger):
        super().__init__(config, logger)
        # Adjust endpoint for Neo4j
        if not self.config.url.endswith('/db/neo4j/tx/commit'):
            self.config.url = self.config.url.rstrip('/') + '/db/neo4j/tx/commit'
    
    def introspect_database(self) -> Optional[Dict[str, Any]]:
        """Perform database introspection"""
        queries = [
            "CALL db.labels()",
            "CALL db.relationshipTypes()",
            "MATCH (n) RETURN labels(n), count(*) LIMIT 10"
        ]
        
        results = {}
        for query in queries:
            try:
                result = self._execute_query(query)
                if result and result.success:
                    results[query] = result.response_snippet
            except Exception as e:
                self.logger.debug(f"Introspection query failed: {e}")
        
        return results if results else None
    
    def _execute_query(self, query: str) -> TestResult:
        """Execute a Cypher query"""
        start_time = time.time()
        
        try:
            self._rate_limit()
            payload = {"statements": [{"statement": query}]}
            
            response = self.session.post(
                self.config.url,
                json=payload,
                auth=self.config.auth,
                headers={"Content-Type": "application/json"},
                timeout=self.config.timeout
            )
            
            elapsed = time.time() - start_time
            result_data = response.json()
            snippet = self._extract_snippet(result_data)
            
            return TestResult(
                mode="cypher",
                payload=query,
                status_code=response.status_code,
                response_time=elapsed,
                response_snippet=snippet
            )
            
        except Exception as e:
            elapsed = time.time() - start_time
            return TestResult(
                mode="cypher",
                payload=query,
                status_code=-1,
                response_time=elapsed,
                response_snippet="",
                error=str(e)
            )
    
    def test_payload(self, payload: str) -> TestResult:
        """Test a single Cypher payload"""
        return self._execute_query(payload)
    
    def _extract_snippet(self, data: Dict[str, Any]) -> str:
        """Extract relevant snippet from Neo4j response"""
        try:
            if "results" in data:
                return str(data["results"])[:300]
            elif "errors" in data:
                return str(data["errors"])[:300]
            else:
                return str(data)[:300]
        except:
            return str(data)[:300]


# ─── Results Management ────────────────────────────────────────────────────────
class ResultsManager:
    """Manage and export test results"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.results: List[TestResult] = []
        self._lock = threading.Lock()
    
    def add_result(self, result: TestResult) -> None:
        """Thread-safe result addition"""
        with self._lock:
            self.results.append(result)
    
    def get_summary(self) -> Dict[str, Any]:
        """Generate results summary"""
        if not self.results:
            return {}
        
        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        suspicious = sum(1 for r in self.results if r.suspicious)
        errors = sum(1 for r in self.results if r.error)
        
        avg_time = sum(r.response_time for r in self.results) / total
        
        return {
            "total_tests": total,
            "successful": successful,
            "suspicious": suspicious,
            "errors": errors,
            "average_response_time": avg_time,
            "success_rate": successful / total * 100
        }
    
    def export_csv(self, filepath: Path) -> None:
        """Export results to CSV"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "mode", "payload", "status_code", "response_time", 
                "response_snippet", "error", "success", "suspicious"
            ])
            
            for result in self.results:
                writer.writerow([
                    result.mode,
                    result.payload,
                    result.status_code,
                    f"{result.response_time:.3f}",
                    result.response_snippet,
                    result.error or "",
                    result.success,
                    result.suspicious
                ])
        
        self.logger.info(f"Results exported to {filepath}")
    
    def export_json(self, filepath: Path) -> None:
        """Export results to JSON"""
        data = {
            "summary": self.get_summary(),
            "results": [asdict(result) for result in self.results]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Results exported to {filepath}")


# ─── Main CLI Interface ────────────────────────────────────────────────────────
def parse_headers(header_strings: Optional[List[str]]) -> Dict[str, str]:
    """Parse header strings into dictionary"""
    headers = {"Content-Type": "application/json"}
    
    if header_strings:
        for header_str in header_strings:
            if ":" not in header_str:
                continue
            key, value = header_str.split(":", 1)
            headers[key.strip()] = value.strip()
    
    return headers


def run_tests(config: TestConfig, payloads: List[str], logger: Logger) -> ResultsManager:
    """Run penetration tests"""
    results_manager = ResultsManager(logger)
    
    # Create appropriate pentester
    if config.mode == "graphql":
        pentester = GraphQLPentester(config, logger)
        logger.info("Performing GraphQL introspection...")
        schema = pentester.introspect()
        if schema:
            logger.info("GraphQL schema accessible")
        else:
            logger.info("GraphQL introspection blocked or failed")
    else:
        pentester = CypherPentester(config, logger)
        logger.info("Performing Cypher database introspection...")
        db_info = pentester.introspect_database()
        if db_info:
            logger.info("Database information accessible")
    
    logger.info(f"Testing {len(payloads)} payloads with {config.workers} workers")
    
    try:
        with ThreadPoolExecutor(max_workers=config.workers) as executor:
            # Submit all tasks
            future_to_payload = {
                executor.submit(pentester.test_payload, payload): payload 
                for payload in payloads
            }
            
            # Process results as they complete
            for future in as_completed(future_to_payload):
                result = future.result()
                results_manager.add_result(result)
                
                # Display result
                color = Fore.GREEN if result.success else Fore.RED
                if result.suspicious:
                    color = Fore.YELLOW
                
                mode_prefix = "GQL" if config.mode == "graphql" else "CYP"
                status = result.status_code if result.status_code != -1 else "ERR"
                
                print(f"{color}[{mode_prefix}] {status} {result.response_time:.2f}s{Style.RESET_ALL} — {result.payload[:60]}...")
                
                if result.suspicious:
                    logger.info(f"Suspicious response: {result.response_snippet[:100]}")
    
    finally:
        pentester.close()
    
    return results_manager


def main() -> int:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced GraphQL & Cypher penetration testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--mode", choices=["graphql", "cypher"], required=True,
                        help="Testing mode")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--user", help="Neo4j username (for cypher mode)")
    parser.add_argument("--password", help="Neo4j password (for cypher mode)")
    parser.add_argument("--payload-file", type=Path, required=True,
                        help="JSON or newline-delimited payload file")
    parser.add_argument("--workers", type=int, default=5,
                        help="Number of concurrent workers (default: 5)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--rate-limit", type=float, default=0.1,
                        help="Minimum delay between requests (default: 0.1s)")
    parser.add_argument("--header", action="append",
                        help="Additional HTTP header (Key:Value)")
    parser.add_argument("--export-csv", type=Path, help="Export results to CSV")
    parser.add_argument("--export-json", type=Path, help="Export results to JSON")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Initialize logger
    logger = Logger(level=logging.DEBUG if args.verbose else logging.INFO)
    
    try:
        # Load payloads
        payloads = load_payloads(args.payload_file)
        logger.info(f"Loaded {len(payloads)} payloads from {args.payload_file}")
        
        # Build configuration
        headers = parse_headers(args.header)
        auth = None
        if args.mode == "cypher" and args.user and args.password:
            auth = (args.user, args.password)
        
        config = TestConfig(
            mode=args.mode,
            url=args.url,
            headers=headers,
            timeout=args.timeout,
            workers=args.workers,
            rate_limit=args.rate_limit,
            auth=auth
        )
        
        # Run tests
        results_manager = run_tests(config, payloads, logger)
        
        # Display summary
        summary = results_manager.get_summary()
        logger.info(f"Testing complete: {summary['total_tests']} tests, "
                   f"{summary['successful']} successful, "
                   f"{summary['suspicious']} suspicious, "
                   f"{summary['errors']} errors")
        logger.info(f"Success rate: {summary['success_rate']:.1f}%, "
                   f"Avg response time: {summary['average_response_time']:.3f}s")
        
        # Export results
        if args.export_csv:
            results_manager.export_csv(args.export_csv)
        if args.export_json:
            results_manager.export_json(args.export_json)
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Testing interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
