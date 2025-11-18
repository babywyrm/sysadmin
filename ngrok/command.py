#!/usr/bin/env python3
"""
webhook_commander.py - Comprehensive webhook testing, benchmarking, and comparison tool
Supports ngrok, webhook.site, and custom endpoints with advanced features.
"""

import asyncio
import aiohttp
import json
import time
import csv
import statistics
import argparse
import logging
import os
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Union, Tuple, Any
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import ssl

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class WebhookRequest:
    """Represents a webhook request configuration."""
    url: str
    method: str = "POST"
    headers: Optional[Dict[str, str]] = None
    auth: Optional[Tuple[str, str]] = None
    timeout: float = 30.0
    
    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}

@dataclass
class ResponseMetrics:
    """Metrics for a single response."""
    status_code: int
    response_time: float
    success: bool
    error: Optional[str] = None
    content_length: int = 0

@dataclass
class BenchmarkResult:
    """Comprehensive benchmark results."""
    endpoint_name: str
    url: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    response_times: List[float]
    status_codes: Dict[int, int]
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p50_response_time: float
    p95_response_time: float
    p99_response_time: float
    requests_per_second: float
    total_duration: float
    errors: List[str]

class WebhookSiteManager:
    """Manages webhook.site endpoints."""
    
    BASE_URL = "https://webhook.site"
    
    def __init__(self) -> None:
        self.token: Optional[str] = None
        self.url: Optional[str] = None
    
    async def create_endpoint(self) -> str:
        """Create a new webhook.site endpoint."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.BASE_URL}/token") as response:
                    if response.status != 200:
                        raise ValueError(f"Failed to create webhook.site endpoint: {response.status}")
                    
                    data = await response.json()
                    self.token = data.get('uuid')
                    if not self.token:
                        raise ValueError("No UUID returned from webhook.site")
                    
                    self.url = f"{self.BASE_URL}/{self.token}"
                    return self.url
        except Exception as e:
            logger.error(f"Error creating webhook.site endpoint: {e}")
            raise
    
    async def get_requests(self) -> List[Dict[str, Any]]:
        """Retrieve requests sent to the webhook.site endpoint."""
        if not self.token:
            return []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.BASE_URL}/token/{self.token}/requests") as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('data', [])
                    return []
        except Exception as e:
            logger.warning(f"Error retrieving webhook.site requests: {e}")
            return []
    
    def get_web_interface_url(self) -> Optional[str]:
        """Get the web interface URL."""
        return f"{self.BASE_URL}/#!/{self.token}" if self.token else None

class PayloadGenerator:
    """Generates various types of test payloads."""
    
    @staticmethod
    def simple_payload(request_id: int) -> Dict[str, Any]:
        """Generate a simple test payload."""
        return {
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "webhook_test",
            "data": {"message": f"Test message {request_id}"}
        }
    
    @staticmethod
    def large_payload(request_id: int, size_kb: int = 1) -> Dict[str, Any]:
        """Generate a large payload for testing data transfer."""
        data_size = size_kb * 1024
        large_data = "x" * (data_size - 200)  # Account for other fields
        
        return {
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "large_payload_test",
            "large_data": large_data
        }
    
    @staticmethod
    def complex_payload(request_id: int) -> Dict[str, Any]:
        """Generate a complex nested payload."""
        return {
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "complex_test",
            "metadata": {
                "source": "webhook_commander",
                "version": "1.0.0",
                "environment": "test"
            },
            "user": {
                "id": request_id,
                "name": f"user_{request_id}",
                "email": f"user{request_id}@example.com"
            },
            "items": [
                {"name": f"item_{i}", "value": i * 10} 
                for i in range(1, 6)
            ]
        }

class WebhookCommander:
    """Main webhook testing and benchmarking class."""
    
    def __init__(self, max_concurrency: int = 10) -> None:
        self.max_concurrency = max_concurrency
        self.webhook_site = WebhookSiteManager()
        self.results: Dict[str, BenchmarkResult] = {}
    
    async def health_check(self, url: str) -> bool:
        """Check if endpoint is reachable."""
        try:
            connector = aiohttp.TCPConnector(ssl=ssl.create_default_context())
            timeout = aiohttp.ClientTimeout(total=5.0)
            
            async with aiohttp.ClientSession(
                connector=connector, 
                timeout=timeout
            ) as session:
                async with session.get(url) as response:
                    return response.status < 500
        except Exception:
            return False
    
    async def benchmark_endpoint(
        self,
        name: str,
        request_config: WebhookRequest,
        total_requests: int = 100,
        concurrency: int = 10,
        payload_type: str = "simple",
        payload_size_kb: int = 1,
        rate_limit: Optional[float] = None,
        retry_attempts: int = 0
    ) -> BenchmarkResult:
        """Benchmark a webhook endpoint with comprehensive metrics."""
        
        logger.info(f"🚀 Benchmarking {name} - {total_requests} requests, concurrency {concurrency}")
        
        # Validate URL
        parsed_url = urlparse(request_config.url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"Invalid URL: {request_config.url}")
        
        # Health check
        if not await self.health_check(request_config.url):
            logger.warning(f"⚠️ Health check failed for {name}")
        
        # Setup SSL context
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(
            limit=concurrency,
            ssl=ssl_context,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=request_config.timeout)
        
        semaphore = asyncio.Semaphore(concurrency)
        rate_limiter = asyncio.Semaphore(1) if rate_limit else None
        
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": "WebhookCommander/1.0"}
            ) as session:
                
                tasks = [
                    self._send_webhook_request(
                        session=session,
                        semaphore=semaphore,
                        rate_limiter=rate_limiter,
                        rate_limit=rate_limit,
                        request_config=request_config,
                        request_id=i,
                        payload_type=payload_type,
                        payload_size_kb=payload_size_kb,
                        retry_attempts=retry_attempts
                    )
                    for i in range(1, total_requests + 1)
                ]
                
                # Progress tracking
                completed_tasks = 0
                results = []
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    completed_tasks += 1
                    
                    if completed_tasks % max(1, total_requests // 10) == 0:
                        progress = (completed_tasks / total_requests) * 100
                        logger.info(f"📊 {name} progress: {progress:.1f}%")
        
        except Exception as e:
            logger.error(f"❌ Benchmark failed for {name}: {e}")
            raise
        finally:
            await connector.close()
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Process results
        benchmark_result = self._process_results(
            name, request_config.url, total_requests, results, total_duration
        )
        
        self.results[name] = benchmark_result
        logger.info(f"✅ {name} benchmark complete: {benchmark_result.successful_requests}/{total_requests} successful")
        
        return benchmark_result
    
    async def _send_webhook_request(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        rate_limiter: Optional[asyncio.Semaphore],
        rate_limit: Optional[float],
        request_config: WebhookRequest,
        request_id: int,
        payload_type: str,
        payload_size_kb: int,
        retry_attempts: int
    ) -> ResponseMetrics:
        """Send a single webhook request with retry logic."""
        
        async with semaphore:
            if rate_limiter and rate_limit:
                async with rate_limiter:
                    await asyncio.sleep(1.0 / rate_limit)
            
            # Generate payload
            if payload_type == "large":
                payload = PayloadGenerator.large_payload(request_id, payload_size_kb)
            elif payload_type == "complex":
                payload = PayloadGenerator.complex_payload(request_id)
            else:
                payload = PayloadGenerator.simple_payload(request_id)
            
            for attempt in range(retry_attempts + 1):
                start_time = time.time()
                
                try:
                    request_kwargs = {
                        "method": request_config.method,
                        "url": request_config.url,
                        "json": payload,
                        "headers": {
                            **request_config.headers,
                            "X-Request-ID": str(request_id),
                            "X-Attempt": str(attempt + 1)
                        }
                    }
                    
                    if request_config.auth:
                        request_kwargs["auth"] = aiohttp.BasicAuth(
                            request_config.auth[0],
                            request_config.auth[1]
                        )
                    
                    async with session.request(**request_kwargs) as response:
                        content = await response.text()
                        response_time = time.time() - start_time
                        
                        return ResponseMetrics(
                            status_code=response.status,
                            response_time=response_time,
                            success=200 <= response.status < 400,
                            content_length=len(content)
                        )
                
                except Exception as e:
                    response_time = time.time() - start_time
                    
                    if attempt < retry_attempts:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    
                    return ResponseMetrics(
                        status_code=0,
                        response_time=response_time,
                        success=False,
                        error=str(e)
                    )
    
    def _process_results(
        self,
        name: str,
        url: str,
        total_requests: int,
        results: List[ResponseMetrics],
        total_duration: float
    ) -> BenchmarkResult:
        """Process benchmark results into comprehensive metrics."""
        
        successful_requests = sum(1 for r in results if r.success)
        failed_requests = total_requests - successful_requests
        
        response_times = [r.response_time for r in results]
        status_codes = {}
        errors = []
        
        for result in results:
            status_codes[result.status_code] = status_codes.get(result.status_code, 0) + 1
            if result.error:
                errors.append(result.error)
        
        if response_times:
            avg_time = statistics.mean(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            
            sorted_times = sorted(response_times)
            p50 = sorted_times[len(sorted_times) // 2]
            p95 = sorted_times[int(len(sorted_times) * 0.95)]
            p99 = sorted_times[int(len(sorted_times) * 0.99)]
        else:
            avg_time = min_time = max_time = p50 = p95 = p99 = 0.0
        
        rps = successful_requests / total_duration if total_duration > 0 else 0.0
        
        return BenchmarkResult(
            endpoint_name=name,
            url=url,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            response_times=response_times,
            status_codes=status_codes,
            avg_response_time=avg_time,
            min_response_time=min_time,
            max_response_time=max_time,
            p50_response_time=p50,
            p95_response_time=p95,
            p99_response_time=p99,
            requests_per_second=rps,
            total_duration=total_duration,
            errors=list(set(errors))  # Unique errors only
        )
    
    async def setup_webhook_site_endpoint(self) -> str:
        """Setup a webhook.site endpoint."""
        url = await self.webhook_site.create_endpoint()
        logger.info(f"✅ Webhook.site URL: {url}")
        logger.info(f"🔍 Web interface: {self.webhook_site.get_web_interface_url()}")
        return url
    
    async def analyze_webhook_site_requests(self) -> Dict[str, Any]:
        """Analyze requests received by webhook.site."""
        requests = await self.webhook_site.get_requests()
        
        if not requests:
            return {"total": 0, "requests": []}
        
        analysis = {
            "total": len(requests),
            "methods": {},
            "content_types": {},
            "request_times": []
        }
        
        for req in requests:
            method = req.get('method', 'UNKNOWN')
            analysis["methods"][method] = analysis["methods"].get(method, 0) + 1
            
            content_type = req.get('headers', {}).get('content-type', 'unknown')
            analysis["content_types"][content_type] = analysis["content_types"].get(content_type, 0) + 1
            
            if 'created_at' in req:
                analysis["request_times"].append(req['created_at'])
        
        return analysis
    
    def print_results(self) -> None:
        """Print comprehensive benchmark results."""
        if not self.results:
            logger.warning("No results to display")
            return
        
        print("\n" + "=" * 100)
        print("🏆 WEBHOOK BENCHMARK RESULTS")
        print("=" * 100)
        
        for name, result in self.results.items():
            success_rate = (result.successful_requests / result.total_requests) * 100
            
            print(f"\n📊 {name.upper()}")
            print(f"   URL: {result.url}")
            print(f"   Total Requests: {result.total_requests}")
            print(f"   Success Rate: {result.successful_requests}/{result.total_requests} ({success_rate:.1f}%)")
            print(f"   Requests/Second: {result.requests_per_second:.2f}")
            print(f"   Total Duration: {result.total_duration:.2f}s")
            print(f"   Response Times (ms):")
            print(f"     • Average: {result.avg_response_time * 1000:.2f}")
            print(f"     • Min: {result.min_response_time * 1000:.2f}")
            print(f"     • Max: {result.max_response_time * 1000:.2f}")
            print(f"     • 50th percentile: {result.p50_response_time * 1000:.2f}")
            print(f"     • 95th percentile: {result.p95_response_time * 1000:.2f}")
            print(f"     • 99th percentile: {result.p99_response_time * 1000:.2f}")
            
            if result.status_codes:
                print(f"   Status Codes: {result.status_codes}")
            
            if result.errors:
                print(f"   ❌ Unique Errors ({len(result.errors)}):")
                for error in result.errors[:5]:  # Show first 5 errors
                    print(f"     • {error}")
        
        # Comparative analysis
        if len(self.results) > 1:
            print(f"\n🔄 COMPARATIVE ANALYSIS")
            
            # Sort by average response time
            sorted_results = sorted(
                self.results.items(), 
                key=lambda x: x[1].avg_response_time
            )
            
            fastest = sorted_results[0]
            print(f"   🥇 Fastest: {fastest[0]} ({fastest[1].avg_response_time * 1000:.2f}ms avg)")
            
            # Sort by success rate
            sorted_by_reliability = sorted(
                self.results.items(),
                key=lambda x: x[1].successful_requests / x[1].total_requests,
                reverse=True
            )
            
            most_reliable = sorted_by_reliability[0]
            reliability_rate = (most_reliable[1].successful_requests / most_reliable[1].total_requests) * 100
            print(f"   🛡️ Most Reliable: {most_reliable[0]} ({reliability_rate:.1f}% success)")
            
            # Sort by throughput
            sorted_by_throughput = sorted(
                self.results.items(),
                key=lambda x: x[1].requests_per_second,
                reverse=True
            )
            
            highest_throughput = sorted_by_throughput[0]
            print(f"   🚀 Highest Throughput: {highest_throughput[0]} ({highest_throughput[1].requests_per_second:.2f} req/s)")
    
    async def export_results(self, format: str = "json", filename: Optional[str] = None) -> str:
        """Export results to file."""
        if not self.results:
            raise ValueError("No results to export")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if filename is None:
            filename = f"webhook_benchmark_{timestamp}.{format}"
        
        filepath = Path(filename)
        
        if format == "json":
            # Convert results to JSON-serializable format
            export_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "results": {}
            }
            
            for name, result in self.results.items():
                result_dict = asdict(result)
                # Remove response_times list to reduce file size
                result_dict.pop("response_times", None)
                export_data["results"][name] = result_dict
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
        
        elif format == "csv":
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    "endpoint_name", "url", "total_requests", "successful_requests",
                    "failed_requests", "success_rate_percent", "avg_response_time_ms",
                    "min_response_time_ms", "max_response_time_ms", "p95_response_time_ms",
                    "requests_per_second", "total_duration_s"
                ])
                
                # Write data
                for name, result in self.results.items():
                    success_rate = (result.successful_requests / result.total_requests) * 100
                    writer.writerow([
                        name, result.url, result.total_requests, result.successful_requests,
                        result.failed_requests, f"{success_rate:.2f}", 
                        f"{result.avg_response_time * 1000:.2f}",
                        f"{result.min_response_time * 1000:.2f}",
                        f"{result.max_response_time * 1000:.2f}",
                        f"{result.p95_response_time * 1000:.2f}",
                        f"{result.requests_per_second:.2f}",
                        f"{result.total_duration:.2f}"
                    ])
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        logger.info(f"📄 Results exported to: {filepath}")
        return str(filepath)

async def main() -> None:
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="Webhook Commander - Advanced webhook testing and benchmarking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test webhook.site only
  python webhook_commander.py --webhook-site --requests 50 --concurrency 5
  
  # Test custom endpoint with authentication
  python webhook_commander.py --url https://api.example.com/webhook --auth user:pass
  
  # Benchmark multiple endpoints
  python webhook_commander.py --webhook-site --url https://example.com/hook --requests 100
  
  # Export results
  python webhook_commander.py --webhook-site --export json --output results.json
        """
    )
    
    # Endpoint configuration
    parser.add_argument("--webhook-site", action="store_true", help="Test webhook.site endpoint")
    parser.add_argument("--url", action="append", help="Custom webhook URL to test")
    parser.add_argument("--auth", help="Basic auth in format 'user:password'")
    
    # Test configuration
    parser.add_argument("--requests", "-r", type=int, default=10, help="Number of requests per endpoint")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="Concurrent requests")
    parser.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds")
    parser.add_argument("--retry", type=int, default=0, help="Number of retry attempts")
    parser.add_argument("--rate-limit", type=float, help="Rate limit (requests per second)")
    
    # Payload options
    parser.add_argument("--payload-type", choices=["simple", "large", "complex"], 
                       default="simple", help="Type of test payload")
    parser.add_argument("--payload-size", type=int, default=1, help="Payload size in KB (for large payloads)")
    
    # Output options
    parser.add_argument("--export", choices=["json", "csv"], help="Export format")
    parser.add_argument("--output", help="Output filename")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    
    # Advanced options
    parser.add_argument("--max-concurrency", type=int, default=50, help="Global max concurrency")
    
    args = parser.parse_args()
    
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Validate arguments
    if not args.webhook_site and not args.url:
        print("❌ Must specify at least --webhook-site or --url")
        sys.exit(1)
    
    # Parse authentication
    auth = None
    if args.auth:
        if ":" not in args.auth:
            print("❌ Auth format must be 'username:password'")
            sys.exit(1)
        auth = tuple(args.auth.split(":", 1))
    
    commander = WebhookCommander(max_concurrency=args.max_concurrency)
    endpoints = []
    
    try:
        # Setup webhook.site if requested
        if args.webhook_site:
            webhook_site_url = await commander.setup_webhook_site_endpoint()
            endpoints.append(("webhook.site", WebhookRequest(url=webhook_site_url)))
        
        # Setup custom URLs
        if args.url:
            for i, url in enumerate(args.url):
                name = f"custom_{i+1}" if len(args.url) > 1 else "custom"
                endpoints.append((
                    name, 
                    WebhookRequest(
                        url=url,
                        auth=auth,
                        timeout=args.timeout
                    )
                ))
        
        # Run benchmarks
        for name, request_config in endpoints:
            try:
                await commander.benchmark_endpoint(
                    name=name,
                    request_config=request_config,
                    total_requests=args.requests,
                    concurrency=args.concurrency,
                    payload_type=args.payload_type,
                    payload_size_kb=args.payload_size,
                    rate_limit=args.rate_limit,
                    retry_attempts=args.retry
                )
            except Exception as e:
                logger.error(f"❌ Failed to benchmark {name}: {e}")
        
        # Print results
        if not args.quiet:
            commander.print_results()
        
        # Analyze webhook.site requests if available
        if args.webhook_site and not args.quiet:
            print("\n🔍 WEBHOOK.SITE ANALYSIS")
            print("-" * 50)
            analysis = await commander.analyze_webhook_site_requests()
            print(f"Total requests received: {analysis['total']}")
            if analysis['methods']:
                print(f"HTTP methods: {analysis['methods']}")
        
        # Export results
        if args.export:
            await commander.export_results(format=args.export, filename=args.output)
        
        print(f"\n✅ Webhook Commander completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Handle Windows event loop policy
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())
