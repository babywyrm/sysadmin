#!/usr/bin/env python3
"""
webhook_benchmark.py - Performance comparison between webhook services.. (..ngrok, webhook..)
"""
import asyncio
import aiohttp
import time
import statistics
from dataclasses import dataclass
from typing import List, Dict
import json

@dataclass
class BenchmarkResult:
    url: str
    response_times: List[float]
    success_count: int
    error_count: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p95_response_time: float

class WebhookBenchmarker:
    def __init__(self):
        self.results = {}
    
    async def benchmark_endpoint(self, name: str, url: str, requests: int = 100, concurrency: int = 10) -> BenchmarkResult:
        """Benchmark a single webhook endpoint"""
        print(f"🚀 Benchmarking {name} with {requests} requests, concurrency {concurrency}")
        
        connector = aiohttp.TCPConnector(limit=concurrency)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(concurrency)
            
            tasks = [
                self._send_timed_request(session, semaphore, url, i)
                for i in range(requests)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        response_times = []
        success_count = 0
        error_count = 0
        
        for result in results:
            if isinstance(result, Exception):
                error_count += 1
            else:
                response_times.append(result['response_time'])
                if result['success']:
                    success_count += 1
                else:
                    error_count += 1
        
        if response_times:
            avg_time = statistics.mean(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            p95_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        else:
            avg_time = min_time = max_time = p95_time = 0
        
        result = BenchmarkResult(
            url=url,
            response_times=response_times,
            success_count=success_count,
            error_count=error_count,
            avg_response_time=avg_time,
            min_response_time=min_time,
            max_response_time=max_time,
            p95_response_time=p95_time
        )
        
        self.results[name] = result
        return result
    
    async def _send_timed_request(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, url: str, request_id: int):
        """Send a timed request"""
        async with semaphore:
            payload = {
                "benchmark": True,
                "request_id": request_id,
                "timestamp": time.time()
            }
            
            start_time = time.time()
            try:
                async with session.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    await response.text()  # Read response body
                    response_time = time.time() - start_time
                    return {
                        "response_time": response_time,
                        "success": 200 <= response.status < 300,
                        "status": response.status
                    }
            except Exception as e:
                response_time = time.time() - start_time
                return {
                    "response_time": response_time,
                    "success": False,
                    "error": str(e)
                }
    
    def print_results(self):
        """Print benchmark results"""
        print("\n" + "="*80)
        print("🏆 BENCHMARK RESULTS")
        print("="*80)
        
        for name, result in self.results.items():
            print(f"\n📊 {name.upper()}")
            print(f"   URL: {result.url}")
            print(f"   Success Rate: {result.success_count}/{result.success_count + result.error_count} ({result.success_count/(result.success_count + result.error_count)*100:.1f}%)")
            print(f"   Avg Response Time: {result.avg_response_time*1000:.2f}ms")
            print(f"   Min Response Time: {result.min_response_time*1000:.2f}ms")
            print(f"   Max Response Time: {result.max_response_time*1000:.2f}ms")
            print(f"   95th Percentile: {result.p95_response_time*1000:.2f}ms")
            if result.error_count > 0:
                print(f"   ❌ Errors: {result.error_count}")
        
        # Comparison
        if len(self.results) > 1:
            print(f"\n🔄 COMPARISON")
            sorted_results = sorted(self.results.items(), key=lambda x: x[1].avg_response_time)
            fastest = sorted_results[0]
            print(f"   🥇 Fastest: {fastest[0]} ({fastest[1].avg_response_time*1000:.2f}ms avg)")
            
            for name, result in sorted_results[1:]:
                slowdown = result.avg_response_time / fastest[1].avg_response_time
                print(f"   📈 {name}: {slowdown:.2f}x slower than fastest")

async def main():
    # Example usage
    benchmarker = WebhookBenchmarker()
    
    # You would replace these with actual URLs
    endpoints = {
        "webhook.site": "https://webhook.site/your-webhook-site-id",
        "ngrok": "https://your-ngrok-url.ngrok-free.app",
    }
    
    print("🎯 Starting webhook performance benchmark")
    
    for name, url in endpoints.items():
        try:
            await benchmarker.benchmark_endpoint(name, url, requests=50, concurrency=5)
        except Exception as e:
            print(f"❌ Failed to benchmark {name}: {e}")
    
    benchmarker.print_results()

if __name__ == "__main__":
    asyncio.run(main())
