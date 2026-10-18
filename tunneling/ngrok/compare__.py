#!/usr/bin/env python3
"""
webhook_tester.py - Advanced webhook testing with both ngrok and webhook.site
"""
import asyncio
import aiohttp
import json
import time
import subprocess
import requests
from datetime import datetime
from typing import Dict, List, Optional
import argparse

class WebhookSiteClient:
    """Client for webhook.site API"""
    BASE_URL = "https://webhook.site"
    
    def __init__(self):
        self.token = None
        self.url = None
    
    async def create_endpoint(self) -> str:
        """Create a new webhook.site endpoint"""
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.BASE_URL}/token") as response:
                data = await response.json()
                self.token = data['uuid']
                self.url = f"{self.BASE_URL}/{self.token}"
                return self.url
    
    async def get_requests(self) -> List[Dict]:
        """Get all requests sent to the endpoint"""
        if not self.token:
            return []
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.BASE_URL}/token/{self.token}/requests") as response:
                data = await response.json()
                return data.get('data', [])
    
    def get_web_url(self) -> str:
        """Get the web interface URL"""
        return f"{self.BASE_URL}/#!/{self.token}"

class NgrokManager:
    """Manage ngrok tunnel"""
    
    def __init__(self, port: int = 3000):
        self.port = port
        self.process = None
        self.url = None
    
    def start(self) -> str:
        """Start ngrok tunnel"""
        cmd = ["ngrok", "http", str(self.port), "--log", "stdout"]
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for ngrok to start
        time.sleep(3)
        
        # Get the public URL
        try:
            response = requests.get("http://localhost:4040/api/tunnels")
            tunnels = response.json()['tunnels']
            if tunnels:
                self.url = tunnels[0]['public_url']
                return self.url
        except Exception as e:
            print(f"Error getting ngrok URL: {e}")
        
        return None
    
    def stop(self):
        """Stop ngrok tunnel"""
        if self.process:
            self.process.terminate()
            self.process.wait()

class WebhookTester:
    """Main webhook testing class"""
    
    def __init__(self):
        self.webhook_site = WebhookSiteClient()
        self.ngrok = NgrokManager()
        self.local_server = None
    
    async def setup_webhook_site(self) -> str:
        """Setup webhook.site endpoint"""
        url = await self.webhook_site.create_endpoint()
        print(f"✅ Webhook.site URL: {url}")
        print(f"🔍 View at: {self.webhook_site.get_web_url()}")
        return url
    
    def setup_ngrok(self) -> Optional[str]:
        """Setup ngrok tunnel"""
        url = self.ngrok.start()
        if url:
            print(f"✅ Ngrok URL: {url}")
            print(f"🔍 View at: http://localhost:4040")
        else:
            print("❌ Failed to setup ngrok")
        return url
    
    async def send_test_webhooks(self, urls: List[str], payload: Dict, count: int = 1):
        """Send test webhooks to multiple URLs"""
        print(f"🚀 Sending {count} webhook(s) to {len(urls)} endpoint(s)")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for i in range(count):
                test_payload = {
                    **payload,
                    "test_id": i + 1,
                    "timestamp": datetime.now().isoformat(),
                }
                
                for url in urls:
                    task = self._send_webhook(session, url, test_payload, i + 1)
                    tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            error_count = len(results) - success_count
            
            print(f"✅ Successful requests: {success_count}")
            if error_count > 0:
                print(f"❌ Failed requests: {error_count}")
    
    async def _send_webhook(self, session: aiohttp.ClientSession, url: str, payload: Dict, request_id: int):
        """Send a single webhook"""
        headers = {
            "Content-Type": "application/json",
            "X-Test-Request-ID": str(request_id),
            "X-Test-Source": "webhook-tester-python"
        }
        
        try:
            async with session.post(url, json=payload, headers=headers) as response:
                return {
                    "url": url,
                    "status": response.status,
                    "request_id": request_id
                }
        except Exception as e:
            print(f"❌ Error sending to {url}: {e}")
            raise
    
    async def compare_responses(self):
        """Compare responses between services"""
        print("🔍 Analyzing webhook deliveries...")
        
        # Get webhook.site requests
        webhook_requests = await self.webhook_site.get_requests()
        
        print(f"\n📊 Webhook.site received {len(webhook_requests)} requests")
        for req in webhook_requests[:5]:  # Show first 5
            print(f"  - {req.get('method', 'POST')} at {req.get('created_at', 'unknown')}")
        
        print(f"\n💡 For ngrok analysis, check: http://localhost:4040")
    
    def cleanup(self):
        """Cleanup resources"""
        print("🧹 Cleaning up...")
        self.ngrok.stop()

async def main():
    parser = argparse.ArgumentParser(description="Advanced webhook testing")
    parser.add_argument("--count", "-c", type=int, default=5, help="Number of test webhooks")
    parser.add_argument("--ngrok-port", "-p", type=int, default=3000, help="Local port for ngrok")
    parser.add_argument("--payload", "-d", help="Custom JSON payload")
    parser.add_argument("--webhook-site-only", action="store_true", help="Only test webhook.site")
    parser.add_argument("--ngrok-only", action="store_true", help="Only test ngrok")
    
    args = parser.parse_args()
    
    # Default test payload
    payload = {
        "event": "test_webhook",
        "source": "webhook_tester_python",
        "data": {"message": "Hello from webhook tester!"}
    }
    
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            print("❌ Invalid JSON payload")
            return
    
    tester = WebhookTester()
    urls = []
    
    try:
        print("🚀 Starting webhook testing framework")
        
        # Setup endpoints
        if not args.ngrok_only:
            webhook_site_url = await tester.setup_webhook_site()
            urls.append(webhook_site_url)
        
        if not args.webhook_site_only:
            ngrok_url = tester.setup_ngrok()
            if ngrok_url:
                urls.append(ngrok_url)
        
        if not urls:
            print("❌ No valid endpoints configured")
            return
        
        # Send test webhooks
        await tester.send_test_webhooks(urls, payload, args.count)
        
        # Wait a moment for processing
        await asyncio.sleep(2)
        
        # Compare responses
        await tester.compare_responses()
        
        print(f"\n✅ Testing complete!")
        print(f"🔗 Webhook.site: {tester.webhook_site.get_web_url()}")
        print(f"🔗 Ngrok: http://localhost:4040")
        
    finally:
        tester.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
