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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
from enum import Enum

class LayerType(Enum):
    URL = "url"
    BASE64 = "b64"

@dataclass
class Config:
    port: int = 80
    show_html: bool = False
    json_log: bool = False
    allowed_ips: Optional[set] = None
    max_depth: int = 5
    save_dir: str = 'decoded_html'

class RecursiveDecoder:
    """Handles recursive URL and Base64 decoding"""
    
    def __init__(self, max_depth: int = 5):
        self.max_depth = max_depth
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
    
    def decode(self, data: str) -> Tuple[str, List[Tuple[LayerType, str]]]:
        """Recursively decode data, returning final result and layer history"""
        layers = []
        current = data
        
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
                 file_manager: FileManager, **kwargs):
        self.config = config
        self.decoder = decoder
        self.file_manager = file_manager
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

    def handle_data(self, raw_data: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        
        if '=' not in raw_data:
            self.log.warning(f"[!] Bad format: {raw_data}")
            return

        key, _, val = raw_data.partition('=')
        val = urllib.parse.unquote(val)
        
        self.log.info(f"[+] Raw ({key}): {val[:60]}{'...' if len(val) > 60 else ''}")
        
        # Decode the data
        final, layers = self.decoder.decode(val)
        
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
        if self._is_html_content(final):
            saved_path = self.file_manager.save_html(final, timestamp)
            if saved_path:
                entry["saved_html"] = str(saved_path)
            
            if self.config.show_html:
                print("--- BEGIN DECODED HTML ---")
                print(final)
                print("--- END DECODED HTML ---")
        else:
            self.log.info("[!] Not HTML, skip saving.")
        
        # Save JSON log if enabled
        if self.config.json_log:
            self.file_manager.append_json_log(entry)

    def do_POST(self):
        if self.config.allowed_ips and self.client_address[0] not in self.config.allowed_ips:
            self.send_error(403, "Forbidden")
            return
            
        self.log.info(f"🔍 POST {self.path}")
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        self.log.info(f"    Body: {body[:100]}{'...' if len(body) > 100 else ''}")
        
        self.handle_data(body)
        self._send_success_response()

    def do_GET(self):
        if self.config.allowed_ips and self.client_address[0] not in self.config.allowed_ips:
            self.send_error(403, "Forbidden")
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
                        file_manager: FileManager):
    """Factory function to create handler class with dependencies"""
    class ConfiguredHandler(DecodeHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, config=config, decoder=decoder, 
                           file_manager=file_manager, **kwargs)
    return ConfiguredHandler

def parse_args() -> Config:
    parser = argparse.ArgumentParser(description='Decode server for URL/Base64 exfiltration')
    parser.add_argument('--port', '-p', type=int, default=80, 
                       help='Port to listen on (default: 80)')
    parser.add_argument('--show', '-s', action='store_true', 
                       help='Print decoded HTML to console')
    parser.add_argument('--json-log', action='store_true', 
                       help='Enable JSON log output (to decoded_html/log.jsonl)')
    parser.add_argument('--allow-ip', nargs='*', 
                       help='List of allowed IP addresses')
    
    args = parser.parse_args()
    
    return Config(
        port=args.port,
        show_html=args.show,
        json_log=args.json_log,
        allowed_ips=set(args.allow_ip) if args.allow_ip else None
    )

def main():
    config = parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    log = logging.getLogger(__name__)
    
    # Initialize components
    base_dir = Path(__file__).parent.absolute()
    save_path = base_dir / config.save_dir
    
    decoder = RecursiveDecoder(max_depth=config.max_depth)
    file_manager = FileManager(save_path)
    
    print(f"Working dir: {base_dir}")
    print(f"Saving decoded HTML to: {save_path}")
    print(f"Listening on port: {config.port}, show mode: {config.show_html}, "
          f"json log: {config.json_log}")
    
    # Create and start server
    handler_class = create_handler_class(config, decoder, file_manager)
    
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    
    server = socketserver.ThreadingTCPServer(('0.0.0.0', config.port), handler_class)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt received, shutting down server...")
    finally:
        server.shutdown()
        server.server_close()
        log.info("Server has exited cleanly.")

if __name__ == '__main__':
    main()
