import http.server
import socketserver
import urllib.parse
import base64
import re
import sys
import os
from datetime import datetime

# Configuration
PORT = 80
MAX_DEPTH = 5  # max recursive decoding layers
SAVE_DIR = 'decoded_html'

# Ensure save directory exists
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SAVE_PATH = os.path.join(BASE_DIR, SAVE_DIR)
os.makedirs(SAVE_PATH, exist_ok=True)

print(f"Working dir: {BASE_DIR}")
print(f"Saving decoded HTML to: {SAVE_PATH}")

# Helpers

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
    for depth in range(MAX_DEPTH):
        # URL decode
        url_decoded = urllib.parse.unquote(current)
        if url_decoded != current:
            layers.append(('url', url_decoded[:60]))
            current = url_decoded
            continue
        # Base64 decode
        candidate = re.sub(r"\s+", "", current)
        # accept +,/,= in base64 regex
        if re.fullmatch(r'[A-Za-z0-9+/]+=*', candidate):
            b64_decoded = try_base64_decode(candidate)
            if b64_decoded is not None:
                layers.append(('b64', b64_decoded[:60]))
                current = b64_decoded
                continue
        break
    return current, layers


def save_html(content: str):
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    filename = os.path.join(SAVE_PATH, f'decoded_{timestamp}.html')
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[+] Saved HTML: {filename}")
    except Exception as e:
        print(f"[!] Error saving HTML: {e}")

class DecodeHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write("%s - - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            fmt % args
        ))
        sys.stdout.flush()

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def handle_data(self, raw_data: str):
        key, sep, val = raw_data.partition('=')
        if not sep:
            print(f"[!] Bad format: {raw_data}")
            return
        val = urllib.parse.unquote(val)
        print(f"[+] Raw ({key}): {val[:60]}{'...' if len(val)>60 else ''}")
        final, layers = recursive_decode(val)
        for i, (lt, snippet) in enumerate(layers, 1):
            print(f"    Layer {i} ({lt}): {snippet}{'...' if len(snippet)>60 else ''}")
        print(f"[+] Final length: {len(final)} chars")
        # Log beginning of final for debug
        print(f"    Final startswith: {final[:20]!r}")
        # Save if contains HTML tags
        low = final.lower()
        if '<html' in low or '<!doctype' in low:
            save_html(final)
        else:
            print("[!] Content does not appear to be HTML, skipping save.")
        sys.stdout.flush()

    def do_POST(self):
        print(f"🔍 POST {self.path}")
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        print(f"    Body: {body[:100]}{'...' if len(body)>100 else ''}")
        self.handle_data(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        filepath = parsed.path.lstrip('/')
        if filepath and os.path.isfile(os.path.join(BASE_DIR, filepath)):
            return super().do_GET()

        print(f"🔍 GET {self.path}")
        if parsed.query:
            self.handle_data(parsed.query)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

    def do_HEAD(self):
        return self.do_GET()

if __name__ == '__main__':
    print(f"Starting decode server on port {PORT}...")
    with socketserver.TCPServer(('0.0.0.0', PORT), DecodeHandler) as httpd:
        httpd.serve_forever()

