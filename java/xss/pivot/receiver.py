#!/usr/bin/env python3
"""
Blind browser callback receiver.

This server is intended for controlled research environments.
It captures and decodes semi-blind callbacks from browser-executed payloads.

This tool intentionally omits exploit automation and target-specific logic.
"""

import http.server
import socketserver
import urllib.parse
import base64
from pathlib import Path
from datetime import datetime

PORT = 8080
SAVE_DIR = Path("captures")
SAVE_DIR.mkdir(exist_ok=True)

class Receiver(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.query:
            key, _, val = parsed.query.partition("=")
            decoded = urllib.parse.unquote(val)

            try:
                decoded = base64.b64decode(decoded + "===").decode(
                    errors="replace"
                )
            except Exception:
                pass

            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
            fname = SAVE_DIR / f"{ts}_{key}.txt"
            fname.write_text(decoded)

            print(f"\n[+] Callback: {key}\n{decoded}\n")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

if __name__ == "__main__":
    print(f"[+] Receiver listening on port {PORT}")
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Receiver) as httpd:
        httpd.serve_forever()
