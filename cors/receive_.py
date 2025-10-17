#!/usr/bin/env python3
"""
Flexible CORS-enabled HTTP server (for demo/lab/testing use).

Examples:
  python cors_server.py --port 8080 \
      --allow-origin https://app.example.com --allow-origin https://admin.example.com \
      --allow-credentials --save-dir ./received --max-body-size 1048576 --verbose

Notes:
- Do NOT use this in production. Harden before deployment.
- When --allow-credentials is set, '*' cannot be used for Access-Control-Allow-Origin.
  The server will echo only allowed origins.
"""

import argparse
import base64
import http.server
import json
import os
import re
import signal
import socketserver
import sys
import threading
import urllib.parse
from datetime import datetime
from http import HTTPStatus
from pathlib import Path
from typing import Iterable, List, Optional, Pattern

# ------------------------------------------------------------------------------
# Origin matching utilities
# ------------------------------------------------------------------------------

def compile_origin_patterns(origins: Iterable[str]) -> List[Pattern]:
    """Compile regex patterns for allowed origins."""
    patterns = []
    for origin in origins:
        o = origin.strip()
        if not o:
            continue
        if o == "*":
            patterns.append(re.compile(r"^.*$"))
        elif o.startswith("*."):
            host = re.escape(o[2:])
            patterns.append(re.compile(rf"^https?://([a-zA-Z0-9_-]+\.)?{host}(:\d+)?$"))
        else:
            patterns.append(re.compile(rf"^{re.escape(o)}$"))
    return patterns


def origin_allowed(origin: Optional[str], patterns: List[Pattern]) -> bool:
    """Check if the provided origin matches any allowed pattern."""
    return bool(origin and any(p.match(origin.strip()) for p in patterns))


# ------------------------------------------------------------------------------
# Request Handler
# ------------------------------------------------------------------------------

class FlexibleCORSHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler supporting configurable CORS and safe payload saving."""

    server_version = "FlexibleCORS/2025"

    cors_patterns: List[Pattern] = []
    allow_credentials: bool = False
    allow_methods: str = "GET, POST, OPTIONS"
    allow_headers: str = "Content-Type, Authorization"
    expose_headers: Optional[str] = None
    max_age: int = 600
    max_body_size: int = 4 * 1024 * 1024  # 4 MiB
    save_dir: Path = Path("./received")
    verbose: bool = True

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def log(self, *parts):
        if self.verbose:
            print(f"[{datetime.utcnow().isoformat()}]", *parts, file=sys.stderr)

    # ------------------------------------------------------------------
    # CORS helpers
    # ------------------------------------------------------------------
    def _get_origin(self) -> Optional[str]:
        return self.headers.get("Origin")

    def _set_cors_headers(self):
        """Set CORS headers appropriately before end_headers()."""
        origin = self._get_origin()

        if self.allow_credentials:
            if origin and origin_allowed(origin, self.cors_patterns):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            if any(p.pattern == r"^.*$" for p in self.cors_patterns):
                self.send_header("Access-Control-Allow-Origin", "*")
            elif origin and origin_allowed(origin, self.cors_patterns):
                self.send_header("Access-Control-Allow-Origin", origin)

        self.send_header("Access-Control-Allow-Methods", self.allow_methods)
        self.send_header("Access-Control-Allow-Headers", self.allow_headers)
        if self.expose_headers:
            self.send_header("Access-Control-Expose-Headers", self.expose_headers)
        if self.max_age:
            self.send_header("Access-Control-Max-Age", str(self.max_age))
        self.send_header("Vary", "Origin")

    # ------------------------------------------------------------------
    # Preflight
    # ------------------------------------------------------------------
    def do_OPTIONS(self):
        self.log(f"OPTIONS {self.path} from {self.client_address}")
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_cors_headers()
        self.end_headers()

    # ------------------------------------------------------------------
    # POST
    # ------------------------------------------------------------------
    def do_POST(self):
        self.log(f"POST {self.path} from {self.client_address}")
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > self.max_body_size:
            self._respond_text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Payload too large\n")
            return

        content_type = self.headers.get("Content-Type", "")
        raw = self.rfile.read(content_length)
        parsed, body_to_save = self._parse_payload(raw, content_type)

        os.makedirs(self.save_dir, exist_ok=True)
        filename = self.save_dir / f"received_{datetime.utcnow().strftime('%Y%m%dT%H%M%S%f')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(body_to_save)

        response = {"status": "ok", "saved": str(filename.resolve()), "parsed": parsed}
        self._respond_json(HTTPStatus.OK, response)

    def _parse_payload(self, raw: bytes, content_type: str):
        """Parse incoming payload based on content type."""
        parsed = None
        try:
            if "application/json" in content_type:
                parsed = json.loads(raw.decode("utf-8"))
                return parsed, json.dumps(parsed, indent=2)
            elif "application/x-www-form-urlencoded" in content_type:
                parsed_qs = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
                parsed = {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()}
                return parsed, urllib.parse.unquote_plus(raw.decode("utf-8"))
            else:
                # binary or unknown data
                try:
                    return None, raw.decode("utf-8")
                except UnicodeDecodeError:
                    return {"_base64": True, "size": len(raw)}, base64.b64encode(raw).decode("ascii")
        except Exception as e:
            self.log("Parse error:", e)
            raise

    def _respond_json(self, status: int, payload: dict):
        """Send JSON response."""
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))

    def _respond_text(self, status: int, text: str):
        """Send plain text response."""
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    # ------------------------------------------------------------------
    # GET
    # ------------------------------------------------------------------
    def do_GET(self):
        if self.path in ("/", "/status"):
            info = {
                "server": self.server_version,
                "time": datetime.utcnow().isoformat(),
                "allowed_origins": [p.pattern for p in self.cors_patterns],
                "allow_credentials": self.allow_credentials,
                "max_body_size": self.max_body_size,
            }
            self._respond_json(HTTPStatus.OK, info)
        else:
            super().do_GET()


# ------------------------------------------------------------------------------
# Server runner
# ------------------------------------------------------------------------------

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def run_server(args):
    patterns = compile_origin_patterns(args.allow_origin)
    FlexibleCORSHandler.cors_patterns = patterns
    FlexibleCORSHandler.allow_credentials = args.allow_credentials
    FlexibleCORSHandler.allow_methods = args.allow_methods
    FlexibleCORSHandler.allow_headers = args.allow_headers
    FlexibleCORSHandler.expose_headers = args.expose_headers
    FlexibleCORSHandler.max_age = args.preflight_max_age
    FlexibleCORSHandler.max_body_size = args.max_body_size
    FlexibleCORSHandler.save_dir = Path(args.save_dir)
    FlexibleCORSHandler.verbose = args.verbose

    address = ("0.0.0.0", args.port)
    server = ThreadingTCPServer(address, FlexibleCORSHandler)

    def shutdown_handler(signum, _):
        print("Shutting down gracefully...", file=sys.stderr)
        threading.Thread(target=server.shutdown).start()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print(f"Serving on {address[0]}:{address[1]} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    finally:
        server.server_close()
        print("Server stopped")


def parse_args():
    p = argparse.ArgumentParser(description="Flexible CORS demo server (lab use only)")
    p.add_argument("--port", "-p", type=int, default=8000, help="Port to listen on")
    p.add_argument("--allow-origin", "-o", action="append", default=["*"],
                   help="Allowed origin(s). Supports exact, wildcard (*.example.com), or '*'.")
    p.add_argument("--allow-credentials", action="store_true",
                   help="Allow credentials (cookies). Disables wildcard origin responses.")
    p.add_argument("--allow-methods", default="GET, POST, OPTIONS", help="Allowed HTTP methods.")
    p.add_argument("--allow-headers", default="Content-Type, Authorization", help="Allowed headers.")
    p.add_argument("--expose-headers", help="Expose headers to browser.")
    p.add_argument("--preflight-max-age", type=int, default=600, help="Preflight cache duration (seconds).")
    p.add_argument("--max-body-size", type=int, default=4 * 1024 * 1024, help="Maximum request body size in bytes.")
    p.add_argument("--save-dir", default="./received", help="Directory to store received payloads.")
    p.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.allow_credentials and "*" in args.allow_origin:
        print("WARNING: --allow-credentials used with '*'. Browser will reject credentials with wildcard origins.",
              file=sys.stderr)
    run_server(args)
