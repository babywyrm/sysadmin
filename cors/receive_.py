#!/usr/bin/env python3
"""
Flexible CORS-enabled HTTP server (demo / lab use only)... beta edition ...

Usage (examples):
  python cors_server.py --port 8080 --allow-origin https://app.example.com --allow-origin https://admin.example.com \
       --allow-credentials --save-dir ./received --max-body-size 1048576 --threaded

Notes:
- Do NOT use this in production as-is. Validate and harden appropriately.
- If --allow-credentials is set, the server will *never* return Access-Control-Allow-Origin: *.
  Instead it will echo back an allowed origin from the allowlist (if present).
"""
import argparse
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
from typing import Iterable, List, Optional, Pattern, Tuple

# --------- Utilities for origin matching ---------
def compile_origin_patterns(origins: Iterable[str]) -> List[Pattern]:
    """Compile a list of origin match regexes from user-provided allowlist.
    Accepts exact origins (https://foo.example) or simple wildcard like *.example.com
    """
    patterns = []
    for o in origins:
        o = o.strip()
        if not o:
            continue
        if o == "*":
            patterns.append(re.compile(r"^.*$"))
            continue
        # If user provided a wildcard like *.example.com -> convert to regex
        if o.startswith("*."):
            host = re.escape(o[2:])
            patterns.append(re.compile(r"^https?://([a-zA-Z0-9_\-]+\.)?%s(:\d+)?$" % host))
            continue
        # Exact origin (allow scheme and optional port)
        # Ensure we match scheme://host(:port)?
        # escape
        esc = re.escape(o)
        patterns.append(re.compile(rf"^{esc}$"))
    return patterns

def origin_allowed(origin: Optional[str], patterns: List[Pattern]) -> bool:
    if origin is None:
        return False
    origin = origin.strip()
    for p in patterns:
        if p.match(origin):
            return True
    return False

# --------- Request Handler ---------
class FlexibleCORSHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "FlexibleCORS/2025"

    # configuration set at server creation
    cors_patterns: List[Pattern] = []
    allow_credentials: bool = False
    allow_methods: str = "GET, POST, OPTIONS"
    allow_headers: str = "Content-Type, Authorization"
    expose_headers: Optional[str] = None
    max_age: int = 600
    max_body_size: int = 4 * 1024 * 1024  # 4 MiB
    save_dir: Path = Path(".")
    verbose: bool = True

    def log(self, *parts):
        if self.verbose:
            now = datetime.utcnow().isoformat()
            print(f"[{now}] ", *parts, file=sys.stderr)

    def _get_origin(self) -> Optional[str]:
        return self.headers.get("Origin")

    def _set_cors_headers(self):
        """Set the appropriate CORS headers for the current request.
        Must be called BEFORE end_headers() / after send_response().
        """
        origin = self._get_origin()

        # If credentials are allowed, we cannot return '*' as origin.
        if self.allow_credentials:
            # echo allowed origin if present and allowed
            if origin and origin_allowed(origin, self.cors_patterns):
                self.send_header("Access-Control-Allow-Origin", origin)
            else:
                # No allowed origin: don't advertise credentials support
                # we won't set Access-Control-Allow-Origin at all in this case.
                pass
            # Indicate credentials allowed only when we echoed an allowed origin
            if origin and origin_allowed(origin, self.cors_patterns):
                self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            # credentials not allowed -> we can use wildcard if patterns include wildcard
            # If the allowlist contains a global pattern, return '*'
            if any(p.pattern == r"^.*$" for p in self.cors_patterns):
                self.send_header("Access-Control-Allow-Origin", "*")
            else:
                # try to echo origin if allowed
                if origin and origin_allowed(origin, self.cors_patterns):
                    self.send_header("Access-Control-Allow-Origin", origin)

        # Common headers
        self.send_header("Access-Control-Allow-Methods", self.allow_methods)
        self.send_header("Access-Control-Allow-Headers", self.allow_headers)
        if self.expose_headers:
            self.send_header("Access-Control-Expose-Headers", self.expose_headers)
        # allow caching of preflight
        if self.max_age:
            self.send_header("Access-Control-Max-Age", str(self.max_age))
        # Vary header when origin is dynamic (important for caching)
        self.send_header("Vary", "Origin")

    def end_headers(self):
        # end_headers might be called in many contexts; only add CORS if we haven't already
        # Note: This pattern is safe because send_header appends headers prior to sending.
        # But we guard to avoid duplicating.
        # We'll call set headers only if the handler didn't previously add Access-Control-Allow-Origin.
        if "Access-Control-Allow-Origin" not in self._headers_buffer:
            # can't easily introspect previous send_header calls; use _get_origin to decide
            # We'll still attempt to set CORS headers (set_cors_headers will skip if mismatch)
            try:
                self._set_cors_headers()
            except Exception as e:
                # never fail header emission because of header logic
                self.log("CORS header error:", e)
        super().end_headers()

    # Preflight handler
    def do_OPTIONS(self):
        self.log(f"OPTIONS {self.path} from {self.client_address}")
        self.send_response(HTTPStatus.NO_CONTENT)
        # set CORS headers then finish
        self._set_cors_headers()
        # No body for preflight
        self.end_headers()

    # POST handler with safe parsing and saving
    def do_POST(self):
        self.log(f"POST {self.path} from {self.client_address}")
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > self.max_body_size:
            self.send_response(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            self._set_cors_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Payload too large\n")
            return

        raw = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type", "")

        parsed = None
        saved_filename = None
        try:
            if "application/json" in content_type:
                parsed = json.loads(raw.decode("utf-8"))
                body_to_save = json.dumps(parsed, indent=2)
            elif "application/x-www-form-urlencoded" in content_type:
                parsed_qs = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
                parsed = {k: v if len(v) > 1 else v[0] for k, v in parsed_qs.items()}
                body_to_save = urllib.parse.unquote_plus(raw.decode("utf-8"))
            else:
                # fallback: save raw bytes safely as hex or utf-8 attempt
                try:
                    body_to_save = raw.decode("utf-8")
                except UnicodeDecodeError:
                    # binary payload, save as base64 for safety
                    import base64
                    body_to_save = base64.b64encode(raw).decode("ascii")
                    parsed = {"_base64": True, "size": len(raw)}

            # Persist to file - unique name with timestamp
            fname = f"received_{datetime.utcnow().strftime('%Y%m%dT%H%M%S%f')}.txt"
            target = (self.save_dir / fname)
            os.makedirs(self.save_dir, exist_ok=True)
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(body_to_save)
            saved_filename = str(target.resolve())

            # Respond success with JSON body summarizing
            self.send_response(HTTPStatus.OK)
            # set CORS headers then content-type then end
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()

            response = {
                "status": "ok",
                "saved": saved_filename,
                "parsed": parsed,
            }
            self.wfile.write(json.dumps(response, indent=2).encode("utf-8"))

        except json.JSONDecodeError as jde:
            self.log("JSON error:", jde)
            self.send_response(HTTPStatus.BAD_REQUEST)
            self._set_cors_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Invalid JSON\n")
        except Exception as e:
            self.log("Unhandled error:", e)
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self._set_cors_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Internal Server Error\n")

    # Optional: show a friendly root endpoint
    def do_GET(self):
        if self.path == "/" or self.path == "/status":
            info = {
                "server": self.server_version,
                "time": datetime.utcnow().isoformat(),
                "allowed_origins": [p.pattern for p in self.cors_patterns],
                "allow_credentials": self.allow_credentials,
                "max_body_size": self.max_body_size,
            }
            self.send_response(HTTPStatus.OK)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(info, indent=2).encode("utf-8"))
            return
        # otherwise fallback to static file handler behavior
        super().do_GET()

# --------- Server runner and arg parsing ---------
class ThreadingTCPServerReusable(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

def run_server(args):
    # compile origin patterns
    patterns = compile_origin_patterns(args.allow_origin) if args.allow_origin else [re.compile(r"^.*$")]
    # attach configuration to handler class
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
    server = ThreadingTCPServerReusable(address, FlexibleCORSHandler)

    def shutdown_handler(signum, frame):
        print("Shutting down gracefully...", file=sys.stderr)
        threading.Thread(target=server.shutdown).start()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print(f"Serving on {address[0]}:{address[1]} (ctrl-c to stop)", file=sys.stderr)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        print("Server stopped", file=sys.stderr)

def parse_args():
    p = argparse.ArgumentParser(description="Flexible CORS demo server (lab use only)")
    p.add_argument("--port", "-p", type=int, default=8000, help="Port to listen on")
    p.add_argument("--allow-origin", "-o", action="append", default=["*"],
                   help="Allowed Origin (repeatable). Accepts exact origin (https://a.com) or wildcard (*.example.com) or '*'")
    p.add_argument("--allow-credentials", action="store_true", help="Allow credentials (cookies). NOTE: will not emit '*' as origin.")
    p.add_argument("--allow-methods", default="GET, POST, OPTIONS", help="Comma-separated Allowed Methods")
    p.add_argument("--allow-headers", default="Content-Type, Authorization", help="Comma-separated Allowed Headers")
    p.add_argument("--expose-headers", default=None, help="Comma-separated Expose-Headers")
    p.add_argument("--preflight-max-age", type=int, default=600, help="Access-Control-Max-Age (seconds)")
    p.add_argument("--max-body-size", type=int, default=4 * 1024 * 1024, help="Max body size in bytes")
    p.add_argument("--save-dir", default="./received", help="Directory to save received payloads")
    p.add_argument("--threaded", action="store_true", help="Use threading (default server uses threads class anyway)")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    # basic sanity checks
    if args.allow_credentials and ("*" in args.allow_origin):
        print("WARNING: --allow-credentials set while --allow-origin contains '*'.\n"
              "Browsers will reject Access-Control-Allow-Origin: * with credentials; "
              "server will echo origins only when they match the allowlist.", file=sys.stderr)

    run_server(args)

##
##

##
##

import http.server
import socketserver
import urllib.parse

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Credentials', 'true')  # Allow credentials
        super().end_headers()

    def do_OPTIONS(self):
        # Respond to preflight OPTIONS request
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        # Handle POST request
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        try:
            # Save data to a file
            file_name = 'received_data.txt'
            with open(file_name, 'w') as file:
                file.write(post_data)

            # Decode URL-encoded data
            decoded_data = urllib.parse.unquote(post_data)
            print('Decoded data:', decoded_data)

            # Process the decoded data as needed

            # Send a response
            response = 'Success'
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            # Handle other exceptions
            print('Error:', str(e))
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

# Set up the server
port = 80
httpd = socketserver.TCPServer(("0.0.0.0", port), MyHandler)

print(f"Serving at port {port}")
httpd.serve_forever()

##
