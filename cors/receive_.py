#!/usr/bin/env python3
"""
Secure CORS-Enabled HTTP/HTTPS Server (2025 Hardened Edition) ..beta..
-------------------------------------------------------------
- Flexible origin control with regex and wildcard support
- Structured logging with rotation
- Optional HTTPS with modern TLS defaults
- Threaded, safe, lab/staging use only

Example:
  python cors_server.py --port 8443 \
      --allow-origin https://app.example.com \
      --allow-credentials \
      --certfile server.crt --keyfile server.key \
      --save-dir ./received --log-dir ./logs --verbose
"""

from __future__ import annotations
import argparse, base64, http.server, json, os, re, signal, socketserver, ssl, sys, threading, urllib.parse
from datetime import datetime
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple
from logging.handlers import RotatingFileHandler
import logging

# ------------------------------------------------------------------------------
# Core Configuration Classes
# ------------------------------------------------------------------------------

class CORSConfig:
    """Encapsulates all configuration for CORS behavior."""

    def __init__(
        self,
        allow_origins: Iterable[str],
        allow_credentials: bool,
        allow_methods: str,
        allow_headers: str,
        expose_headers: Optional[str],
        preflight_max_age: int,
        max_body_size: int,
        save_dir: Path,
        log_dir: Path,
        verbose: bool = False,
    ) -> None:
        self.allow_origins = list(allow_origins)
        self.allow_credentials = allow_credentials
        self.allow_methods = allow_methods
        self.allow_headers = allow_headers
        self.expose_headers = expose_headers
        self.preflight_max_age = preflight_max_age
        self.max_body_size = max_body_size
        self.save_dir = save_dir
        self.log_dir = log_dir
        self.verbose = verbose

    @property
    def compiled_patterns(self) -> List[Pattern]:
        patterns: List[Pattern] = []
        for o in self.allow_origins:
            o = o.strip()
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

    def origin_allowed(self, origin: Optional[str]) -> bool:
        return bool(origin and any(p.match(origin.strip()) for p in self.compiled_patterns))


class RequestLogger:
    """JSON-structured, rotating logger for both audit and debugging."""

    def __init__(self, log_dir: Path, verbose: bool) -> None:
        self.log_dir = log_dir
        self.verbose = verbose
        os.makedirs(self.log_dir, exist_ok=True)

        self.logger = logging.getLogger("CORS_Server")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        file_handler = RotatingFileHandler(
            self.log_dir / "cors_server.log", maxBytes=2 * 1024 * 1024, backupCount=5
        )
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(file_handler)

    def info(self, msg: str, **extra: Any) -> None:
        record = {"message": msg, **extra}
        self.logger.info(json.dumps(record))
        if self.verbose:
            print(f"[INFO] {msg} {extra}", file=sys.stderr)

    def error(self, msg: str, **extra: Any) -> None:
        record = {"error": msg, **extra}
        self.logger.error(json.dumps(record))
        if self.verbose:
            print(f"[ERROR] {msg} {extra}", file=sys.stderr)


class PayloadSaver:
    """Persist received payloads safely to disk."""
    def __init__(self, save_dir: Path) -> None:
        self.save_dir = save_dir
        os.makedirs(self.save_dir, exist_ok=True)

    def save(self, content: str) -> Path:
        fname = f"received_{datetime.utcnow().strftime('%Y%m%dT%H%M%S%f')}.txt"
        path = self.save_dir / fname
        path.write_text(content, encoding="utf-8")
        return path.resolve()


# ------------------------------------------------------------------------------
# HTTP Handler
# ------------------------------------------------------------------------------

class SecureCORSHandler(http.server.SimpleHTTPRequestHandler):
    """Thread-safe handler for configurable CORS and HTTPS support."""

    server_version = "SecureCORS/2025"
    cors_config: CORSConfig
    logger: RequestLogger
    saver: PayloadSaver

    def log(self, msg: str, **extra: Any) -> None:
        self.logger.info(msg, client=str(self.client_address), **extra)

    # --------------------------- CORS Headers ---------------------------
    def _set_cors_headers(self) -> None:
        cfg = self.cors_config
        origin = self.headers.get("Origin")

        if cfg.allow_credentials:
            if origin and cfg.origin_allowed(origin):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            if any(p.pattern == r"^.*$" for p in cfg.compiled_patterns):
                self.send_header("Access-Control-Allow-Origin", "*")
            elif origin and cfg.origin_allowed(origin):
                self.send_header("Access-Control-Allow-Origin", origin)

        self.send_header("Access-Control-Allow-Methods", cfg.allow_methods)
        self.send_header("Access-Control-Allow-Headers", cfg.allow_headers)
        if cfg.expose_headers:
            self.send_header("Access-Control-Expose-Headers", cfg.expose_headers)
        if cfg.preflight_max_age:
            self.send_header("Access-Control-Max-Age", str(cfg.preflight_max_age))
        self.send_header("Vary", "Origin")

    # --------------------------- OPTIONS ---------------------------
    def do_OPTIONS(self) -> None:
        self.log("OPTIONS", path=self.path)
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_cors_headers()
        self.end_headers()

    # --------------------------- POST ---------------------------
    def do_POST(self) -> None:
        cfg = self.cors_config
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond_text(HTTPStatus.LENGTH_REQUIRED, "Missing Content-Length")
            return

        if length > cfg.max_body_size:
            self._respond_text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Payload too large")
            return

        content_type = self.headers.get("Content-Type", "")
        raw = self.rfile.read(length)
        parsed, text_to_save = self._parse_payload(raw, content_type)

        saved_path = self.saver.save(text_to_save)
        self.logger.info(
            "Payload received",
            client_ip=self.client_address[0],
            file=str(saved_path),
            content_type=content_type,
            bytes=len(raw),
        )

        self._respond_json(HTTPStatus.OK, {"status": "ok", "saved": str(saved_path), "parsed": parsed})

    def _parse_payload(self, raw: bytes, content_type: str) -> Tuple[Optional[dict], str]:
        try:
            if "application/json" in content_type:
                parsed = json.loads(raw.decode("utf-8"))
                return parsed, json.dumps(parsed, indent=2)
            elif "application/x-www-form-urlencoded" in content_type:
                parsed_qs = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
                parsed = {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()}
                return parsed, urllib.parse.unquote_plus(raw.decode("utf-8"))
            else:
                try:
                    text = raw.decode("utf-8")
                    return None, text
                except UnicodeDecodeError:
                    b64 = base64.b64encode(raw).decode("ascii")
                    return {"_base64": True, "size": len(raw)}, b64
        except Exception as e:
            self.logger.error("Parse error", error=str(e))
            raise

    def _respond_json(self, status: int, payload: dict) -> None:
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))

    def _respond_text(self, status: int, text: str) -> None:
        self.send_response(status)
        self._set_cors_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    # --------------------------- GET ---------------------------
    def do_GET(self) -> None:
        if self.path in ("/", "/status"):
            info = {
                "server": self.server_version,
                "time": datetime.utcnow().isoformat(),
                "allowed_origins": [p.pattern for p in self.cors_config.compiled_patterns],
                "allow_credentials": self.cors_config.allow_credentials,
                "max_body_size": self.cors_config.max_body_size,
                "https_enabled": isinstance(getattr(self.connection, "_ssl_context", None), ssl.SSLContext),
            }
            self._respond_json(HTTPStatus.OK, info)
        else:
            super().do_GET()


# ------------------------------------------------------------------------------
# Server Setup
# ------------------------------------------------------------------------------

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def run_server(args: argparse.Namespace) -> None:
    cfg = CORSConfig(
        allow_origins=args.allow_origin,
        allow_credentials=args.allow_credentials,
        allow_methods=args.allow_methods,
        allow_headers=args.allow_headers,
        expose_headers=args.expose_headers,
        preflight_max_age=args.preflight_max_age,
        max_body_size=args.max_body_size,
        save_dir=Path(args.save_dir),
        log_dir=Path(args.log_dir),
        verbose=args.verbose,
    )

    logger = RequestLogger(cfg.log_dir, cfg.verbose)
    saver = PayloadSaver(cfg.save_dir)
    SecureCORSHandler.cors_config = cfg
    SecureCORSHandler.logger = logger
    SecureCORSHandler.saver = saver

    server = ThreadedTCPServer(("0.0.0.0", args.port), SecureCORSHandler)

    # ---- HTTPS Wrapping ----
    if args.certfile and args.keyfile:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers("ECDHE+AESGCM:!SHA1:!aNULL:!eNULL")
            context.load_cert_chain(certfile=args.certfile, keyfile=args.keyfile)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            logger.info("HTTPS enabled", certfile=args.certfile)
        except Exception as e:
            logger.error("Failed to enable HTTPS", error=str(e))
    else:
        logger.info("Running in HTTP mode (no --certfile/--keyfile provided)")

    # ---- Graceful shutdown ----
    def shutdown_handler(signum: int, _frame: Any) -> None:
        logger.info("Received shutdown signal", signal=signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    scheme = "https" if args.certfile else "http"
    logger.info(f"Serving on {scheme}://0.0.0.0:{args.port}")

    try:
        server.serve_forever()
    finally:
        server.server_close()
        logger.info("Server stopped")


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Secure CORS-enabled HTTP/HTTPS server")
    p.add_argument("--port", "-p", type=int, default=8000, help="Port to listen on")
    p.add_argument("--allow-origin", "-o", action="append", default=["*"], help="Allowed origins")
    p.add_argument("--allow-credentials", action="store_true", help="Allow cookies/auth headers")
    p.add_argument("--allow-methods", default="GET, POST, OPTIONS", help="Allowed methods")
    p.add_argument("--allow-headers", default="Content-Type, Authorization", help="Allowed headers")
    p.add_argument("--expose-headers", help="Expose response headers")
    p.add_argument("--preflight-max-age", type=int, default=600, help="Cache preflight duration")
    p.add_argument("--max-body-size", type=int, default=4 * 1024 * 1024, help="Max body size (bytes)")
    p.add_argument("--save-dir", default="./received", help="Directory to save POST data")
    p.add_argument("--log-dir", default="./logs", help="Directory for logs")
    p.add_argument("--certfile", help="Path to TLS certificate (PEM)")
    p.add_argument("--keyfile", help="Path to TLS private key (PEM)")
    p.add_argument("--verbose", action="store_true", help="Verbose console output")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.allow_credentials and "*" in args.allow_origin:
        print("WARNING: Using --allow-credentials with '*' may fail in browsers", file=sys.stderr)
    run_server(args)
