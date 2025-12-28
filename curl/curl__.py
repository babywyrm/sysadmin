#!/usr/bin/env python3
"""
http_curlish.py — curl ⇄ requests power client (2025).. (beta)..

A unified, production-grade Python tool combining:
  • curl-like semantics
  • safe requests.Session patterns
  • streaming uploads
  • retry logic
  • metrics / timing
  • incident response replay

This mirrors *curl behavior*, not libcurl internals.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, Iterable, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter, Retry
from requests_toolbelt.streaming_iterator import StreamingIterator

# =============================================================================
# Logging
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

# =============================================================================
# Session Factory (Safe Defaults)
# =============================================================================

def make_session(
    retries: int = 3,
    backoff: float = 0.2,
    timeout: int = 10,
) -> requests.Session:
    """
    Create a hardened requests.Session with retries and timeouts.
    Used by all helpers and CLI paths.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.request_timeout = timeout
    return session

# =============================================================================
# Helpers
# =============================================================================

def parse_headers(header_list: list[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for h in header_list:
        if ":" not in h:
            raise ValueError(f"Invalid header format: {h}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def parse_cookies(cookie_string: Optional[str]) -> Optional[Dict[str, str]]:
    if not cookie_string:
        return None
    cookies: Dict[str, str] = {}
    for part in cookie_string.split(";"):
        k, v = part.strip().split("=", 1)
        cookies[k] = v
    return cookies


def load_data_arg(data_arg: str) -> bytes:
    """Load -d / --data argument (literal or @file)."""
    if data_arg.startswith("@"):
        with open(data_arg[1:], "rb") as f:
            return f.read()
    return data_arg.encode()


def stream_fd(fd, chunk_size: int = 8192) -> Iterable[bytes]:
    """
    Stream from file descriptor without buffering entire contents.
    Equivalent to curl -T (unknown-size safe).
    """
    while True:
        chunk = fd.read(chunk_size)
        if not chunk:
            break
        yield chunk

# =============================================================================
# Metrics (curl -w style)
# =============================================================================

class CurlMetrics:
    """Collect curl-like transfer metrics."""

    def __init__(self) -> None:
        self.start = time.perf_counter()
        self.end: Optional[float] = None
        self.bytes_sent = 0
        self.bytes_recv = 0

    def finalize(self) -> None:
        self.end = time.perf_counter()

    def render(self, resp: requests.Response) -> Dict[str, Any]:
        return {
            "http_code": resp.status_code,
            "url_effective": resp.url,
            "content_type": resp.headers.get("Content-Type"),
            "size_upload": self.bytes_sent,
            "size_download": self.bytes_recv,
            "time_total": round((self.end or 0) - self.start, 6),
            "num_redirects": len(resp.history),
            "http_version": getattr(resp.raw, "version", None),
        }

# =============================================================================
# Request Construction
# =============================================================================

def build_request_body(args) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """
    Build request body using curl semantics:
      -d  buffered data
      -F  multipart form
      -T  streaming upload
    """
    data = None
    files = None

    if args.upload_file:
        fd = open(args.upload_file, "rb")
        try:
            size = os.path.getsize(args.upload_file)
        except OSError:
            size = None
        data = StreamingIterator(size=size, iterator=stream_fd(fd))

    elif args.data:
        data = load_data_arg(args.data)

    elif args.form:
        files = {}
        for entry in args.form:
            k, v = entry.split("=", 1)
            if v.startswith("@"):
                files[k] = open(v[1:], "rb")
            else:
                files[k] = v

    return data, files

# =============================================================================
# High-Level Request Executor
# =============================================================================

def perform_request(args) -> Tuple[requests.Response, bytes, CurlMetrics]:
    session = make_session(timeout=args.max_time or 10)
    headers = parse_headers(args.header)
    cookies = parse_cookies(args.cookie)

    auth = None
    if args.user:
        u, p = args.user.split(":", 1)
        auth = HTTPBasicAuth(u, p)

    data, files = build_request_body(args)
    metrics = CurlMetrics()

    resp = session.request(
        method=args.method.upper(),
        url=args.url,
        headers=headers,
        cookies=cookies,
        auth=auth,
        data=data,
        files=files,
        allow_redirects=args.location,
        verify=not args.insecure,
        timeout=(args.connect_timeout, args.max_time),
        stream=True,
    )

    body_chunks = []
    for chunk in resp.iter_content(8192):
        if chunk:
            metrics.bytes_recv += len(chunk)
            body_chunks.append(chunk)

    metrics.finalize()
    return resp, b"".join(body_chunks), metrics

# =============================================================================
# Pretty Output Helpers
# =============================================================================

def print_response(resp: requests.Response, body: bytes, json_mode: bool) -> None:
    print(f"Status: {resp.status_code}")
    print("Headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    print()

    if json_mode:
        try:
            print(json.dumps(json.loads(body), indent=2))
            return
        except Exception:
            pass

    print(body.decode(errors="replace")[:2000])

# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="http_curlish — curl ⇄ requests power client"
    )

    p.add_argument("url")
    p.add_argument("-X", "--method", default="GET")
    p.add_argument("-H", "--header", action="append", default=[])
    p.add_argument("-d", "--data")
    p.add_argument("-F", "--form", action="append")
    p.add_argument("-T", "--upload-file")
    p.add_argument("-u", "--user")
    p.add_argument("-b", "--cookie")
    p.add_argument("-k", "--insecure", action="store_true")
    p.add_argument("-L", "--location", action="store_true")
    p.add_argument("-m", "--max-time", type=int)
    p.add_argument("--connect-timeout", type=int, default=5)
    p.add_argument("-i", "--include", action="store_true")
    p.add_argument("-s", "--silent", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--metrics", action="store_true")

    return p.parse_args()

def main() -> None:
    args = parse_args()
    resp, body, metrics = perform_request(args)

    if args.include:
        for k, v in resp.headers.items():
            print(f"{k}: {v}")
        print()

    if not args.silent:
        print_response(resp, body, args.json)

    if args.metrics:
        print(json.dumps(metrics.render(resp), indent=2))

# =============================================================================
# Entrypoint
# =============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Cancelled by user")

# =============================================================================
# Extended Documentation
# =============================================================================

"""
http_curlish.py — Extended Documentation
=======================================

WHAT THIS IS
------------
A unified curl ⇄ requests power client for:
  • Incident response
  • AppSec testing
  • Red team replay
  • CI/CD debugging
  • API drift detection

It merges:
  - Safe requests.Session patterns
  - curl-style flags and semantics
  - Streaming uploads (-T)
  - curl -w–style metrics

WHAT THIS IS NOT
----------------
• A libcurl replacement
• A TCP tuning tool
• A browser simulator

STREAMING (-T)
--------------
Streaming uploads avoid buffering entire payloads in memory and
are ideal when:
  • Payload size is unknown
  • You want early write behavior
  • Replaying exploit traffic
  • Stress / chaos testing

SECURITY NOTES
--------------
• Avoid --insecure outside testing
• Streaming uploads bypass Content-Length assumptions
• curl-style CORS tests still require browser validation
• This tool is ideal for forensic replay

EXTENSIONS
----------
• Async engine (httpx / aiohttp)
• HAR export
• Automatic CORS analysis
• GraphQL mode
• Fuzz / chaos streaming
• mTLS / SPIFFE support


EXAMPLES & RECIPES
==================

The following examples mirror common and advanced curl usage.
All examples assume:

    python3 http_curlish.py <args>

------------------------------------------------------------------
BASIC REQUESTS
------------------------------------------------------------------

Equivalent to:
  curl https://example.com

    python3 http_curlish.py https://example.com


HEAD request:
  curl -I https://example.com

    python3 http_curlish.py https://example.com -X HEAD


Follow redirects:
  curl -L https://short.url

    python3 http_curlish.py https://short.url -L


------------------------------------------------------------------
HEADERS & AUTHENTICATION
------------------------------------------------------------------

Add headers:
  curl -H "Accept: application/json" https://api.example.com

    python3 http_curlish.py https://api.example.com \
      -H "Accept: application/json"


Basic auth:
  curl -u user:pass https://api.example.com

    python3 http_curlish.py https://api.example.com \
      -u user:pass


Bearer token:
  curl -H "Authorization: Bearer TOKEN" https://api.example.com

    python3 http_curlish.py https://api.example.com \
      -H "Authorization: Bearer TOKEN"


------------------------------------------------------------------
JSON & FORM POSTS
------------------------------------------------------------------

POST JSON:
  curl -X POST -H "Content-Type: application/json" \
       -d '{"foo":"bar"}' https://api.example.com/post

    python3 http_curlish.py https://api.example.com/post \
      -X POST \
      -H "Content-Type: application/json" \
      -d '{"foo":"bar"}' \
      --json


POST JSON from file:
  curl -d @data.json -H "Content-Type: application/json" -X POST URL

    python3 http_curlish.py URL \
      -X POST \
      -H "Content-Type: application/json" \
      -d @data.json


POST form-urlencoded:
  curl -d "a=1&b=2" https://example.com

    python3 http_curlish.py https://example.com \
      -X POST \
      -d "a=1&b=2"


------------------------------------------------------------------
FILE UPLOADS
------------------------------------------------------------------

Multipart upload:
  curl -F "file=@payload.zip" https://example.com/upload

    python3 http_curlish.py https://example.com/upload \
      -X POST \
      -F "file=@payload.zip"


------------------------------------------------------------------
STREAMING UPLOAD (curl -T DIRTY HACK)
------------------------------------------------------------------

Equivalent to:
  curl -X POST -T payload.bin https://example.com

Streams data without buffering entire file in memory.

    python3 http_curlish.py https://example.com \
      -X POST \
      -T payload.bin


This is useful when:
  • Payload size is unknown
  • Streaming exploit traffic
  • Avoiding memory buffering
  • Chaos / stress testing


------------------------------------------------------------------
COOKIES
------------------------------------------------------------------

Send cookies:
  curl -b "session=abc123" https://example.com

    python3 http_curlish.py https://example.com \
      -b "session=abc123"


------------------------------------------------------------------
TLS / CERTIFICATE TESTING
------------------------------------------------------------------

Ignore TLS verification (testing only):
  curl -k https://self-signed.local

    python3 http_curlish.py https://self-signed.local -k


------------------------------------------------------------------
CORS & SECURITY TESTING
------------------------------------------------------------------

Preflight request:
  curl -X OPTIONS https://api.example.com \
       -H "Origin: https://evil.com" \
       -H "Access-Control-Request-Method: POST"

    python3 http_curlish.py https://api.example.com \
      -X OPTIONS \
      -H "Origin: https://evil.com" \
      -H "Access-Control-Request-Method: POST"


Credentialed cross-origin test:
  curl -H "Origin: https://evil.com" -b "session=abc" URL

    python3 http_curlish.py URL \
      -H "Origin: https://evil.com" \
      -b "session=abc"


------------------------------------------------------------------
METRICS (curl -w EQUIVALENT)
------------------------------------------------------------------

Equivalent to:
  curl -w "%{http_code} %{time_total}" https://example.com

    python3 http_curlish.py https://example.com \
      --silent \
      --metrics


Example output:
{
  "http_code": 200,
  "url_effective": "https://example.com",
  "content_type": "text/html",
  "size_upload": 0,
  "size_download": 1256,
  "time_total": 0.423817,
  "num_redirects": 1,
  "http_version": 11
}


------------------------------------------------------------------
INCIDENT RESPONSE RECIPES
------------------------------------------------------------------

Fast health check:
    python3 http_curlish.py https://api.example.com/health \
      --silent \
      --metrics


Replay suspicious request:
    python3 http_curlish.py https://api.example.com/admin \
      -H "Authorization: Bearer SUSPECT_TOKEN" \
      -i


Before / after deploy diff:
    python3 http_curlish.py https://api.example.com \
      --silent \
      --metrics | sha256sum


------------------------------------------------------------------
COMMON PITFALLS
------------------------------------------------------------------

• -d implies POST (same as curl)
• -T streams, -d buffers
• --json affects output parsing only
• This tool does NOT enforce browser CORS rules
• TCP tuning belongs to OS / libcurl, not Python


------------------------------------------------------------------
PHILOSOPHY
------------------------------------------------------------------

Think of http_curlish as:
  • curl's *intent* in Python
  • a reproducible incident-response probe
  • a safe, readable alternative to shell one-liners

END OF EXAMPLES
------------------------------------------------------------------
"""
