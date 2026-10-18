#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A modernized simple HTTP forward proxy using Flask.

Improvements:
  ✓ Type hints and docstrings
  ✓ Unified handling for JSON, form, and query parameters
  ✓ Safe header forwarding (optional)
  ✓ Error handling and logging
  ✓ Better streaming and timeouts
  ✓ Security: restrict allowed schemes and methods
  ✓ Runs well under Python 3.10–3.13
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from flask import Flask, Response, request, stream_with_context, abort
import requests

app = Flask(__name__)

# --- Configuration ---
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_METHODS = {"GET", "POST"}
TIMEOUT = 10  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
)


# --- Utility Functions ---
def is_valid_target(url: str) -> bool:
    """Ensure the target URL uses an allowed scheme and looks sane."""
    return any(url.startswith(f"{scheme}://") for scheme in ALLOWED_SCHEMES)


def build_request_kwargs() -> dict[str, Any]:
    """Extract payload and type from the incoming Flask request."""
    if request.is_json:
        payload = request.get_json(silent=True)
        logging.debug("Proxy payload (JSON): %s", payload)
        return {"json": payload}

    elif request.form:
        payload = request.form.to_dict(flat=False)
        logging.debug("Proxy payload (FORM): %s", payload)
        return {"data": payload}

    elif request.data:
        payload = request.data
        logging.debug("Proxy payload (RAW): %s bytes", len(payload))
        return {"data": payload}

    return {}


def forward_request(url: str) -> Response:
    """Stream the response from the target request back to the caller."""
    if not is_valid_target(url):
        abort(400, f"Invalid or disallowed URL scheme: {url}")

    if request.method not in ALLOWED_METHODS:
        abort(405, f"Method {request.method} not allowed.")

    http_method = requests.post if request.method == "POST" else requests.get
    request_kwargs = build_request_kwargs()

    # Optional: selectively forward safe headers
    safe_headers = {"User-Agent": request.headers.get("User-Agent", "ProxyClient")}
    try:
        upstream = http_method(
            url,
            headers=safe_headers,
            stream=True,
            timeout=TIMEOUT,
            **request_kwargs,
        )
    except requests.RequestException as exc:
        logging.exception("Request to %s failed: %s", url, exc)
        abort(502, f"Upstream error: {exc}")

    def generate_stream():
        try:
            for chunk in upstream.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    logging.info("[%s] %s → %s [%s]",
                 request.remote_addr,
                 request.method,
                 url,
                 upstream.status_code)

    return Response(
        stream_with_context(generate_stream()),
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type", "application/octet-stream"),
    )


# --- Routes ---
@app.route("/<path:url>", methods=list(ALLOWED_METHODS))
def proxy(url: str) -> Response:
    """Forward the request to the target URL (e.g., /https://example.com/api)."""
    logging.info("Proxy requested: %s %s", request.method, url)
    return forward_request(url)


# --- Run Server ---
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
