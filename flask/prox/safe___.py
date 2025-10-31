#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Safely stream external responses through a simple Flask proxy.
Modernized version of an older educational example.

Usage:
  http://localhost:8080/p/<target-host>/<target-path>

Example:
  http://localhost:8080/p/www.google.com/
  http://localhost:8080/p/google.com/search?q=flask+proxy
"""

from __future__ import annotations
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse
import logging

from flask import (
    Flask,
    Response,
    request,
    abort,
    redirect,
    render_template,
    stream_with_context,
)
import requests

# --- Configuration ---
app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
)
LOG = logging.getLogger("safe_proxy")

# Only allow these target hosts (prevents open proxy abuse)
APPROVED_HOSTS = {"google.com", "www.google.com", "yahoo.com"}
CHUNK_SIZE = 8192
TIMEOUT = 10  # seconds


# --------------------------------------------------------------------------------
# Utility helpers
# --------------------------------------------------------------------------------
def split_url(url: str) -> Tuple[str, str, str]:
    """Split the URL into (scheme, host, path)."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.scheme, parsed.netloc or parsed.path, parsed.path or ""


def is_approved(url: str) -> bool:
    """Verify host is in APPROVED_HOSTS."""
    scheme, host, _ = split_url(url)
    return host in APPROVED_HOSTS


def proxy_ref_info(req) -> Optional[Tuple[str, str]]:
    """
    Determine if a request came from a proxied page.
    Example Referer:
      http://localhost:8080/p/google.com/search?q=foo
    Returns:
      ("google.com", "search?q=foo")
    """
    ref = req.headers.get("Referer")
    if not ref:
        return None
    _, _, uri = split_url(ref)
    if "/" not in uri:
        return None
    prefix, rest = uri.split("/", 1)
    if prefix in {"p", "d"}:
        parts = rest.split("/", 1)
        return (parts[0], parts[1]) if len(parts) == 2 else (parts[0], "")
    return None


# --------------------------------------------------------------------------------
# Core request functions
# --------------------------------------------------------------------------------
def fetch_target(url: str) -> requests.Response:
    """Fetch the remote resource safely, with streaming."""
    full_url = f"http://{url}" if not url.startswith(("http://", "https://")) else url
    if not is_approved(full_url):
        LOG.warning("Disallowed URL: %s", full_url)
        abort(403, f"URL not approved: {full_url}")

    proxy_ref = proxy_ref_info(request)
    headers = {}
    if proxy_ref:
        headers["Referer"] = f"http://{proxy_ref[0]}/{proxy_ref[1]}"
    LOG.info("Fetching %s with headers %s", full_url, headers)

    try:
        resp = requests.get(
            full_url, stream=True, headers=headers, timeout=TIMEOUT, params=request.args
        )
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        LOG.exception("Upstream fetch failed: %s", e)
        abort(502, f"Upstream fetch error: {e}")


# --------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------
@app.route("/<path:url>")
def root(url: str):
    """Root path: handle directly or redirect to a proxied version."""
    LOG.info("Root request path: %s", url)
    proxy_ref = proxy_ref_info(request)
    if proxy_ref:
        # redirect URLs coming from proxied content
        q = f"?{request.query_string.decode()}" if request.query_string else ""
        redirect_url = f"/p/{proxy_ref[0]}/{url}{q}"
        LOG.info("Redirecting proxied ref to %s", redirect_url)
        return redirect(redirect_url)
    # default: render placeholder
    return render_template("hello.html", name=url, request=request)


@app.route("/p/<path:url>")
def proxy(url: str):
    """Stream a proxied request response to the client."""
    LOG.info("Proxy request for: %s", url)
    upstream = fetch_target(url)

    def generate():
        for chunk in upstream.iter_content(CHUNK_SIZE):
            if chunk:
                yield chunk
        upstream.close()

    headers = {k: v for k, v in upstream.headers.items() if k.lower() not in {"content-encoding", "transfer-encoding", "content-length"}}

    LOG.info("Upstream %s %s -> %s", request.method, url, upstream.status_code)

    return Response(
        stream_with_context(generate()),
        status=upstream.status_code,
        headers=headers,
        content_type=upstream.headers.get("Content-Type", "application/octet-stream"),
    )


# --------------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------------
if __name__ == "__main__":
    # Start simple dev server
    app.run(debug=True, host="127.0.0.1", port=8080)
