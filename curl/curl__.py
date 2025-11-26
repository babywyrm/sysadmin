#!/usr/bin/env python3
"""
http_cheatsheet.py .. curl <> requests 
------------------
Comprehensive Python equivalents of curl patterns using the 'requests' library.
Designed for clarity and security.  Includes session management, authentication,
JSON APIs, file uploads, TLS configuration, and retry handling.
"""

import base64
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter, Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

# ----------------------------------------------------------------------
#  Session Factory - used by all examples for safe retries and timeouts
# ----------------------------------------------------------------------


def make_session(
    retries: int = 3, backoff: float = 0.2, timeout: int = 10
) -> requests.Session:
    """Create a Session with retry and timeout configuration."""
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


# ----------------------------------------------------------------------
#  Utility: response printer
# ----------------------------------------------------------------------


def print_response(resp: requests.Response) -> None:
    """Pretty‑print response info."""
    print(f"Status: {resp.status_code}")
    print("Headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    print()
    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text)
    else:
        print(resp.text[:500])  # preview only


# ----------------------------------------------------------------------
#  Basic Requests
# ----------------------------------------------------------------------


def get_url(url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
    s = make_session()
    return s.get(url, params=params, timeout=s.request_timeout)


def head_url(url: str) -> requests.Response:
    s = make_session()
    return s.head(url, timeout=s.request_timeout)


def download_file(url: str, filename: str) -> None:
    s = make_session()
    with s.get(url, stream=True, timeout=s.request_timeout) as r:
        r.raise_for_status()
        with open(filename, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    logging.info(f"Downloaded {filename}")


# ----------------------------------------------------------------------
#  Authentication Examples
# ----------------------------------------------------------------------


def basic_auth(url: str, user: str, password: str) -> requests.Response:
    s = make_session()
    return s.get(url, auth=(user, password), timeout=s.request_timeout)


def bearer_auth(url: str, token: str) -> requests.Response:
    s = make_session()
    headers = {"Authorization": f"Bearer {token}"}
    return s.get(url, headers=headers, timeout=s.request_timeout)


def oauth2_password_grant(
    auth_url: str, username: str, password: str, client_id: str, client_secret: str
) -> Dict[str, Any]:
    s = make_session()
    payload = {
        "grant_type": "password",
        "username": username,
        "password": password,
    }
    r = s.post(
        auth_url, data=payload, auth=(client_id, client_secret), timeout=s.request_timeout
    )
    r.raise_for_status()
    return r.json()


# ----------------------------------------------------------------------
#  Sending JSON, Form Data, and Files
# ----------------------------------------------------------------------


def post_json(url: str, data: Dict[str, Any], token: Optional[str] = None) -> requests.Response:
    s = make_session()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return s.post(url, headers=headers, data=json.dumps(data), timeout=s.request_timeout)


def post_form(url: str, data: Dict[str, str]) -> requests.Response:
    s = make_session()
    return s.post(url, data=data, timeout=s.request_timeout)


def upload_file(url: str, filepath: str, extra_fields: Optional[Dict[str, str]] = None) -> requests.Response:
    s = make_session()
    files = {"file": open(filepath, "rb")}
    data = extra_fields or {}
    try:
        return s.post(url, files=files, data=data, timeout=s.request_timeout)
    finally:
        files["file"].close()


# ----------------------------------------------------------------------
#  Advanced / Secure Options
# ----------------------------------------------------------------------


def custom_ca_request(url: str, ca_path: str) -> requests.Response:
    """Verify server against custom CA certificate."""
    s = make_session()
    return s.get(url, verify=ca_path, timeout=s.request_timeout)


def client_cert_request(url: str, cert: str, key: Optional[str] = None) -> requests.Response:
    s = make_session()
    cert_param = (cert, key) if key else cert
    return s.get(url, cert=cert_param, timeout=s.request_timeout)


def ignore_tls_request(url: str) -> requests.Response:
    s = make_session()
    return s.get(url, verify=False, timeout=s.request_timeout)


# ----------------------------------------------------------------------
#  HTTP Methods
# ----------------------------------------------------------------------


def put_json(url: str, data: Dict[str, Any]) -> requests.Response:
    s = make_session()
    return s.put(url, json=data, timeout=s.request_timeout)


def patch_json(url: str, data: Dict[str, Any]) -> requests.Response:
    s = make_session()
    return s.patch(url, json=data, timeout=s.request_timeout)


def delete_resource(url: str) -> requests.Response:
    s = make_session()
    return s.delete(url, timeout=s.request_timeout)


# ----------------------------------------------------------------------
#  Timing and Measurement
# ----------------------------------------------------------------------


def timed_get(url: str) -> Tuple[float, requests.Response]:
    s = make_session()
    start = time.perf_counter()
    r = s.get(url, timeout=s.request_timeout)
    duration = time.perf_counter() - start
    return duration, r


# ----------------------------------------------------------------------
#  Example Interactive Entry Point
# ----------------------------------------------------------------------


def main() -> None:
    """Simple demo sequence showing typical usage patterns."""
    url = "https://httpbin.org/get"
    logging.info("Performing GET example...")
    r = get_url(url)
    print_response(r)

    logging.info("\nPOST JSON example")
    r = post_json("https://httpbin.org/post", {"foo": "bar"})
    print_response(r)

    logging.info("\nHEAD example")
    r = head_url(url)
    logging.info(f"HEAD status: {r.status_code}")

    logging.info("\nTiming example")
    t, r = timed_get(url)
    logging.info(f"GET completed in {t:.3f}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Cancelled by user")
