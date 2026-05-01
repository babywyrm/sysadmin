#!/usr/bin/env python3
"""
DesyncCL0 - HTTP CL.0 Desync Vulnerability Detector

Based on: https://github.com/riramar/DesyncCL0
"""

import base64
import socket
import ssl
import sys
from argparse import ArgumentParser, ArgumentTypeError, Namespace
from dataclasses import dataclass, field
from http.client import HTTPResponse
from io import BytesIO
from urllib.parse import ParseResult, urlparse

__version__ = "0.0.4"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Config:
    """All runtime options in one place."""

    url: ParseResult
    smuggled_line: str = DEFAULT_SMUGGLED_LINE
    user_agent: str = DEFAULT_USER_AGENT
    timeout: int = DEFAULT_TIMEOUT
    debug: bool = False

    @property
    def host(self) -> str:
        return self.url.netloc

    @property
    def full_path(self) -> str:
        path = self.url.path or "/"
        return f"{path}?{self.url.query}" if self.url.query else path


@dataclass
class ProbeResult:
    """Holds the status codes returned by the two requests."""

    probe_status: int
    baseline_status: int
    probe_headers: dict[str, str] = field(default_factory=dict)
    baseline_headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        return self.probe_status != self.baseline_status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeSocket:
    """Wraps raw bytes so HTTPResponse can parse them."""

    def __init__(self, data: bytes) -> None:
        self._file = BytesIO(data)

    def makefile(self, *args, **kwargs) -> BytesIO:
        return self._file


def print_banner() -> None:
    print(base64.b64decode(BANNER_B64).decode())
    print(f"Version {__version__}\n")


def dbg(msg: str, flag: bool) -> None:
    """Print a debug message only when *flag* is True."""
    if flag:
        print(f"[DEBUG] {msg}")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _validate_url(value: str) -> ParseResult:
    """argparse type-validator: parse and validate a URL string."""
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ArgumentTypeError(
            f"Invalid URL: {value!r}. Example: https://www.example.com/path"
        )
    return parsed


def parse_args() -> Namespace:
    parser = ArgumentParser(
        prog="DesyncCL0",
        description="Detects HTTP desync CL.0 vulnerabilities.",
    )
    parser.add_argument(
        "URL",
        type=_validate_url,
        help="Target URL to test.",
    )
    parser.add_argument(
        "-s", "--smuggledrequestline",
        default=DEFAULT_SMUGGLED_LINE,
        metavar="LINE",
        help=f'Smuggled request line (default: "{DEFAULT_SMUGGLED_LINE}").',
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SEC",
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "-u", "--user-agent",
        dest="user_agent",
        default=DEFAULT_USER_AGENT,
        metavar="UA",
        help="User-Agent header value.",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Print raw request/response debug data.",
    )
    return parser.parse_args()


def config_from_args(args: Namespace) -> Config:
    return Config(
        url=args.URL,
        smuggled_line=args.smuggledrequestline,
        user_agent=args.user_agent,
        timeout=args.timeout,
        debug=args.debug,
    )


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------


def connect(cfg: Config) -> socket.socket:
    """Open a (TLS-wrapped) TCP connection described by *cfg*."""
    hostname = cfg.url.hostname
    port = cfg.url.port or (443 if cfg.url.scheme == "https" else 80)
    sock = socket.create_connection((hostname, port), cfg.timeout)

    if cfg.url.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=hostname)

    return sock


def _response_is_complete(data: bytes) -> bool:
    """
    Return True when *data* contains a full HTTP response.
    Handles both Content-Length and chunked Transfer-Encoding.
    """
    try:
        resp = HTTPResponse(FakeSocket(data))
        resp.begin()

        match resp.getheader("Transfer-Encoding"), resp.getheader("Content-Length"):
            case (te, _) if te is not None:
                return b"0\r\n\r\n" in data
            case (_, cl) if cl is not None:
                body = resp.read(int(cl))
                return len(body) == int(cl)
    except Exception:
        pass
    return False


def send_recv(
    sock: socket.socket,
    raw: bytes,
    debug: bool = False,
) -> tuple[HTTPResponse, bytes]:
    """
    Send *raw* over *sock*, accumulate the full response, return it.
    Exits on unrecoverable socket errors or an empty response.
    """
    sock.sendall(raw)

    data = b""
    while True:
        try:
            chunk = sock.recv(RECV_BUFFER)
        except TimeoutError:
            # Timeout during receive — treat accumulated data as complete.
            break
        except OSError as exc:
            print(f"[ERROR] Socket error after {len(data)} bytes: {exc}")
            dbg(f"Partial response:\n{data!r}", debug and bool(data))
            sys.exit(1)

        if not chunk:
            break
        data += chunk
        if _response_is_complete(data):
            break

    if not data:
        print("[ERROR] Empty response from server.")
        sys.exit(1)

    resp = HTTPResponse(FakeSocket(data))
    resp.begin()
    dbg(f"Raw response ({len(data)} bytes):\n{data!r}\n", debug)
    return resp, data


# ---------------------------------------------------------------------------
# Request building
# ---------------------------------------------------------------------------


def _build_request(
    method: str,
    path: str,
    host: str,
    user_agent: str,
    extra_headers: dict[str, str] | None = None,
    body: str = "",
) -> bytes:
    """Assemble a minimal HTTP/1.1 request."""
    headers: dict[str, str] = {
        "Host": host,
        "User-Agent": user_agent,
        "Connection": "close",
    }
    if extra_headers:
        headers |= extra_headers

    header_block = "\r\n".join(
        [f"{method} {path} HTTP/1.1"]
        + [f"{k}: {v}" for k, v in headers.items()]
        + ["", body]
    )
    return header_block.encode()


def build_probe(cfg: Config) -> bytes:
    """
    Build the CL.0 desync payload.

    The front-end honours Content-Length: 0 and forwards the whole
    blob; the back-end ignores it and treats the trailing bytes as the
    start of a new request.
    """
    smuggled_prefix = f"{cfg.smuggled_line}\r\nFoo: x"
    return _build_request(
        method="POST",
        path="/",
        host=cfg.host,
        user_agent=cfg.user_agent,
        extra_headers={
            "Content-Length": str(len(smuggled_prefix.encode())),
            "Connection": "keep-alive",
        },
        body=smuggled_prefix,
    )


def build_normal(cfg: Config) -> bytes:
    """Build a plain GET request for the target path."""
    return _build_request(
        method="GET",
        path=cfg.full_path,
        host=cfg.host,
        user_agent=cfg.user_agent,
    )


# ---------------------------------------------------------------------------
# Vulnerability check
# ---------------------------------------------------------------------------


def run_probe(cfg: Config) -> ProbeResult:
    """
    Send the two-request probe sequence and return raw status codes.

    Request 1 — probe + follow-up on the same connection.
    Request 2 — clean baseline on a fresh connection.
    """
    probe_bytes = build_probe(cfg)
    normal_bytes = build_normal(cfg)

    dbg(f"Probe request:\n{probe_bytes!r}\n", cfg.debug)
    dbg(f"Normal request:\n{normal_bytes!r}\n", cfg.debug)

    print("[*] Sending smuggled probe + follow-up request...")
    with connect(cfg) as sock:
        resp_probe, _ = send_recv(sock, probe_bytes + normal_bytes, cfg.debug)

    print("[*] Sending baseline request...")
    with connect(cfg) as sock:
        resp_baseline, _ = send_recv(sock, normal_bytes, cfg.debug)

    return ProbeResult(
        probe_status=resp_probe.status,
        baseline_status=resp_baseline.status,
        probe_headers=dict(resp_probe.getheaders()),
        baseline_headers=dict(resp_baseline.getheaders()),
    )


def report(result: ProbeResult) -> None:
    """Print a human-readable verdict."""
    print()
    print(f"  Probe    status : {result.probe_status}")
    print(f"  Baseline status : {result.baseline_status}")
    print()

    if result.is_vulnerable:
        print("[!] WARNING: Inconsistent responses detected.")
        print("    This may indicate a CL.0 desync vulnerability.")
        print("    Verify manually before drawing conclusions.")
    else:
        print("[=] Responses match — target does not appear vulnerable.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    if sys.version_info < (3, 10):
        print("Error: Python 3.10 or later is required.")
        sys.exit(1)

    print_banner()
    cfg = config_from_args(parse_args())

    print(f"[*] Target : {cfg.url.geturl()}")
    print("[*] Testing for CL.0 HTTP desync vulnerability...\n")

    result = run_probe(cfg)
    report(result)


if __name__ == "__main__":
    main()
