#!/usr/bin/env python3
"""
url_hex_tool.py ..testing..
================

Educational tool for safely encoding or decoding URLs in hexadecimal form,
and optionally detecting XSS payloads within encoded strings.

Based on early prototypes like:
    https://github.com/tradle/urlsafe-base64
    https://gist.github.com/kodekracker/f43d274d8fe446566d02c0a3ec276db0

Modernized and rewritten for clarity, correctness, and maintainability.

Example usage:
    python3 url_hex_tool.py --encode --url "https://example.com/?a=1&b=<script>"
    python3 url_hex_tool.py --decode --url "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    python3 url_hex_tool.py --detect-xss --url "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
"""

import argparse
import re
import sys
import urllib.parse
from typing import Optional


# ==========================================================
# Core functionality
# ==========================================================

SAFE_CHARS = "-._~"


def encode_url(url: str, full_encode: bool = False, uppercase: bool = False) -> str:
    """
    Encode a URL string into hexadecimal (%XX) form.

    Args:
        url: The input URL or string to encode.
        full_encode: If True, encode all characters (not just unsafe ones).
        uppercase: If True, hex digits will be uppercase.
    Returns:
        Encoded URL string.
    """
    if full_encode:
        # Encode all bytes
        encoded = ''.join(
            f"%{ord(c):02X}" if uppercase else f"%{ord(c):02x}" for c in url
        )
    else:
        # Use urllib for correct partial encoding behavior
        encoded = urllib.parse.quote(url, safe=SAFE_CHARS)
        if uppercase:
            # urllib uses lowercase hex by default
            encoded = re.sub(r"%[0-9a-f]{2}", lambda m: m.group(0).upper(), encoded)
    return encoded


def decode_url(encoded_url: str) -> str:
    """
    Decode a percent-encoded URL string.

    Args:
        encoded_url: Input string (e.g., "%3Cscript%3E").
    Returns:
        Decoded (human-readable) string.
    """
    try:
        return urllib.parse.unquote(encoded_url)
    except Exception as e:
        sys.exit(f"Decoding error: {e}")


def detect_xss_payload(decoded_str: str) -> bool:
    """
    Detect potential XSS payloads in decoded strings.
    Uses heuristic search for <script>, javascript:, on* event handlers, etc.

    Args:
        decoded_str: The decoded string to analyze.
    Returns:
        True if XSS-like patterns are detected.
    """
    xss_patterns = [
        r"<\s*script.*?>.*?<\s*/\s*script\s*>",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"document\.cookie",
        r"window\.location",
        r"alert\s*\(",
    ]
    for pattern in xss_patterns:
        if re.search(pattern, decoded_str, re.IGNORECASE):
            return True
    return False


# ==========================================================
# CLI and UX Layer
# ==========================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encode/decode URLs in hex format and detect XSS payloads.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Encode a URL:
    python3 url_hex_tool.py --encode --url "https://example.com/a?x=<script>"

  Decode a URL:
    python3 url_hex_tool.py --decode --url "%3Cscript%3Ealert(1)%3C%2Fscript%3E"

  Detect possible XSS:
    python3 url_hex_tool.py --detect-xss --url "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
"""
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encode", "-e", action="store_true", help="Encode the URL string.")
    group.add_argument("--decode", "-d", action="store_true", help="Decode the URL string.")
    group.add_argument("--detect-xss", "-x", action="store_true", help="Detect XSS payloads.")

    parser.add_argument("--url", "-u", required=True, help="Specify the URL or string to process.")
    parser.add_argument("--full-encode", "-f", action="store_true", help="Encode all characters (not just unsafe ones).")
    parser.add_argument("--uppercase", "-U", action="store_true", help="Use uppercase hex letters in encoding.")

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.encode:
        result = encode_url(args.url, full_encode=args.full_encode, uppercase=args.uppercase)
        print(result)

    elif args.decode:
        result = decode_url(args.url)
        print(result)

    elif args.detect_xss:
        decoded = decode_url(args.url)
        print(f"Decoded string: {decoded}")
        if detect_xss_payload(decoded):
            print("Potential XSS payload detected! Avoid rendering this input.")
        else:
            print("No obvious XSS payload patterns detected.")


if __name__ == "__main__":
    main()
    ##
    ##
