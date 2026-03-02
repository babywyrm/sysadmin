#!/usr/bin/env python3
"""
Binary Analysis Utility — Byte Manipulation & Decoding Toolkit
For use in reverse engineering / CTF workflows (e.g., Ghidra post-analysis).

Usage:
    python3 revutil.py
    python3 revutil.py --hex "a5a9f4bcf0b5e3b2d6f4a0fda0b3d6fdb3d6e7f7bbfdc8a4b3a3f3f0e7abd6"
    python3 revutil.py --hex "..." --xor 0x96 --swap --decode ascii
"""

import argparse
import binascii
import struct
import sys
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Encoding(str, Enum):
    ASCII = "ascii"
    UTF8 = "utf-8"
    UTF16 = "utf-16"
    LATIN1 = "latin-1"
    HEX = "hex"


# ---------------------------------------------------------------------------
# Core byte operations
# ---------------------------------------------------------------------------


def swap_endian(data: bytes) -> bytes:
    """Reverse byte order (correct for Ghidra's little-endian hex display)."""
    return data[::-1]


def xor_bytes(data: bytes, key: int) -> bytes:
    """XOR every byte against a single-byte key."""
    if not 0x00 <= key <= 0xFF:
        raise ValueError(f"XOR key must be a single byte (0x00–0xFF), got {hex(key)}")
    return bytes(b ^ key for b in data)


def xor_bytes_rolling(data: bytes, key: bytes) -> bytes:
    """XOR data against a repeating multi-byte key."""
    if not key:
        raise ValueError("Rolling XOR key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rotate_left(data: bytes, n: int = 1) -> bytes:
    """Rotate each byte left by n bits."""
    n %= 8
    return bytes(((b << n) | (b >> (8 - n))) & 0xFF for b in data)


def rotate_right(data: bytes, n: int = 1) -> bytes:
    """Rotate each byte right by n bits."""
    n %= 8
    return bytes(((b >> n) | (b << (8 - n))) & 0xFF for b in data)


def add_bytes(data: bytes, key: int) -> bytes:
    """Add key to every byte (mod 256)."""
    return bytes((b + key) % 256 for b in data)


def sub_bytes(data: bytes, key: int) -> bytes:
    """Subtract key from every byte (mod 256)."""
    return bytes((b - key) % 256 for b in data)


def not_bytes(data: bytes) -> bytes:
    """Bitwise NOT every byte."""
    return bytes(~b & 0xFF for b in data)


# ---------------------------------------------------------------------------
# Encoding / decoding
# ---------------------------------------------------------------------------


def try_decode(data: bytes, encoding: Encoding = Encoding.ASCII) -> str:
    """Attempt to decode bytes using the specified encoding."""
    if encoding == Encoding.HEX:
        return data.hex()
    try:
        return data.decode(encoding.value, errors="replace")
    except (UnicodeDecodeError, LookupError) as e:
        raise ValueError(f"Failed to decode as {encoding.value}: {e}") from e


def from_hex_string(hex_str: str) -> bytes:
    """Parse a hex string (with or without 0x prefixes / spaces / colons)."""
    cleaned = (
        hex_str.strip()
        .replace("0x", "")
        .replace(" ", "")
        .replace(":", "")
        .replace("-", "")
        .replace("\n", "")
    )
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}") from e


def to_hex_string(data: bytes, sep: str = " ") -> str:
    """Format bytes as a spaced hex string."""
    return sep.join(f"{b:02x}" for b in data)


def to_c_array(data: bytes, var_name: str = "buf") -> str:
    """Format bytes as a C-style byte array."""
    hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
    return f"unsigned char {var_name}[{len(data)}] = {{ {hex_bytes} }};"


def entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    High entropy (>7.0) often indicates encryption or compression.
    """
    if not data:
        return 0.0
    from math import log2

    freq = [data.count(b) / len(data) for b in set(data)]
    return -sum(p * log2(p) for p in freq if p > 0)


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------


def bruteforce_xor(
    data: bytes,
    printable_only: bool = True,
    min_printable_ratio: float = 0.85,
) -> list[tuple[int, str]]:
    """
    Try all single-byte XOR keys (0x00–0xFF).
    Returns a list of (key, decoded_string) for candidates that look printable.
    """
    results: list[tuple[int, str]] = []
    for key in range(0x100):
        candidate = xor_bytes(data, key)
        try:
            decoded = candidate.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            continue
        if printable_only:
            printable = sum(0x20 <= ord(c) < 0x7F or c in "\t\n\r" for c in decoded)
            if printable / len(decoded) < min_printable_ratio:
                continue
        results.append((key, decoded))
    return results


def find_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable ASCII strings from raw bytes (like `strings` utility)."""
    results: list[str] = []
    current: list[str] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def hexdump(data: bytes, width: int = 16) -> str:
    """
    Classic hexdump output.
    Example:
        00000000  68 65 6c 6c 6f  |hello|
    """
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def detect_magic(data: bytes) -> Optional[str]:
    """Identify common file types by magic bytes."""
    MAGIC: dict[bytes, str] = {
        b"\x7fELF": "ELF binary",
        b"MZ": "PE/DOS executable",
        b"\x89PNG": "PNG image",
        b"PK\x03\x04": "ZIP / JAR / DOCX archive",
        b"\x1f\x8b": "GZIP compressed",
        b"BZh": "BZIP2 compressed",
        b"\xfd7zXZ": "XZ compressed",
        b"OggS": "OGG media",
        b"JFIF": "JPEG image",
        b"\xff\xd8\xff": "JPEG image",
        b"%PDF": "PDF document",
        b"\xca\xfe\xba\xbe": "Java class file",
        b"\x50\x4b\x05\x06": "ZIP (empty)",
        b"Rar!": "RAR archive",
        b"7z\xbc\xaf": "7-Zip archive",
    }
    for magic, label in MAGIC.items():
        if data.startswith(magic):
            return label
    return None


# ---------------------------------------------------------------------------
# Pipeline: chain operations in sequence
# ---------------------------------------------------------------------------


def run_pipeline(
    data: bytes,
    *,
    swap: bool = False,
    xor_key: Optional[int] = None,
    xor_rolling: Optional[bytes] = None,
    add_key: Optional[int] = None,
    sub_key: Optional[int] = None,
    rot_left: Optional[int] = None,
    rot_right: Optional[int] = None,
    bitwise_not: bool = False,
    decode: Optional[Encoding] = None,
    verbose: bool = True,
) -> bytes:
    """
    Apply a sequence of transforms to a byte sequence.
    Mirrors the manual process used when reversing obfuscated payloads in Ghidra.
    """

    def step(label: str, result: bytes) -> bytes:
        if verbose:
            print(f"  [{label}] {to_hex_string(result[:32])}"
                  + (" ..." if len(result) > 32 else ""))
        return result

    if verbose:
        print(f"\n[*] Input  ({len(data)} bytes): {to_hex_string(data[:32])}"
              + (" ..." if len(data) > 32 else ""))
        magic = detect_magic(data)
        if magic:
            print(f"[*] Magic bytes detected: {magic}")
        print(f"[*] Entropy: {entropy(data):.3f}")

    if swap:
        data = step("swap_endian", swap_endian(data))
    if xor_key is not None:
        data = step(f"xor({hex(xor_key)})", xor_bytes(data, xor_key))
    if xor_rolling is not None:
        data = step(f"xor_rolling({xor_rolling.hex()})", xor_bytes_rolling(data, xor_rolling))
    if add_key is not None:
        data = step(f"add({hex(add_key)})", add_bytes(data, add_key))
    if sub_key is not None:
        data = step(f"sub({hex(sub_key)})", sub_bytes(data, sub_key))
    if rot_left is not None:
        data = step(f"rol({rot_left})", rotate_left(data, rot_left))
    if rot_right is not None:
        data = step(f"ror({rot_right})", rotate_right(data, rot_right))
    if bitwise_not:
        data = step("not", not_bytes(data))
    if decode is not None:
        result_str = try_decode(data, decode)
        print(f"\n[+] Decoded ({decode.value}): {result_str}")

    return data


# ---------------------------------------------------------------------------
# HTB Undetected example — preserved and modernized
# ---------------------------------------------------------------------------


def htb_undetected_example() -> None:
    """
    HTB Undetected — backdoor password recovery.
    Ref: https://secnigma.wordpress.com/2022/07/03/hack-the-box-undetected/

    Steps:
      1. Ghidra shows bytes in reversed order — swap endianness
      2. XOR each byte with 0x96
      3. Decode as ASCII
    """
    print("=" * 60)
    print("HTB Undetected — Backdoor Password Recovery")
    print("=" * 60)

    # Raw bytes as extracted from Ghidra (little-endian display)
    raw = bytes([
        0xa5, 0xa9, 0xf4, 0xbc, 0xf0, 0xb5, 0xe3,
        0xb2, 0xd6, 0xf4, 0xa0, 0xfd, 0xa0, 0xb3, 0xd6,
        0xfd, 0xb3, 0xd6, 0xe7, 0xf7, 0xbb, 0xfd, 0xc8,
        0xa4, 0xb3, 0xa3, 0xf3, 0xf0, 0xe7, 0xab, 0xd6,
    ])

    result = run_pipeline(
        raw,
        swap=True,
        xor_key=0x96,
        decode=Encoding.ASCII,
        verbose=True,
    )

    print("\n[*] Hexdump of result:")
    print(hexdump(result))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Binary analysis utility — byte manipulation & decoding toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # HTB Undetected example (default demo)
  python3 revutil.py

  # Decode a hex string with swap + XOR
  python3 revutil.py --hex "a5a9f4..." --swap --xor 0x96 --decode ascii

  # Brute-force XOR key
  python3 revutil.py --hex "deadbeef..." --bruteforce-xor

  # Hexdump a file
  python3 revutil.py --file ./binary.bin --hexdump

  # Extract strings from a file
  python3 revutil.py --file ./binary.bin --strings
""",
    )

    src = p.add_mutually_exclusive_group()
    src.add_argument("--hex", metavar="HEX", help="Input as hex string")
    src.add_argument("--file", metavar="PATH", help="Input from binary file")

    p.add_argument("--swap", action="store_true", help="Swap byte order")
    p.add_argument("--xor", metavar="KEY", help="XOR with single byte key (e.g. 0x96)")
    p.add_argument("--xor-rolling", metavar="KEY", help="XOR with repeating key (e.g. 0x1337)")
    p.add_argument("--add", metavar="KEY", help="Add byte key (mod 256)")
    p.add_argument("--sub", metavar="KEY", help="Subtract byte key (mod 256)")
    p.add_argument("--rol", metavar="N", type=int, help="Rotate bits left by N")
    p.add_argument("--ror", metavar="N", type=int, help="Rotate bits right by N")
    p.add_argument("--not", dest="bitwise_not", action="store_true", help="Bitwise NOT")
    p.add_argument(
        "--decode",
        metavar="ENC",
        choices=[e.value for e in Encoding],
        help="Decode result as: ascii, utf-8, utf-16, latin-1, hex",
    )
    p.add_argument("--hexdump", action="store_true", help="Print hexdump of result")
    p.add_argument("--c-array", action="store_true", help="Print result as C byte array")
    p.add_argument("--entropy", action="store_true", help="Print Shannon entropy of input")
    p.add_argument("--strings", action="store_true", help="Extract printable strings")
    p.add_argument("--bruteforce-xor", action="store_true", help="Brute-force single-byte XOR key")
    p.add_argument("--min-len", type=int, default=4, help="Min string length for --strings (default: 4)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress pipeline step output")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # No args — run the built-in HTB example
    if len(sys.argv) == 1:
        htb_undetected_example()
        return

    # Load input
    if args.hex:
        data = from_hex_string(args.hex)
    elif args.file:
        try:
            with open(args.file, "rb") as f:
                data = f.read()
        except OSError as e:
            print(f"[!] Could not read file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)

    # Analysis-only flags (no pipeline)
    if args.bruteforce_xor:
        print(f"[*] Brute-forcing XOR key over {len(data)} bytes...\n")
        candidates = bruteforce_xor(data)
        if not candidates:
            print("[!] No printable candidates found.")
        for key, decoded in candidates:
            print(f"  key={hex(key)}  →  {decoded[:80]}")
        return

    if args.strings:
        found = find_strings(data, min_len=args.min_len)
        print(f"[*] Found {len(found)} strings (min_len={args.min_len}):\n")
        for s in found:
            print(f"  {s}")
        return

    if args.entropy:
        print(f"[*] Shannon entropy: {entropy(data):.4f}")
        magic = detect_magic(data)
        if magic:
            print(f"[*] Magic bytes: {magic}")
        return

    # Build pipeline kwargs
    xor_key: Optional[int] = None
    if args.xor:
        xor_key = int(args.xor, 16) if args.xor.startswith("0x") else int(args.xor, 0)

    xor_rolling: Optional[bytes] = None
    if args.xor_rolling:
        xor_rolling = from_hex_string(args.xor_rolling)

    add_key: Optional[int] = None
    if args.add:
        add_key = int(args.add, 0)

    sub_key: Optional[int] = None
    if args.sub:
        sub_key = int(args.sub, 0)

    decode: Optional[Encoding] = None
    if args.decode:
        decode = Encoding(args.decode)

    result = run_pipeline(
        data,
        swap=args.swap,
        xor_key=xor_key,
        xor_rolling=xor_rolling,
        add_key=add_key,
        sub_key=sub_key,
        rot_left=args.rol,
        rot_right=args.ror,
        bitwise_not=args.bitwise_not,
        decode=decode,
        verbose=not args.quiet,
    )

    if args.hexdump:
        print("\n[*] Hexdump:")
        print(hexdump(result))

    if args.c_array:
        print("\n[*] C array:")
        print(to_c_array(result))


if __name__ == "__main__":
    main()
