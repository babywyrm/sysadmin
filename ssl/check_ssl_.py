#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
tls_ciphertest.py - Enumerate and test TLS ciphers/protocols using OpenSSL.

Features:
- Tests TLS 1.0/1.1/1.2/1.3 independently
- Proper TLS 1.3 handling via -ciphersuites
- Parses cipher metadata (Kx/Auth/Enc/Bits)
- Concurrent scanning for speed
- Multiple output formats (table/CSV/JSON)
- SNI, ALPN, and verification controls
"""

import argparse
import concurrent.futures as futures
import csv
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Constants
TLS13_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
]

OPENSSL_MIN_VERSION_TLS13 = (1, 1, 1)
DEFAULT_TIMEOUT = 7
DEFAULT_CONCURRENCY = 8


class Protocol(str, Enum):
    TLS10 = "tls1"
    TLS11 = "tls1_1"
    TLS12 = "tls1_2"
    TLS13 = "tls1_3"

    @property
    def display_name(self) -> str:
        return self.value.upper().replace("_", ".")

    @property
    def openssl_flag(self) -> str:
        return f"-{self.value}"


class OutputFormat(str, Enum):
    TABLE = "table"
    CSV = "csv"
    JSON = "json"


@dataclass
class CipherMetadata:
    name: str
    version: str
    kx: str = "?"
    auth: str = "?"
    enc: str = "?"
    bits: str = "?"


@dataclass
class TestResult:
    target: str
    sni: str
    alpn: str
    protocol_requested: str
    protocol_used: str
    cipher_requested: str
    cipher_used: str
    status: str
    error: str
    time_s: str
    kx: str = ""
    auth: str = ""
    enc: str = ""
    bits: str = ""


class OpenSSLRunner:
    """Handles OpenSSL command execution and version detection."""

    @staticmethod
    def run_command(
        cmd: List[str], input_data: Optional[str] = None, timeout: int = 10
    ) -> Tuple[int, str, str]:
        """Execute OpenSSL command and return result."""
        try:
            result = subprocess.run(
                cmd,
                input=input_data or "",
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"Timeout after {timeout}s"
        except FileNotFoundError:
            return 127, "", "OpenSSL not found"
        except Exception as e:
            return 1, "", f"Error: {e}"

    @staticmethod
    def get_version() -> Tuple[int, int, int]:
        """Get OpenSSL version as tuple."""
        rc, out, _ = OpenSSLRunner.run_command(["openssl", "version"])
        if rc != 0:
            sys.exit("[!] OpenSSL not available")

        match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", out)
        return tuple(map(int, match.groups())) if match else (0, 0, 0)

    @staticmethod
    def supports_tls13() -> bool:
        """Check if OpenSSL supports TLS 1.3."""
        return OpenSSLRunner.get_version() >= OPENSSL_MIN_VERSION_TLS13


class CipherParser:
    """Parses and filters cipher information from OpenSSL."""

    ERROR_PATTERNS = [
        r"handshake failure",
        r"no cipher match",
        r"wrong version number",
        r"alert\s+\w+",
        r"unsupported protocol",
        r"sslv3 alert handshake failure",
        r"internal error",
        r"unexpected message",
        r"timeout",
    ]

    @staticmethod
    def get_ciphers_verbose(spec: str) -> List[CipherMetadata]:
        """Get detailed cipher list from OpenSSL."""
        rc, out, err = OpenSSLRunner.run_command(
            ["openssl", "ciphers", "-v", spec]
        )
        if rc != 0:
            sys.exit(f"[!] Error fetching cipher list: {err or out}")

        ciphers = []
        # Example: ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH Au=RSA ...
        for line in out.strip().splitlines():
            parts = line.split()
            if not parts:
                continue

            cipher = CipherMetadata(
                name=parts[0], version=parts[1] if len(parts) > 1 else "?"
            )

            for token in parts[2:]:
                if token.startswith("Kx="):
                    cipher.kx = token[3:]
                elif token.startswith("Au="):
                    cipher.auth = token[3:]
                elif token.startswith("Enc="):
                    cipher.enc = token[4:]

            # Extract bits from enc field like AESGCM(128)
            if match := re.search(r"\((\d+)\)", cipher.enc):
                cipher.bits = match.group(1)

            ciphers.append(cipher)

        return ciphers

    @staticmethod
    def filter_ciphers(
        ciphers: List[CipherMetadata], only: List[str], exclude: List[str]
    ) -> List[CipherMetadata]:
        """Filter ciphers by inclusion/exclusion patterns."""
        import fnmatch

        def should_include(name: str) -> bool:
            if only:
                return any(fnmatch.fnmatch(name, pat) for pat in only)
            return True

        def should_exclude(name: str) -> bool:
            return any(fnmatch.fnmatch(name, pat) for pat in exclude)

        return [
            c
            for c in ciphers
            if should_include(c.name) and not should_exclude(c.name)
        ]

    @staticmethod
    def get_tls13_ciphers(only: List[str], exclude: List[str]) -> List[CipherMetadata]:
        """Get available TLS 1.3 cipher suites."""
        rc, out, _ = OpenSSLRunner.run_command(
            ["openssl", "ciphers", "-v", "TLSv1.3"]
        )

        if rc == 0:
            available_names = {
                line.split()[0] for line in out.strip().splitlines() if line.strip()
            }
            ciphers = [
                CipherMetadata(
                    name=suite, version="TLSv1.3", enc="AEAD"
                )
                for suite in TLS13_SUITES
                if suite in available_names
            ]
        else:
            # Fallback to known list
            ciphers = [
                CipherMetadata(name=suite, version="TLSv1.3", enc="AEAD")
                for suite in TLS13_SUITES
            ]

        return CipherParser.filter_ciphers(ciphers, only, exclude)

    @staticmethod
    def parse_error(output: str) -> str:
        """Extract error message from OpenSSL output."""
        for pattern in CipherParser.ERROR_PATTERNS:
            if match := re.search(pattern, output, re.IGNORECASE):
                return match.group(0)
        
        lines = output.strip().splitlines()
        return lines[-1] if lines else "unknown"


class CipherTester:
    """Tests individual cipher/protocol combinations."""

    def __init__(self, config: argparse.Namespace):
        self.config = config

    def test_cipher(
        self, protocol: Protocol, cipher: str, metadata: CipherMetadata
    ) -> TestResult:
        """Test a single cipher/protocol combination."""
        cmd = self._build_command(protocol, cipher)
        start = time.time()
        rc, out, err = OpenSSLRunner.run_command(
            cmd, input_data="\n", timeout=self.config.timeout
        )
        elapsed = f"{(time.time() - start):.2f}"

        combined = f"{out}\n{err}"
        protocol_used = self._extract_protocol(combined)
        cipher_used = self._extract_cipher(combined)

        status = "YES" if rc == 0 and protocol_used and cipher_used else "NO"
        error = "" if status == "YES" else CipherParser.parse_error(combined)

        result = TestResult(
            target=f"{self.config.host}:{self.config.port}",
            sni=self.config.servername or self.config.host,
            alpn=self.config.alpn or "",
            protocol_requested=protocol.display_name,
            protocol_used=protocol_used or "",
            cipher_requested=cipher,
            cipher_used=cipher_used or "",
            status=status,
            error=error,
            time_s=elapsed,
            kx=metadata.kx,
            auth=metadata.auth,
            enc=metadata.enc,
            bits=metadata.bits,
        )

        return result

    def _build_command(self, protocol: Protocol, cipher: str) -> List[str]:
        """Build OpenSSL s_client command."""
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{self.config.host}:{self.config.port}",
            "-quiet",
            protocol.openssl_flag,
        ]

        # Cipher specification
        if protocol == Protocol.TLS13:
            cmd += ["-ciphersuites", cipher]
        else:
            cmd += ["-cipher", cipher]

        # SNI and ALPN
        if sni := (self.config.servername or self.config.host):
            cmd += ["-servername", sni]
        if self.config.alpn:
            cmd += ["-alpn", self.config.alpn]

        # Verification
        if self.config.insecure:
            cmd += ["-verify", "0"]
        else:
            if self.config.verify_hostname:
                cmd += ["-verify_hostname", self.config.verify_hostname]
            if self.config.cafile:
                cmd += ["-CAfile", self.config.cafile]
            cmd += ["-verify_return_error"]

        cmd += ["-brief"]
        return cmd

    @staticmethod
    def _extract_protocol(output: str) -> Optional[str]:
        """Extract protocol version from output."""
        if match := re.search(r"Protocol\s*:\s*(TLSv[^\s]+)", output):
            return match.group(1)
        return None

    @staticmethod
    def _extract_cipher(output: str) -> Optional[str]:
        """Extract cipher name from output."""
        if match := re.search(r"Cipher\s*:\s*([A-Za-z0-9_\-]+)", output):
            return match.group(1)
        return None


class OutputWriter:
    """Handles output formatting and writing."""

    @staticmethod
    def write(results: List[TestResult], format: OutputFormat, filepath: Optional[str]):
        """Write results in specified format."""
        if format == OutputFormat.JSON:
            OutputWriter._write_json(results, filepath)
        elif format == OutputFormat.CSV:
            OutputWriter._write_csv(results, filepath)
        else:
            OutputWriter._write_table(results)

    @staticmethod
    def _write_json(results: List[TestResult], filepath: Optional[str]):
        """Write JSON output."""
        data = json.dumps([asdict(r) for r in results], indent=2)
        if filepath:
            with open(filepath, "w") as f:
                f.write(data)
            print(f"[+] Wrote JSON to {filepath}")
        else:
            print(data)

    @staticmethod
    def _write_csv(results: List[TestResult], filepath: Optional[str]):
        """Write CSV output."""
        headers = list(asdict(results[0]).keys()) if results else []
        output = open(filepath, "w", newline="") if filepath else sys.stdout

        try:
            writer = csv.DictWriter(output, fieldnames=headers)
            writer.writeheader()
            writer.writerows([asdict(r) for r in results])
            if filepath:
                print(f"[+] Wrote CSV to {filepath}")
        finally:
            if filepath:
                output.close()

    @staticmethod
    def _write_table(results: List[TestResult]):
        """Write formatted table output."""
        headers = [
            "PROTO(req)",
            "PROTO(used)",
            "CIPHER(req)",
            "CIPHER(used)",
            "Kx",
            "Au",
            "Enc(bits)",
            "OK",
            "Time(s)",
            "Error",
        ]

        widths = [11, 11, 30, 30, 8, 8, 14, 3, 7, 0]
        header_line = "".join(
            f"{h:<{w}}" if w else h for h, w in zip(headers, widths)
        )
        print(header_line)

        for r in results:
            encbits = r.enc
            if r.bits:
                encbits += f"({r.bits})"

            values = [
                r.protocol_requested,
                r.protocol_used,
                r.cipher_requested,
                r.cipher_used,
                r.kx,
                r.auth,
                encbits,
                "Y" if r.status == "YES" else "N",
                r.time_s,
                r.error,
            ]

            line = "".join(
                f"{v:<{w}}" if w else v for v, w in zip(values, widths)
            )
            print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate and test TLS ciphers/protocols via OpenSSL s_client"
    )

    # Target configuration
    target_group = parser.add_argument_group("target")
    target_group.add_argument(
        "-H", "--host", default="localhost", help="Target host/IP"
    )
    target_group.add_argument(
        "-p", "--port", type=int, default=443, help="Target port"
    )
    target_group.add_argument("-s", "--servername", help="SNI server name")
    target_group.add_argument("--alpn", help="ALPN protocols (e.g. 'h2,http/1.1')")

    # Protocol selection
    proto_group = parser.add_argument_group("protocols")
    proto_group.add_argument("--no-tls10", action="store_true", help="Skip TLS 1.0")
    proto_group.add_argument("--no-tls11", action="store_true", help="Skip TLS 1.1")
    proto_group.add_argument("--no-tls12", action="store_true", help="Skip TLS 1.2")
    proto_group.add_argument("--no-tls13", action="store_true", help="Skip TLS 1.3")

    # Cipher filtering
    cipher_group = parser.add_argument_group("cipher filtering")
    cipher_group.add_argument(
        "--only",
        action="append",
        default=[],
        help="Only test matching ciphers (can repeat)",
    )
    cipher_group.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude matching ciphers (can repeat)",
    )

    # Performance
    perf_group = parser.add_argument_group("performance")
    perf_group.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Connection timeout"
    )
    perf_group.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="Parallel workers",
    )
    perf_group.add_argument(
        "--retries", type=int, default=0, help="Retries on failure"
    )

    # Output
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--format",
        type=OutputFormat,
        choices=list(OutputFormat),
        default=OutputFormat.TABLE,
        help="Output format",
    )
    output_group.add_argument("--out", help="Output file (for csv/json)")

    # Verification
    verify_group = parser.add_argument_group("verification")
    verify_group.add_argument("--verify-hostname", help="Verify certificate hostname")
    verify_group.add_argument("--cafile", help="CA bundle path")
    verify_group.add_argument(
        "--insecure", action="store_true", help="Disable certificate verification"
    )

    args = parser.parse_args()

    # Display configuration
    version_info = subprocess.check_output(
        ["openssl", "version"], text=True
    ).strip()
    print(f"[+] OpenSSL: {version_info}")
    print(
        f"[+] Target:  {args.host}:{args.port} "
        f"(SNI: {args.servername or args.host})"
    )

    # Check TLS 1.3 support
    supports_tls13 = OpenSSLRunner.supports_tls13()
    if not supports_tls13 and not args.no_tls13:
        print(
            "[!] OpenSSL lacks TLS 1.3 support; skipping TLS 1.3",
            file=sys.stderr,
        )

    # Build protocol list
    protocols = []
    if not args.no_tls10:
        protocols.append(Protocol.TLS10)
    if not args.no_tls11:
        protocols.append(Protocol.TLS11)
    if not args.no_tls12:
        protocols.append(Protocol.TLS12)
    if not args.no_tls13 and supports_tls13:
        protocols.append(Protocol.TLS13)

    # Gather ciphers
    ciphers_legacy = CipherParser.get_ciphers_verbose("ALL:!eNULL")
    ciphers_legacy = CipherParser.filter_ciphers(
        ciphers_legacy, args.only, args.exclude
    )

    ciphers_tls13 = []
    if Protocol.TLS13 in protocols:
        ciphers_tls13 = CipherParser.get_tls13_ciphers(args.only, args.exclude)

    # Build work queue
    work = []
    for proto in protocols:
        cipher_list = ciphers_tls13 if proto == Protocol.TLS13 else ciphers_legacy
        for cipher in cipher_list:
            work.append((proto, cipher.name, cipher))

    print(
        f"[+] Testing {len(work)} combinations "
        f"(concurrency={args.concurrency})\n"
    )

    # Run tests
    tester = CipherTester(args)
    results = []

    def test_with_retry(item):
        proto, cipher_name, metadata = item
        for attempt in range(args.retries + 1):
            result = tester.test_cipher(proto, cipher_name, metadata)
            if result.status == "YES":
                return result
        return result

    with futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        for result in executor.map(test_with_retry, work):
            results.append(result)

    # Sort results: successful first, then by protocol and cipher
    results.sort(
        key=lambda r: (
            0 if r.status == "YES" else 1,
            r.protocol_requested,
            r.cipher_requested,
        )
    )

    # Output results
    OutputWriter.write(results, args.format, args.out)


if __name__ == "__main__":
    main()
