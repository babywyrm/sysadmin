#!/usr/bin/env python3
"""
Socket Parser - A utility for parsing /proc/net/* connection tables (..beta..)

This script reads Linux socket info (TCP/UDP) from /proc/net/* files,
decodes the hex IP/port addresses, and formats them in a readable table
showing: sequence ID, UID, local IP:port, remote IP:port, timeout, and inode.

Examples:
  ./proc_net_parser.py --file /proc/net/tcp
  ./proc_net_parser.py --all
  ./proc_net_parser.py --proto tcp6

By default, if no options are given, it parses /proc/net/tcp and /proc/net/udp.
"""

import argparse
import logging
import os,sys,re
from typing import List, Dict

# ──────────────────────────────────────────────────────────────── #
def setup_logger():
    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)

def parse_proc_net(content: str) -> List[str]:
    return [line.strip() for line in content.strip().splitlines()[1:] if line.strip()]

def split_every_n(s: str, n: int) -> List[str]:
    return [s[i:i+n] for i in range(0, len(s), n)]

def convert_netaddr(addr_port: str, ipv6: bool = False) -> str:
    hex_addr, hex_port = addr_port.split(':')
    port = str(int(hex_port, 16))

    if ipv6:
        parts = [hex_addr[i:i+4] for i in range(0, 32, 4)]
        ip = ':'.join(parts)
        ip = re.sub(r'(:0+)+', '::', ip, 1)
        return f"{ip}:{port}"

    parts = split_every_n(hex_addr, 2)
    ip = '.'.join(str(int(part, 16)) for part in reversed(parts))
    return f"{ip}:{port}"

def format_entry(entry: Dict[str, str]) -> str:
    return f"{entry['seq']:<4} {entry['uid']:>5} {entry['local']:<25} {entry['remote']:<25} {entry['timeout']:>8} {entry['inode']:>8}"

def parse_socket_file(path: str, ipv6: bool = False) -> List[Dict[str, str]]:
    try:
        with open(path, 'r') as f:
            lines = parse_proc_net(f.read())
    except Exception as e:
        logging.warning(f"Skipping {path}: {e}")
        return []

    entries = []
    for line in lines:
        fields = re.split(r'\s+', line)
        if len(fields) < 10:
            continue
        try:
            entries.append({
                'seq': fields[0],
                'local': convert_netaddr(fields[1], ipv6),
                'remote': convert_netaddr(fields[2], ipv6),
                'uid': fields[7],
                'timeout': fields[8],
                'inode': fields[9]
            })
        except Exception as e:
            logging.debug(f"Malformed line in {path}: {line} -> {e}")
            continue

    return entries

# ──────────────────────────────────────────────────────────────── #
def auto_detect_files(proto: str = None) -> List[str]:
    files = []
    base_paths = {
        'tcp': '/proc/net/tcp',
        'udp': '/proc/net/udp',
        'tcp6': '/proc/net/tcp6',
        'udp6': '/proc/net/udp6',
    }

    if proto:
        if proto not in base_paths:
            raise ValueError(f"Unsupported protocol: {proto}")
        if os.path.exists(base_paths[proto]):
            files.append(base_paths[proto])
    else:
        for f in ('tcp', 'udp'):
            if os.path.exists(base_paths[f]):
                files.append(base_paths[f])
    return files

def run_analysis(paths: List[str]):
    for path in paths:
        ipv6 = '6' in os.path.basename(path)
        results = parse_socket_file(path, ipv6)
        print(f"\n--- {path} ---")
        if results:
            header = {'seq': 'SEQ', 'uid': 'UID', 'local': 'LOCAL ADDRESS',
                      'remote': 'REMOTE ADDRESS', 'timeout': 'TIMEOUT', 'inode': 'INODE'}
            print(format_entry(header))
            for entry in results:
                print(format_entry(entry))
        else:
            print("No entries found.")

# ──────────────────────────────────────────────────────────────── #
def main():
    setup_logger()

    parser = argparse.ArgumentParser(
        description="Parse and display socket info from /proc/net/{tcp,udp,tcp6,udp6}"
    )
    parser.add_argument("--file", help="Specify one file to parse (e.g., /proc/net/tcp)")
    parser.add_argument("--all", action="store_true", help="Parse all known protocols (tcp, udp, tcp6, udp6)")
    parser.add_argument("--proto", choices=["tcp", "udp", "tcp6", "udp6"], help="Shortcut to parse one protocol")

    args = parser.parse_args()

    paths = []
    if args.file:
        paths = [args.file]
    elif args.all:
        paths = [f for f in auto_detect_files('tcp') + auto_detect_files('udp') +
                 auto_detect_files('tcp6') + auto_detect_files('udp6')]
    elif args.proto:
        paths = auto_detect_files(args.proto)
    else:
        paths = auto_detect_files()  # Default to tcp + udp

    if not paths:
        logging.error("No valid files to parse.")
        exit(1)

    run_analysis(paths)

if __name__ == "__main__":
    main()

