#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import re
from typing import List, Dict

def setup_logger():
    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=logging.INFO
    )

def parse_proc_net(content: str) -> List[str]:
    """Extract raw socket lines from /proc/net/* (excluding header/footer)."""
    return [line.strip() for line in content.strip().splitlines()[1:] if line.strip()]

def split_every_n(s: str, n: int) -> List[str]:
    return [s[i:i+n] for i in range(0, len(s), n)]

def convert_linux_netaddr(hex_addr_port: str) -> str:
    hex_addr, hex_port = hex_addr_port.split(':')
    ip_parts = split_every_n(hex_addr, 2)
    ip_parts.reverse()
    ip = ".".join(str(int(part, 16)) for part in ip_parts)
    port = str(int(hex_port, 16))
    return f"{ip}:{port}"

def format_entry(entry: Dict[str, str]) -> str:
    return (f"{entry['seq']:<4} {entry['uid']:>5} {entry['local']:<25} "
            f"{entry['remote']:<25} {entry['timeout']:>8} {entry['inode']:>8}")

def process_socket_file(path: str) -> List[Dict[str, str]]:
    try:
        with open(path, 'r') as f:
            lines = parse_proc_net(f.read())
    except Exception as e:
        logging.error(f"Failed to open {path}: {e}")
        return []

    entries = []
    for line in lines:
        fields = re.split(r'\s+', line)
        if len(fields) < 10:
            continue
        entries.append({
            'seq': fields[0],
            'local': convert_linux_netaddr(fields[1]),
            'remote': convert_linux_netaddr(fields[2]),
            'uid': fields[7],
            'timeout': fields[8],
            'inode': fields[9]
        })

    return entries

def main():
    setup_logger()

    parser = argparse.ArgumentParser(description="Parse /proc/net/* socket files.")
    parser.add_argument("file", help="Path to /proc/net/tcp or similar")
    args = parser.parse_args()

    results = process_socket_file(args.file)

    if results:
        header = {'seq': 'seq', 'uid': 'uid', 'local': 'local address',
                  'remote': 'remote address', 'timeout': 'timeout', 'inode': 'inode'}
        print(format_entry(header))
        for entry in results:
            print(format_entry(entry))
    else:
        logging.warning("No valid entries found.")

if __name__ == "__main__":
    main()

##
##
