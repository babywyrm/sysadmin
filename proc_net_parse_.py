#!/usr/bin/env python3
"""
Socket Parser - A comprehensive utility for parsing /proc/net/* connection tables.. (linux)..

This script reads Linux socket info (TCP/UDP) from /proc/net/* files,
decodes the hex IP/port addresses, resolves process names, and formats 
them in a readable table with filtering and sorting capabilities.

Features:
- Support for TCP/UDP IPv4/IPv6
- Process name resolution
- Connection state decoding
- Filtering by port, IP, state, process
- Multiple output formats (table, JSON, CSV)
- Colored output
- Sorting options

Examples:
  ./socket_parser.py                           # Default: show all TCP/UDP
  ./socket_parser.py --proto tcp --state LISTEN
  ./socket_parser.py --filter-port 80,443     # Show HTTP/HTTPS connections
  ./socket_parser.py --filter-ip 192.168.1.0/24
  ./socket_parser.py --output json --no-resolve
  ./socket_parser.py --sort port --reverse
"""

import argparse
import json
import csv
import logging
import os
import sys
import re
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional, Set, Union
from dataclasses import dataclass, asdict
from collections import defaultdict
import subprocess

# ──────────────────────────────────────────────────────────────── #
# Constants and Configuration
# ──────────────────────────────────────────────────────────────── #

TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV'
}

PROC_NET_FILES = {
    'tcp': '/proc/net/tcp',
    'udp': '/proc/net/udp',
    'tcp6': '/proc/net/tcp6',
    'udp6': '/proc/net/udp6',
}

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ──────────────────────────────────────────────────────────────── #
# Data Classes
# ──────────────────────────────────────────────────────────────── #

@dataclass
class SocketEntry:
    seq: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    uid: int
    inode: int
    timeout: str = ""
    process_name: str = ""
    pid: str = ""
    protocol: str = ""
    
    @property
    def local_address(self) -> str:
        return f"{self.local_ip}:{self.local_port}"
    
    @property
    def remote_address(self) -> str:
        return f"{self.remote_ip}:{self.remote_port}"

# ──────────────────────────────────────────────────────────────── #
# Utility Functions
# ──────────────────────────────────────────────────────────────── #

def setup_logger(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='[%(levelname)s] %(message)s', 
        level=level,
        stream=sys.stderr
    )

def hex_to_ip_port(addr_port: str, ipv6: bool = False) -> tuple:
    """Convert hex address:port to IP and port"""
    try:
        hex_addr, hex_port = addr_port.split(':')
        port = int(hex_port, 16)
        
        if ipv6:
            # Handle IPv6 - 32 hex chars
            if len(hex_addr) == 32:
                parts = [hex_addr[i:i+4] for i in range(0, 32, 4)]
                ip = ':'.join(parts)
                # Simplify IPv6 address
                ip = str(ipaddress.IPv6Address(int(hex_addr, 16)))
            else:
                ip = hex_addr  # Fallback
        else:
            # Handle IPv4 - 8 hex chars, little-endian
            if len(hex_addr) == 8:
                parts = [hex_addr[i:i+2] for i in range(0, 8, 2)]
                ip = '.'.join(str(int(part, 16)) for part in reversed(parts))
            else:
                ip = hex_addr  # Fallback
                
        return ip, port
    except Exception as e:
        logging.debug(f"Failed to parse address {addr_port}: {e}")
        return addr_port, 0

def get_process_info(inode: int) -> tuple:
    """Get process name and PID for a given inode"""
    try:
        # Search through /proc/*/fd/* for socket inodes
        for proc_dir in Path('/proc').glob('[0-9]*'):
            try:
                fd_dir = proc_dir / 'fd'
                if not fd_dir.exists():
                    continue
                    
                for fd_link in fd_dir.iterdir():
                    try:
                        target = fd_link.readlink()
                        if f'socket:[{inode}]' in str(target):
                            pid = proc_dir.name
                            # Get process name from cmdline
                            cmdline_file = proc_dir / 'cmdline'
                            if cmdline_file.exists():
                                cmdline = cmdline_file.read_text().replace('\0', ' ').strip()
                                process_name = cmdline.split()[0] if cmdline else f"pid:{pid}"
                                return os.path.basename(process_name), pid
                            return f"pid:{pid}", pid
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except Exception as e:
        logging.debug(f"Error getting process info for inode {inode}: {e}")
    
    return "", ""

# ──────────────────────────────────────────────────────────────── #
# Parsing Functions
# ──────────────────────────────────────────────────────────────── #

def parse_socket_file(file_path: str, resolve_processes: bool = True) -> List[SocketEntry]:
    """Parse a /proc/net/* file and return socket entries"""
    
    if not os.path.exists(file_path):
        logging.warning(f"File not found: {file_path}")
        return []
    
    protocol = os.path.basename(file_path)
    ipv6 = '6' in protocol
    
    entries = []
    process_cache = {}  # Cache for process lookups
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()[1:]  # Skip header
    except Exception as e:
        logging.error(f"Failed to read {file_path}: {e}")
        return []
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
            
        try:
            fields = line.split()
            if len(fields) < 10:
                continue
                
            # Parse basic fields
            seq = fields[0].rstrip(':')
            local_addr = fields[1]
            remote_addr = fields[2]
            state_hex = fields[3]
            uid = int(fields[7])
            timeout = fields[8] if len(fields) > 8 else ""
            inode = int(fields[9])
            
            # Convert addresses
            local_ip, local_port = hex_to_ip_port(local_addr, ipv6)
            remote_ip, remote_port = hex_to_ip_port(remote_addr, ipv6)
            
            # Decode state
            state = TCP_STATES.get(state_hex, state_hex) if 'tcp' in protocol else 'UDP'
            
            # Get process info (with caching)
            process_name, pid = "", ""
            if resolve_processes and inode > 0:
                if inode not in process_cache:
                    process_cache[inode] = get_process_info(inode)
                process_name, pid = process_cache[inode]
            
            entry = SocketEntry(
                seq=seq,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                uid=uid,
                inode=inode,
                timeout=timeout,
                process_name=process_name,
                pid=pid,
                protocol=protocol
            )
            
            entries.append(entry)
            
        except Exception as e:
            logging.debug(f"Failed to parse line {line_num} in {file_path}: {e}")
            continue
    
    logging.info(f"Parsed {len(entries)} entries from {file_path}")
    return entries

# ──────────────────────────────────────────────────────────────── #
# Filtering Functions
# ──────────────────────────────────────────────────────────────── #

def filter_entries(entries: List[SocketEntry], filters: Dict) -> List[SocketEntry]:
    """Apply various filters to socket entries"""
    
    filtered = entries
    
    # Filter by ports
    if filters.get('ports'):
        port_set = set(filters['ports'])
        filtered = [e for e in filtered if e.local_port in port_set or e.remote_port in port_set]
    
    # Filter by IP addresses/networks
    if filters.get('networks'):
        networks = [ipaddress.ip_network(net, strict=False) for net in filters['networks']]
        filtered = [e for e in filtered if any(
            ipaddress.ip_address(e.local_ip) in net or 
            ipaddress.ip_address(e.remote_ip) in net
            for net in networks
        )]
    
    # Filter by states
    if filters.get('states'):
        state_set = set(s.upper() for s in filters['states'])
        filtered = [e for e in filtered if e.state in state_set]
    
    # Filter by process names
    if filters.get('processes'):
        process_patterns = [re.compile(p, re.IGNORECASE) for p in filters['processes']]
        filtered = [e for e in filtered if any(
            pattern.search(e.process_name) for pattern in process_patterns
        )]
    
    # Filter by protocols
    if filters.get('protocols'):
        proto_set = set(filters['protocols'])
        filtered = [e for e in filtered if e.protocol in proto_set]
    
    return filtered

# ──────────────────────────────────────────────────────────────── #
# Output Functions
# ──────────────────────────────────────────────────────────────── #

def format_table_output(entries: List[SocketEntry], use_colors: bool = True) -> str:
    """Format entries as a table"""
    
    if not entries:
        return "No entries found."
    
    # Color functions
    def colorize(text: str, color: str) -> str:
        if not use_colors:
            return text
        return f"{color}{text}{Colors.RESET}"
    
    def state_color(state: str) -> str:
        color_map = {
            'LISTEN': Colors.GREEN,
            'ESTABLISHED': Colors.BLUE,
            'TIME_WAIT': Colors.YELLOW,
            'CLOSE_WAIT': Colors.RED,
            'UDP': Colors.MAGENTA
        }
        return color_map.get(state, Colors.WHITE)
    
    # Calculate column widths
    widths = {
        'proto': max(len(e.protocol) for e in entries),
        'state': max(len(e.state) for e in entries),
        'local': max(len(e.local_address) for e in entries),
        'remote': max(len(e.remote_address) for e in entries),
        'process': max(len(f"{e.process_name}({e.pid})") for e in entries) if entries[0].process_name else 0
    }
    
    # Ensure minimum widths
    widths.update({
        'proto': max(widths['proto'], 5),
        'state': max(widths['state'], 5),
        'local': max(widths['local'], 15),
        'remote': max(widths['remote'], 15),
        'process': max(widths['process'], 10)
    })
    
    lines = []
    
    # Header
    if widths['process'] > 0:
        header = f"{'PROTO':<{widths['proto']}} {'STATE':<{widths['state']}} {'LOCAL':<{widths['local']}} {'REMOTE':<{widths['remote']}} {'PROCESS':<{widths['process']}} {'UID':>5}"
    else:
        header = f"{'PROTO':<{widths['proto']}} {'STATE':<{widths['state']}} {'LOCAL':<{widths['local']}} {'REMOTE':<{widths['remote']}} {'UID':>5}"
    
    lines.append(colorize(header, Colors.BOLD))
    lines.append('─' * len(header.replace(Colors.BOLD, '').replace(Colors.RESET, '')))
    
    # Entries
    for entry in entries:
        proto = entry.protocol.ljust(widths['proto'])
        state = colorize(entry.state.ljust(widths['state']), state_color(entry.state))
        local = entry.local_address.ljust(widths['local'])
        remote = entry.remote_address.ljust(widths['remote'])
        uid = f"{entry.uid:>5}"
        
        if widths['process'] > 0:
            process = f"{entry.process_name}({entry.pid})".ljust(widths['process'])
            line = f"{proto} {state} {local} {remote} {process} {uid}"
        else:
            line = f"{proto} {state} {local} {remote} {uid}"
        
        lines.append(line)
    
    return '\n'.join(lines)

def format_json_output(entries: List[SocketEntry]) -> str:
    """Format entries as JSON"""
    return json.dumps([asdict(entry) for entry in entries], indent=2)

def format_csv_output(entries: List[SocketEntry]) -> str:
    """Format entries as CSV"""
    if not entries:
        return ""
    
    import io
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=asdict(entries[0]).keys())
    writer.writeheader()
    for entry in entries:
        writer.writerow(asdict(entry))
    
    return output.getvalue()

# ──────────────────────────────────────────────────────────────── #
# Main Functions
# ──────────────────────────────────────────────────────────────── #

def get_target_files(protocols: List[str]) -> List[str]:
    """Get list of files to parse based on protocols"""
    files = []
    
    for proto in protocols:
        if proto in PROC_NET_FILES:
            file_path = PROC_NET_FILES[proto]
            if os.path.exists(file_path):
                files.append(file_path)
            else:
                logging.warning(f"File not found: {file_path}")
    
    return files

def main():
    parser = argparse.ArgumentParser(
        description="Advanced socket parser for /proc/net/* files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Examples:')[1] if 'Examples:' in __doc__ else ""
    )
    
    # Input options
    parser.add_argument('--proto', choices=['tcp', 'udp', 'tcp6', 'udp6'], 
                       action='append', help='Protocols to parse (can specify multiple)')
    parser.add_argument('--file', help='Specific file to parse')
    parser.add_argument('--all', action='store_true', 
                       help='Parse all available protocols')
    
    # Filtering options
    parser.add_argument('--filter-port', help='Filter by ports (comma-separated)')
    parser.add_argument('--filter-ip', help='Filter by IP/network (comma-separated)')
    parser.add_argument('--filter-state', help='Filter by connection state (comma-separated)')
    parser.add_argument('--filter-process', help='Filter by process name (regex)')
    
    # Output options
    parser.add_argument('--output', choices=['table', 'json', 'csv'], 
                       default='table', help='Output format')
    parser.add_argument('--sort', choices=['proto', 'state', 'local', 'remote', 'port', 'process'],
                       help='Sort by field')
    parser.add_argument('--reverse', action='store_true', help='Reverse sort order')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--no-resolve', action='store_true', help='Skip process name resolution')
    
    # Other options
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logger(args.verbose)
    
    # Determine files to parse
    if args.file:
        files = [args.file]
    elif args.all:
        files = list(PROC_NET_FILES.values())
    elif args.proto:
        files = get_target_files(args.proto)
    else:
        files = get_target_files(['tcp', 'udp'])  # Default
    
    if not files:
        logging.error("No files to parse")
        return 1
    
    # Parse all files
    all_entries = []
    for file_path in files:
        entries = parse_socket_file(file_path, not args.no_resolve)
        all_entries.extend(entries)
    
    if not all_entries:
        print("No socket entries found.")
        return 0
    
    # Apply filters
    filters = {}
    if args.filter_port:
        filters['ports'] = [int(p.strip()) for p in args.filter_port.split(',')]
    if args.filter_ip:
        filters['networks'] = [ip.strip() for ip in args.filter_ip.split(',')]
    if args.filter_state:
        filters['states'] = [s.strip() for s in args.filter_state.split(',')]
    if args.filter_process:
        filters['processes'] = [args.filter_process]
    
    filtered_entries = filter_entries(all_entries, filters)
    
    # Sort entries
    if args.sort:
        sort_key_map = {
            'proto': lambda x: x.protocol,
            'state': lambda x: x.state,
            'local': lambda x: (x.local_ip, x.local_port),
            'remote': lambda x: (x.remote_ip, x.remote_port),
            'port': lambda x: x.local_port,
            'process': lambda x: x.process_name
        }
        filtered_entries.sort(key=sort_key_map[args.sort], reverse=args.reverse)
    
    # Generate output
    use_colors = not args.no_color and sys.stdout.isatty()
    
    if args.output == 'json':
        print(format_json_output(filtered_entries))
    elif args.output == 'csv':
        print(format_csv_output(filtered_entries))
    else:  # table
        print(format_table_output(filtered_entries, use_colors))
    
    logging.info(f"Displayed {len(filtered_entries)} of {len(all_entries)} total entries")
    return 0

if __name__ == "__main__":
    sys.exit(main())
