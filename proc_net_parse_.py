#!/usr/bin/env python3
"""
Socket Parser - A comprehensive utility for parsing /proc/net/* connection tables (Linux)

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
  ./socket_parser.py --filter-port 80,443      # Show HTTP/HTTPS
  ./socket_parser.py --filter-ip 192.168.1.0/24
  ./socket_parser.py --output json --no-resolve
  ./socket_parser.py --sort port --reverse
"""

import argparse
import csv
import io
import ipaddress
import json
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

# ──────────────────────────────────────────────────────────────── #
# Constants and Configuration
# ──────────────────────────────────────────────────────────────── #

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

PROC_NET_FILES = {
    "tcp": "/proc/net/tcp",
    "udp": "/proc/net/udp",
    "tcp6": "/proc/net/tcp6",
    "udp6": "/proc/net/udp6",
}

MIN_PARSE_FIELDS = 10  # Minimum fields required in /proc/net/* line


# ANSI color codes
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


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
    protocol: str
    timeout: str = ""
    process_name: str = ""
    pid: str = ""

    @property
    def local_address(self) -> str:
        # Format IPv6 addresses with brackets
        if ":" in self.local_ip and not self.local_ip.startswith("["):
            return f"[{self.local_ip}]:{self.local_port}"
        return f"{self.local_ip}:{self.local_port}"

    @property
    def remote_address(self) -> str:
        if ":" in self.remote_ip and not self.remote_ip.startswith("["):
            return f"[{self.remote_ip}]:{self.remote_port}"
        return f"{self.remote_ip}:{self.remote_port}"


# ──────────────────────────────────────────────────────────────── #
# Utility Functions
# ──────────────────────────────────────────────────────────────── #


def setup_logger(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(levelname)s] %(message)s", level=level, stream=sys.stderr
    )


def hex_to_ip_port(addr_port: str, ipv6: bool = False) -> Tuple[str, int]:
    """Convert hex address:port to IP and port."""
    try:
        hex_addr, hex_port = addr_port.split(":")
        port = int(hex_port, 16)

        if ipv6:
            # Handle IPv6 - convert 32 hex chars to IPv6 address
            if len(hex_addr) == 32:
                # Convert to integer, then to IPv6Address for proper formatting
                addr_int = int(hex_addr, 16)
                ip = str(ipaddress.IPv6Address(addr_int))
            else:
                logging.debug(f"Unexpected IPv6 hex length: {len(hex_addr)}")
                ip = hex_addr
        else:
            # Handle IPv4 - 8 hex chars in little-endian byte order
            if len(hex_addr) == 8:
                # Split into byte pairs and reverse
                octets = [int(hex_addr[i : i + 2], 16) for i in range(6, -1, -2)]
                ip = ".".join(map(str, octets))
            else:
                logging.debug(f"Unexpected IPv4 hex length: {len(hex_addr)}")
                ip = hex_addr

        return ip, port
    except ValueError as e:
        logging.debug(f"Failed to parse address {addr_port}: {e}")
        return addr_port, 0


def get_process_info(inode: int) -> Tuple[str, str]:
    """Get process name and PID for a given inode."""
    if inode == 0:
        return "", ""

    try:
        # Iterate through /proc/[pid]/fd/[fd] looking for socket inodes
        proc_path = Path("/proc")
        socket_target = f"socket:[{inode}]"

        for proc_dir in proc_path.iterdir():
            if not proc_dir.name.isdigit():
                continue

            fd_dir = proc_dir / "fd"
            if not fd_dir.exists():
                continue

            try:
                for fd_link in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd_link)
                        if socket_target in target:
                            pid = proc_dir.name

                            # Try to get process name from comm first (faster)
                            comm_file = proc_dir / "comm"
                            if comm_file.exists():
                                process_name = comm_file.read_text().strip()
                                return process_name, pid

                            # Fallback to cmdline
                            cmdline_file = proc_dir / "cmdline"
                            if cmdline_file.exists():
                                cmdline = (
                                    cmdline_file.read_text()
                                    .replace("\0", " ")
                                    .strip()
                                )
                                if cmdline:
                                    process_name = os.path.basename(
                                        cmdline.split()[0]
                                    )
                                    return process_name, pid

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


def parse_socket_file(
    file_path: str, resolve_processes: bool = True
) -> List[SocketEntry]:
    """Parse a /proc/net/* file and return socket entries."""

    if not os.path.exists(file_path):
        logging.warning(f"File not found: {file_path}")
        return []

    protocol = os.path.basename(file_path)
    ipv6 = "6" in protocol

    entries = []
    process_cache: Dict[int, Tuple[str, str]] = {}

    try:
        with open(file_path, "r") as f:
            lines = f.readlines()[1:]  # Skip header
    except PermissionError:
        logging.error(
            f"Permission denied reading {file_path}. Try running with sudo."
        )
        return []
    except Exception as e:
        logging.error(f"Failed to read {file_path}: {e}")
        return []

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        try:
            fields = line.split()
            if len(fields) < MIN_PARSE_FIELDS:
                logging.debug(
                    f"Line {line_num}: insufficient fields ({len(fields)})"
                )
                continue

            # Parse fields by position
            seq = fields[0].rstrip(":")
            local_addr = fields[1]
            remote_addr = fields[2]
            state_hex = fields[3]
            uid = int(fields[7])
            inode = int(fields[9])
            timeout = fields[8] if len(fields) > 8 else ""

            # Convert addresses
            local_ip, local_port = hex_to_ip_port(local_addr, ipv6)
            remote_ip, remote_port = hex_to_ip_port(remote_addr, ipv6)

            # Decode state
            state = (
                TCP_STATES.get(state_hex, state_hex)
                if "tcp" in protocol
                else "UDP"
            )

            # Get process info with caching
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
                protocol=protocol,
            )

            entries.append(entry)

        except (ValueError, IndexError) as e:
            logging.debug(f"Failed to parse line {line_num} in {file_path}: {e}")
            continue

    logging.info(f"Parsed {len(entries)} entries from {file_path}")
    return entries


# ──────────────────────────────────────────────────────────────── #
# Filtering Functions
# ──────────────────────────────────────────────────────────────── #


def filter_entries(
    entries: List[SocketEntry], filters: Dict
) -> List[SocketEntry]:
    """Apply various filters to socket entries."""

    filtered = entries

    # Filter by ports
    if filters.get("ports"):
        port_set = set(filters["ports"])
        filtered = [
            e
            for e in filtered
            if e.local_port in port_set or e.remote_port in port_set
        ]

    # Filter by IP addresses/networks
    if filters.get("networks"):
        try:
            networks = [
                ipaddress.ip_network(net, strict=False)
                for net in filters["networks"]
            ]
            filtered = [
                e
                for e in filtered
                if any(
                    _ip_in_network(e.local_ip, net)
                    or _ip_in_network(e.remote_ip, net)
                    for net in networks
                )
            ]
        except ValueError as e:
            logging.error(f"Invalid IP network: {e}")
            return []

    # Filter by states
    if filters.get("states"):
        state_set = {s.upper() for s in filters["states"]}
        filtered = [e for e in filtered if e.state in state_set]

    # Filter by process names
    if filters.get("processes"):
        try:
            process_patterns = [
                re.compile(p, re.IGNORECASE) for p in filters["processes"]
            ]
            filtered = [
                e
                for e in filtered
                if any(
                    pattern.search(e.process_name) for pattern in process_patterns
                )
            ]
        except re.error as e:
            logging.error(f"Invalid regex pattern: {e}")
            return []

    # Filter by protocols
    if filters.get("protocols"):
        proto_set = set(filters["protocols"])
        filtered = [e for e in filtered if e.protocol in proto_set]

    return filtered


def _ip_in_network(ip_str: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Check if IP address is in network, handling errors gracefully."""
    try:
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────── #
# Output Functions
# ──────────────────────────────────────────────────────────────── #


def format_table_output(
    entries: List[SocketEntry], use_colors: bool = True
) -> str:
    """Format entries as a table."""

    if not entries:
        return "No entries found."

    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}" if use_colors else text

    def state_color(state: str) -> str:
        color_map = {
            "LISTEN": Colors.GREEN,
            "ESTABLISHED": Colors.BLUE,
            "TIME_WAIT": Colors.YELLOW,
            "CLOSE_WAIT": Colors.RED,
            "UDP": Colors.MAGENTA,
        }
        return color_map.get(state, Colors.WHITE)

    # Calculate column widths dynamically
    has_process = any(e.process_name for e in entries)

    widths = {
        "proto": max(len(e.protocol) for e in entries),
        "state": max(len(e.state) for e in entries),
        "local": max(len(e.local_address) for e in entries),
        "remote": max(len(e.remote_address) for e in entries),
    }

    if has_process:
        widths["process"] = max(
            len(f"{e.process_name}({e.pid})" if e.process_name else "")
            for e in entries
        )

    # Ensure minimum widths
    widths = {
        "proto": max(widths["proto"], 5),
        "state": max(widths["state"], 11),
        "local": max(widths["local"], 21),
        "remote": max(widths["remote"], 21),
    }

    if has_process:
        widths["process"] = max(widths.get("process", 0), 15)

    lines = []

    # Build header
    header_parts = [
        f"{'PROTO':<{widths['proto']}}",
        f"{'STATE':<{widths['state']}}",
        f"{'LOCAL':<{widths['local']}}",
        f"{'REMOTE':<{widths['remote']}}",
    ]

    if has_process:
        header_parts.append(f"{'PROCESS':<{widths['process']}}")

    header_parts.append("UID")

    header = " ".join(header_parts)
    lines.append(colorize(header, Colors.BOLD))
    lines.append("─" * len(header))

    # Build rows
    for entry in entries:
        row_parts = [
            entry.protocol.ljust(widths["proto"]),
            colorize(
                entry.state.ljust(widths["state"]), state_color(entry.state)
            ),
            entry.local_address.ljust(widths["local"]),
            entry.remote_address.ljust(widths["remote"]),
        ]

        if has_process:
            process_info = (
                f"{entry.process_name}({entry.pid})" if entry.process_name else ""
            )
            row_parts.append(process_info.ljust(widths["process"]))

        row_parts.append(str(entry.uid))

        lines.append(" ".join(row_parts))

    return "\n".join(lines)


def format_json_output(entries: List[SocketEntry]) -> str:
    """Format entries as JSON."""
    return json.dumps([asdict(entry) for entry in entries], indent=2)


def format_csv_output(entries: List[SocketEntry]) -> str:
    """Format entries as CSV."""
    if not entries:
        return ""

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
    """Get list of files to parse based on protocols."""
    files = []

    for proto in protocols:
        if proto in PROC_NET_FILES:
            file_path = PROC_NET_FILES[proto]
            if os.path.exists(file_path):
                files.append(file_path)
            else:
                logging.warning(f"File not found: {file_path}")

    return files


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Advanced socket parser for /proc/net/* files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            __doc__.split("Examples:")[1] if "Examples:" in __doc__ else ""
        ),
    )

    # Input options
    parser.add_argument(
        "--proto",
        choices=["tcp", "udp", "tcp6", "udp6"],
        action="append",
        help="Protocols to parse (can specify multiple)",
    )
    parser.add_argument("--file", help="Specific file to parse")
    parser.add_argument(
        "--all", action="store_true", help="Parse all available protocols"
    )

    # Filtering options
    parser.add_argument(
        "--filter-port", help="Filter by ports (comma-separated)"
    )
    parser.add_argument(
        "--filter-ip", help="Filter by IP/network (comma-separated)"
    )
    parser.add_argument(
        "--filter-state", help="Filter by connection state (comma-separated)"
    )
    parser.add_argument(
        "--filter-process", help="Filter by process name (regex)"
    )

    # Output options
    parser.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--sort",
        choices=["proto", "state", "local", "remote", "port", "process"],
        help="Sort by field",
    )
    parser.add_argument(
        "--reverse", action="store_true", help="Reverse sort order"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip process name resolution",
    )

    # Other options
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose logging"
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Setup logging
    setup_logger(args.verbose)

    # Check if running on Linux
    if sys.platform != "linux":
        logging.error("This script only works on Linux systems")
        return 1

    # Determine files to parse
    if args.file:
        if not os.path.exists(args.file):
            logging.error(f"File not found: {args.file}")
            return 1
        files = [args.file]
    elif args.all:
        files = [
            f for f in PROC_NET_FILES.values() if os.path.exists(f)
        ]
    elif args.proto:
        files = get_target_files(args.proto)
    else:
        files = get_target_files(["tcp", "udp"])  # Default

    if not files:
        logging.error("No valid files to parse")
        return 1

    # Parse all files
    all_entries = []
    for file_path in files:
        entries = parse_socket_file(file_path, not args.no_resolve)
        all_entries.extend(entries)

    if not all_entries:
        print("No socket entries found.")
        return 0

    # Build filters dictionary
    filters = {}
    if args.filter_port:
        try:
            filters["ports"] = [
                int(p.strip()) for p in args.filter_port.split(",")
            ]
        except ValueError as e:
            logging.error(f"Invalid port number: {e}")
            return 1

    if args.filter_ip:
        filters["networks"] = [ip.strip() for ip in args.filter_ip.split(",")]

    if args.filter_state:
        filters["states"] = [s.strip() for s in args.filter_state.split(",")]

    if args.filter_process:
        filters["processes"] = [args.filter_process]

    # Apply filters
    filtered_entries = filter_entries(all_entries, filters)

    if not filtered_entries:
        print("No entries match the specified filters.")
        return 0

    # Sort entries
    if args.sort:
        sort_key_map = {
            "proto": lambda x: x.protocol,
            "state": lambda x: x.state,
            "local": lambda x: (x.local_ip, x.local_port),
            "remote": lambda x: (x.remote_ip, x.remote_port),
            "port": lambda x: x.local_port,
            "process": lambda x: x.process_name.lower(),
        }
        filtered_entries.sort(
            key=sort_key_map[args.sort], reverse=args.reverse
        )

    # Generate output
    use_colors = not args.no_color and sys.stdout.isatty()

    if args.output == "json":
        print(format_json_output(filtered_entries))
    elif args.output == "csv":
        print(format_csv_output(filtered_entries))
    else:  # table
        print(format_table_output(filtered_entries, use_colors))

    logging.info(
        f"Displayed {len(filtered_entries)} of {len(all_entries)} entries"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
