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
- Summary statistics

Examples:
  ./socket__.py                                # Default: show all TCP/UDP
  ./socket__.py --proto tcp --filter-state LISTEN
  ./socket__.py --filter-port 80,443          # Show HTTP/HTTPS
  ./socket__.py --filter-ip 192.168.1.0/24
  ./socket__.py --output json --no-resolve
  ./socket__.py --sort port --reverse
  ./socket__.py --stats                       # Show statistics
  ./socket__.py --all --group-by process      # Group by process
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
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Union

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

WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-S",
    68: "DHCP-C",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    443: "HTTPS",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    6443: "K8S-API",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "ELASTICSEARCH",
    10250: "KUBELET",
}

MIN_PARSE_FIELDS = 10


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
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
        if ":" in self.local_ip and not self.local_ip.startswith("["):
            return f"[{self.local_ip}]:{self.local_port}"
        return f"{self.local_ip}:{self.local_port}"

    @property
    def remote_address(self) -> str:
        if ":" in self.remote_ip and not self.remote_ip.startswith("["):
            return f"[{self.remote_ip}]:{self.remote_port}"
        return f"{self.remote_ip}:{self.remote_port}"

    @property
    def local_port_name(self) -> str:
        """Get service name for local port if known."""
        return WELL_KNOWN_PORTS.get(self.local_port, str(self.local_port))

    @property
    def remote_port_name(self) -> str:
        """Get service name for remote port if known."""
        return WELL_KNOWN_PORTS.get(self.remote_port, str(self.remote_port))


# ──────────────────────────────────────────────────────────────── #
# Utility Functions
# ──────────────────────────────────────────────────────────────── #


def setup_logger(verbose: bool = False) -> None:
    """Setup logging configuration."""
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
            if len(hex_addr) == 32:
                addr_int = int(hex_addr, 16)
                ip = str(ipaddress.IPv6Address(addr_int))
            else:
                logging.debug(f"Unexpected IPv6 hex length: {len(hex_addr)}")
                ip = hex_addr
        else:
            if len(hex_addr) == 8:
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

                            # Try comm first (faster)
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

            # Parse fields
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


def _ip_in_network(
    ip_str: str, network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
) -> bool:
    """Check if IP address is in network."""
    try:
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────── #
# Statistics Functions
# ──────────────────────────────────────────────────────────────── #


def generate_statistics(entries: List[SocketEntry], use_colors: bool = True) -> str:
    """Generate statistics from socket entries."""
    if not entries:
        return "No entries to analyze."

    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}" if use_colors else text

    lines = [
        colorize("═" * 60, Colors.BOLD),
        colorize("SOCKET STATISTICS", Colors.BOLD + Colors.CYAN),
        colorize("═" * 60, Colors.BOLD),
        "",
    ]

    # Protocol breakdown
    proto_count = Counter(e.protocol for e in entries)
    lines.append(colorize("Protocols:", Colors.BOLD))
    for proto, count in sorted(proto_count.items()):
        lines.append(f"  {proto:8} {count:5} connections")
    lines.append("")

    # State breakdown (for TCP)
    tcp_entries = [e for e in entries if "tcp" in e.protocol]
    if tcp_entries:
        state_count = Counter(e.state for e in tcp_entries)
        lines.append(colorize("TCP States:", Colors.BOLD))
        for state, count in sorted(state_count.items(), key=lambda x: -x[1]):
            lines.append(f"  {state:15} {count:5}")
        lines.append("")

    # Top processes
    process_entries = [e for e in entries if e.process_name]
    if process_entries:
        process_count = Counter(e.process_name for e in process_entries)
        lines.append(colorize("Top 10 Processes:", Colors.BOLD))
        for proc, count in process_count.most_common(10):
            lines.append(f"  {proc:30} {count:5} connections")
        lines.append("")

    # Top local ports
    port_count = Counter(e.local_port for e in entries)
    lines.append(colorize("Top 10 Local Ports:", Colors.BOLD))
    for port, count in port_count.most_common(10):
        port_name = WELL_KNOWN_PORTS.get(port, "")
        port_display = f"{port} ({port_name})" if port_name else str(port)
        lines.append(f"  {port_display:30} {count:5} connections")
    lines.append("")

    # Unique IPs
    local_ips = set(e.local_ip for e in entries if e.local_ip not in ("0.0.0.0", "::"))
    remote_ips = set(
        e.remote_ip for e in entries if e.remote_ip not in ("0.0.0.0", "::")
    )
    lines.append(colorize("Unique Addresses:", Colors.BOLD))
    lines.append(f"  Local IPs:   {len(local_ips)}")
    lines.append(f"  Remote IPs:  {len(remote_ips)}")
    lines.append("")

    # Total connections
    lines.append(colorize("Summary:", Colors.BOLD))
    lines.append(f"  Total Connections: {len(entries)}")
    lines.append("")

    lines.append(colorize("═" * 60, Colors.BOLD))

    return "\n".join(lines)


def group_by_field(
    entries: List[SocketEntry], field: str, use_colors: bool = True
) -> str:
    """Group entries by a specific field."""
    if not entries:
        return "No entries to group."

    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}" if use_colors else text

    grouped = defaultdict(list)

    for entry in entries:
        if field == "process":
            key = entry.process_name or "Unknown"
        elif field == "state":
            key = entry.state
        elif field == "protocol":
            key = entry.protocol
        elif field == "port":
            key = f"{entry.local_port} ({entry.local_port_name})"
        else:
            key = "Unknown"

        grouped[key].append(entry)

    lines = [
        colorize(f"Grouped by {field.upper()}", Colors.BOLD + Colors.CYAN),
        colorize("═" * 60, Colors.BOLD),
        "",
    ]

    for key in sorted(grouped.keys()):
        count = len(grouped[key])
        lines.append(colorize(f"{key} ({count} connections)", Colors.BOLD))

        for entry in grouped[key][:5]:  # Show first 5
            lines.append(
                f"  {entry.local_address:25} -> "
                f"{entry.remote_address:25} [{entry.state}]"
            )

        if count > 5:
            lines.append(colorize(f"  ... and {count - 5} more", Colors.DIM))
        lines.append("")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────── #
# Output Functions
# ──────────────────────────────────────────────────────────────── #


def format_table_output(
    entries: List[SocketEntry], use_colors: bool = True, show_ports: bool = False
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

    has_process = any(e.process_name for e in entries)

    # Calculate column widths
    widths = {
        "proto": max(len(e.protocol) for e in entries),
        "state": max(len(e.state) for e in entries),
        "local": max(len(e.local_address) for e in entries),
        "remote": max(len(e.remote_address) for e in entries),
    }

    # Calculate port service widths if needed
    if show_ports:
        widths["lport"] = max(len(e.local_port_name) for e in entries)
        widths["rport"] = max(len(e.remote_port_name) for e in entries)

    if has_process:
        widths["process"] = max(
            len(f"{e.process_name}({e.pid})" if e.process_name else "")
            for e in entries
        )

    # Ensure minimum widths
    widths["proto"] = max(widths["proto"], 5)
    widths["state"] = max(widths["state"], 11)
    widths["local"] = max(widths["local"], 21)
    widths["remote"] = max(widths["remote"], 21)

    if show_ports:
        widths["lport"] = max(widths.get("lport", 0), 10)
        widths["rport"] = max(widths.get("rport", 0), 10)

    if has_process:
        widths["process"] = max(widths.get("process", 0), 15)

    lines = []

    # Build header
    header_parts = [
        f"{'PROTO':<{widths['proto']}}",
        f"{'STATE':<{widths['state']}}",
        f"{'LOCAL':<{widths['local']}}",
    ]

    if show_ports:
        header_parts.append(f"{'L-SERVICE':<{widths['lport']}}")

    header_parts.append(f"{'REMOTE':<{widths['remote']}}")

    if show_ports:
        header_parts.append(f"{'R-SERVICE':<{widths['rport']}}")

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
            colorize(entry.state.ljust(widths["state"]), state_color(entry.state)),
            entry.local_address.ljust(widths["local"]),
        ]

        if show_ports:
            row_parts.append(entry.local_port_name.ljust(widths["lport"]))

        row_parts.append(entry.remote_address.ljust(widths["remote"]))

        if show_ports:
            row_parts.append(entry.remote_port_name.ljust(widths["rport"]))

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
        help="Skip process name resolution (faster)",
    )
    parser.add_argument(
        "--show-ports",
        action="store_true",
        help="Show service names for well-known ports",
    )

    # Advanced options
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show connection statistics summary",
    )
    parser.add_argument(
        "--group-by",
        choices=["process", "state", "protocol", "port"],
        help="Group output by specified field",
    )
    parser.add_argument(
        "--limit", type=int, help="Limit number of results displayed"
    )

    # Other options
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Setup logging
    setup_logger(args.verbose)

    # Check platform
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
        files = [f for f in PROC_NET_FILES.values() if os.path.exists(f)]
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
        filtered_entries.sort(key=sort_key_map[args.sort], reverse=args.reverse)

    # Limit results if requested
    if args.limit and args.limit > 0:
        filtered_entries = filtered_entries[: args.limit]

    # Determine color usage
    use_colors = not args.no_color and sys.stdout.isatty()

    # Statistics output
    if args.stats:
        print(generate_statistics(filtered_entries, use_colors))
        return 0

    # Grouped output
    if args.group_by:
        print(group_by_field(filtered_entries, args.group_by, use_colors))
        return 0

    # Regular output
    if args.output == "json":
        print(format_json_output(filtered_entries))
    elif args.output == "csv":
        print(format_csv_output(filtered_entries))
    else:  # table
        print(format_table_output(filtered_entries, use_colors, args.show_ports))

    logging.info(
        f"Displayed {len(filtered_entries)} of {len(all_entries)} entries"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
  
