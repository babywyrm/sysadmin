#!/usr/bin/env python3
"""
scan__.py - Simple Network Scanner
Lightweight nmap wrapper with progress indication.. (beta)..
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


class Spinner:
    """Simple CLI spinner."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = "Scanning"):
        self.message = message
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def _spin(self):
        idx = 0
        while self.running:
            frame = self.FRAMES[idx % len(self.FRAMES)]
            sys.stdout.write(f"\r{frame} {self.message}...")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stdout.flush()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()


@dataclass
class ScanPreset:
    """Scan configuration preset."""

    name: str
    description: str
    ports: str
    extra_args: list[str]


@dataclass
class HostResult:
    """Individual host scan result."""

    ip: str
    hostname: Optional[str]
    open_ports: list[tuple[str, str]]  # [(port, service), ...]


class NetworkScanner:
    """Simple network scanner wrapper."""

    PRESETS = {
        "quick": ScanPreset(
            name="Quick Scan",
            description="Fast top 100 ports",
            ports="",
            extra_args=["-F"],
        ),
        "common": ScanPreset(
            name="Common Ports",
            description="Standard service ports",
            ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
            extra_args=[],
        ),
        "ssh": ScanPreset(
            name="SSH",
            description="SSH service discovery",
            ports="22,2022,2222",
            extra_args=[],
        ),
        "web": ScanPreset(
            name="Web Services",
            description="HTTP/HTTPS ports",
            ports="80,443,8000,8080,8443,8888",
            extra_args=[],
        ),
        "full": ScanPreset(
            name="Full Scan",
            description="All 65535 ports (slow)",
            ports="1-65535",
            extra_args=[],
        ),
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.nmap_path = self._find_nmap()

    def _find_nmap(self) -> str:
        """Locate nmap binary."""
        nmap = shutil.which("nmap")
        if not nmap:
            raise FileNotFoundError(
                "nmap not found. Install: brew install nmap (macOS) "
                "or apt install nmap (Linux)"
            )
        return nmap

    def _build_command(
        self,
        network: str,
        scan_type: str,
        ports: Optional[str],
        output_base: str,
        extra_args: list[str],
    ) -> list[str]:
        """Build nmap command."""
        cmd = [self.nmap_path]

        # Scan type
        if scan_type == "syn" and os.geteuid() == 0:
            cmd.append("-sS")
        else:
            cmd.append("-sT")

        # Ports
        if ports:
            cmd.extend(["-p", ports])

        # Output
        cmd.extend(["-oN", f"{output_base}.txt"])

        # Extra args
        cmd.extend(extra_args)

        # Target
        cmd.append(network)

        return cmd

    def _parse_results(self, results: str) -> list[HostResult]:
        """Parse nmap output into structured data."""
        hosts = []
        current_host = None
        current_hostname = None
        current_ports = []

        lines = results.split("\n")

        for line in lines:
            line = line.strip()

            # Match host line: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
            host_match = re.match(
                r"Nmap scan report for (?:(.+?) \()?(\d+\.\d+\.\d+\.\d+)\)?", line
            )
            if host_match:
                # Save previous host if exists
                if current_host:
                    hosts.append(
                        HostResult(
                            ip=current_host,
                            hostname=current_hostname,
                            open_ports=current_ports,
                        )
                    )

                # Start new host
                current_hostname = host_match.group(1)
                current_host = host_match.group(2)
                current_ports = []
                continue

            # Match open port line: "22/tcp   open   ssh"
            port_match = re.match(r"(\d+)/(\w+)\s+open\s+(.+)", line)
            if port_match and current_host:
                port = port_match.group(1)
                protocol = port_match.group(2)
                service = port_match.group(3).strip()
                current_ports.append((f"{port}/{protocol}", service))

        # Save last host
        if current_host:
            hosts.append(
                HostResult(
                    ip=current_host, hostname=current_hostname, open_ports=current_ports
                )
            )

        return hosts

    def _format_report(self, hosts: list[HostResult]) -> str:
        """Format structured report."""
        report = []

        # Filter hosts with open ports
        hosts_with_ports = [h for h in hosts if h.open_ports]

        if not hosts_with_ports:
            return "No hosts with open ports found."

        # Summary header
        report.append("\n" + "=" * 70)
        report.append("SCAN RESULTS SUMMARY")
        report.append("=" * 70)
        report.append(f"Total hosts up: {len(hosts)}")
        report.append(f"Hosts with open ports: {len(hosts_with_ports)}")
        report.append(
            f"Total open ports: {sum(len(h.open_ports) for h in hosts_with_ports)}"
        )
        report.append("=" * 70)

        # Detailed results
        report.append("\n" + "=" * 70)
        report.append("HOSTS WITH OPEN PORTS")
        report.append("=" * 70)

        for host in hosts_with_ports:
            # Host header
            if host.hostname:
                report.append(f"\n┌─ {host.hostname} ({host.ip})")
            else:
                report.append(f"\n┌─ {host.ip}")

            # Ports
            for port, service in host.open_ports:
                report.append(f"│  ├─ {port:12} {service}")

            report.append("│")

        report.append("=" * 70)

        # Port statistics
        report.append("\n" + "=" * 70)
        report.append("PORT STATISTICS")
        report.append("=" * 70)

        port_counts = defaultdict(int)
        for host in hosts_with_ports:
            for port, _ in host.open_ports:
                port_counts[port] += 1

        # Sort by count descending
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)

        for port, count in sorted_ports:
            report.append(f"  {port:12} found on {count} host(s)")

        report.append("=" * 70 + "\n")

        return "\n".join(report)

    def scan(
        self,
        network: str,
        scan_type: str = "tcp",
        ports: Optional[str] = None,
        preset: Optional[str] = None,
    ) -> dict:
        """Execute network scan."""

        # Apply preset
        extra_args = []
        if preset:
            if preset not in self.PRESETS:
                raise ValueError(f"Unknown preset: {preset}")
            preset_obj = self.PRESETS[preset]
            ports = preset_obj.ports
            extra_args = preset_obj.extra_args
            print(f"[+] Using preset: {preset_obj.name}")
            print(f"    {preset_obj.description}\n")

        # Output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_base = f"scan_{timestamp}"

        # Show config
        print("[*] Configuration:")
        print(f"    Target:  {network}")
        print(f"    Type:    {scan_type}")
        if ports:
            print(f"    Ports:   {ports}")
        print(f"    Output:  {output_base}.txt\n")

        # Build command
        cmd = self._build_command(network, scan_type, ports, output_base, extra_args)

        if self.verbose:
            print(f"[*] Command: {' '.join(cmd)}\n")

        # Execute
        print("[*] Starting scan...\n")

        try:
            if self.verbose:
                # Live output
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )

                for line in process.stdout:
                    line = line.rstrip()
                    if line:
                        print(f"    {line}")

                process.wait()
                return_code = process.returncode
            else:
                # Spinner mode
                spinner = Spinner("Scanning")
                spinner.start()

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                return_code = result.returncode

                spinner.stop()

                if return_code != 0:
                    print(f"[!] Scan failed (code {return_code})")
                    if result.stderr:
                        print(f"    {result.stderr}")
                    return {"success": False, "error": result.stderr}

            # Success
            print("[+] Scan complete!\n")

            # Parse and display results
            results_file = f"{output_base}.txt"
            if Path(results_file).exists():
                with open(results_file, "r") as f:
                    results = f.read()

                print(f"[+] Results saved: {results_file}")

                # Parse and format report
                hosts = self._parse_results(results)
                report = self._format_report(hosts)
                print(report)

                return {"success": True, "output_file": results_file, "hosts": hosts}
            else:
                return {"success": False, "error": "Output file not created"}

        except subprocess.TimeoutExpired:
            print("[!] Scan timed out")
            return {"success": False, "error": "timeout"}
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            return {"success": False, "error": "interrupted"}
        except Exception as e:
            print(f"[!] Error: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def list_presets():
        """List available presets."""
        print("\nAvailable Presets:\n")
        for key, preset in NetworkScanner.PRESETS.items():
            print(f"  {key:12} - {preset.description}")
            if preset.ports:
                print(f"               Ports: {preset.ports}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Simple Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scan__.py -n 192.168.1.0/24
  scan__.py -n 192.168.1.0/24 --preset ssh
  scan__.py -n 192.168.1.0/24 -p 80,443,8080
  scan__.py -n 192.168.1.0/24 --preset full -v
  scan__.py --list-presets
        """,
    )

    parser.add_argument("-n", "--network", help="Target network (CIDR)")
    parser.add_argument(
        "-t",
        "--type",
        choices=["tcp", "syn"],
        default="tcp",
        help="Scan type (default: tcp)",
    )
    parser.add_argument("-p", "--ports", help="Ports (e.g., 22,80,443)")
    parser.add_argument(
        "--preset", choices=list(NetworkScanner.PRESETS.keys()), help="Use preset"
    )
    parser.add_argument("--list-presets", action="store_true", help="List presets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show live output")

    args = parser.parse_args()

    print("\n=== Network Scanner ===\n")

    if args.list_presets:
        NetworkScanner.list_presets()
        return

    if not args.network:
        parser.print_help()
        print("\n[!] Error: --network is required\n")
        sys.exit(1)

    try:
        scanner = NetworkScanner(verbose=args.verbose)
        result = scanner.scan(
            network=args.network,
            scan_type=args.type,
            ports=args.ports,
            preset=args.preset,
        )

        sys.exit(0 if result.get("success") else 1)

    except KeyboardInterrupt:
        print("\n[!] Interrupted\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
