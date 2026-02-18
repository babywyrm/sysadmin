#!/usr/bin/env python3
"""
scan__.py - Simple Network Scanner
Lightweight nmap wrapper with progress indication.. (beta)..
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


class Spinner:
    """Simple CLI spinner with progress tracking."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = "Scanning"):
        self.message = message
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._completed = 0
        self._total = 0
        self._lock = threading.Lock()

    def update(self, completed: int, total: int):
        with self._lock:
            self._completed = completed
            self._total = total

    def _spin(self):
        idx = 0
        while self.running:
            with self._lock:
                c, t = self._completed, self._total
            progress = f" ({c}/{t})" if t > 0 else ""
            line = f"\r{self.FRAMES[idx % len(self.FRAMES)]} {self.message}{progress}..."
            sys.stdout.write(line)
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * 60 + "\r")
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

    # Max parallel nmap workers. Keep this reasonable — too many
    # simultaneous nmap processes will saturate the network and
    # actually slow things down.
    DEFAULT_WORKERS = 8

    def __init__(self, verbose: bool = False, workers: int = DEFAULT_WORKERS):
        self.verbose = verbose
        self.workers = workers
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

    def _chunk_network(self, network: str) -> list[str]:
        """
        Split a CIDR network into per-host targets for parallel scanning.
        For small networks (<=16 hosts) or non-CIDR targets, return as-is.
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            # Not a CIDR — single host or hostname, scan as-is
            return [network]

        hosts = list(net.hosts())

        # Small networks: no benefit splitting further
        if len(hosts) <= 16:
            return [network]

        # Chunk into /28 blocks (16 hosts each) for parallel scanning
        chunks = []
        for subnet in net.subnets(new_prefix=min(28, net.prefixlen + 4)):
            chunks.append(str(subnet))

        return chunks if chunks else [network]

    def _build_command(
        self,
        target: str,
        scan_type: str,
        ports: Optional[str],
        output_base: str,
        extra_args: list[str],
    ) -> list[str]:
        """Build nmap command for a single target."""
        cmd = [self.nmap_path]

        if scan_type == "syn" and os.geteuid() == 0:
            cmd.append("-sS")
        else:
            cmd.append("-sT")

        if ports:
            cmd.extend(["-p", ports])

        cmd.extend(["-oN", f"{output_base}.txt"])
        cmd.extend(extra_args)
        cmd.append(target)

        return cmd

    def _scan_chunk(
        self,
        target: str,
        scan_type: str,
        ports: Optional[str],
        output_base: str,
        extra_args: list[str],
    ) -> tuple[bool, str, str]:
        """
        Run nmap on a single target chunk.
        Returns (success, output_file, stderr).
        """
        cmd = self._build_command(target, scan_type, ports, output_base, extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.returncode != 0:
                return False, "", result.stderr
            return True, f"{output_base}.txt", result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "timeout"
        except Exception as e:
            return False, "", str(e)

    def _parse_results(self, results: str) -> list[HostResult]:
        """Parse nmap output into structured data."""
        hosts = []
        current_host = None
        current_hostname = None
        current_ports: list[tuple[str, str]] = []

        for line in results.split("\n"):
            line = line.strip()

            host_match = re.match(
                r"Nmap scan report for (?:(.+?) \()?(\d+\.\d+\.\d+\.\d+)\)?",
                line,
            )
            if host_match:
                if current_host:
                    hosts.append(
                        HostResult(
                            ip=current_host,
                            hostname=current_hostname,
                            open_ports=current_ports,
                        )
                    )
                current_hostname = host_match.group(1)
                current_host = host_match.group(2)
                current_ports = []
                continue

            port_match = re.match(r"(\d+)/(\w+)\s+open\s+(.+)", line)
            if port_match and current_host:
                port = port_match.group(1)
                protocol = port_match.group(2)
                service = port_match.group(3).strip()
                current_ports.append((f"{port}/{protocol}", service))

        if current_host:
            hosts.append(
                HostResult(
                    ip=current_host,
                    hostname=current_hostname,
                    open_ports=current_ports,
                )
            )

        return hosts

    def _format_report(self, hosts: list[HostResult]) -> str:
        """Format structured report."""
        report = []
        hosts_with_ports = [h for h in hosts if h.open_ports]

        if not hosts_with_ports:
            return "No hosts with open ports found."

        report.append("\n" + "=" * 70)
        report.append("SCAN RESULTS SUMMARY")
        report.append("=" * 70)
        report.append(f"Total hosts up: {len(hosts)}")
        report.append(f"Hosts with open ports: {len(hosts_with_ports)}")
        report.append(
            f"Total open ports: {sum(len(h.open_ports) for h in hosts_with_ports)}"
        )
        report.append("=" * 70)

        report.append("\n" + "=" * 70)
        report.append("HOSTS WITH OPEN PORTS")
        report.append("=" * 70)

        # Sort by IP for consistent output
        for host in sorted(hosts_with_ports, key=lambda h: ipaddress.ip_address(h.ip)):
            if host.hostname:
                report.append(f"\n┌─ {host.hostname} ({host.ip})")
            else:
                report.append(f"\n┌─ {host.ip}")
            for port, service in host.open_ports:
                report.append(f"│  ├─ {port:12} {service}")
            report.append("│")

        report.append("=" * 70)

        report.append("\n" + "=" * 70)
        report.append("PORT STATISTICS")
        report.append("=" * 70)

        port_counts: dict[str, int] = defaultdict(int)
        for host in hosts_with_ports:
            for port, _ in host.open_ports:
                port_counts[port] += 1

        for port, count in sorted(
            port_counts.items(), key=lambda x: x[1], reverse=True
        ):
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
        """Execute network scan, parallelised across target chunks."""

        extra_args: list[str] = []
        if preset:
            if preset not in self.PRESETS:
                raise ValueError(f"Unknown preset: {preset}")
            preset_obj = self.PRESETS[preset]
            ports = preset_obj.ports
            extra_args = preset_obj.extra_args
            print(f"[+] Using preset: {preset_obj.name}")
            print(f"    {preset_obj.description}\n")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        chunks = self._chunk_network(network)
        total_chunks = len(chunks)

        print("[*] Configuration:")
        print(f"    Target:   {network}")
        print(f"    Type:     {scan_type}")
        if ports:
            print(f"    Ports:    {ports}")
        print(f"    Chunks:   {total_chunks}")
        print(f"    Workers:  {min(self.workers, total_chunks)}\n")

        all_hosts: list[HostResult] = []
        output_files: list[str] = []
        errors: list[str] = []
        completed = 0
        lock = threading.Lock()

        if self.verbose:
            print("[*] Starting parallel scan...\n")
        else:
            spinner = Spinner("Scanning")
            spinner.update(0, total_chunks)
            spinner.start()

        def run_chunk(idx: int, target: str):
            nonlocal completed
            output_base = f"scan_{timestamp}_chunk{idx:03d}"
            if self.verbose:
                print(f"    [chunk {idx+1}/{total_chunks}] scanning {target}")
            success, out_file, stderr = self._scan_chunk(
                target, scan_type, ports, output_base, extra_args
            )
            with lock:
                completed += 1
                if not self.verbose:
                    spinner.update(completed, total_chunks)
                if success and Path(out_file).exists():
                    output_files.append(out_file)
                    content = Path(out_file).read_text()
                    all_hosts.extend(self._parse_results(content))
                elif stderr:
                    errors.append(f"[chunk {idx+1}] {stderr.strip()}")

        try:
            with ThreadPoolExecutor(
                max_workers=min(self.workers, total_chunks)
            ) as executor:
                futures = {
                    executor.submit(run_chunk, i, chunk): i
                    for i, chunk in enumerate(chunks)
                }
                # Propagate KeyboardInterrupt cleanly
                for future in as_completed(futures):
                    future.result()

        except KeyboardInterrupt:
            if not self.verbose:
                spinner.stop()
            print("\n[!] Interrupted")
            return {"success": False, "error": "interrupted"}
        finally:
            if not self.verbose:
                spinner.stop()

        if errors:
            for err in errors:
                print(f"[!] {err}")

        # Deduplicate hosts by IP (multiple chunks may overlap on subnet edges)
        seen: dict[str, HostResult] = {}
        for host in all_hosts:
            if host.ip not in seen:
                seen[host.ip] = host
            else:
                # Merge open ports
                existing_ports = {p for p, _ in seen[host.ip].open_ports}
                for port, svc in host.open_ports:
                    if port not in existing_ports:
                        seen[host.ip].open_ports.append((port, svc))
        merged_hosts = list(seen.values())

        # Write merged output file
        merged_output = f"scan_{timestamp}.txt"
        with open(merged_output, "w") as f:
            f.write(f"# Merged scan results - {datetime.now()}\n")
            f.write(f"# Target: {network}\n")
            f.write(f"# Chunks: {total_chunks}\n\n")
            for out_file in sorted(output_files):
                f.write(Path(out_file).read_text())
                f.write("\n")

        print("[+] Scan complete!\n")
        print(f"[+] Results saved: {merged_output}")
        if len(output_files) > 1:
            print(f"    (merged from {len(output_files)} chunk files)\n")

        report = self._format_report(merged_hosts)
        print(report)

        return {
            "success": True,
            "output_file": merged_output,
            "chunk_files": output_files,
            "hosts": merged_hosts,
        }

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
  scan__.py -n 192.168.1.0/24 --workers 16
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
    parser.add_argument(
        "--workers",
        type=int,
        default=NetworkScanner.DEFAULT_WORKERS,
        help=f"Parallel workers (default: {NetworkScanner.DEFAULT_WORKERS})",
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
        scanner = NetworkScanner(verbose=args.verbose, workers=args.workers)
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
