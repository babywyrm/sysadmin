#!/usr/bin/env python3
"""scan__.py - Lightweight nmap wrapper with parallel scanning."""

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
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class Spinner:
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = "Scanning"):
        self.message = message
        self.running = False
        self._c = self._t = 0
        self._lock = threading.Lock()

    def update(self, c: int, t: int):
        with self._lock:
            self._c, self._t = c, t

    def _spin(self):
        for idx in range(10**9):
            if not self.running:
                break
            with self._lock:
                progress = f" ({self._c}/{self._t})" if self._t else ""
            sys.stdout.write(f"\r{self.FRAMES[idx % 10]} {self.message}{progress}...")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

    def start(self):
        self.running = True
        threading.Thread(target=self._spin, daemon=True).start()

    def stop(self):
        self.running = False
        time.sleep(0.15)  # let _spin exit cleanly


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class ScanPreset:
    name: str
    description: str
    ports: str
    extra_args: list[str] = field(default_factory=list)


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str]
    open_ports: list[tuple[str, str]]  # [(port/proto, service)]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

PRESETS: dict[str, ScanPreset] = {
    "quick":  ScanPreset("Quick",   "Top 100 ports",          "",         ["-F"]),
    "common": ScanPreset("Common",  "Standard service ports", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"),
    "ssh":    ScanPreset("SSH",     "SSH discovery",          "22,2022,2222"),
    "web":    ScanPreset("Web",     "HTTP/HTTPS ports",       "80,443,8000,8080,8443,8888"),
    "full":   ScanPreset("Full",    "All 65535 ports (slow)", "1-65535"),
}


class NetworkScanner:
    DEFAULT_WORKERS = 8

    def __init__(self, verbose: bool = False, workers: int = DEFAULT_WORKERS):
        self.verbose = verbose
        self.workers = workers
        self.nmap = shutil.which("nmap") or self._no_nmap()

    @staticmethod
    def _no_nmap():
        raise FileNotFoundError(
            "nmap not found — brew install nmap (macOS) / apt install nmap (Linux)"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _chunks(self, network: str) -> list[str]:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return [network]
        if len(list(net.hosts())) <= 16:
            return [network]
        subs = list(net.subnets(new_prefix=min(28, net.prefixlen + 4)))
        return [str(s) for s in subs] or [network]

    def _build_cmd(self, target: str, scan_type: str, ports: Optional[str],
                   out_base: str, extra: list[str]) -> list[str]:
        cmd = [self.nmap, "-sS" if scan_type == "syn" and os.geteuid() == 0 else "-sT"]
        if ports:
            cmd += ["-p", ports]
        cmd += ["-oN", f"{out_base}.txt"] + extra + [target]
        return cmd

    def _run_chunk(self, target: str, scan_type: str, ports: Optional[str],
                   out_base: str, extra: list[str]) -> tuple[bool, str, str]:
        try:
            r = subprocess.run(
                self._build_cmd(target, scan_type, ports, out_base, extra),
                capture_output=True, text=True, timeout=600,
            )
            return (r.returncode == 0, f"{out_base}.txt", r.stderr)
        except subprocess.TimeoutExpired:
            return False, "", "timeout"
        except Exception as e:
            return False, "", str(e)

    # ------------------------------------------------------------------
    # Parse / report
    # ------------------------------------------------------------------

    def _parse(self, text: str) -> list[HostResult]:
        hosts, cur_ip, cur_name, cur_ports = [], None, None, []
        for line in text.splitlines():
            line = line.strip()
            m = re.match(r"Nmap scan report for (?:(.+?) \()?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if m:
                if cur_ip:
                    hosts.append(HostResult(cur_ip, cur_name, cur_ports))
                cur_name, cur_ip, cur_ports = m.group(1), m.group(2), []
                continue
            m = re.match(r"(\d+)/(\w+)\s+open\s+(.+)", line)
            if m and cur_ip:
                cur_ports.append((f"{m.group(1)}/{m.group(2)}", m.group(3).strip()))
        if cur_ip:
            hosts.append(HostResult(cur_ip, cur_name, cur_ports))
        return hosts

    def _report(self, hosts: list[HostResult]) -> str:
        active = [h for h in hosts if h.open_ports]
        if not active:
            return "No hosts with open ports found."

        div = "=" * 70
        lines = [
            f"\n{div}", "SCAN RESULTS SUMMARY", div,
            f"Hosts up: {len(hosts)}  |  With open ports: {len(active)}"
            f"  |  Total open ports: {sum(len(h.open_ports) for h in active)}",
            div, f"\n{div}", "HOSTS WITH OPEN PORTS", div,
        ]

        for h in sorted(active, key=lambda h: ipaddress.ip_address(h.ip)):
            label = f"{h.hostname} ({h.ip})" if h.hostname else h.ip
            lines.append(f"\n┌─ {label}")
            for port, svc in h.open_ports:
                lines.append(f"│  ├─ {port:12} {svc}")
            lines.append("│")

        port_counts: dict[str, int] = defaultdict(int)
        for h in active:
            for port, _ in h.open_ports:
                port_counts[port] += 1

        lines += [f"\n{div}", "PORT STATISTICS", div]
        for port, count in sorted(port_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {port:12} {count} host(s)")
        lines.append(f"{div}\n")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    def scan(self, network: str, scan_type: str = "tcp",
             ports: Optional[str] = None, preset: Optional[str] = None) -> dict:

        extra: list[str] = []
        if preset:
            p = PRESETS[preset]
            ports, extra = p.ports, p.extra_args
            print(f"[+] Preset: {p.name} — {p.description}\n")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        chunks = self._chunks(network)
        n = len(chunks)

        print(f"[*] Target: {network} | Type: {scan_type}"
              + (f" | Ports: {ports}" if ports else "")
              + f" | Chunks: {n} | Workers: {min(self.workers, n)}\n")

        all_hosts: list[HostResult] = []
        out_files: list[str] = []
        errors: list[str] = []
        completed = 0
        lock = threading.Lock()

        spinner = None if self.verbose else Spinner()
        if spinner:
            spinner.update(0, n)
            spinner.start()

        def run_chunk(i: int, target: str):
            nonlocal completed
            ok, out, err = self._run_chunk(
                target, scan_type, ports, f"scan_{ts}_chunk{i:03d}", extra
            )
            with lock:
                completed += 1
                if spinner:
                    spinner.update(completed, n)
                if ok and Path(out).exists():
                    out_files.append(out)
                    all_hosts.extend(self._parse(Path(out).read_text()))
                elif err:
                    errors.append(f"[chunk {i+1}] {err.strip()}")
            if self.verbose:
                print(f"  [{completed}/{n}] {target} — {'ok' if ok else 'error'}")

        try:
            with ThreadPoolExecutor(max_workers=min(self.workers, n)) as ex:
                for f in as_completed(
                    {ex.submit(run_chunk, i, c): i for i, c in enumerate(chunks)}
                ):
                    f.result()
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            return {"success": False, "error": "interrupted"}
        finally:
            if spinner:
                spinner.stop()

        for err in errors:
            print(f"[!] {err}")

        # Deduplicate / merge hosts across chunk boundaries
        seen: dict[str, HostResult] = {}
        for h in all_hosts:
            if h.ip not in seen:
                seen[h.ip] = h
            else:
                have = {p for p, _ in seen[h.ip].open_ports}
                seen[h.ip].open_ports += [(p, s) for p, s in h.open_ports if p not in have]

        merged = f"scan_{ts}.txt"
        with open(merged, "w") as f:
            f.write(f"# Target: {network} | {datetime.now()}\n\n")
            for fp in sorted(out_files):
                f.write(Path(fp).read_text() + "\n")

        print(f"[+] Done — {merged}" + (f" (merged {len(out_files)} chunks)" if len(out_files) > 1 else ""))
        print(self._report(list(seen.values())))

        return {"success": True, "output_file": merged,
                "chunk_files": out_files, "hosts": list(seen.values())}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Simple Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "Examples:",
            "  scan__.py -n 192.168.1.0/24",
            "  scan__.py -n 192.168.1.0/24 --preset ssh",
            "  scan__.py -n 192.168.1.0/24 -p 80,443,8080",
            "  scan__.py -n 192.168.1.0/24 --preset full -v",
            "  scan__.py --list-presets",
        ]),
    )
    parser.add_argument("-n", "--network")
    parser.add_argument("-t", "--type", choices=["tcp", "syn"], default="tcp")
    parser.add_argument("-p", "--ports")
    parser.add_argument("--preset", choices=list(PRESETS))
    parser.add_argument("--workers", type=int, default=NetworkScanner.DEFAULT_WORKERS)
    parser.add_argument("--list-presets", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    print("\n=== Network Scanner ===\n")

    if args.list_presets:
        for key, p in PRESETS.items():
            print(f"  {key:8} {p.description}" + (f"  [{p.ports}]" if p.ports else ""))
        print()
        return

    if not args.network:
        parser.print_help()
        sys.exit(1)

    try:
        scanner = NetworkScanner(verbose=args.verbose, workers=args.workers)
        result = scanner.scan(args.network, args.type, args.ports, args.preset)
        sys.exit(0 if result.get("success") else 1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
