#!/usr/bin/env python3
"""
package-info.py — Query installed Debian/Ubuntu package versions and
installation timestamps across multiple remote hosts via SSH.

Usage:
    python3 package-info.py <username> [--hosts hosts.txt] [--filter <prefix>]
                                       [--output report.json] [--concurrency 5]

Examples:
    python3 package-info.py admin --filter nginx
    python3 package-info.py admin --filter python3 --output report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fabric import Connection, Config
from termcolor import cprint

# ------------------------------------------------------------------------------
# Fabric config
# ------------------------------------------------------------------------------

FABRIC_CONFIG = Config(overrides={"run": {"warn": True, "hide": True}})

# ------------------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------------------

@dataclass
class PackageEntry:
    name: str
    version: str
    install_date: str | None  # ISO 8601 or None if unavailable

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "install_date": self.install_date,
        }


@dataclass
class HostReport:
    host: str
    success: bool
    packages: list[PackageEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "success": self.success,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 2),
            "packages_found": len(self.packages),
            "warnings": self.warnings,
            "packages": [p.to_dict() for p in self.packages],
        }

# ------------------------------------------------------------------------------
# Remote helper
# ------------------------------------------------------------------------------

def remote(c: Connection, cmd: str) -> tuple[str, int]:
    """Run a remote command and return (stdout, exit_code)."""
    result = c.run(cmd, warn=True, hide=True)
    return result.stdout.strip(), result.return_code

# ------------------------------------------------------------------------------
# Core logic
# ------------------------------------------------------------------------------

def query_packages(
    c: Connection,
    report: HostReport,
    filter_prefix: str | None = None,
) -> None:
    stdout, rc = remote(
        c,
        "dpkg-query -W -f='${Package} ${Version}\n'",
    )
    if rc != 0 or not stdout:
        report.warnings.append("dpkg-query returned no output or failed.")
        return

    for line in stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            report.warnings.append(f"Skipping malformed line: {line!r}")
            continue

        name, version = parts

        if filter_prefix and not name.startswith(filter_prefix):
            continue

        install_date = resolve_install_date(c, report, name)
        report.packages.append(PackageEntry(
            name=name,
            version=version,
            install_date=install_date,
        ))


def resolve_install_date(
    c: Connection,
    report: HostReport,
    package: str,
) -> str | None:
    """
    Return the install date of a package as an ISO 8601 UTC string,
    or None if the .list file does not exist.
    """
    # Sanitize package name — only allow alphanumeric, dash, dot, plus
    if not all(ch.isalnum() or ch in "-+." for ch in package):
        report.warnings.append(
            f"Skipping suspicious package name: {package!r}"
        )
        return None

    status_file = f"/var/lib/dpkg/info/{package}.list"
    _, rc = remote(c, f"test -e {status_file}")
    if rc != 0:
        report.warnings.append(
            f"No .list file for {package} — install date unavailable."
        )
        return None

    stdout, rc = remote(c, f"stat -c %Y {status_file}")
    if rc != 0 or not stdout.isdigit():
        report.warnings.append(
            f"Could not read mtime for {package}."
        )
        return None

    return datetime.fromtimestamp(int(stdout), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

# ------------------------------------------------------------------------------
# Per-host entry point
# ------------------------------------------------------------------------------

def audit_host(
    host: str,
    username: str,
    filter_prefix: str | None,
) -> HostReport:
    report = HostReport(host=host, success=False)
    start = datetime.now(timezone.utc)

    try:
        with Connection(f"{username}@{host}", config=FABRIC_CONFIG) as c:
            report.success = True
            query_packages(c, report, filter_prefix)
    except Exception as e:
        report.error = str(e)
    finally:
        report.duration_seconds = (
            datetime.now(timezone.utc) - start
        ).total_seconds()

    return report

# ------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------

def print_report(report: HostReport) -> None:
    status_color = "green" if report.success else "red"
    cprint(
        f"\n[{report.host}] {'Connected' if report.success else 'FAILED'}"
        f" ({report.duration_seconds:.1f}s)",
        status_color,
        attrs=["bold"],
    )

    if report.error:
        cprint(f"  Error: {report.error}", "red")
        return

    if not report.packages:
        cprint("  No matching packages found.", "yellow")
    else:
        cprint(
            f"  {'Package':<40} {'Version':<30} {'Installed':<25}",
            "cyan",
            attrs=["bold"],
        )
        cprint(f"  {'-'*95}", "cyan")
        for pkg in sorted(report.packages, key=lambda p: p.name):
            date_str = pkg.install_date or "unknown"
            cprint(f"  {pkg.name:<40} {pkg.version:<30} {date_str:<25}", "white")

    for warning in report.warnings:
        cprint(f"  [WARN] {warning}", "yellow")


def print_summary(reports: list[HostReport]) -> None:
    cprint(
        "\n====================================================================",
        "cyan", attrs=["bold"],
    )
    cprint("  Summary", "cyan", attrs=["bold"])
    cprint(
        "====================================================================",
        "cyan", attrs=["bold"],
    )
    for r in reports:
        status = "OK" if r.success else "FAILED"
        color  = "green" if r.success else "red"
        cprint(
            f"  {r.host:<30} {status:<8} "
            f"packages={len(r.packages)}  warnings={len(r.warnings)}"
            f"  ({r.duration_seconds:.1f}s)",
            color,
        )


def write_json_report(reports: list[HostReport], path: str) -> None:
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts_audited": len(reports),
        "reports": [r.to_dict() for r in reports],
    }
    Path(path).write_text(json.dumps(output, indent=2))
    cprint(f"\nReport written to: {path}", "cyan")

# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query installed package info across remote Debian/Ubuntu hosts."
    )
    parser.add_argument("username", help="SSH username")
    parser.add_argument(
        "--hosts",
        default="hosts",
        help="Path to newline-delimited hosts file (default: hosts)",
    )
    parser.add_argument(
        "--filter",
        dest="filter_prefix",
        default=None,
        help="Only show packages whose name starts with this prefix",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON report to this file",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of hosts to query in parallel (default: 5)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    hosts_path = Path(args.hosts)
    if not hosts_path.exists():
        cprint(f"Hosts file not found: {hosts_path}", "red")
        sys.exit(1)

    hosts = [
        line.strip()
        for line in hosts_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not hosts:
        cprint("No hosts found in hosts file.", "red")
        sys.exit(1)

    cprint(
        f"\nQuerying {len(hosts)} host(s) "
        f"[filter={args.filter_prefix or 'none'}, concurrency={args.concurrency}]",
        "cyan",
    )

    reports: list[HostReport] = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {
            executor.submit(audit_host, host, args.username, args.filter_prefix): host
            for host in hosts
        }
        for future in as_completed(futures):
            report = future.result()
            reports.append(report)
            print_report(report)

    print_summary(reports)

    if args.output:
        write_json_report(reports, args.output)


if __name__ == "__main__":
    main()
