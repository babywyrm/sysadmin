#!/usr/bin/env python3
"""
parse_fim.py — Advanced Auditd Log Parser for File Integrity Monitoring (FIM)
Enhanced version with typing, dataclass modeling, and concurrency.
..beta edition..

"""

from __future__ import annotations
import argparse
import csv
import datetime
import gzip
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Union

# -------------------------------------------------------------------
# Dataclass: AuditRecord
# -------------------------------------------------------------------
@dataclass
class AuditRecord:
    """Structured representation of a single parsed auditd record."""
    type: str
    timestamp: str
    id: str
    fields: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        """Return a flattened dict including core fields."""
        base = {"type": self.type, "timestamp": self.timestamp, "id": self.id}
        base.update(self.fields)
        return base


# -------------------------------------------------------------------
# Log parsing helpers
# -------------------------------------------------------------------
def open_log_file(filename: str) -> Iterable[str]:
    """Yield lines from plain or gzipped audit logs."""
    try:
        if filename.endswith(".gz"):
            with gzip.open(filename, "rt", encoding="utf-8", errors="replace") as f:
                yield from f
        else:
            with open(filename, "r", encoding="utf-8", errors="replace") as f:
                yield from f
    except OSError as e:
        logging.error(f"Failed to open {filename}: {e}")


def parse_audit_line(line: str) -> Optional[AuditRecord]:
    """Parse a single auditd line into an AuditRecord."""
    pattern = re.compile(
        r'^type=(?P<type>\S+)\s+msg=audit\((?P<timestamp>[0-9.]+):(?P<id>\d+)\):\s*(?P<kvpairs>.*)$'
    )
    m = pattern.match(line)
    if not m:
        return None

    data = m.groupdict()
    kvpairs = data.pop("kvpairs", "")
    kv_pattern = re.compile(r'(\w+)=(".*?(?<!\\)"|\S+)')
    fields: Dict[str, str] = {}

    for match in kv_pattern.finditer(kvpairs):
        key, value = match.groups()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value

    return AuditRecord(type=data["type"], timestamp=data["timestamp"], id=data["id"], fields=fields)


def parse_time(timestamp_str: str) -> Optional[float]:
    """Convert timestamp to float seconds."""
    try:
        return float(timestamp_str)
    except ValueError:
        return None


# -------------------------------------------------------------------
# Filtering
# -------------------------------------------------------------------
def record_matches(record: AuditRecord, args: argparse.Namespace) -> bool:
    """Return True if record passes filters."""
    f = record.fields

    # Key filter
    if args.filter_key and f.get("key") != args.filter_key:
        return False

    # Path filter
    if args.filter_path and not re.search(args.filter_path, f.get("name", "")):
        return False

    # Syscall filter
    if args.filter_syscall and f.get("syscall") != args.filter_syscall:
        return False

    # Time range filter
    if args.time_start or args.time_end:
        t = parse_time(record.timestamp)
        if not t:
            return False
        if args.time_start and t < args.time_start:
            return False
        if args.time_end and t > args.time_end:
            return False

    return True


# -------------------------------------------------------------------
# Output Formatting
# -------------------------------------------------------------------
def output_records(records: List[AuditRecord], args: argparse.Namespace) -> None:
    """Write output in plain, JSON, or CSV format."""
    if not records:
        logging.info("No matching FIM records found.")
        return

    if args.output_format == "json":
        content = json.dumps([r.to_dict() for r in records], indent=2)
        _write_output(content, args.output_file)

    elif args.output_format == "csv":
        all_keys = sorted(
            {k for r in records for k in r.to_dict().keys()}
        )
        out_stream = open(args.output_file, "w", newline="", encoding="utf-8") if args.output_file else sys.stdout
        writer = csv.DictWriter(out_stream, fieldnames=all_keys)
        writer.writeheader()
        for rec in records:
            writer.writerow(rec.to_dict())
        if args.output_file:
            out_stream.close()

    else:  # plain text
        for rec in records:
            ts_str = _format_timestamp(rec.timestamp)
            msg = f"[{ts_str}] {rec.type} (id={rec.id})"
            if "name" in rec.fields:
                msg += f" File: {rec.fields['name']}"
            if "syscall" in rec.fields:
                msg += f" Syscall: {rec.fields['syscall']}"
            if "key" in rec.fields:
                msg += f" Key: {rec.fields['key']}"
            print(msg)


def _write_output(content: str, filename: Optional[str]) -> None:
    """Write text output to file or stdout."""
    if filename:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        print(content)


def _format_timestamp(ts: str) -> str:
    """Format epoch timestamp to human-readable time."""
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


# -------------------------------------------------------------------
# Main processing
# -------------------------------------------------------------------
def process_file(file_path: str, args: argparse.Namespace) -> List[AuditRecord]:
    """Parse one file and return matching records."""
    logging.debug(f"Parsing file: {file_path}")
    matched: List[AuditRecord] = []
    for line in open_log_file(file_path):
        line = line.strip()
        if not line:
            continue
        record = parse_audit_line(line)
        if record and record_matches(record, args):
            matched.append(record)
    return matched


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse auditd logs for FIM events.")
    parser.add_argument("-f", "--files", type=str,
                        default="/var/log/audit/audit.log",
                        help="Comma-separated list or glob of audit logs (supports .gz).")
    parser.add_argument("--filter-key", type=str, default="fim",
                        help="Filter by audit key (default: fim).")
    parser.add_argument("--filter-path", type=str,
                        help="Regex to match file paths.")
    parser.add_argument("--filter-syscall", type=str,
                        help="Filter by syscall (e.g., open, unlink, chmod).")
    parser.add_argument("--time-start", type=float,
                        help="Include records >= this epoch timestamp.")
    parser.add_argument("--time-end", type=float,
                        help="Include records <= this epoch timestamp.")
    parser.add_argument("--output-format", choices=["plain", "json", "csv"],
                        default="plain", help="Output format.")
    parser.add_argument("--output-file", type=str,
                        help="File to write output to (optional).")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose debugging output.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    # Expand any globs or comma-separated files
    paths: List[str] = []
    for token in args.files.split(","):
        token = token.strip()
        paths.extend([str(p) for p in Path(".").glob(token)] if "*" in token else [token])

    all_records: List[AuditRecord] = []
    with ThreadPoolExecutor(max_workers=min(4, len(paths))) as executor:
        futures = {executor.submit(process_file, p, args): p for p in paths}
        for fut in as_completed(futures):
            try:
                all_records.extend(fut.result())
            except Exception as e:
                logging.error(f"Error processing {futures[fut]}: {e}")

    output_records(all_records, args)


if __name__ == "__main__":
    main()
