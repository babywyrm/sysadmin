#!/usr/bin/env python3
"""
parse_fim.py — Auditd log parser for File Integrity Monitoring (FIM)

Refinements:
- Precompiled regexes
- Safer file expansion
- Deterministic output ordering
- Fixed timestamp filtering bug
- Plain output now respects --output-file
- Safer thread-pool sizing
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, TextIO


LINE_PATTERN = re.compile(
    r"^type=(?P<type>\S+)\s+msg=audit\((?P<timestamp>[0-9.]+):"
    r"(?P<id>\d+)\):\s*(?P<kvpairs>.*)$"
)
KV_PATTERN = re.compile(r'(\w+)=(".*?(?<!\\)"|\S+)')


@dataclass(slots=True)
class AuditRecord:
    """Structured representation of a single parsed auditd record."""

    type: str
    timestamp: str
    id: str
    fields: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "type": self.type,
            "timestamp": self.timestamp,
            "id": self.id,
        }
        data.update(self.fields)
        return data

    def sort_key(self) -> tuple[float, int, str]:
        ts = parse_time(self.timestamp)
        return (ts if ts is not None else -1.0, int(self.id), self.type)


def open_log_file(filename: str) -> Iterable[str]:
    """Yield lines from a plain-text or gzipped audit log."""
    try:
        if filename.endswith(".gz"):
            with gzip.open(filename, "rt", encoding="utf-8", errors="replace") as fh:
                yield from fh
        else:
            with open(filename, "r", encoding="utf-8", errors="replace") as fh:
                yield from fh
    except OSError as exc:
        logging.error("Failed to open %s: %s", filename, exc)


def parse_audit_line(line: str) -> Optional[AuditRecord]:
    """Parse a single auditd line into an AuditRecord."""
    match = LINE_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    kvpairs = data["kvpairs"]
    fields: Dict[str, str] = {}

    for kv_match in KV_PATTERN.finditer(kvpairs):
        key, value = kv_match.groups()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value

    return AuditRecord(
        type=data["type"],
        timestamp=data["timestamp"],
        id=data["id"],
        fields=fields,
    )


def parse_time(timestamp_str: str) -> Optional[float]:
    """Convert timestamp string to float seconds since epoch."""
    try:
        return float(timestamp_str)
    except ValueError:
        return None


def record_matches(record: AuditRecord, args: argparse.Namespace) -> bool:
    """Return True if the record passes the active filters."""
    fields = record.fields

    if args.filter_key and fields.get("key") != args.filter_key:
        return False

    if args.filter_path and not re.search(args.filter_path, fields.get("name", "")):
        return False

    if args.filter_syscall and fields.get("syscall") != args.filter_syscall:
        return False

    if args.time_start is not None or args.time_end is not None:
        ts = parse_time(record.timestamp)
        if ts is None:
            return False
        if args.time_start is not None and ts < args.time_start:
            return False
        if args.time_end is not None and ts > args.time_end:
            return False

    return True


def _format_timestamp(timestamp: str) -> str:
    """Format epoch timestamp into human-readable local time."""
    try:
        return dt.datetime.fromtimestamp(float(timestamp)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (TypeError, ValueError, OSError):
        return timestamp


def _open_output_stream(filename: Optional[str]) -> tuple[TextIO, bool]:
    """Return (stream, should_close)."""
    if filename:
        return open(filename, "w", encoding="utf-8", newline=""), True
    return sys.stdout, False


def output_records(records: Sequence[AuditRecord], args: argparse.Namespace) -> None:
    """Write records in plain, JSON, or CSV format."""
    if not records:
        logging.info("No matching FIM records found.")
        return

    ordered = sorted(records, key=lambda r: r.sort_key())

    if args.output_format == "json":
        content = json.dumps([record.to_dict() for record in ordered], indent=2)
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as fh:
                fh.write(content)
        else:
            print(content)
        return

    if args.output_format == "csv":
        all_keys = sorted({key for record in ordered for key in record.to_dict()})
        stream, should_close = _open_output_stream(args.output_file)
        try:
            writer = csv.DictWriter(stream, fieldnames=all_keys)
            writer.writeheader()
            for record in ordered:
                writer.writerow(record.to_dict())
        finally:
            if should_close:
                stream.close()
        return

    stream, should_close = _open_output_stream(args.output_file)
    try:
        for record in ordered:
            ts_str = _format_timestamp(record.timestamp)
            parts = [f"[{ts_str}] {record.type} (id={record.id})"]

            name = record.fields.get("name")
            syscall = record.fields.get("syscall")
            key = record.fields.get("key")

            if name:
                parts.append(f"File: {name}")
            if syscall:
                parts.append(f"Syscall: {syscall}")
            if key:
                parts.append(f"Key: {key}")

            print(" ".join(parts), file=stream)
    finally:
        if should_close:
            stream.close()


def process_file(file_path: str, args: argparse.Namespace) -> List[AuditRecord]:
    """Parse one file and return matching records."""
    logging.debug("Parsing file: %s", file_path)
    matched: List[AuditRecord] = []

    for raw_line in open_log_file(file_path):
        line = raw_line.strip()
        if not line:
            continue

        record = parse_audit_line(line)
        if record is not None and record_matches(record, args):
            matched.append(record)

    return matched


def expand_input_paths(spec: str) -> List[str]:
    """Expand comma-separated filenames and glob patterns."""
    paths: List[str] = []

    for token in (part.strip() for part in spec.split(",")):
        if not token:
            continue

        matches = sorted(glob(token))
        if matches:
            paths.extend(matches)
        else:
            paths.append(token)

    deduped = list(dict.fromkeys(paths))
    return deduped


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parse auditd logs for FIM events.")
    parser.add_argument(
        "-f",
        "--files",
        type=str,
        default="/var/log/audit/audit.log",
        help="Comma-separated list or glob of audit logs (supports .gz).",
    )
    parser.add_argument(
        "--filter-key",
        type=str,
        default="fim",
        help="Filter by audit key (default: fim).",
    )
    parser.add_argument(
        "--filter-path",
        type=str,
        help="Regex to match file paths.",
    )
    parser.add_argument(
        "--filter-syscall",
        type=str,
        help="Filter by syscall (e.g., open, unlink, chmod).",
    )
    parser.add_argument(
        "--time-start",
        type=float,
        help="Include records >= this epoch timestamp.",
    )
    parser.add_argument(
        "--time-end",
        type=float,
        help="Include records <= this epoch timestamp.",
    )
    parser.add_argument(
        "--output-format",
        choices=["plain", "json", "csv"],
        default="plain",
        help="Output format.",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        help="File to write output to.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debugging output.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    paths = expand_input_paths(args.files)
    if not paths:
        logging.error("No input files provided.")
        raise SystemExit(1)

    missing = [path for path in paths if not Path(path).exists()]
    for path in missing:
        logging.warning("Input path does not exist: %s", path)

    existing_paths = [path for path in paths if Path(path).exists()]
    if not existing_paths:
        logging.error("No readable input files found.")
        raise SystemExit(1)

    all_records: List[AuditRecord] = []
    max_workers = min(4, max(1, len(existing_paths)))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_file, path, args): path for path in existing_paths
        }
        for future in as_completed(futures):
            path = futures[future]
            try:
                all_records.extend(future.result())
            except Exception as exc:
                logging.error("Error processing %s: %s", path, exc)

    output_records(all_records, args)


if __name__ == "__main__":
    main()
