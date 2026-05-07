#!/usr/bin/env python3
"""
parse_fim.py — Modern auditd File Integrity Monitoring parser.

Purpose:
    Parse Linux auditd logs for file integrity monitoring events, especially
    records tagged with a FIM audit key such as:

        -w /etc/passwd -p wa -k fim

Features:
    - Parses plain and gzip-compressed audit logs
    - Supports glob and comma-separated input paths
    - Filters by audit key, path, syscall, record type, UID/AUID, executable
    - Supports epoch and ISO-8601-ish time filters
    - Outputs plain text, JSON, JSONL, CSV, and summary views
    - Optionally groups audit records by audit event ID
    - Deterministic output ordering
    - Safe file handling and size limits
    - Typed dataclasses and clear structure
    - No third-party dependencies

Examples:
    Parse default audit log:

        ./parse_fim.py

    Parse rotated logs:

        ./parse_fim.py -f '/var/log/audit/audit.log*'

    Parse only /etc changes:

        ./parse_fim.py --filter-path '^/etc/'

    Parse writes/unlinks only:

        ./parse_fim.py --filter-syscall openat,unlink,rename,chmod,chown

    Output JSON:

        ./parse_fim.py --output-format json --output-file fim.json

    Summary mode:

        ./parse_fim.py --summary

    Group records by audit event ID:

        ./parse_fim.py --group-events --output-format json

Notes:
    auditd often splits one event across multiple records with the same ID:
        SYSCALL, PATH, CWD, PROCTITLE, EXECVE, etc.

    By default, this parser outputs individual records. Use --group-events to
    correlate related records into one event object.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import json
import logging
import os
import re
import shlex
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from glob import glob
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence, TextIO


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_FILES = "/var/log/audit/audit.log"
DEFAULT_KEY = "fim"

DEFAULT_MAX_FILE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_WORKERS = 4

AUDIT_LINE_RE = re.compile(
    r"^type=(?P<record_type>\S+)\s+msg=audit\("
    r"(?P<timestamp>[0-9]+(?:\.[0-9]+)?):(?P<event_id>\d+)"
    r"\):\s*(?P<body>.*)$"
)

# Handles:
#   key=value
#   key="quoted value"
#   key='single quoted value'
#
# auditd usually uses double quotes, but accepting single quotes makes the
# parser more tolerant for synthetic test data.
KV_RE = re.compile(
    r"""
    (?P<key>[A-Za-z_][A-Za-z0-9_]*)
    =
    (?P<value>
        "(?:\\.|[^"\\])*"
        |
        '(?:\\.|[^'\\])*'
        |
        \S+
    )
    """,
    re.VERBOSE,
)

HEX_PROCTITLE_RE = re.compile(r"^[0-9A-Fa-f]+$")

COMMON_WRITE_SYSCALLS = {
    "creat",
    "open",
    "openat",
    "openat2",
    "truncate",
    "ftruncate",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
    "lchown",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "utime",
    "utimes",
    "utimensat",
    "mknod",
    "mknodat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "symlink",
    "symlinkat",
    "link",
    "linkat",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class AuditRecord:
    """Single auditd record."""

    record_type: str
    timestamp: str
    event_id: str
    fields: dict[str, str]
    source_file: str
    source_line: int

    @property
    def epoch(self) -> float | None:
        return parse_epoch(self.timestamp)

    @property
    def key(self) -> str | None:
        return self.fields.get("key")

    @property
    def name(self) -> str | None:
        return self.fields.get("name")

    @property
    def syscall(self) -> str | None:
        return self.fields.get("syscall")

    @property
    def exe(self) -> str | None:
        return self.fields.get("exe")

    @property
    def auid(self) -> str | None:
        return self.fields.get("auid")

    @property
    def uid(self) -> str | None:
        return self.fields.get("uid")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "record_type": self.record_type,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "source_file": self.source_file,
            "source_line": self.source_line,
        }
        data.update(self.fields)

        human_time = format_timestamp(self.timestamp)
        if human_time:
            data["human_time"] = human_time

        decoded_proctitle = decode_proctitle(self.fields.get("proctitle"))
        if decoded_proctitle:
            data["proctitle_decoded"] = decoded_proctitle

        return data

    def sort_key(self) -> tuple[float, int, str, str, int]:
        epoch = self.epoch if self.epoch is not None else -1.0
        try:
            event_id_int = int(self.event_id)
        except ValueError:
            event_id_int = -1

        return (
            epoch,
            event_id_int,
            self.record_type,
            self.source_file,
            self.source_line,
        )


@dataclass(slots=True)
class AuditEvent:
    """Correlated auditd event, grouped by audit event ID."""

    event_id: str
    timestamp: str
    records: list[AuditRecord] = field(default_factory=list)

    @property
    def epoch(self) -> float | None:
        return parse_epoch(self.timestamp)

    @property
    def record_types(self) -> list[str]:
        return sorted({record.record_type for record in self.records})

    @property
    def paths(self) -> list[str]:
        values = {
            record.fields["name"]
            for record in self.records
            if record.fields.get("name")
        }
        return sorted(values)

    @property
    def keys(self) -> list[str]:
        values = {
            record.fields["key"]
            for record in self.records
            if record.fields.get("key")
        }
        return sorted(values)

    @property
    def syscall(self) -> str | None:
        for record in self.records:
            if record.fields.get("syscall"):
                return record.fields["syscall"]
        return None

    @property
    def exe(self) -> str | None:
        for record in self.records:
            if record.fields.get("exe"):
                return record.fields["exe"]
        return None

    @property
    def auid(self) -> str | None:
        for record in self.records:
            if record.fields.get("auid"):
                return record.fields["auid"]
        return None

    @property
    def uid(self) -> str | None:
        for record in self.records:
            if record.fields.get("uid"):
                return record.fields["uid"]
        return None

    @property
    def proctitle_decoded(self) -> str | None:
        for record in self.records:
            decoded = decode_proctitle(record.fields.get("proctitle"))
            if decoded:
                return decoded
        return None

    def to_dict(self) -> dict[str, Any]:
        human_time = format_timestamp(self.timestamp)

        data: dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "record_types": self.record_types,
            "paths": self.paths,
            "keys": self.keys,
            "syscall": self.syscall,
            "exe": self.exe,
            "uid": self.uid,
            "auid": self.auid,
            "record_count": len(self.records),
            "records": [record.to_dict() for record in sorted(self.records, key=lambda r: r.sort_key())],
        }

        if human_time:
            data["human_time"] = human_time

        if self.proctitle_decoded:
            data["proctitle_decoded"] = self.proctitle_decoded

        return data

    def sort_key(self) -> tuple[float, int]:
        epoch = self.epoch if self.epoch is not None else -1.0
        try:
            event_id_int = int(self.event_id)
        except ValueError:
            event_id_int = -1
        return epoch, event_id_int


@dataclass(slots=True, frozen=True)
class ScannerConfig:
    """Runtime configuration derived from CLI args."""

    files: str
    filter_key: str | None
    filter_path: re.Pattern[str] | None
    filter_syscalls: set[str]
    filter_record_types: set[str]
    filter_uid: str | None
    filter_auid: str | None
    filter_exe: re.Pattern[str] | None
    time_start: float | None
    time_end: float | None
    output_format: str
    output_file: str | None
    group_events: bool
    summary: bool
    include_source: bool
    max_workers: int
    max_file_bytes: int
    hash_input_files: bool


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_epoch(value: str) -> float | None:
    """Parse an audit epoch timestamp."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_time_filter(value: str | None) -> float | None:
    """
    Parse a CLI time filter.

    Accepted:
        1710000000
        1710000000.123
        2026-05-06
        2026-05-06T13:00:00
        2026-05-06 13:00:00
        2026-05-06T13:00:00Z

    Naive date/time values are interpreted in local time.
    """
    if not value:
        return None

    value = value.strip()

    try:
        return float(value)
    except ValueError:
        pass

    normalized = value.replace("Z", "+00:00")

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", normalized):
        parsed = dt.datetime.strptime(normalized, "%Y-%m-%d")
        return parsed.timestamp()

    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid time value {value!r}; use epoch or ISO date/time"
        ) from exc

    return parsed.timestamp()


def format_timestamp(timestamp: str) -> str | None:
    """Convert epoch timestamp to local time string."""
    epoch = parse_epoch(timestamp)
    if epoch is None:
        return None

    try:
        return dt.datetime.fromtimestamp(epoch).isoformat(timespec="seconds")
    except (ValueError, OSError):
        return None


def unquote_audit_value(value: str) -> str:
    """Unquote and unescape a parsed audit value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        inner = value[1:-1]
        try:
            return bytes(inner, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return inner
    return value


def parse_kv_pairs(body: str) -> dict[str, str]:
    """Parse audit key/value body into a dictionary."""
    fields: dict[str, str] = {}

    for match in KV_RE.finditer(body):
        key = match.group("key")
        value = unquote_audit_value(match.group("value"))
        fields[key] = value

    return fields


def parse_audit_line(line: str, source_file: str, source_line: int) -> AuditRecord | None:
    """Parse a single auditd log line."""
    match = AUDIT_LINE_RE.match(line)
    if not match:
        return None

    groups = match.groupdict()
    fields = parse_kv_pairs(groups["body"])

    return AuditRecord(
        record_type=groups["record_type"],
        timestamp=groups["timestamp"],
        event_id=groups["event_id"],
        fields=fields,
        source_file=source_file,
        source_line=source_line,
    )


def decode_proctitle(value: str | None) -> str | None:
    """
    Decode auditd proctitle.

    auditd usually hex-encodes proctitle with NUL separators between argv values.
    """
    if not value:
        return None

    if not HEX_PROCTITLE_RE.fullmatch(value) or len(value) % 2 != 0:
        return None

    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None

    parts = [part.decode("utf-8", errors="replace") for part in raw.split(b"\x00") if part]
    if not parts:
        return None

    return " ".join(shlex.quote(part) for part in parts)


# ---------------------------------------------------------------------------
# File handling
# ---------------------------------------------------------------------------

def expand_input_paths(spec: str) -> list[Path]:
    """Expand comma-separated input specs and glob patterns."""
    paths: list[Path] = []

    for token in (part.strip() for part in spec.split(",")):
        if not token:
            continue

        expanded_token = os.path.expanduser(os.path.expandvars(token))
        matches = sorted(glob(expanded_token))

        if matches:
            paths.extend(Path(match) for match in matches)
        else:
            paths.append(Path(expanded_token))

    deduped: dict[str, Path] = {}
    for path in paths:
        deduped[str(path)] = path

    return list(deduped.values())


def validate_input_paths(paths: Sequence[Path], max_file_bytes: int) -> list[Path]:
    """Return readable regular files within size limit."""
    valid: list[Path] = []

    for path in paths:
        try:
            if not path.exists():
                logging.warning("Input path does not exist: %s", path)
                continue

            if not path.is_file():
                logging.warning("Input path is not a regular file: %s", path)
                continue

            size = path.stat().st_size
            if size > max_file_bytes:
                logging.warning(
                    "Skipping %s because it is too large: %d bytes > %d bytes",
                    path,
                    size,
                    max_file_bytes,
                )
                continue

            valid.append(path)

        except OSError as exc:
            logging.warning("Cannot inspect %s: %s", path, exc)

    return valid


def open_log_file(path: Path) -> Iterator[str]:
    """Yield lines from a plain-text or gzip-compressed audit log."""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                yield from handle
        else:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                yield from handle
    except OSError as exc:
        logging.error("Failed to open %s: %s", path, exc)


def sha256_file(path: Path) -> str | None:
    """Compute SHA-256 of an input file."""
    digest = hashlib.sha256()

    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        logging.warning("Could not hash %s: %s", path, exc)
        return None


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def normalize_csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip() for part in value.split(",") if part.strip()}


def record_matches(record: AuditRecord, config: ScannerConfig) -> bool:
    """Return True if the record matches active filters."""
    fields = record.fields

    if config.filter_key is not None and fields.get("key") != config.filter_key:
        return False

    if config.filter_path is not None:
        name = fields.get("name", "")
        if not config.filter_path.search(name):
            return False

    if config.filter_syscalls:
        syscall = fields.get("syscall")
        if syscall not in config.filter_syscalls:
            return False

    if config.filter_record_types and record.record_type not in config.filter_record_types:
        return False

    if config.filter_uid is not None and fields.get("uid") != config.filter_uid:
        return False

    if config.filter_auid is not None and fields.get("auid") != config.filter_auid:
        return False

    if config.filter_exe is not None:
        exe = fields.get("exe", "")
        if not config.filter_exe.search(exe):
            return False

    if config.time_start is not None or config.time_end is not None:
        epoch = record.epoch
        if epoch is None:
            return False

        if config.time_start is not None and epoch < config.time_start:
            return False

        if config.time_end is not None and epoch > config.time_end:
            return False

    return True


def event_matches(event: AuditEvent, config: ScannerConfig) -> bool:
    """
    Return True if an event matches active filters.

    This lets --group-events retain useful context records from the same event
    even when only one record contains key/path/syscall fields.
    """
    return any(record_matches(record, config) for record in event.records)


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------

def process_file(path: Path, config: ScannerConfig) -> list[AuditRecord]:
    """Parse one file and return matching records."""
    logging.debug("Parsing file: %s", path)

    matched: list[AuditRecord] = []

    for line_number, raw_line in enumerate(open_log_file(path), start=1):
        line = raw_line.strip()
        if not line:
            continue

        record = parse_audit_line(line, str(path), line_number)
        if record is None:
            continue

        if record_matches(record, config):
            matched.append(record)

    return matched


def process_file_all_records(path: Path) -> list[AuditRecord]:
    """Parse one file and return all audit records."""
    logging.debug("Parsing file for event grouping: %s", path)

    records: list[AuditRecord] = []

    for line_number, raw_line in enumerate(open_log_file(path), start=1):
        line = raw_line.strip()
        if not line:
            continue

        record = parse_audit_line(line, str(path), line_number)
        if record is not None:
            records.append(record)

    return records


def group_records(records: Iterable[AuditRecord]) -> list[AuditEvent]:
    """Group audit records by event ID."""
    grouped: dict[str, list[AuditRecord]] = defaultdict(list)

    for record in records:
        grouped[record.event_id].append(record)

    events: list[AuditEvent] = []

    for event_id, event_records in grouped.items():
        ordered = sorted(event_records, key=lambda record: record.sort_key())
        timestamp = ordered[0].timestamp if ordered else "0"
        events.append(AuditEvent(event_id=event_id, timestamp=timestamp, records=ordered))

    return sorted(events, key=lambda event: event.sort_key())


def collect_records(paths: Sequence[Path], config: ScannerConfig) -> list[AuditRecord]:
    """Collect matching records from all input files."""
    records: list[AuditRecord] = []

    workers = min(config.max_workers, max(1, len(paths)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(process_file, path, config): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            try:
                records.extend(future.result())
            except Exception as exc:
                logging.error("Error processing %s: %s", path, exc)

    return sorted(records, key=lambda record: record.sort_key())


def collect_events(paths: Sequence[Path], config: ScannerConfig) -> list[AuditEvent]:
    """
    Collect grouped events.

    This parses all records first, then applies filters at event level so useful
    sibling records are preserved.
    """
    all_records: list[AuditRecord] = []
    workers = min(config.max_workers, max(1, len(paths)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(process_file_all_records, path): path
            for path in paths
        }

        for future in as_completed(futures):
            path = futures[future]
            try:
                all_records.extend(future.result())
            except Exception as exc:
                logging.error("Error processing %s: %s", path, exc)

    events = group_records(all_records)
    return [event for event in events if event_matches(event, config)]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def open_output_stream(filename: str | None) -> tuple[TextIO, bool]:
    """Return output stream and whether the caller should close it."""
    if filename:
        path = Path(filename).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        return path.open("w", encoding="utf-8", newline=""), True

    return sys.stdout, False


def write_json(data: Any, output_file: str | None) -> None:
    stream, should_close = open_output_stream(output_file)
    try:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
    finally:
        if should_close:
            stream.close()


def write_jsonl(rows: Iterable[Mapping[str, Any]], output_file: str | None) -> None:
    stream, should_close = open_output_stream(output_file)
    try:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True))
            stream.write("\n")
    finally:
        if should_close:
            stream.close()


def write_csv(rows: Sequence[Mapping[str, Any]], output_file: str | None) -> None:
    stream, should_close = open_output_stream(output_file)

    try:
        if not rows:
            return

        fieldnames = sorted({key for row in rows for key in row.keys()})
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for row in rows:
            normalized = {
                key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
                for key, value in row.items()
            }
            writer.writerow(normalized)

    finally:
        if should_close:
            stream.close()


def write_plain_records(records: Sequence[AuditRecord], config: ScannerConfig) -> None:
    stream, should_close = open_output_stream(config.output_file)

    try:
        for record in records:
            row = record.to_dict()

            parts = [
                f"[{row.get('human_time', record.timestamp)}]",
                record.record_type,
                f"event_id={record.event_id}",
            ]

            if record.name:
                parts.append(f"path={record.name}")

            if record.syscall:
                parts.append(f"syscall={record.syscall}")

            if record.key:
                parts.append(f"key={record.key}")

            if record.exe:
                parts.append(f"exe={record.exe}")

            if record.auid:
                parts.append(f"auid={record.auid}")

            decoded = row.get("proctitle_decoded")
            if decoded:
                parts.append(f"cmd={decoded}")

            if config.include_source:
                parts.append(f"source={record.source_file}:{record.source_line}")

            print(" ".join(parts), file=stream)

    finally:
        if should_close:
            stream.close()


def write_plain_events(events: Sequence[AuditEvent], config: ScannerConfig) -> None:
    stream, should_close = open_output_stream(config.output_file)

    try:
        for event in events:
            row = event.to_dict()

            parts = [
                f"[{row.get('human_time', event.timestamp)}]",
                f"event_id={event.event_id}",
                f"records={len(event.records)}",
            ]

            if event.paths:
                parts.append(f"paths={','.join(event.paths)}")

            if event.syscall:
                parts.append(f"syscall={event.syscall}")

            if event.keys:
                parts.append(f"keys={','.join(event.keys)}")

            if event.exe:
                parts.append(f"exe={event.exe}")

            if event.auid:
                parts.append(f"auid={event.auid}")

            if event.proctitle_decoded:
                parts.append(f"cmd={event.proctitle_decoded}")

            print(" ".join(parts), file=stream)

    finally:
        if should_close:
            stream.close()


def summarize_records(records: Sequence[AuditRecord]) -> dict[str, Any]:
    paths = Counter(record.name for record in records if record.name)
    syscalls = Counter(record.syscall for record in records if record.syscall)
    keys = Counter(record.key for record in records if record.key)
    exes = Counter(record.exe for record in records if record.exe)
    record_types = Counter(record.record_type for record in records)

    return {
        "total_records": len(records),
        "record_types": dict(record_types.most_common()),
        "top_paths": dict(paths.most_common(20)),
        "top_syscalls": dict(syscalls.most_common(20)),
        "top_keys": dict(keys.most_common(20)),
        "top_executables": dict(exes.most_common(20)),
    }


def summarize_events(events: Sequence[AuditEvent]) -> dict[str, Any]:
    paths: Counter[str] = Counter()
    syscalls: Counter[str] = Counter()
    keys: Counter[str] = Counter()
    exes: Counter[str] = Counter()
    record_types: Counter[str] = Counter()

    for event in events:
        paths.update(event.paths)
        if event.syscall:
            syscalls[event.syscall] += 1
        keys.update(event.keys)
        if event.exe:
            exes[event.exe] += 1
        record_types.update(event.record_types)

    return {
        "total_events": len(events),
        "record_types": dict(record_types.most_common()),
        "top_paths": dict(paths.most_common(20)),
        "top_syscalls": dict(syscalls.most_common(20)),
        "top_keys": dict(keys.most_common(20)),
        "top_executables": dict(exes.most_common(20)),
    }


def output_records(records: Sequence[AuditRecord], config: ScannerConfig) -> None:
    if config.summary:
        write_json(summarize_records(records), config.output_file)
        return

    rows = [record.to_dict() for record in records]

    if config.output_format == "json":
        write_json(rows, config.output_file)
    elif config.output_format == "jsonl":
        write_jsonl(rows, config.output_file)
    elif config.output_format == "csv":
        write_csv(rows, config.output_file)
    else:
        write_plain_records(records, config)


def output_events(events: Sequence[AuditEvent], config: ScannerConfig) -> None:
    if config.summary:
        write_json(summarize_events(events), config.output_file)
        return

    rows = [event.to_dict() for event in events]

    if config.output_format == "json":
        write_json(rows, config.output_file)
    elif config.output_format == "jsonl":
        write_jsonl(rows, config.output_file)
    elif config.output_format == "csv":
        write_csv(rows, config.output_file)
    else:
        write_plain_events(events, config)


def output_input_hashes(paths: Sequence[Path]) -> None:
    for path in paths:
        digest = sha256_file(path)
        if digest:
            logging.info("Input SHA-256 %s  %s", digest, path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def compile_optional_regex(value: str | None, label: str) -> re.Pattern[str] | None:
    if not value:
        return None

    try:
        return re.compile(value)
    except re.error as exc:
        raise argparse.ArgumentTypeError(f"invalid {label} regex {value!r}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse auditd logs for File Integrity Monitoring events.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-f",
        "--files",
        default=DEFAULT_FILES,
        help="Comma-separated list or glob of audit logs. Supports .gz files.",
    )

    parser.add_argument(
        "--filter-key",
        default=DEFAULT_KEY,
        help="Filter by audit key. Use empty string to disable.",
    )

    parser.add_argument(
        "--filter-path",
        help="Regex matched against audit PATH name fields.",
    )

    parser.add_argument(
        "--filter-syscall",
        help=(
            "Comma-separated syscall names to include. "
            "Example: openat,unlink,rename,chmod"
        ),
    )

    parser.add_argument(
        "--write-syscalls-only",
        action="store_true",
        help="Shortcut for common write/metadata-changing syscalls.",
    )

    parser.add_argument(
        "--filter-record-type",
        help="Comma-separated audit record types. Example: SYSCALL,PATH,CWD",
    )

    parser.add_argument(
        "--filter-uid",
        help="Filter by uid field.",
    )

    parser.add_argument(
        "--filter-auid",
        help="Filter by auid field.",
    )

    parser.add_argument(
        "--filter-exe",
        help="Regex matched against executable path.",
    )

    parser.add_argument(
        "--time-start",
        type=parse_time_filter,
        help="Include records at or after this time. Accepts epoch or ISO date/time.",
    )

    parser.add_argument(
        "--time-end",
        type=parse_time_filter,
        help="Include records at or before this time. Accepts epoch or ISO date/time.",
    )

    parser.add_argument(
        "--output-format",
        choices=("plain", "json", "jsonl", "csv"),
        default="plain",
        help="Output format.",
    )

    parser.add_argument(
        "--output-file",
        help="Write output to this file instead of stdout.",
    )

    parser.add_argument(
        "--group-events",
        action="store_true",
        help="Group related audit records by event ID.",
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Output a JSON summary instead of individual records.",
    )

    parser.add_argument(
        "--include-source",
        action="store_true",
        help="Include source file and line number in plain output.",
    )

    parser.add_argument(
        "--hash-input-files",
        action="store_true",
        help="Log SHA-256 hashes of input files for evidence tracking.",
    )

    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="Maximum parser worker threads.",
    )

    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Skip input files larger than this many bytes.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )

    return parser


def config_from_args(args: argparse.Namespace) -> ScannerConfig:
    filter_key = args.filter_key
    if filter_key == "":
        filter_key = None

    filter_syscalls = normalize_csv_set(args.filter_syscall)
    if args.write_syscalls_only:
        filter_syscalls.update(COMMON_WRITE_SYSCALLS)

    max_workers = max(1, min(args.max_workers, 32))

    return ScannerConfig(
        files=args.files,
        filter_key=filter_key,
        filter_path=compile_optional_regex(args.filter_path, "path"),
        filter_syscalls=filter_syscalls,
        filter_record_types=normalize_csv_set(args.filter_record_type),
        filter_uid=args.filter_uid,
        filter_auid=args.filter_auid,
        filter_exe=compile_optional_regex(args.filter_exe, "exe"),
        time_start=args.time_start,
        time_end=args.time_end,
        output_format=args.output_format,
        output_file=args.output_file,
        group_events=args.group_events,
        summary=args.summary,
        include_source=args.include_source,
        max_workers=max_workers,
        max_file_bytes=max(1, args.max_file_bytes),
        hash_input_files=args.hash_input_files,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    try:
        config = config_from_args(args)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    paths = expand_input_paths(config.files)
    if not paths:
        logging.error("No input files provided.")
        return 1

    valid_paths = validate_input_paths(paths, config.max_file_bytes)
    if not valid_paths:
        logging.error("No readable input files found.")
        return 1

    if config.hash_input_files:
        output_input_hashes(valid_paths)

    if config.group_events:
        events = collect_events(valid_paths, config)
        if not events:
            logging.info("No matching FIM events found.")
        output_events(events, config)
    else:
        records = collect_records(valid_paths, config)
        if not records:
            logging.info("No matching FIM records found.")
        output_records(records, config)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
