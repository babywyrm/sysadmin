#!/usr/bin/env python3
##
##

"""
parse_audit_advanced.py - A comprehensive auditd log parser

This script parses auditd logs from one or more files, including support for
gzip-compressed logs. It extracts the key fields from each audit record, and
supports filtering by audit type, UID (or AUID), syscall, and time ranges.
Output can be produced in plain text, JSON, or CSV.

Usage Examples:
  # Parse the default audit log in plain text:
  python3 parse_audit_advanced.py

  # Parse specific log files (comma separated) with filtering by audit type:
  python3 parse_audit_advanced.py --files "/var/log/audit/audit.log,/var/log/audit/audit.log.1" --filter-type SYSCALL

  # Filter by UID and time range, output as JSON:
  python3 parse_audit_advanced.py --filter-uid 1000 --time-start 1611272000 --time-end 1611272600 --output-format json

  # Save CSV output to a file:
  python3 parse_audit_advanced.py --output-format csv --output-file audit_results.csv

Note:
  Audit log lines are expected to follow a format like:
    type=SYSCALL msg=audit(1611272033.562:104): arch=c000003e syscall=59 success=yes exit=0 ...
  Lines that do not match are skipped.
"""

import argparse
import json
import csv
import os,sys,re
import logging
import gzip
import datetime

def open_log_file(filename):
    """Open a log file, supporting gzip if the filename ends with '.gz'."""
    if filename.endswith('.gz'):
        return gzip.open(filename, 'rt', encoding='utf-8', errors='replace')
    else:
        return open(filename, 'r', encoding='utf-8', errors='replace')

def parse_audit_line(line):
    """
    Parse a single auditd log line.

    Expected format:
      type=TYPE msg=audit(TIMESTAMP:ID): key1=value1 key2="value with spaces" ...

    Returns:
      A dictionary with parsed fields if successful; otherwise, None.
    """
    pattern = r'^type=(?P<type>\S+)\s+msg=audit\((?P<timestamp>[0-9.]+):(?P<id>\d+)\):\s*(?P<kvpairs>.*)$'
    m = re.match(pattern, line)
    if not m:
        return None

    data = m.groupdict()
    kvpairs = data.pop('kvpairs', '')
    
    # Capture key=value pairs (handles quoted values)
    kv_pattern = re.compile(r'(\w+)=(".*?"|\S+)')
    fields = {}
    for match in kv_pattern.finditer(kvpairs):
        key = match.group(1)
        value = match.group(2)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value

    data.update(fields)
    return data

def parse_time(timestamp_str):
    """Convert the timestamp string (epoch seconds) to a float."""
    try:
        return float(timestamp_str)
    except Exception:
        return None

def filter_record(record, args):
    """
    Apply filters to a parsed audit record based on command-line arguments.
    Returns True if the record should be included.
    """
    # Filter by audit type (e.g., SYSCALL)
    if args.filter_type and record.get("type") != args.filter_type:
        return False

    # Filter by UID or AUID
    if args.filter_uid:
        uid = record.get("uid") or record.get("auid")
        if uid != args.filter_uid:
            return False

    # Filter by syscall (number or name)
    if args.filter_syscall:
        syscall = record.get("syscall")
        if syscall != args.filter_syscall:
            return False

    # Filter by time range (timestamps are in epoch seconds)
    if args.time_start or args.time_end:
        t = parse_time(record.get("timestamp"))
        if t is None:
            return False
        if args.time_start and t < args.time_start:
            return False
        if args.time_end and t > args.time_end:
            return False

    return True

def output_records(records, args):
    """Output parsed records in the specified format (plain, json, or csv)."""
    if args.output_format == "json":
        output = json.dumps(records, indent=2)
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
    elif args.output_format == "csv":
        # Determine CSV header from union of all keys
        keys = set()
        for rec in records:
            keys.update(rec.keys())
        keys = sorted(list(keys))
        if args.output_file:
            fout = open(args.output_file, "w", newline="", encoding="utf-8")
        else:
            fout = sys.stdout
        writer = csv.DictWriter(fout, fieldnames=keys)
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
        if args.output_file:
            fout.close()
    else:
        # Plain text output (human-friendly)
        for rec in records:
            timestamp = rec.get("timestamp", "")
            audit_type = rec.get("type", "")
            audit_id = rec.get("id", "")
            try:
                ts_float = float(timestamp)
                dt = datetime.datetime.fromtimestamp(ts_float).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                dt = timestamp
            # Build a string for the remaining fields
            other = ", ".join(f"{k}={v}" for k, v in rec.items() if k not in ["timestamp", "type", "id"])
            print(f"[{dt}] {audit_type} (id={audit_id}) {other}")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced auditd log parser for Ubuntu and RH systems"
    )
    parser.add_argument(
        "--files", "-f",
        type=str,
        default="/var/log/audit/audit.log",
        help=("Comma-separated list of audit log files to parse. "
              "Defaults to '/var/log/audit/audit.log'.")
    )
    parser.add_argument(
        "--filter-type",
        type=str,
        help="Filter records by audit type (e.g., SYSCALL)"
    )
    parser.add_argument(
        "--filter-uid",
        type=str,
        help="Filter records by UID (or AUID) value"
    )
    parser.add_argument(
        "--filter-syscall",
        type=str,
        help="Filter records by syscall number or name"
    )
    parser.add_argument(
        "--time-start",
        type=float,
        help=("Filter records with timestamp >= this epoch value. "
              "For example, 1611272000")
    )
    parser.add_argument(
        "--time-end",
        type=float,
        help="Filter records with timestamp <= this epoch value."
    )
    parser.add_argument(
        "--output-format",
        choices=["plain", "json", "csv"],
        default="plain",
        help="Output format: plain (default), json, or csv."
    )
    parser.add_argument(
        "--output-file",
        type=str,
        help="Optional file to write output to (otherwise stdout is used)."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging."
    )
    args = parser.parse_args()

    # Set logging level
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format="[%(levelname)s] %(message)s")

    # Split the files argument by comma and trim whitespace
    file_list = [f.strip() for f in args.files.split(",")]

    all_records = []
    for file_path in file_list:
        if not os.path.exists(file_path):
            logging.warning(f"File not found: {file_path}")
            continue

        logging.info(f"Processing file: {file_path}")
        try:
            with open_log_file(file_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = parse_audit_line(line)
                    if not record:
                        logging.debug("Skipping unrecognized line: " + line)
                        continue
                    if filter_record(record, args):
                        all_records.append(record)
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {e}")

    if not all_records:
        logging.info("No audit records found that match the specified criteria.")
    else:
        output_records(all_records, args)

if __name__ == "__main__":
    main()

