#!/usr/bin/env python3
"""
parse_audit.py - A Python3 script to parse auditd logs

Usage examples:
  # Parse the default audit log and print in plain text:
  python3 parse_audit.py

  # Specify a different log file and filter by audit type (e.g. SYSCALL)
  python3 parse_audit.py --file /var/log/audit/audit.log --filter-type SYSCALL

  # Output results in JSON format
  python3 parse_audit.py --json

Note:
  This script expects auditd log entries to be in the common format, for example:
    type=SYSCALL msg=audit(1611272033.562:104): arch=c000003e syscall=59 success=yes exit=0 ...
  It uses regular expressions to capture the fields and key=value pairs.
"""

import re
import argparse
import json
import sys

def parse_audit_line(line):
    """
    Parse a single auditd log line.

    Expected format:
      type=TYPE msg=audit(TIMESTAMP:ID): key1=value1 key2="value with spaces" ...

    Returns a dictionary with the parsed fields or None if the line does not match.
    """
    # Regular expression to capture the audit type, timestamp, id, and remaining key/value pairs.
    pattern = r'^type=(?P<type>\S+)\s+msg=audit\((?P<timestamp>[0-9.]+):(?P<id>\d+)\):\s*(?P<kvpairs>.*)$'
    m = re.match(pattern, line)
    if not m:
        return None

    data = m.groupdict()
    kvpairs = data.pop('kvpairs', '')
    
    # Regex to capture key=value pairs.
    # This matches keys composed of word characters and values that are either quoted or non‑whitespace.
    kv_pattern = re.compile(r'(\w+)=(".*?"|\S+)')
    fields = {}
    for match in kv_pattern.finditer(kvpairs):
        key = match.group(1)
        value = match.group(2)
        # Remove surrounding quotes if present.
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value

    # Merge the key/value fields with the primary fields.
    data.update(fields)
    return data

def main():
    parser = argparse.ArgumentParser(
        description="Parse auditd logs and output them in JSON or plain text."
    )
    parser.add_argument(
        "--file", "-f", type=str,
        default="/var/log/audit/audit.log",
        help="Path to the auditd log file (default: /var/log/audit/audit.log)"
    )
    parser.add_argument(
        "--filter-type", type=str,
        help="Only output log entries of the specified audit type (e.g., SYSCALL)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output the parsed results in JSON format"
    )
    args = parser.parse_args()

    try:
        with open(args.file, "r") as f:
            lines = f.readlines()
    except Exception as e:
        sys.stderr.write(f"Error reading file {args.file}: {e}\n")
        sys.exit(1)

    parsed_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parsed = parse_audit_line(line)
        if not parsed:
            # If a line doesn't match the expected format, skip it.
            continue
        # If --filter-type is specified, only include matching entries.
        if args.filter_type and parsed.get("type") != args.filter_type:
            continue
        parsed_lines.append(parsed)

    if args.json:
        # Output the parsed data as a formatted JSON string.
        print(json.dumps(parsed_lines, indent=2))
    else:
        # Print each parsed log entry in a simple human‑readable format.
        for entry in parsed_lines:
            timestamp = entry.get("timestamp", "")
            audit_type = entry.get("type", "")
            audit_id = entry.get("id", "")
            # Build a string of additional key/value pairs.
            additional = ", ".join(
                f"{k}={v}" for k, v in entry.items() if k not in ["timestamp", "type", "id"]
            )
            print(f"[{timestamp}] {audit_type} (id={audit_id}) {additional}")

if __name__ == "__main__":
    main()
