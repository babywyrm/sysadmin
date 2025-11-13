#!/usr/bin/env python3
"""
vim_swp_recover.py — Modern forensic parser for Vim swap (.swp) files
======================================================================
Extracts readable text, reconstructs fragments, and highlights likely
config, secrets, and code from binary Vim swap files.

Usage examples:
  python3 vim_swp_recover.py ~/.vim/swap/.index.php.swp
  python3 vim_swp_recover.py /tmp/.env.swp --grep DB_ --json

Features:
  - Parses binary .swp via `strings`
  - Extracts metadata (owner, host, pid, file, etc.)
  - Detects common secret/config patterns (DB_, password, AWS keys)
  - Optional regex filtering (--grep)
  - JSON or text output (--json)
  - Safe for DFIR, read-only mode
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Dict, Any


# ----------------------------------------------------------
# Core functions
# ----------------------------------------------------------

def run_strings(file_path: str) -> List[str]:
    """Run the `strings` command on a binary file and return the output lines."""
    if not shutil.which("strings"):
        sys.exit("Error: `strings` command not found in PATH. Please install binutils.")
    try:
        result = subprocess.run(
            ["strings", "-a", file_path],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        sys.exit(f"Error running strings: {e}")


def extract_metadata(lines: List[str]) -> Dict[str, str]:
    """Extract metadata lines from the early part of the swap file."""
    metadata = {}
    patterns = {
        "owner": re.compile(r"owner:\s*(.+)", re.I),
        "host": re.compile(r"host:\s*(.+)", re.I),
        "pid": re.compile(r"pid:\s*(\d+)", re.I),
        "file": re.compile(r"file:\s*(.+)", re.I),
        "timestamp": re.compile(r"timestamp:\s*(.+)", re.I),
        "mode": re.compile(r"mode:\s*(.+)", re.I),
    }
    for line in lines[:60]:
        for key, pattern in patterns.items():
            m = pattern.search(line)
            if m:
                metadata[key] = m.group(1).strip()
    return metadata


def extract_interesting_content(lines: List[str], grep: Optional[str] = None) -> List[str]:
    """Identify potentially valuable or sensitive lines."""
    interesting = []
    patterns = [
        re.compile(r"\b(?:define|const|var|let|function)\b", re.I),
        re.compile(r"DB_[A-Z_]+"),
        re.compile(r"https?://[^\s\"']+", re.I),
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
        re.compile(r"password\s*[:=]\s*.+", re.I),
        re.compile(r"secret\s*[:=]\s*.+", re.I),
        re.compile(r"token\s*[:=]\s*.+", re.I),
    ]
    if grep:
        try:
            patterns.insert(0, re.compile(grep, re.I))
        except re.error as e:
            sys.exit(f"Invalid regex for --grep: {e}")

    for line in lines:
        for p in patterns:
            if p.search(line):
                interesting.append(line.strip())
                break
    return interesting


# ----------------------------------------------------------
# Output helpers
# ----------------------------------------------------------

def print_text_output(metadata: Dict[str, str], hits: List[str], total_lines: int) -> None:
    """Print a formatted text report to stdout."""
    print("\n=== Vim Swap File Forensics ===\n")
    if metadata:
        print("🧩  Metadata (guessed):")
        for k, v in metadata.items():
            print(f"  {k:10s}: {v}")
        print()
    else:
        print("No metadata found.\n")

    if hits:
        print("🔍  Interesting Lines:")
        for line in hits:
            print(f"  - {line}")
    else:
        print("No interesting strings found.\n")

    print(f"\n✅  Extracted {total_lines} readable lines.\n")


def print_json_output(metadata: Dict[str, str], hits: List[str], total_lines: int) -> None:
    """Print a structured JSON report to stdout."""
    report: Dict[str, Any] = {
        "metadata": metadata,
        "findings": hits,
        "stats": {"total_strings": total_lines},
    }
    print(json.dumps(report, indent=2))


# ----------------------------------------------------------
# Main CLI
# ----------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Recover readable text and metadata from Vim swap (.swp) files."
    )
    parser.add_argument("file", help="Path to the Vim swap file (.swp)")
    parser.add_argument("--grep", "-g", help="Optional regex to search for specific patterns.")
    parser.add_argument("--json", "-j", action="store_true", help="Output results as JSON.")
    args = parser.parse_args()

    file_path = args.file
    if not os.path.isfile(file_path):
        sys.exit(f"Error: {file_path} is not a valid file.")

    lines = run_strings(file_path)
    metadata = extract_metadata(lines)
    hits = extract_interesting_content(lines, args.grep)

    if args.json:
        print_json_output(metadata, hits, len(lines))
    else:
        print_text_output(metadata, hits, len(lines))


if __name__ == "__main__":
    main()
