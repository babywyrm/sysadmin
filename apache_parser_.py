#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
advanced_apache_parser.py

An advanced, high-performance Python 3 tool to parse and analyze Apache log files.

Features:
  - High-speed parallel processing for large files.
  - Data enrichment with GeoIP lookups and User-Agent parsing.
  - Advanced filtering capabilities.
  - Multiple output formats: terminal, CSV, JSON, JSON Lines, and HTML.
  - Intuitive CLI with sub-commands.
  - Progress bar for a better user experience.
"""

import argparse
import re
import sys
from collections import Counter
from functools import reduce
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Generator, List, Optional, Dict

import pandas as pd
import user_agents
from tqdm import tqdm

# --- Optional Dependency Handling ---
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# --- Constants ---
LOG_PATTERN = re.compile(
    r'(?P<ip>[.:0-9a-fA-F]+) - - \[(?P<time>.*?)\] '
    r'"GET (?P<uri>.*?) HTTP/1.\d" (?P<status_code>\d+) \d+ '
    r'"(?P<referral>.*?)" "(?P<agent>.*?)"'
)
CHUNK_SIZE = 100000  # Number of lines per chunk for parallel processing

# --- Global GeoIP Reader ---
geoip_reader = None

# --- Core Logic ---

def setup_geoip_reader(db_path: str) -> None:
    """Initializes the GeoIP database reader."""
    global geoip_reader
    if not GEOIP_AVAILABLE:
        print("Warning: 'geoip2' library not installed. GeoIP enrichment is disabled.", file=sys.stderr)
        return
    
    if not Path(db_path).exists():
        print(f"Warning: GeoLite2 database not found at '{db_path}'. GeoIP enrichment is disabled.", file=sys.stderr)
        print("Download it from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", file=sys.stderr)
        return
        
    try:
        geoip_reader = geoip2.database.Reader(db_path)
        print(f"[*] GeoIP database loaded from '{db_path}'.")
    except Exception as e:
        print(f"Error loading GeoIP database: {e}", file=sys.stderr)


def enrich_entry(entry: dict) -> dict:
    """Enriches a log entry with GeoIP and parsed User-Agent data."""
    # User-Agent Parsing
    ua = user_agents.parse(entry['agent'])
    entry['browser'] = ua.browser.family
    entry['os'] = ua.os.family
    entry['device'] = ua.device.family

    # GeoIP Lookup
    if geoip_reader:
        try:
            response = geoip_reader.city(entry['ip'])
            entry['country'] = response.country.name
            entry['city'] = response.city.name
        except geoip2.errors.AddressNotFoundError:
            entry['country'] = 'Unknown'
            entry['city'] = 'Unknown'
    return entry


def process_chunk(chunk: List[str], enrich: bool, filters: Dict[str, str]) -> Dict[str, Counter]:
    """Processes a chunk of log lines and returns counters for various keys."""
    counters = {
        'uri': Counter(), 'ip': Counter(), 'status_code': Counter(),
        'agent': Counter(), 'referral': Counter(), 'country': Counter(),
        'browser': Counter(), 'os': Counter()
    }
    
    for line in chunk:
        match = LOG_PATTERN.search(line)
        if not match:
            continue
        
        entry = match.groupdict()

        # Apply filters
        if filters and not all(entry.get(k) == v for k, v in filters.items()):
            continue

        if enrich:
            entry = enrich_entry(entry)

        for key in counters.keys():
            if key in entry:
                counters[key][entry[key]] += 1
                
    return counters


def parse_log_parallel(filename: str, enrich: bool, filters: Dict[str, str], num_processes: int) -> Dict[str, Counter]:
    """
    Parses a log file in parallel across multiple CPU cores.
    """
    print(f"[*] Starting parallel processing with {num_processes} workers...")
    
    # Read file and create chunks
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        chunks = [f.readlines(CHUNK_SIZE) for _ in iter(lambda: 1, 0) if f.tell() != f.seek(0, 2)]
        f.seek(0) # Reset file pointer

    # Create a pool of worker processes
    with Pool(processes=num_processes) as pool:
        # Map chunks to the process_chunk function
        results = list(tqdm(
            pool.starmap(process_chunk, [(chunk, enrich, filters) for chunk in chunks]),
            total=len(chunks),
            desc="Processing Chunks"
        ))

    # Aggregate results from all chunks
    print("[*] Aggregating results from all processes...")
    aggregated_counters = reduce(
        lambda c1, c2: {k: c1[k] + c2[k] for k in c1},
        results
    )
    return aggregated_counters


def generate_report(
    counters: Dict[str, Counter],
    report_type: str,
    quantity: Optional[int],
    cutoff: Optional[int]
) -> pd.DataFrame:
    """Generates a report DataFrame from aggregated counter data."""
    if report_type not in counters:
        print(f"Error: Report type '{report_type}' is not a valid counter key.", file=sys.stderr)
        return pd.DataFrame()

    # Get the most common items, already sorted
    results = counters[report_type].most_common()

    # Apply filters
    if cutoff:
        results = [item for item in results if item[1] >= cutoff]
    if quantity:
        results = results[:quantity]

    return pd.DataFrame(results, columns=['Item', 'Hits'])


def save_results(df: pd.DataFrame, output_file: str, format: str) -> None:
    """Saves the DataFrame to the specified format."""
    print(f"\n[*] Exporting {len(df)} results to '{output_file}' as {format.upper()}...")
    try:
        if format == 'csv':
            df.to_csv(output_file, index=False)
        elif format == 'json':
            df.to_json(output_file, orient='records', indent=2)
        elif format == 'jsonl':
            df.to_json(output_file, orient='records', lines=True)
        elif format == 'html':
            html_content = f"""
            <html>
            <head><title>Apache Log Report</title></head>
            <body style="font-family: sans-serif;">
            <h1>Apache Log Report</h1>
            {df.to_html(index=False, border=1)}
            </body>
            </html>
            """
            with open(output_file, 'w') as f:
                f.write(html_content)
        print(f"[+] Report successfully saved to '{output_file}'.")
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="An advanced, high-performance tool to parse and analyze Apache log files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("filename", help="Path to the Apache access log file.")
    
    # Top-level options
    parser.add_argument(
        '--parallel',
        type=int,
        nargs='?',
        const=cpu_count(),
        default=1,
        help="Enable parallel processing. Optionally specify number of cores, defaults to all available."
    )
    parser.add_argument(
        '--enrich',
        action='store_true',
        help="Enable data enrichment (GeoIP and User-Agent parsing)."
    )
    parser.add_argument(
        '--geoip-db',
        default='GeoLite2-City.mmdb',
        help="Path to the GeoLite2 City database file (default: GeoLite2-City.mmdb)."
    )
    parser.add_argument(
        '--filter',
        action='append',
        help="Filter log entries by a key=value pair (e.g., --filter status_code=404)."
    )

    # Sub-parsers for different report types
    subparsers = parser.add_subparsers(dest='report_type', required=True, help='Type of report to generate')
    
    report_keys = ['uri', 'ip', 'status_code', 'agent', 'referral', 'country', 'browser', 'os']
    for key in report_keys:
        subparser = subparsers.add_parser(key, help=f"Generate a report on {key} frequency.")
        subparser.add_argument('-o', '--output', default='stdout', help="Output file path (default: print to screen).")
        subparser.add_argument('-f', '--format', choices=['csv', 'json', 'jsonl', 'html'], help="Output format for file saving.")
        subparser.add_argument('-q', '--quantity', type=int, help="Maximum number of results to return.")
        subparser.add_argument('-c', '--cutoff', type=int, help="Minimum hit count to include in the report.")

    args = parser.parse_args()

    # Setup
    if args.enrich:
        setup_geoip_reader(args.geoip_db)
        
    filters = dict(f.split('=', 1) for f in args.filter) if args.filter else {}
    if filters:
        print(f"[*] Applying filters: {filters}")

    # Parsing
    if args.parallel > 1:
        aggregated_data = parse_log_parallel(args.filename, args.enrich, filters, args.parallel)
    else:
        # For single-core, we can still use the parallel function for consistency
        aggregated_data = process_chunk(
            list(open(args.filename, 'r', encoding='utf-8', errors='ignore')),
            args.enrich,
            filters
        )

    # Reporting
    report_df = generate_report(aggregated_data, args.report_type, args.quantity, args.cutoff)

    if report_df.empty:
        print("\nNo data to report after processing and filtering.")
        return

    # Output
    if args.output == 'stdout':
        print(f"\n--- Top Results for '{args.report_type.title()}' ---")
        print(report_df.to_string(index=False))
    else:
        if not args.format:
            # Infer format from output file extension
            ext = Path(args.output).suffix.lower().lstrip('.')
            if ext in ['csv', 'json', 'jsonl', 'html']:
                args.format = ext
            else:
                print("Error: Cannot infer format from file extension. Please specify with --format.", file=sys.stderr)
                return
        save_results(report_df, args.output, args.format)


if __name__ == '__main__':
    main()

##
##
