#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This script requires a `named.conf` file to discover DNS zones and their
corresponding zone files. It then uses the `dnspython` library to parse
these files and aggregates all records into a pandas DataFrame, which can be
exported to various formats like CSV or JSON.
"""

import argparse
import os,sys,re
import pandas as pd
import dns.zone
from dns.exception import DNSException

# --- Configuration ---
# Regular expression to find 'zone' blocks in named.conf
# This is a simplified parser; it won't handle complex nested statements.
ZONE_RE = re.compile(r'zone\s+"([^"]+)"\s*\{[^}]*file\s+"([^"]+)";[^}]*};', re.DOTALL)
# Regular expression to find the 'directory' option
DIRECTORY_RE = re.compile(r'directory\s+"([^"]+)";')


def find_zones_in_config(config_path: str) -> dict:
    """
    Parses a named.conf file to find the data directory and a map of zones to their files.

    Args:
        config_path: The absolute path to the named.conf file.

    Returns:
        A dictionary mapping zone names to their absolute file paths.
    """
    print(f"[*] Parsing BIND configuration file: {config_path}")
    if not os.path.exists(config_path):
        print(f"[!] Error: Configuration file not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, 'r') as f:
        config_content = f.read()

    # Find the data directory path
    dir_match = DIRECTORY_RE.search(config_content)
    if not dir_match:
        print("[!] Error: Could not find 'directory' option in named.conf.", file=sys.stderr)
        # Fallback to the directory of the config file itself
        data_directory = os.path.dirname(config_path)
        print(f"[*] Warning: Falling back to directory: {data_directory}")
    else:
        data_directory = dir_match.group(1)

    # Ensure the data directory is an absolute path
    if not os.path.isabs(data_directory):
        # If named is chrooted, the path might be relative to the chroot jail.
        # This logic assumes the config path gives a hint about the base.
        # A more robust solution might require another argument for the chroot base.
        config_dir = os.path.dirname(config_path)
        potential_chroot_base = config_dir.split('/etc')[0]
        data_directory = os.path.join(potential_chroot_base, data_directory.lstrip('/'))
        print(f"[*] Interpreted data directory as: {data_directory}")


    zones = {}
    for zone_name, zone_file in ZONE_RE.findall(config_content):
        # We are not interested in reverse lookup zones for this export
        if 'in-addr.arpa' in zone_name or 'ip6.arpa' in zone_name:
            continue
        
        # Construct the absolute path to the zone file
        absolute_zone_path = os.path.join(data_directory, zone_file)
        zones[zone_name] = absolute_zone_path
        print(f"    -> Found zone '{zone_name}' with file '{absolute_zone_path}'")

    return zones


def parse_zone_file(zone_name: str, zone_file_path: str) -> list:
    """
    Parses a single DNS zone file and extracts all records.

    Args:
        zone_name: The name of the zone (e.g., 'example.com').
        zone_file_path: The absolute path to the zone file.

    Returns:
        A list of dictionaries, where each dictionary represents a DNS record.
    """
    print(f"[*] Parsing zone file: {zone_file_path}")
    records = []
    if not os.path.exists(zone_file_path):
        print(f"[!] Warning: Zone file not found for zone '{zone_name}': {zone_file_path}", file=sys.stderr)
        return records

    try:
        # Use dnspython to parse the zone file, which handles all complexities
        zone = dns.zone.from_file(zone_file_path, origin=zone_name, relativize=False)
        
        # Iterate through all records in the zone
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for record in rdataset:
                    records.append({
                        'Zone': zone_name,
                        'Name': name.to_text(omit_final_dot=True),
                        'TTL': rdataset.ttl,
                        'Type': dns.rdatatype.to_text(rdataset.rdtype),
                        'Value': record.to_text(),
                    })
    except DNSException as e:
        print(f"[!] Error parsing zone file {zone_file_path}: {e}", file=sys.stderr)

    return records


def main():
    """
    Main function to drive the DNS zone export process.
    """
    parser = argparse.ArgumentParser(
        description="Export BIND DNS zone files to a structured format like CSV or JSON.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-c', '--config',
        default='/etc/named.conf',
        help='Path to the named.conf file (default: /etc/named.conf).\n'
             'If using a chroot, provide the path to the config inside the chroot, e.g., /var/named/chroot/etc/named.conf'
    )
    parser.add_argument(
        '-o', '--output',
        default='dns_export.csv',
        help='Path to the output file (default: dns_export.csv).'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['csv', 'json', 'stdout'],
        default='csv',
        help='Output format (default: csv).'
    )
    args = parser.parse_args()

    # Find all zones and their corresponding files from the config
    zones_to_parse = find_zones_in_config(args.config)
    if not zones_to_parse:
        print("[!] No valid zones found in the configuration file. Exiting.")
        sys.exit(1)

    # Parse all zone files and aggregate the records
    all_records = []
    for zone_name, zone_file_path in zones_to_parse.items():
        records = parse_zone_file(zone_name, zone_file_path)
        all_records.extend(records)

    if not all_records:
        print("[!] No DNS records were extracted. Exiting.")
        sys.exit(0)

    # Create a pandas DataFrame from the collected records
    df = pd.DataFrame(all_records)
    
    # Sort the data for better readability
    df.sort_values(by=['Zone', 'Type', 'Name'], inplace=True)

    # Output the DataFrame based on the chosen format
    print(f"\n[*] Exporting {len(df)} total records...")
    try:
        if args.format == 'csv':
            df.to_csv(args.output, index=False)
            print(f"[+] Successfully exported data to {args.output}")
        elif args.format == 'json':
            df.to_json(args.output, orient='records', indent=2)
            print(f"[+] Successfully exported data to {args.output}")
        elif args.format == 'stdout':
            print("\n--- DNS Records Summary ---")
            print(df.to_string())
    except Exception as e:
        print(f"[!] Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
