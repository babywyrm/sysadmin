#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
apache_parser_modern.py

A modern Python 3 script and command-line tool to parse and analyze Apache log files.
This script generates reports on URIs, status codes, user agents, referrers, and
calculates feed subscriber counts from user agent strings.
"""

import argparse
import re
from collections import Counter, defaultdict
from typing import Generator, List, Tuple, Optional

# --- Constants ---

# A robust regex to parse the common Apache log format using named capture groups.
LOG_PATTERN = re.compile(
    r'(?P<ip>[.:0-9a-fA-F]+) - - \[(?P<time>.*?)\] '
    r'"GET (?P<uri>.*?) HTTP/1.\d" (?P<status_code>\d+) \d+ '
    r'"(?P<referral>.*?)" "(?P<agent>.*?)"'
)

# Regexes to extract subscriber counts from various feed reader user agents.
FEED_SUBSCRIBER_PATTERNS = [
    re.compile(r'(?P<name>.*?) \(.*?; (?P<count>\d+) subscribers?(;.*?)?\)'),
    re.compile(r'(?P<name>.*?);? (?P<count>\d+) [Ss]ubscribers?'),
]


# --- Core Logic ---

def parse_log_entries(filename: str) -> Generator[dict, None, None]:
    """
    Lazily parses an Apache log file line by line using a generator.

    This approach is memory-efficient, as it doesn't load the entire file
    into memory at once, making it suitable for very large log files.

    Args:
        filename: The path to the Apache access log file.

    Yields:
        A dictionary representing a single parsed log entry.
    """
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as log_file:
            for line in log_file:
                match = LOG_PATTERN.search(line)
                if match:
                    yield match.groupdict()
    except FileNotFoundError:
        print(f"Error: Log file not found at '{filename}'")
        exit(1)


def generate_generic_report(
    filename: str,
    key: str,
    quantity: Optional[int],
    cutoff: Optional[int]
) -> None:
    """
    Generates a generic frequency count report for a given key in the log data.

    Args:
        filename: The path to the log file.
        key: The dictionary key to count values for (e.g., 'uri', 'agent').
        quantity: The maximum number of results to display.
        cutoff: The minimum hit count for a result to be included.
    """
    print(f"\n--- Report for '{key.replace('_', ' ').title()}' ---")
    log_entries = parse_log_entries(filename)
    
    # Use collections.Counter for efficient counting.
    counts = Counter(entry[key] for entry in log_entries)
    
    # Get the most common items, already sorted in descending order.
    results = counts.most_common()
    
    # Filter results based on cutoff and quantity.
    if cutoff:
        results = [item for item in results if item[1] > cutoff]
    if quantity:
        results = results[:quantity]
        
    print_report_results(results)


def generate_subscriptions_report(
    filename: str,
    quantity: Optional[int],
    cutoff: Optional[int]
) -> None:
    """
    Generates a custom report to estimate feed subscribers based on user agents.

    Args:
        filename: The path to the log file.
        quantity: The maximum number of results to display.
        cutoff: The minimum subscriber count for a result to be included.
    """
    print("\n--- Report for Feed Subscriptions ---")
    log_entries = parse_log_entries(filename)
    
    # Filter for entries that appear to be from feed readers.
    subscriber_entries = (
        entry for entry in log_entries if 'subscriber' in entry['agent'].lower()
    )
    
    # Group user agents by the feed URI they are accessing.
    feeds = defaultdict(list)
    for entry in subscriber_entries:
        feeds[entry['uri']].append(entry['agent'])
        
    # Process each feed to calculate the total subscriber count.
    feed_totals = []
    for uri, agents in feeds.items():
        # Use a dictionary to store the highest subscriber count per reader name
        # to avoid double-counting from the same source.
        sources = {}
        for agent in agents:
            for pattern in FEED_SUBSCRIBER_PATTERNS:
                match = pattern.search(agent)
                if match:
                    name = match.group('name').strip()
                    count = int(match.group('count'))
                    # Only update if the new count is higher.
                    if sources.get(name, 0) < count:
                        sources[name] = count
                    break # Move to the next agent once a pattern matches.

        total_subscribers = sum(sources.values())
        if total_subscribers > 0:
            feed_totals.append((uri, total_subscribers))
            
    # Sort results by subscriber count in descending order.
    results = sorted(feed_totals, key=lambda item: item[1], reverse=True)
    
    # Filter results based on cutoff and quantity.
    if cutoff:
        results = [item for item in results if item[1] > cutoff]
    if quantity:
        results = results[:quantity]
        
    print_report_results(results)


def print_report_results(results: List[Tuple[str, int]]) -> None:
    """
    Prints a formatted table of results.

    Args:
        results: A list of (item, count) tuples.
    """
    if not results:
        print("No results to display with the current filters.")
        return
        
    # Use f-strings for modern, readable formatting.
    # :<60 left-aligns the item in a 60-character space.
    # :>10 right-aligns the count in a 10-character space.
    print(f"{'Item':<60} {'Hits':>10}")
    print("-" * 71)
    for item, count in results:
        print(f"{item:<60} {count:>10}")


def main() -> None:
    """
    Parses command-line arguments and runs the appropriate report.
    """
    parser = argparse.ArgumentParser(
        description="Parse and analyze Apache access log files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "filename",
        help="Path to the Apache access log file to parse."
    )
    parser.add_argument(
        "report_type",
        choices=['uri', 'time', 'status_code', 'agent', 'referral', 'subscriptions'],
        help="The type of report to generate."
    )
    parser.add_argument(
        '-c', '--cutoff',
        type=int,
        help="Minimum number of hits for an item to be included in the report."
    )
    parser.add_argument(
        '-q', '--quantity',
        type=int,
        help="Maximum number of results to return, sorted by frequency."
    )
    
    args = parser.parse_args()
    
    if args.report_type == 'subscriptions':
        generate_subscriptions_report(args.filename, args.quantity, args.cutoff)
    else:
        # All other reports use the same generic logic.
        generate_generic_report(args.filename, args.report_type, args.quantity, args.cutoff)


if __name__ == '__main__':
    main()
