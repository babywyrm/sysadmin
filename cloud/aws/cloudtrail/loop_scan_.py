#!/usr/bin/env python3
"""
CloudTrail Forensics Query Script

This script continuously queries CloudTrail for events within a specified time window
and applies user-supplied filters. It is designed for forensic analysis and can output
matching events to the console and/or an output file.

Features:
  - Select AWS profile and region at runtime.
  - Specify a time window (in minutes) to query CloudTrail from "now".
  - Filter events using a generic search string (--search), specific event names
    (--event-name), event source (--event-source) and account ID (--account).
  - Output results in verbose mode (prints full event JSON) or as summaries of key fields.
  - Optionally, append matching events to a file for later analysis.
  - Loops continuously with a default interval of 5 seconds between queries.

Usage Example:

minimal --
python3 alert__.py --profile thing-ro --region us-east-1 --search .

  python3 alert__.py --profile thing-ro --region us-east-1 --minutes 40 \
    --search secretsmanager --event-name "ListSecrets,GetSecretValue" \
    --account 417930572748 --output forensic_results.json --interval 5 --verbose
"""

import argparse
import boto3
import time
import json
from datetime import datetime, timedelta, timezone

def lookup_events(cloudtrail_client, start_time, end_time):
    """
    Retrieves all CloudTrail events within the given time range.
    
    This function uses CloudTrail's lookup_events API and handles pagination
    to return all events between start_time and end_time.

    :param cloudtrail_client: A boto3 CloudTrail client.
    :param start_time: Start of the time window (UTC datetime).
    :param end_time: End of the time window (UTC datetime).
    :return: List of CloudTrail event dictionaries.
    """
    events = []
    next_token = None
    while True:
        params = {"StartTime": start_time, "EndTime": end_time}
        if next_token:
            params["NextToken"] = next_token
        response = cloudtrail_client.lookup_events(**params)
        events.extend(response.get("Events", []))
        next_token = response.get("NextToken")
        if not next_token:
            break
    return events

def apply_filters(events, search_string=None, event_name_filter=None,
                  event_source_filter=None, account_filter=None):
    """
    Applies user-supplied filters to the list of events.
    
    Filters include:
      - A generic case-insensitive search string (--search)
      - Specific event names (--event-name, comma-separated)
      - Specific event source (--event-source)
      - A target account ID (--account)
    
    :param events: List of events (dictionaries).
    :param search_string: Generic search substring for entire event JSON.
    :param event_name_filter: Comma-separated event name(s) to match exactly.
    :param event_source_filter: String to match against eventSource.
    :param account_filter: Account ID to filter on.
    :return: Filtered list of event dictionaries.
    """
    filtered = []
    search_lower = search_string.lower() if search_string else None
    event_names = None
    if event_name_filter:
        event_names = [en.strip() for en in event_name_filter.split(",") if en.strip()]

    for event in events:
        event_json = json.dumps(event, default=str)
        event_json_lower = event_json.lower()
        
        # Generic search string filter
        if search_lower and search_lower not in event_json_lower:
            continue
        
        # Filter by eventName if specified
        if event_names:
            en = event.get("eventName", "")
            if en not in event_names:
                continue
        
        # Filter by eventSource if specified
        if event_source_filter:
            es = event.get("eventSource", "")
            if event_source_filter not in es:
                continue
        
        # Filter by account: Use userIdentity.accountId if present, else recipientAccountId.
        if account_filter:
            acct = event.get("userIdentity", {}).get("accountId", event.get("recipientAccountId", ""))
            if acct != account_filter:
                continue

        filtered.append(event)
    
    return filtered

def output_events(events, output_file=None, verbose=False):
    """
    Outputs events to the console and optionally appends them to an output file.
    
    If verbose is True, the full event JSON is printed; otherwise a summary of key fields
    (eventTime, eventName, eventSource, sourceIPAddress, principalId, and accountId) is printed.

    :param events: List of event dictionaries.
    :param output_file: Optional file path to append output events.
    :param verbose: Boolean flag to control verbosity of output.
    """
    out_list = []
    for event in events:
        # Try to parse nested CloudTrailEvent data.
        ct_event = {}
        if "CloudTrailEvent" in event:
            try:
                ct_event = json.loads(event["CloudTrailEvent"])
            except Exception:
                pass
        
        summary = {
            "eventTime": ct_event.get("eventTime", event.get("eventTime", "")),
            "eventName": ct_event.get("eventName", event.get("eventName", "")),
            "eventSource": ct_event.get("eventSource", event.get("eventSource", "")),
            "sourceIPAddress": ct_event.get("sourceIPAddress", event.get("sourceIPAddress", "")),
            "principalId": ct_event.get("userIdentity", {}).get("principalId", event.get("userIdentity", {}).get("principalId", "")),
            "accountId": ct_event.get("userIdentity", {}).get("accountId", event.get("recipientAccountId", ""))
        }
        out_list.append(event if verbose else summary)
    
    for item in out_list:
        print(json.dumps(item, default=str, indent=2))
    
    if output_file:
        try:
            with open(output_file, "a") as f:
                for item in out_list:
                    f.write(json.dumps(item, default=str) + "\n")
            print(f"Appended {len(out_list)} events to {output_file}")
        except Exception as ex:
            print(f"Error writing to output file {output_file}: {ex}")

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Repeatedly query CloudTrail for events and apply forensic filters.\n\n"
            "Examples:\n"
            "  # Query a 40-minute window and filter events containing the string 'secretsmanager'\n"
            "  python3 alert__.py --profile thing-ro --region us-east-1 --minutes 40 --search secretsmanager\n\n"
            "  # Query and filter by specific event names and account\n"
            "  python3 alert__.py --profile thing-ro --region us-east-1 --minutes 40 --search secretsmanager "
            "--event-name 'ListSecrets,GetSecretValue' --account 417930572748 --interval 5 --verbose\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--profile", required=True, help="AWS profile to use (e.g. thing-ro)")
    parser.add_argument("--region", required=True, help="AWS region for CloudTrail client (e.g. us-east-1)")
    parser.add_argument("--minutes", type=int, default=40, help="Time window in minutes to query (default: 40)")
    parser.add_argument("--search", help="Generic search string (case-insensitive) to filter events")
    parser.add_argument("--event-name", help="Comma-separated list of event names to filter on")
    parser.add_argument("--event-source", help="Event source (or substring) to filter on")
    parser.add_argument("--account", help="Filter on a specific account ID")
    parser.add_argument("--output", help="Optional file to which output events are appended")
    # Default interval is now every 5 seconds for rapid forensic sampling.
    parser.add_argument("--interval", type=int, default=5, help="Time in seconds between queries (default: 5 seconds)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output: print full event JSON")
    
    args = parser.parse_args()

    # Create a boto3 session using the chosen profile and region.
    session = boto3.Session(profile_name=args.profile)
    cloudtrail_client = session.client("cloudtrail", region_name=args.region)
    
    print(f"Using profile: {args.profile}, region: {args.region}")
    if args.search:
        print(f"Filtering events with search string: '{args.search}'")
    if args.event_name:
        print(f"Filtering events with event name(s): '{args.event_name}'")
    if args.event_source:
        print(f"Filtering events with event source: '{args.event_source}'")
    if args.account:
        print(f"Filtering events for account: '{args.account}'")
    if args.output:
        print(f"Output will be appended to: {args.output}")
    
    print("Press Ctrl+C to exit.\n")
    
    while True:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=args.minutes)
        print(f"Querying events from {start_time.isoformat()} to {end_time.isoformat()}")
        
        events = lookup_events(cloudtrail_client, start_time, end_time)
        print(f"Retrieved {len(events)} events from CloudTrail.")
        
        # Apply filters
        filtered_events = apply_filters(
            events,
            search_string=args.search,
            event_name_filter=args.event_name,
            event_source_filter=args.event_source,
            account_filter=args.account
        )
        print(f"Found {len(filtered_events)} matching events:")
        output_events(filtered_events, output_file=args.output, verbose=args.verbose)
        
        print(f"Sleeping for {args.interval} seconds before the next query...\n")
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
