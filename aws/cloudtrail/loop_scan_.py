#!/usr/bin/env python3
"""
CloudTrail Forensics Query Script Beta

This script continuously queries CloudTrail for events in a specified time window
(using a given AWS profile and region) and applies flexible, user-supplied filters.
You can filter by:
  - A generic case-insensitive search string (--search)
  - Specific event names (--event-name, comma-separated or regular expression)
  - Specific event sources (--event-source)
  - A target account ID (--account)
  
Optionally, the script can write matching events to a specified output file for further analysis.
It loops indefinitely (with a configurable interval) and prints the latest matching results.
"""

import argparse
import boto3
import time
import json
from datetime import datetime, timedelta, timezone

def lookup_events(cloudtrail_client, start_time, end_time):
    """
    Look up all CloudTrail events in the given time range using pagination.
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
    Apply user-supplied filters to the list of events.
    
    - search_string: a generic substring (case-insensitive) to match anywhere in the event JSON.
    - event_name_filter: a comma-separated list of event names or a regex pattern to match eventName.
    - event_source_filter: a string or regex to match the eventSource.
    - account_filter: the account ID to filter on.
    
    Returns a list of events that match all the given filter conditions.
    """
    filtered = []
    
    # Convert the search string to lower case if provided.
    search_lower = search_string.lower() if search_string else None
    
    # If multiple event names are provided (comma-separated), split them and trim spaces.
    event_names = None
    if event_name_filter:
        event_names = [en.strip() for en in event_name_filter.split(",") if en.strip()]
    
    for event in events:
        # We'll work on the JSON string representation.
        event_json = json.dumps(event, default=str)
        event_json_lower = event_json.lower()
        
        # Generic search string filter
        if search_lower and search_lower not in event_json_lower:
            continue
        
        # Filter by eventName if specified.
        if event_names:
            # Get eventName from the event; it may be available as a top-level field.
            en = event.get("eventName", "")
            # If not an exact match for one of the provided names, skip.
            if en not in event_names:
                continue
        
        # Filter by eventSource if specified.
        if event_source_filter:
            es = event.get("eventSource", "")
            if event_source_filter not in es:
                continue
        
        # Filter by account if specified. Prefer userIdentity.accountId; if not, use recipientAccountId.
        if account_filter:
            acct = event.get("userIdentity", {}).get("accountId", event.get("recipientAccountId", ""))
            if acct != account_filter:
                continue
        
        filtered.append(event)
    return filtered

def output_events(events, output_file=None, verbose=False):
    """
    Output events to the console (and optionally append to an output file).
    If verbose is True, prints full JSON; otherwise prints a summary.
    """
    out_list = []
    for event in events:
        # For summary display, we'll extract some key fields from the event.
        # We try to parse CloudTrailEvent to extract nested data (if possible)
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
        # If verbose, output the entire event JSON; otherwise, output the summary.
        if verbose:
            out_list.append(event)
        else:
            out_list.append(summary)
    
    # Print out the results to the console
    for item in out_list:
        print(json.dumps(item, default=str, indent=2))
    
    # Optionally, write the JSON array to an output file (append mode)
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
        description="Repeatedly query CloudTrail for all events, apply forensic filters, and output results."
    )
    parser.add_argument("--profile", required=True, help="AWS profile to use (e.g. thing-ro)")
    parser.add_argument("--region", required=True, help="AWS region for CloudTrail client (e.g. us-east-1)")
    parser.add_argument("--minutes", type=int, default=40, help="Time window in minutes to query (default: 40)")
    parser.add_argument("--search", help="Generic search string (case-insensitive) to filter events")
    parser.add_argument("--event-name", help="Comma-separated list of event names to filter on")
    parser.add_argument("--event-source", help="Event source (or pattern) to filter on")
    parser.add_argument("--account", help="Filter on a specific account ID")
    parser.add_argument("--output", help="Optional file to append output events for forensic analysis")
    parser.add_argument("--interval", type=int, default=60, help="Wait interval in seconds between queries (default: 60)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output: print full event JSON")
    
    args = parser.parse_args()
    
    # Create a boto3 session using the chosen profile and region.
    session = boto3.Session(profile_name=args.profile)
    cloudtrail_client = session.client("cloudtrail", region_name=args.region)
    
    print(f"Using profile: {args.profile}, region: {args.region}")
    if args.search:
        print(f"Filtering events with search string: '{args.search}'")
    if args.event_name:
        print(f"Filtering events with names: '{args.event_name}'")
    if args.event_source:
        print(f"Filtering events with event source: '{args.event_source}'")
    if args.account:
        print(f"Filtering events for account: '{args.account}'")
    if args.output:
        print(f"Output will be appended to: {args.output}")
    
    print("Press Ctrl+C to exit.\n")
    
    while True:
        # Using timezone-aware UTC times.
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=args.minutes)
        print(f"Querying events from {start_time.isoformat()} to {end_time.isoformat()}")
        
        events = lookup_events(cloudtrail_client, start_time, end_time)
        print(f"Retrieved {len(events)} events from CloudTrail.")
        
        # Apply forensic filtering
        filtered_events = apply_filters(
            events,
            search_string=args.search,
            event_name_filter=args.event_name,
            event_source_filter=args.event_source,
            account_filter=args.account
        )
        print(f"Found {len(filtered_events)} matching events:")
        output_events(filtered_events, output_file=args.output, verbose=args.verbose)
        
        print(f"Sleeping for {args.interval} seconds before next query...\n")
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
