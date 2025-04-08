#!/usr/bin/env python3

##
##
import boto3
import botocore
import argparse
import os,sys,re,csv
import json
import yaml
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from pathlib import Path
from html import escape

def parse_args():
    parser = argparse.ArgumentParser(description="CloudTrail IOC Hunter")
    parser.add_argument("--profiles", nargs="+", required=True, help="AWS CLI profile names")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--start-date", required=True, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end-date", required=True, help="End date (YYYY-MM-DD)")
    parser.add_argument("--rules", required=True, help="Path to IOC rules file (YAML or JSON)")
    parser.add_argument("--output", required=True, help="Output file name without extension")
    parser.add_argument("--format", choices=["md", "csv", "html"], default="md", help="Output format (default: md)")
    return parser.parse_args()

def load_rules(path):
    try:
        with open(path, "r") as f:
            if path.endswith(".yaml") or path.endswith(".yml"):
                return yaml.safe_load(f)
            else:
                return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load rules file: {e}")
        sys.exit(1)

def assume_session(profile, region):
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"[+] Using profile: {profile} ({identity['Arn']})")
        return session
    except botocore.exceptions.BotoCoreError as e:
        print(f"[!] Failed to assume profile {profile}: {e}")
        return None

def query_cloudtrail(client, start_time, end_time):
    events = []
    token = None
    while True:
        args = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": 50
        }
        if token:
            args["NextToken"] = token
        response = client.lookup_events(**args)
        events.extend(response.get("Events", []))
        token = response.get("NextToken")
        if not token:
            break
    return [json.loads(e["CloudTrailEvent"]) for e in events]

def match_events(events, rules):
    hits = []
    for event in events:
        for rule in rules:
            match_fields = rule.get("match", {})
            for field, values in match_fields.items():
                val = event.get(field)
                if val in values:
                    hits.append({
                        "time": event.get("eventTime"),
                        "rule": rule["id"],
                        "severity": rule.get("severity", "unknown"),
                        "eventName": event.get("eventName"),
                        "user": event.get("userIdentity", {}).get("arn", "N/A"),
                        "sourceIp": event.get("sourceIPAddress", "N/A"),
                        "raw": event
                    })
                    break  # stop at first match for this rule
    return hits

def write_csv(filename, hits):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Rule", "Severity", "EventName", "User", "IP"])
        for hit in hits:
            writer.writerow([
                hit["time"],
                hit["rule"],
                hit["severity"],
                hit["eventName"],
                hit["user"],
                hit["sourceIp"]
            ])
    print(f"[+] CSV written to {filename}")

def write_markdown(filename, hits):
    with open(filename, "w") as f:
        f.write("| Time | Rule | Severity | EventName | User | IP |\n")
        f.write("|------|------|----------|-----------|------|----|\n")
        for hit in hits:
            f.write(f"| {hit['time']} | {hit['rule']} | {hit['severity']} | {hit['eventName']} | {hit['user']} | {hit['sourceIp']} |\n")
    print(f"[+] Markdown written to {filename}")

def write_html(filename, hits):
    with open(filename, "w") as f:
        f.write("<html><head><style>table{border-collapse:collapse;}th,td{border:1px solid #ccc;padding:4px;}</style></head><body>\n")
        f.write("<table>\n<tr><th>Time</th><th>Rule</th><th>Severity</th><th>EventName</th><th>User</th><th>IP</th></tr>\n")
        for hit in hits:
            f.write("<tr>")
            f.write(f"<td>{escape(hit['time'])}</td><td>{escape(hit['rule'])}</td><td>{escape(hit['severity'])}</td>")
            f.write(f"<td>{escape(hit['eventName'])}</td><td>{escape(hit['user'])}</td><td>{escape(hit['sourceIp'])}</td>")
            f.write("</tr>\n")
        f.write("</table>\n</body></html>\n")
    print(f"[+] HTML written to {filename}")

def main():
    args = parse_args()
    rules = load_rules(args.rules)

    try:
        start = datetime.strptime(args.start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = datetime.strptime(args.end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1)
    except ValueError:
        print("[-] Dates must be YYYY-MM-DD format.")
        sys.exit(1)

    all_hits = []

    for profile in args.profiles:
        session = assume_session(profile, args.region)
        if not session:
            continue
        client = session.client("cloudtrail")
        events = query_cloudtrail(client, start, end)
        print(f"[+] Retrieved {len(events)} events from profile {profile}")
        hits = match_events(events, rules)
        for hit in hits:
            print(f"[!] {hit['time']} | {hit['severity'].upper()} | {hit['eventName']} | {hit['user']} | {hit['sourceIp']}")
        all_hits.extend(hits)

    output_path = f"{args.output}.{args.format}"
    if args.format == "csv":
        write_csv(output_path, all_hits)
    elif args.format == "md":
        write_markdown(output_path, all_hits)
    elif args.format == "html":
        write_html(output_path, all_hits)

if __name__ == "__main__":
    main()
