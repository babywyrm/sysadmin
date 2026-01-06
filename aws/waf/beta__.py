#!/usr/bin/env python3
"""
waf_analyze_alb.py

ALB-specific AWS WAF (REGIONAL) log analysis tool.

Capabilities:
- Multi-region CloudWatch Logs Insights queries
- Filter by managed rule group + action (COUNT/BLOCK)
- Summary and detailed views
- CSV and JSON export
- Promotion analysis (COUNT → BLOCK safety signal)

SAFE:
- Read-only
- No WAF / ALB mutations
- No traffic impact

Requirements:
- Python 3.9+
- boto3
- WAF logging enabled to CloudWatch Logs

IAM permissions:
- logs:StartQuery
- logs:GetQueryResults
"""

import argparse
import boto3
import csv
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any


# -------------------------
# CLI
# -------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze AWS WAF (ALB / REGIONAL) logs across regions"
    )

    parser.add_argument("--regions", nargs="+", required=True)
    parser.add_argument("--log-group", required=True)
    parser.add_argument("--rule-group", required=True)
    parser.add_argument("--action", choices=["COUNT", "BLOCK", "ALLOW"], default="COUNT")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--mode", choices=["summary", "detailed"], default="summary")

    parser.add_argument("--csv-out", help="Write results to CSV")
    parser.add_argument("--json-out", help="Write results to JSON")

    parser.add_argument(
        "--promote-threshold",
        type=int,
        default=None,
        help="COUNT hit threshold suggesting safe promotion to BLOCK"
    )

    return parser.parse_args()


# -------------------------
# Query Builder
# -------------------------

def build_query(rule_group: str, action: str, detailed: bool) -> str:
    if detailed:
        return f"""
fields
  @timestamp,
  action,
  terminatingRuleId,
  webaclId,
  httpRequest.clientIp,
  httpRequest.httpMethod,
  httpRequest.uri,
  ruleGroupList
| filter action = "{action}"
| filter ruleGroupList like /{rule_group}/
| sort @timestamp desc
| limit 500
"""
    return f"""
fields
  terminatingRuleId,
  webaclId,
  httpRequest.clientIp,
  httpRequest.uri
| filter action = "{action}"
| filter ruleGroupList like /{rule_group}/
| stats
    count() as hits,
    count_distinct(httpRequest.clientIp) as unique_ips,
    count_distinct(httpRequest.uri) as uris
  by terminatingRuleId, webaclId
| sort hits desc
"""


# -------------------------
# AWS Query Runner
# -------------------------

def run_query(region: str, log_group: str, query: str, start: int, end: int) -> Dict:
    logs = boto3.client("logs", region_name=region)
    q = logs.start_query(
        logGroupName=log_group,
        startTime=start,
        endTime=end,
        queryString=query,
        limit=1000,
    )
    qid = q["queryId"]

    while True:
        r = logs.get_query_results(queryId=qid)
        if r["status"] in ("Complete", "Failed", "Cancelled"):
            return r
        time.sleep(1)


# -------------------------
# Output Helpers
# -------------------------

def rows_to_dicts(rows: List[List[Dict[str, str]]]) -> List[Dict[str, Any]]:
    parsed = []
    for row in rows:
        parsed.append({f["field"]: f["value"] for f in row})
    return parsed


def write_csv(path: str, records: List[Dict[str, Any]]):
    if not records:
        return
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)


def write_json(path: str, records: List[Dict[str, Any]]):
    with open(path, "w") as fh:
        json.dump(records, fh, indent=2)


# -------------------------
# Promotion Logic
# -------------------------

def promotion_candidates(records: List[Dict[str, Any]], threshold: int):
    print("\nPromotion Candidates (COUNT → BLOCK)")
    print("-" * 60)
    for r in records:
        hits = int(r.get("hits", 0))
        if hits >= threshold:
            print(
                f"Rule={r.get('terminatingRuleId')} "
                f"WebACL={r.get('webaclId')} "
                f"hits={hits} "
                f"unique_ips={r.get('unique_ips')}"
            )


# -------------------------
# Main
# -------------------------

def main():
    args = parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)

    print("[+] AWS WAF ALB Analysis")
    print(f"    Rule Group : {args.rule_group}")
    print(f"    Action     : {args.action}")
    print(f"    Window     : {start.isoformat()} → {end.isoformat()}")
    print(f"    Regions    : {', '.join(args.regions)}")

    all_records: List[Dict[str, Any]] = []

    query = build_query(args.rule_group, args.action, args.mode == "detailed")

    for region in args.regions:
        result = run_query(
            region,
            args.log_group,
            query,
            int(start.timestamp()),
            int(end.timestamp()),
        )

        if result["status"] != "Complete":
            print(f"[!] {region} query failed: {result['status']}")
            continue

        if not result["results"]:
            print(f"[+] {region}: no matches")
            continue

        records = rows_to_dicts(result["results"])
        for r in records:
            r["region"] = region
        all_records.extend(records)

        print(f"[+] {region}: {len(records)} records")

    if args.csv_out:
        write_csv(args.csv_out, all_records)
        print(f"[+] CSV written to {args.csv_out}")

    if args.json_out:
        write_json(args.json_out, all_records)
        print(f"[+] JSON written to {args.json_out}")

    if args.promote_threshold and args.action == "COUNT":
        promotion_candidates(all_records, args.promote_threshold)


if __name__ == "__main__":
    main()
