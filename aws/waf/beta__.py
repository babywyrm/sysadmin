#!/usr/bin/env python3
"""
waf_analyze_alb.py ..beta..

Read-only analysis tool for AWS WAF logs associated with
Application Load Balancers (ALB) using REGIONAL WebACLs.

This tool:
- Queries CloudWatch Logs Insights
- Supports multiple AWS regions
- Filters by WAF managed rule group and action (COUNT / BLOCK)
- Produces summary or detailed output

This tool DOES NOT:
- Modify WAF rules
- Modify ALBs
- Affect application traffic

Requirements:
- Python 3.9+
- boto3
- WAF logging enabled to CloudWatch Logs

IAM permissions required:
- logs:StartQuery
- logs:GetQueryResults
"""

import argparse
import boto3
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List


def parse_args() -> argparse.Namespace:
    """
    Parse CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Analyze AWS WAF (ALB / REGIONAL) logs across regions"
    )

    parser.add_argument(
        "--regions",
        nargs="+",
        required=True,
        help="AWS regions to query (e.g. us-west-1 us-west-2)"
    )

    parser.add_argument(
        "--log-group",
        required=True,
        help="CloudWatch Logs group where ALB WAF logs are stored"
    )

    parser.add_argument(
        "--rule-group",
        required=True,
        help="Managed rule group name (e.g. AWSManagedRulesLinuxRuleSet)"
    )

    parser.add_argument(
        "--action",
        choices=["COUNT", "BLOCK", "ALLOW"],
        default="COUNT",
        help="WAF action to filter on (default: COUNT)"
    )

    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Lookback window in hours"
    )

    parser.add_argument(
        "--mode",
        choices=["summary", "detailed"],
        default="summary",
        help="Output mode"
    )

    return parser.parse_args()


def build_query(rule_group: str, action: str, detailed: bool) -> str:
    """
    Build a CloudWatch Logs Insights query for ALB WAF logs.
    """
    if detailed:
        return f"""
fields
  @timestamp,
  action,
  terminatingRuleId,
  httpRequest.clientIp,
  httpRequest.httpMethod,
  httpRequest.uri,
  ruleGroupList
| filter action = "{action}"
| filter ruleGroupList like /{rule_group}/
| sort @timestamp desc
| limit 200
"""
    else:
        return f"""
fields
  action,
  terminatingRuleId,
  httpRequest.clientIp,
  httpRequest.uri,
  ruleGroupList
| filter action = "{action}"
| filter ruleGroupList like /{rule_group}/
| stats
    count() as hits,
    count_distinct(httpRequest.clientIp) as unique_ips,
    count_distinct(httpRequest.uri) as targeted_uris
  by terminatingRuleId
| sort hits desc
"""


def run_query(
    region: str,
    log_group: str,
    query: str,
    start_time: int,
    end_time: int
) -> Dict:
    """
    Execute a Logs Insights query in a specific AWS region.
    """
    logs = boto3.client("logs", region_name=region)

    response = logs.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=end_time,
        queryString=query,
        limit=1000,
    )

    query_id = response["queryId"]

    while True:
        result = logs.get_query_results(queryId=query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            return result
        time.sleep(1)


def print_summary(region: str, results: List[List[Dict[str, str]]]) -> None:
    """
    Print aggregated summary results.
    """
    print(f"\nRegion: {region}")
    print("RuleId | Hits | Unique IPs | Targeted URIs")
    print("-" * 60)

    for row in results:
        data = {f["field"]: f["value"] for f in row}
        print(
            f"{data.get('terminatingRuleId', '-'):<30} "
            f"{data.get('hits', '0'):>6} "
            f"{data.get('unique_ips', '0'):>12} "
            f"{data.get('targeted_uris', '0'):>15}"
        )


def print_detailed(region: str, results: List[List[Dict[str, str]]]) -> None:
    """
    Print per-request detail.
    """
    print(f"\nRegion: {region}")
    for row in results:
        data = {f["field"]: f["value"] for f in row}
        print(
            f"{data.get('@timestamp')} "
            f"{data.get('action')} "
            f"{data.get('httpRequest.clientIp')} "
            f"{data.get('httpRequest.httpMethod')} "
            f"{data.get('httpRequest.uri')} "
            f"rule={data.get('terminatingRuleId')}"
        )


def main():
    args = parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)

    print("[+] AWS WAF ALB log analysis")
    print(f"    Rule group : {args.rule_group}")
    print(f"    Action     : {args.action}")
    print(f"    Time range : {start.isoformat()} → {end.isoformat()}")
    print(f"    Regions    : {', '.join(args.regions)}")

    query = build_query(
        rule_group=args.rule_group,
        action=args.action,
        detailed=(args.mode == "detailed")
    )

    for region in args.regions:
        result = run_query(
            region=region,
            log_group=args.log_group,
            query=query,
            start_time=int(start.timestamp()),
            end_time=int(end.timestamp()),
        )

        if result["status"] != "Complete":
            print(f"[!] Query failed in {region}: {result['status']}")
            continue

        if not result["results"]:
            print(f"\nRegion: {region} — no matching events")
            continue

        if args.mode == "summary":
            print_summary(region, result["results"])
        else:
            print_detailed(region, result["results"])


if __name__ == "__main__":
    main()

