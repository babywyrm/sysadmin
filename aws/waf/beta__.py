#!/usr/bin/env python3

import argparse
import boto3
import time
from datetime import datetime, timedelta, timezone
from typing import List


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze AWS WAF hits by rule group using CloudWatch Logs Insights"
    )
    parser.add_argument(
        "--log-group",
        required=True,
        help="CloudWatch Logs group where WAF logs are stored"
    )
    parser.add_argument(
        "--rule-group",
        required=True,
        help="Managed rule group name (e.g. AWSManagedRulesLinuxRuleSet)"
    )
    parser.add_argument(
        "--action",
        choices=["BLOCK", "COUNT", "ALLOW"],
        default="COUNT",
        help="WAF action to filter on"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Lookback window in hours"
    )
    return parser.parse_args()


def build_query(rule_group: str, action: str) -> str:
    """
    CloudWatch Logs Insights query for WAF logs.
    """
    return f"""
fields @timestamp, action, terminatingRuleId, ruleGroupList, httpRequest.clientIp, httpRequest.uri
| filter action = "{action}"
| filter ruleGroupList like /{rule_group}/
| stats
    count() as hits,
    count_distinct(httpRequest.clientIp) as unique_ips,
    values(terminatingRuleId) as terminating_rules
  by bin(5m)
| sort @timestamp desc
"""


def run_query(
    logs_client,
    log_group: str,
    query: str,
    start_time: int,
    end_time: int
) -> List[dict]:

    response = logs_client.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=end_time,
        queryString=query,
        limit=1000,
    )

    query_id = response["queryId"]

    while True:
        result = logs_client.get_query_results(queryId=query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            return result
        time.sleep(1)


def main():
    args = parse_args()

    logs = boto3.client("logs")

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)

    print(f"[+] Querying WAF logs")
    print(f"    Rule Group : {args.rule_group}")
    print(f"    Action     : {args.action}")
    print(f"    Time Range : {start.isoformat()} → {end.isoformat()}")
    print("")

    query = build_query(args.rule_group, args.action)

    result = run_query(
        logs_client=logs,
        log_group=args.log_group,
        query=query,
        start_time=int(start.timestamp()),
        end_time=int(end.timestamp()),
    )

    if result["status"] != "Complete":
        print(f"[!] Query did not complete successfully: {result['status']}")
        return

    if not result["results"]:
        print("[+] No matching WAF events found")
        return

    print("[+] WAF Hits Summary (5-minute bins)")
    print("")

    for row in result["results"]:
        row_data = {field["field"]: field["value"] for field in row}
        print(
            f"{row_data.get('@timestamp', '')} | "
            f"hits={row_data.get('hits')} | "
            f"unique_ips={row_data.get('unique_ips')} | "
            f"rules={row_data.get('terminating_rules')}"
        )


if __name__ == "__main__":
    main()
