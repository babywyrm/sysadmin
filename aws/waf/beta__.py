#!/usr/bin/env python3
"""
waf_analyze_alb.py

ALB-specific AWS WAF (REGIONAL) analysis tool, ..beta..

Features:
- Multi-region CloudWatch Logs Insights queries
- Managed rule group filtering
- COUNT vs BLOCK analysis
- Correlation (IP / URI / rule / region)
- Promotion readiness scoring
- CSV / JSON export
- Optional Slack webhook alerts

Safety:
- Read-only
- No WAF or ALB mutations
- No tenant-wide impact

Requirements:
- Python 3.9+
- boto3
"""

from __future__ import annotations

import argparse
import boto3
import csv
import json
import time
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Iterable


# -------------------------------------------------------------------
# Data models
# -------------------------------------------------------------------

@dataclass(frozen=True)
class WAFEvent:
    region: str
    webacl_id: str
    rule_id: str
    action: str
    client_ip: str
    uri: str
    timestamp: Optional[str] = None


@dataclass
class CorrelationStats:
    hits: int
    unique_ips: int
    unique_uris: int
    regions: List[str]


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze AWS WAF ALB (REGIONAL) logs safely"
    )

    parser.add_argument("--regions", nargs="+", required=True)
    parser.add_argument("--log-group", required=True)
    parser.add_argument("--rule-group", required=True)

    parser.add_argument(
        "--action",
        choices=("COUNT", "BLOCK", "ALLOW"),
        default="COUNT",
    )

    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--mode", choices=("summary", "detailed"), default="summary")

    parser.add_argument("--csv-out")
    parser.add_argument("--json-out")

    parser.add_argument(
        "--promote-threshold",
        type=int,
        help="COUNT hit threshold suggesting BLOCK promotion"
    )

    parser.add_argument(
        "--slack-webhook",
        help="Slack webhook URL for alerts (optional)"
    )

    return parser.parse_args()


# -------------------------------------------------------------------
# Query builder
# -------------------------------------------------------------------

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
    count_distinct(httpRequest.uri) as unique_uris
  by terminatingRuleId, webaclId
| sort hits desc
"""


# -------------------------------------------------------------------
# AWS query execution
# -------------------------------------------------------------------

def run_query(
    region: str,
    log_group: str,
    query: str,
    start: int,
    end: int,
) -> Dict[str, Any]:
    logs = boto3.client("logs", region_name=region)

    resp = logs.start_query(
        logGroupName=log_group,
        startTime=start,
        endTime=end,
        queryString=query,
        limit=1000,
    )

    query_id = resp["queryId"]

    while True:
        result = logs.get_query_results(queryId=query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            return result
        time.sleep(1)


# -------------------------------------------------------------------
# Parsing helpers
# -------------------------------------------------------------------

def rows_to_dicts(rows: List[List[Dict[str, str]]]) -> List[Dict[str, str]]:
    parsed: List[Dict[str, str]] = []
    for row in rows:
        parsed.append({f["field"]: f["value"] for f in row})
    return parsed


def build_events(
    region: str,
    records: Iterable[Dict[str, str]],
    action: str,
) -> List[WAFEvent]:
    events: List[WAFEvent] = []
    for r in records:
        events.append(
            WAFEvent(
                region=region,
                webacl_id=r.get("webaclId", "-"),
                rule_id=r.get("terminatingRuleId", "-"),
                action=action,
                client_ip=r.get("httpRequest.clientIp", "-"),
                uri=r.get("httpRequest.uri", "-"),
                timestamp=r.get("@timestamp"),
            )
        )
    return events


# -------------------------------------------------------------------
# Correlation + promotion analysis
# -------------------------------------------------------------------

def correlate(events: List[WAFEvent]) -> Dict[str, CorrelationStats]:
    buckets: Dict[str, List[WAFEvent]] = {}

    for e in events:
        key = f"{e.rule_id}:{e.webacl_id}"
        buckets.setdefault(key, []).append(e)

    correlations: Dict[str, CorrelationStats] = {}

    for key, evs in buckets.items():
        correlations[key] = CorrelationStats(
            hits=len(evs),
            unique_ips=len({e.client_ip for e in evs}),
            unique_uris=len({e.uri for e in evs}),
            regions=sorted({e.region for e in evs}),
        )

    return correlations


# -------------------------------------------------------------------
# Slack integration
# -------------------------------------------------------------------

def send_slack(
    webhook: str,
    text: str,
) -> None:
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        print(f"[!] Slack webhook failed: {exc}")


# -------------------------------------------------------------------
# Output
# -------------------------------------------------------------------

def write_csv(path: str, events: List[WAFEvent]) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=asdict(events[0]).keys(),
        )
        writer.writeheader()
        for e in events:
            writer.writerow(asdict(e))


def write_json(path: str, events: List[WAFEvent]) -> None:
    with open(path, "w") as fh:
        json.dump([asdict(e) for e in events], fh, indent=2)


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)

    print("[+] AWS WAF ALB Analysis")
    print(f"    Rule group : {args.rule_group}")
    print(f"    Action     : {args.action}")
    print(f"    Window     : {start.isoformat()} → {end.isoformat()}")

    all_events: List[WAFEvent] = []

    query = build_query(
        args.rule_group,
        args.action,
        args.mode == "detailed",
    )

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
        events = build_events(region, records, args.action)
        all_events.extend(events)

        print(f"[+] {region}: {len(events)} events")

    if not all_events:
        print("[+] No WAF activity found")
        return

    correlations = correlate(all_events)

    print("\nCorrelation Summary")
    print("-" * 70)
    for key, stats in correlations.items():
        print(
            f"{key} | hits={stats.hits} "
            f"ips={stats.unique_ips} "
            f"uris={stats.unique_uris} "
            f"regions={','.join(stats.regions)}"
        )

    if args.promote_threshold and args.action == "COUNT":
        print("\nPromotion Candidates (COUNT → BLOCK)")
        for key, stats in correlations.items():
            if stats.hits >= args.promote_threshold:
                print(f"  {key} hits={stats.hits}")

    if args.csv_out:
        write_csv(args.csv_out, all_events)
        print(f"[+] CSV written to {args.csv_out}")

    if args.json_out:
        write_json(args.json_out, all_events)
        print(f"[+] JSON written to {args.json_out}")

    if args.slack_webhook:
        msg = (
            f"*AWS WAF ALB Summary*\n"
            f"Rule group: `{args.rule_group}`\n"
            f"Action: `{args.action}`\n"
            f"Events: {len(all_events)}\n"
            f"Correlated rules: {len(correlations)}"
        )
        send_slack(args.slack_webhook, msg)


if __name__ == "__main__":
    main()
