#!/usr/bin/env python3
"""
elastic_tail.py
===============

Realtime, CLI-native Elasticsearch log tailer for security analysis,
WAF validation, and behavioral anomaly detection — without Kibana.

────────────────────────────────────────────────────────────────────
WHY THIS EXISTS
────────────────────────────────────────────────────────────────────
Kibana is excellent for dashboards, but slow and awkward for
high-tempo investigation. This tool treats Elasticsearch as a
low-latency event stream and provides a `tail -f`-like experience
with built-in security intelligence.

Think of this as:

    tail -f  +  jq  +  SIEM-lite  +  WAF context

────────────────────────────────────────────────────────────────────
CORE FEATURES
────────────────────────────────────────────────────────────────────
• Near-realtime streaming via Elasticsearch `search_after`
• YAML-defined detection rules (no code edits)
• WAF correlation (allowed vs blocked malicious traffic)
• Per-IP baseline anomaly detection
• Operator filters (IP, CIDR, path prefix, substring)
• JSONL output mode for pipelines and replay
• Zero Kibana dependency

────────────────────────────────────────────────────────────────────
DATA EXPECTATIONS (COMMON ECS FIELDS)
────────────────────────────────────────────────────────────────────
The tool expects ECS-like fields (best-effort):

  @timestamp
  client.ip
  http.method
  http.response.status_code
  url.path
  aws.waf.action
  aws.waf.terminating_rule_id

Missing fields are handled gracefully.

────────────────────────────────────────────────────────────────────
RULES CONFIGURATION
────────────────────────────────────────────────────────────────────
Rules are defined in a YAML file (default: rules.yaml).

Example:

  rules:
    - name: Path Traversal
      severity: HIGH
      match:
        contains: ["../", "..%2f"]

  baseline:
    window_seconds: 60
    burst_multiplier: 4

  waf:
    block_actions: ["BLOCK", "CAPTCHA"]

No Python changes are required to add or tune rules.

────────────────────────────────────────────────────────────────────
COMMON USAGE EXAMPLES
────────────────────────────────────────────────────────────────────

1) Live SOC tail (default behavior)
-----------------------------------
Stream all recent logs in near-realtime:

  python elastic_tail.py \
    --es-url https://elastic.example.com:9200 \
    --api-key $ES_API_KEY

2) Focused attack hunting (path traversal)
-------------------------------------------
Only show requests containing traversal attempts:

  python elastic_tail.py \
    --es-url https://elastic.example.com:9200 \
    --api-key $ES_API_KEY \
    --path-contains ../

3) Deep dive on a single IP or CIDR
-----------------------------------
Track all activity from one host or network:

  python elastic_tail.py \
    --es-url https://elastic.example.com:9200 \
    --api-key $ES_API_KEY \
    --ip 203.0.113.42

  python elastic_tail.py \
    --es-url https://elastic.example.com:9200 \
    --api-key $ES_API_KEY \
    --ip 203.0.113.0/24

4) WAF bypass detection (allowed malicious traffic)
----------------------------------------------------
Look for rule hits that were *not* blocked by WAF:

  python elastic_tail.py \
    --es-url https://elastic.example.com:9200 \
    --api-key $ES_API_KEY \
    --path-prefix /wp-admin

5) JSON pipeline / replay mode
-------------------------------
Emit JSONL (one event per line) for tooling or storage:

  python elastic_tail.py \
    --es-url https://elastic.example.com:9200 \
    --api-key $ES_API_KEY \
    --json | jq

Useful for:
  • piping to another detector
  • saving to disk
  • replaying incidents
  • feeding SIEM / alerting

────────────────────────────────────────────────────────────────────
OUTPUT SEMANTICS
────────────────────────────────────────────────────────────────────
Each event includes:

  detections[]:
    - rule
    - severity
    - score
    - waf_allowed (true/false)

  baseline_rate:
    Requests seen from this IP in the sliding window

  baseline_anomaly:
    True if rate exceeds configured burst threshold

JSON mode emits structured objects.
TTY mode emits human-readable SOC output.

────────────────────────────────────────────────────────────────────
OPERATIONAL NOTES
────────────────────────────────────────────────────────────────────
• This tool is intentionally stateful (per-IP baselines)
• Restarting resets baselines
• Best run in tmux / screen / sidecar container
• Designed for explainability — no opaque ML

────────────────────────────────────────────────────────────────────
AUTHOR / OWNERSHIP
────────────────────────────────────────────────────────────────────
Security Engineering
"""

import argparse
import ipaddress
import json
import sys
import time
import yaml
from collections import defaultdict, deque
from elasticsearch import Elasticsearch
from rich.console import Console

# ───────────────────────────── Defaults ─────────────────────────────

DEFAULT_LOOKBACK = "2m"
DEFAULT_POLL = 2
DEFAULT_PAGE_SIZE = 100

# ───────────────────────────── Helpers ─────────────────────────────

def parse_args():
    """
    Parse CLI arguments and return a populated namespace.
    """
    p = argparse.ArgumentParser(
        description="Realtime Elasticsearch tail for security analysis",
        formatter_class=argparse.RawTextHelpFormatter
    )

    p.add_argument("--es-url", required=True, help="Elasticsearch URL")
    p.add_argument("--api-key", required=True, help="Elasticsearch API key")
    p.add_argument("--index", default="logs-*", help="Index pattern")
    p.add_argument("--rules", default="rules.yaml", help="Rules YAML file")

    p.add_argument("--lookback", default=DEFAULT_LOOKBACK,
                   help="Initial lookback window (default: 2m)")
    p.add_argument("--poll", type=int, default=DEFAULT_POLL,
                   help="Poll interval in seconds")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON output (JSONL)")

    # Filters
    p.add_argument("--ip", help="Filter source IP (single or CIDR)")
    p.add_argument("--path-contains", help="Only paths containing substring")
    p.add_argument("--path-prefix", help="Only paths starting with prefix")

    return p.parse_args()

def load_rules(path):
    """
    Load and validate rules YAML.
    """
    with open(path) as f:
        cfg = yaml.safe_load(f)

    return cfg["rules"], cfg["baseline"], cfg["waf"]

def ip_allowed(event_ip, ip_filter):
    """
    Check if event IP matches operator filter.
    """
    if not ip_filter:
        return True

    net = ipaddress.ip_network(ip_filter, strict=False)
    return ipaddress.ip_address(event_ip) in net

def path_allowed(path, contains, prefix):
    """
    Apply path-based filters.
    """
    if contains and contains not in path:
        return False
    if prefix and not path.startswith(prefix):
        return False
    return True

def severity_score(sev):
    """
    Convert severity label to numeric score.
    """
    return {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 6,
        "CRITICAL": 10
    }.get(sev.upper(), 1)

def rule_match(path, rule):
    """
    Evaluate a rule match against a URL path.
    """
    m = rule["match"]
    if "contains" in m:
        return any(x in path for x in m["contains"])
    if "startswith" in m:
        return any(path.startswith(x) for x in m["startswith"])
    return False

# ───────────────────────────── Main Engine ─────────────────────────────

def main():
    """
    Main execution loop.
    """
    args = parse_args()
    console = Console(stderr=not args.json)

    rules, baseline_cfg, waf_cfg = load_rules(args.rules)

    es = Elasticsearch(
        args.es_url,
        api_key=args.api_key,
        verify_certs=True
    )

    search_after = None
    event_counts = defaultdict(int)
    baseline = defaultdict(deque)

    console.print("[bold green]▶ Elastic Tail started[/bold green]")
    console.print(f"Index: {args.index} | JSON: {args.json}\n")

    while True:
        try:
            body = {
                "size": DEFAULT_PAGE_SIZE,
                "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
                "query": {
                    "range": {
                        "@timestamp": {"gte": f"now-{args.lookback}"}
                    }
                }
            }

            if search_after:
                body["search_after"] = search_after

            resp = es.search(index=args.index, body=body)
            hits = resp["hits"]["hits"]

            if not hits:
                time.sleep(args.poll)
                continue

            for hit in hits:
                s = hit["_source"]
                event = {
                    "timestamp": s.get("@timestamp"),
                    "ip": s.get("client.ip", "-"),
                    "method": s.get("http.method", "-"),
                    "path": s.get("url.path", "-"),
                    "status": s.get("http.response.status_code", "-"),
                    "waf_action": s.get("aws.waf.action", "ALLOW"),
                    "waf_rule": s.get("aws.waf.terminating_rule_id", "-"),
                }

                # Operator filters
                if not ip_allowed(event["ip"], args.ip):
                    continue
                if not path_allowed(event["path"],
                                    args.path_contains,
                                    args.path_prefix):
                    continue

                # ── Baseline tracking ──
                now = time.time()
                win = baseline[event["ip"]]
                win.append(now)

                while win and now - win[0] > baseline_cfg["window_seconds"]:
                    win.popleft()

                rate = len(win)
                anomaly = rate > baseline_cfg["burst_multiplier"]

                detections = []

                for rule in rules:
                    if rule_match(event["path"], rule):
                        key = f"{event['ip']}:{event['path']}"
                        event_counts[key] += 1

                        detections.append({
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "score": severity_score(rule["severity"])
                                     * event_counts[key],
                            "waf_allowed": event["waf_action"]
                                           not in waf_cfg["block_actions"]
                        })

                output = {
                    **event,
                    "detections": detections,
                    "baseline_rate": rate,
                    "baseline_anomaly": anomaly
                }

                if args.json:
                    print(json.dumps(output))
                else:
                    if detections:
                        for d in detections:
                            tag = "ALLOWED" if d["waf_allowed"] else "BLOCKED"
                            console.print(
                                f"[bold]{d['rule']}[/bold] "
                                f"[red]{tag}[/red] "
                                f"{event['ip']} {event['path']} "
                                f"score={d['score']}"
                            )

                    if anomaly:
                        console.print(
                            f"[yellow]ANOMALY[/yellow] "
                            f"{event['ip']} rate={rate}"
                        )

                    console.print(
                        f"{event['timestamp']} {event['ip']:15} "
                        f"{event['method']:6} {event['status']:4} "
                        f"{event['path']}"
                    )

            search_after = hits[-1]["sort"]

        except KeyboardInterrupt:
            console.print("\n[bold yellow]✋ stopped[/bold yellow]")
            sys.exit(0)

        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            time.sleep(3)

# ───────────────────────────── Entry ─────────────────────────────

if __name__ == "__main__":
    main()
