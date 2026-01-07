#!/usr/bin/env python3
"""
elastic_tail.py — realtime Elasticsearch tail with:
  - rule-based detection
  - WAF correlation
  - baseline anomaly detection
"""

import time
import sys
import yaml
from collections import defaultdict, deque
from datetime import datetime

from elasticsearch import Elasticsearch
from rich.console import Console

# ─────────────────────────── Config ───────────────────────────

ES_URL = "https://elastic.example.com:9200"
API_KEY = "REDACTED"
INDEX = "logs-*"
POLL_INTERVAL = 2
PAGE_SIZE = 100
LOOKBACK = "2m"

RULES_FILE = "rules.yaml"

# ─────────────────────────── Setup ───────────────────────────

console = Console()

with open(RULES_FILE) as f:
    cfg = yaml.safe_load(f)

rules = cfg["rules"]
baseline_cfg = cfg["baseline"]
waf_cfg = cfg["waf"]

es = Elasticsearch(
    ES_URL,
    api_key=API_KEY,
    verify_certs=True
)

search_after = None

# state
event_counts = defaultdict(int)
baseline_windows = defaultdict(deque)

# ─────────────────────────── Helpers ───────────────────────────

def extract(hit):
    s = hit["_source"]
    return {
        "ts": s.get("@timestamp"),
        "ip": s.get("client.ip", "-"),
        "method": s.get("http.method", "-"),
        "path": s.get("url.path", "-"),
        "status": s.get("http.response.status_code", "-"),
        "waf_action": s.get("aws.waf.action", "ALLOW"),
        "waf_rule": s.get("aws.waf.terminating_rule_id", "-")
    }

def match_rule(event, rule):
    m = rule["match"]
    path = event["path"]

    if "contains" in m:
        return any(x in path for x in m["contains"])

    if "startswith" in m:
        return any(path.startswith(x) for x in m["startswith"])

    return False

def severity_score(sev):
    return {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 6,
        "CRITICAL": 10
    }.get(sev, 1)

# ─────────────────────────── Query ───────────────────────────

def query():
    body = {
        "size": PAGE_SIZE,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        "query": {
            "range": {
                "@timestamp": {"gte": f"now-{LOOKBACK}"}
            }
        }
    }

    if search_after:
        body["search_after"] = search_after

    return es.search(index=INDEX, body=body)

# ─────────────────────────── Engine ───────────────────────────

console.print("\n[bold green]▶ Elastic Tail (Rules + WAF + Baseline)[/bold green]\n")

while True:
    try:
        resp = query()
        hits = resp["hits"]["hits"]

        if not hits:
            time.sleep(POLL_INTERVAL)
            continue

        for hit in hits:
            event = extract(hit)
            ip = event["ip"]
            path = event["path"]

            # ─── Baseline tracking ───
            now = time.time()
            window = baseline_windows[ip]
            window.append(now)

            while window and now - window[0] > baseline_cfg["window_seconds"]:
                window.popleft()

            baseline_rate = len(window)

            # ─── Rule matching ───
            for rule in rules:
                if match_rule(event, rule):
                    key = f"{ip}:{path}"
                    event_counts[key] += 1

                    score = severity_score(rule["severity"]) * event_counts[key]

                    waf_allowed = event["waf_action"] not in waf_cfg["block_actions"]

                    tag = "[red]ALLOWED[/red]" if waf_allowed else "[green]BLOCKED[/green]"

                    console.print(
                        f"[bold]{rule['name']}[/bold] {tag} "
                        f"{ip} {path} "
                        f"count={event_counts[key]} score={score} "
                        f"waf_rule={event['waf_rule']}"
                    )

            # ─── Baseline anomaly ───
            if baseline_rate > baseline_cfg["burst_multiplier"] * 5:
                console.print(
                    f"[yellow]ANOMALY[/yellow] {ip} "
                    f"rate={baseline_rate}/"
                    f"{baseline_cfg['window_seconds']}s"
                )

            # ─── Normal log line ───
            console.print(
                f"{event['ts']} {ip:15} "
                f"{event['method']:6} {event['status']:4} {path}"
            )

        search_after = hits[-1]["sort"]

    except KeyboardInterrupt:
        console.print("\n[bold yellow]✋ stopped[/bold yellow]")
        sys.exit(0)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        time.sleep(3)
