from elasticsearch import Elasticsearch
from collections import defaultdict
from rich.console import Console
import time
import yaml

from rules import RULES
from scorer import score_event

console = Console()

cfg = yaml.safe_load(open("config.yaml"))

es = Elasticsearch(
    cfg["elastic"]["url"],
    api_key="REDACTED",
    verify_certs=True
)

state = defaultdict(int)
search_after = None

def extract(hit):
    src = hit["_source"]
    return {
        "ts": src.get("@timestamp"),
        "ip": src.get("client.ip", "-"),
        "method": src.get("http.method", "-"),
        "path": src.get("url.path", "-"),
        "status": src.get("http.response.status_code", "-"),
        "waf": src.get("aws.waf.terminating_rule_id", "ALLOW")
    }

def query():
    body = {
        "size": 100,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        "query": {
            "range": {
                "@timestamp": {"gte": f"now-{cfg['elastic']['lookback']}"}
            }
        }
    }
    if search_after:
        body["search_after"] = search_after

    return es.search(index=cfg["elastic"]["index"], body=body)

console.print("[bold green]▶ Elastic Tail w/ Rules Engine[/bold green]\n")

while True:
    resp = query()
    hits = resp["hits"]["hits"]

    if not hits:
        time.sleep(cfg["elastic"]["poll_interval"])
        continue

    for hit in hits:
        event = extract(hit)
        key = f"{event['ip']}:{event['path']}"
        state[key] += 1

        for rule in RULES:
            if rule["match"](event):
                score = score_event(rule, state[key])
                console.print(
                    f"[red]{rule['name']}[/red] "
                    f"{event['ip']} {event['path']} "
                    f"count={state[key]} score={score}"
                )

        console.print(
            f"{event['ts']} {event['ip']:15} "
            f"{event['method']:6} {event['status']:4} {event['path']}"
        )

    search_after = hits[-1]["sort"]
