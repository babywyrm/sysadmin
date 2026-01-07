#!/usr/bin/env python3

from elasticsearch import Elasticsearch
from rich.console import Console
from rich.table import Table
import time

ES_URL = "https://elastic.example.com:9200"
API_KEY = "REDACTED"
INDEX = "logs-*"
INTERVAL = 5  # seconds

es = Elasticsearch(
    ES_URL,
    api_key=API_KEY,
    verify_certs=True
)

console = Console()

def query():
    return es.search(
        index=INDEX,
        size=25,
        sort="@timestamp:desc",
        query={
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-30s"}}}
                ],
                "must": [
                    {"wildcard": {"url.path": "*wp-admin*"}}
                ]
            }
        }
    )

while True:
    try:
        resp = query()

        table = Table(title="Real-Time Web Requests")
        table.add_column("Time")
        table.add_column("IP")
        table.add_column("Method")
        table.add_column("Path")
        table.add_column("Status")

        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            table.add_row(
                src.get("@timestamp", ""),
                src.get("client.ip", ""),
                src.get("http.method", ""),
                src.get("url.path", ""),
                str(src.get("http.response.status_code", ""))
            )

        console.clear()
        console.print(table)
        time.sleep(INTERVAL)

    except KeyboardInterrupt:
        break
