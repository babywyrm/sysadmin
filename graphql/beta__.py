#!/usr/bin/env python3
"""
pentest_tool.py — Concurrent GraphQL & Cypher injection pentester .. (in-development) ..
"""

import argparse
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from colorama import Fore, Style

# ─── Setup Logging ──────────────────────────────────────────────────────────────
logger = logging.getLogger("pentest_tool")
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


# ─── Shared Utilities ──────────────────────────────────────────────────────────
def load_payloads(path: Path) -> List[str]:
    """Load a JSON or plain-text file of payload strings."""
    if not path.exists():
        logger.error("Payload file not found: %s", path)
        sys.exit(1)

    if path.suffix.lower() in {".json"}:
        return json.loads(path.read_text())
    else:
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def save_csv(rows: List[Tuple], filename: Path) -> None:
    import csv
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["mode", "payload", "status", "time_s", "snippet"])
        writer.writerows(rows)
    logger.info("Results exported to %s", filename)


# ─── GraphQL Pentester ─────────────────────────────────────────────────────────
class GraphQLPentester:
    def __init__(self, endpoint: str, headers: Dict[str, str], timeout: int):
        self.endpoint = endpoint
        self.headers = headers
        self.timeout = timeout

    def introspect(self) -> Dict[str, Any]:
        q = {"query": "query { __schema { types { name fields { name } } } }"}
        r = requests.post(self.endpoint, json=q, headers=self.headers, timeout=self.timeout)
        return r.json()

    def test_payload(self, payload: str) -> Tuple[str, int, float, str]:
        """Send one payload, return (payload, status, elapsed, snippet)."""
        start = time.time()
        try:
            r = requests.post(self.endpoint, json={"query": payload},
                              headers=self.headers, timeout=self.timeout)
            elapsed = time.time() - start
            snippet = r.text[:200].replace("\n", " ")
            return payload, r.status_code, elapsed, snippet
        except Exception as e:
            elapsed = time.time() - start
            return payload, -1, elapsed, f"ERROR: {e}"


# ─── Cypher Pentester ──────────────────────────────────────────────────────────
class CypherPentester:
    def __init__(self, endpoint: str, auth: Optional[Tuple[str, str]], timeout: int):
        self.endpoint = endpoint.rstrip("/") + "/db/neo4j/tx/commit"
        self.auth = auth
        self.timeout = timeout

    def introspect_labels(self) -> None:
        q = {"statements": [{"statement": "MATCH (n) RETURN labels(n), count(*) LIMIT 5"}]}
        r = requests.post(self.endpoint, json=q, auth=self.auth, timeout=self.timeout)
        logger.info("Label peek: %s", r.json())

    def test_payload(self, payload: str) -> Tuple[str, int, float, str]:
        start = time.time()
        q = {"statements": [{"statement": payload}]}
        try:
            r = requests.post(self.endpoint, json=q, auth=self.auth, timeout=self.timeout)
            elapsed = time.time() - start
            snippet = str(r.json().get("results", []))[:200]
            return payload, r.status_code, elapsed, snippet
        except Exception as e:
            elapsed = time.time() - start
            return payload, -1, elapsed, f"ERROR: {e}"


# ─── Main & CLI ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser("Pentest GraphQL & Cypher")
    parser.add_argument("--mode", choices=["graphql", "cypher"], required=True)
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--user", help="Neo4j username (for cypher)")
    parser.add_argument("--pass", dest="password", help="Neo4j password (for cypher)")
    parser.add_argument("--payload-file", type=Path, required=True,
                        help="JSON or newline-delimited file of payloads")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (s)")
    parser.add_argument("--header", action="append",
                        help="Additional HTTP header (Key:Value)")
    parser.add_argument("--csv", type=Path, help="Export results to CSV file")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    # configure logging level
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    # build headers
    headers = {"Content-Type": "application/json"}
    if args.header:
        for hdr in args.header:
            k, v = hdr.split(":", 1)
            headers[k.strip()] = v.strip()

    payloads = load_payloads(args.payload_file)
    logger.info("Loaded %d payloads", len(payloads))

    results = []
    if args.mode == "graphql":
        tool = GraphQLPentester(args.url, headers, args.timeout)
        logger.info("Running GraphQL introspection…")
        schema = tool.introspect()
        if args.verbose: logger.debug("Schema: %s", json.dumps(schema)[:500])

        logger.info("Injecting %d payloads with %d workers", len(payloads), args.workers)
        with ThreadPoolExecutor(max_workers=args.workers) as exe:
            futures = [exe.submit(tool.test_payload, p) for p in payloads]
            for f in as_completed(futures):
                payload, status, elapsed, snippet = f.result()
                color = Fore.GREEN if 200 <= status < 300 else Fore.RED
                print(f"{color}[GQL] {status} {elapsed:.2f}s{Style.RESET_ALL} — {payload}")
                if args.verbose:
                    print(f"    → {snippet}")
                results.append(("graphql", payload, status, elapsed, snippet))

    else:
        auth = (args.user, args.password) if args.user and args.password else None
        tool = CypherPentester(args.url, auth, args.timeout)
        logger.info("Running Cypher label introspection…")
        tool.introspect_labels()

        logger.info("Injecting %d payloads with %d workers", len(payloads), args.workers)
        with ThreadPoolExecutor(max_workers=args.workers) as exe:
            futures = [exe.submit(tool.test_payload, p) for p in payloads]
            for f in as_completed(futures):
                payload, status, elapsed, snippet = f.result()
                color = Fore.GREEN if status == 200 else Fore.RED
                print(f"{color}[CYP] {status} {elapsed:.2f}s{Style.RESET_ALL} — {payload}")
                if args.verbose:
                    print(f"    → {snippet}")
                results.append(("cypher", payload, status, elapsed, snippet))

    if args.csv:
        save_csv(results, args.csv)


if __name__ == "__main__":
    main()

