#!/usr/bin/env python3
"""
pentest_tool.py — GraphQL & Cypher injection pentester, ..(condensed, beta edition)..
with baseline-vs-variant analysis, Burp replay, and payload fuzz chaining
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from colorama import Fore, Style, init


# ──────────────────────────────────────────────────────────────────────────────
# Color Handling
# ──────────────────────────────────────────────────────────────────────────────
def init_colors(enabled: bool) -> None:
    if enabled:
        init(autoreset=True)
    else:
        global Fore, Style
        class _NoColor:
            def __getattr__(self, _): return ""
        Fore = Style = _NoColor()


# ──────────────────────────────────────────────────────────────────────────────
# Detection Heuristics
# ──────────────────────────────────────────────────────────────────────────────
GRAPHQL_INDICATORS = [
    "cannot query field",
    "unknown argument",
    "__schema",
    "graphql error",
    "validation error",
]

CYPHER_INDICATORS = [
    "neo.clienterror",
    "syntaxerror",
    "procedure not found",
    "db.labels",
    "stacktrace",
]


# ──────────────────────────────────────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class TestResult:
    mode: str
    payload: str
    mutated_from: Optional[str]
    status_code: int
    response_time: float
    response_len: int
    response_snippet: str
    error: Optional[str] = None
    suspicious: bool = False
    baseline_delta: Optional[int] = None
    classification: str = "NORMAL"
    burp_request: Optional[str] = None

    @property
    def success(self) -> bool:
        return 200 <= self.status_code < 300


@dataclass
class TestConfig:
    mode: str
    url: str
    headers: Dict[str, str]
    timeout: int
    workers: int
    rate_limit: float
    auth: Optional[Tuple[str, str]] = None

    def __post_init__(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("Invalid URL")
        if not urlparse(self.url).netloc:
            raise ValueError("Invalid URL")


# ──────────────────────────────────────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────────────────────────────────────
class Logger:
    def __init__(self, level: int):
        self.logger = logging.getLogger("pentest_tool")
        self.logger.setLevel(level)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                "%H:%M:%S",
            ))
            self.logger.addHandler(h)
        self.lock = threading.Lock()

    def info(self, msg: str) -> None:
        with self.lock:
            self.logger.info(msg)

    def debug(self, msg: str) -> None:
        with self.lock:
            self.logger.debug(msg)

    def error(self, msg: str) -> None:
        with self.lock:
            self.logger.error(msg)


# ──────────────────────────────────────────────────────────────────────────────
# Payload Fuzz Chaining
# ──────────────────────────────────────────────────────────────────────────────
def fuzz_payloads(payload: str, mode: str) -> List[Tuple[str, Optional[str]]]:
    """
    Generate mutated payloads from a base payload.
    Returns (payload, mutated_from)
    """
    mutations = []

    # universal
    mutations.append(payload + "'")
    mutations.append(payload + "\"")
    mutations.append(payload + " --")
    mutations.append(payload.replace(" ", "  "))

    if mode == "graphql":
        mutations.extend([
            payload.replace("}", "} #"),
            payload.replace("{", "{__typename "),
        ])

    if mode == "cypher":
        mutations.extend([
            payload + " RETURN 1",
            payload + " //",
            payload.replace("MATCH", "MATCH /* fuzz */"),
        ])

    results = [(payload, None)]
    results.extend((m, payload) for m in set(mutations) if m != payload)
    return results


# ──────────────────────────────────────────────────────────────────────────────
# HTTP Utilities
# ──────────────────────────────────────────────────────────────────────────────
def create_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def build_burp_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: str,
) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    req = [f"{method} {path} HTTP/1.1"]
    req.append(f"Host: {parsed.netloc}")
    for k, v in headers.items():
        if k.lower() != "authorization":
            req.append(f"{k}: {v}")
    req.append("")
    req.append(body)
    return "\n".join(req)


# ──────────────────────────────────────────────────────────────────────────────
# Pentesters
# ──────────────────────────────────────────────────────────────────────────────
class BasePentester:
    def __init__(self, config: TestConfig):
        self.config = config
        self.session = create_session()
        self.lock = threading.Lock()
        self.last = 0.0

    def rate_limit(self):
        with self.lock:
            delta = time.time() - self.last
            if delta < self.config.rate_limit:
                time.sleep(self.config.rate_limit - delta)
            self.last = time.time()

    def close(self):
        self.session.close()


class GraphQLPentester(BasePentester):
    def test(self, payload: str, origin: Optional[str]) -> TestResult:
        start = time.time()
        self.rate_limit()
        try:
            r = self.session.post(
                self.config.url,
                json={"query": payload},
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            text = r.text
            snippet = text[:300].replace("\n", " ")
            suspicious = any(i in snippet.lower() for i in GRAPHQL_INDICATORS)
            burp = build_burp_request(
                "POST", self.config.url, self.config.headers,
                json.dumps({"query": payload})
            )
            return TestResult(
                "graphql", payload, origin,
                r.status_code, time.time() - start,
                len(text), snippet,
                suspicious=suspicious,
                burp_request=burp,
            )
        except Exception as e:
            return TestResult(
                "graphql", payload, origin, -1,
                time.time() - start, 0, "",
                error=str(e),
            )


class CypherPentester(BasePentester):
    def __init__(self, config: TestConfig):
        super().__init__(config)
        if not self.config.url.endswith("/db/neo4j/tx/commit"):
            self.config.url += "/db/neo4j/tx/commit"

    def test(self, payload: str, origin: Optional[str]) -> TestResult:
        start = time.time()
        self.rate_limit()
        try:
            r = self.session.post(
                self.config.url,
                json={"statements": [{"statement": payload}]},
                auth=self.config.auth,
                headers={"Content-Type": "application/json"},
                timeout=self.config.timeout,
            )
            data = json.dumps(r.json())
            snippet = data[:300]
            suspicious = any(i in snippet.lower() for i in CYPHER_INDICATORS)
            burp = build_burp_request(
                "POST", self.config.url,
                {"Content-Type": "application/json"},
                json.dumps({"statements": [{"statement": payload}]}),
            )
            return TestResult(
                "cypher", payload, origin,
                r.status_code, time.time() - start,
                len(data), snippet,
                suspicious=suspicious,
                burp_request=burp,
            )
        except Exception as e:
            return TestResult(
                "cypher", payload, origin, -1,
                time.time() - start, 0, "",
                error=str(e),
            )


# ──────────────────────────────────────────────────────────────────────────────
# Runner with Baseline vs Variant
# ──────────────────────────────────────────────────────────────────────────────
def run_tests(config: TestConfig, payloads: List[str], logger: Logger):
    results: List[TestResult] = []
    baseline: Optional[TestResult] = None

    pentester = (
        GraphQLPentester(config)
        if config.mode == "graphql"
        else CypherPentester(config)
    )

    expanded: List[Tuple[str, Optional[str]]] = []
    for p in payloads:
        expanded.extend(fuzz_payloads(p, config.mode))

    logger.info(f"Testing {len(expanded)} payloads (with fuzzing)")

    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        futures = {
            pool.submit(pentester.test, p, origin): (p, origin)
            for p, origin in expanded
        }

        for f in as_completed(futures):
            r = f.result()
            if not baseline and r.success:
                baseline = r
                r.classification = "BASELINE"
            elif baseline:
                r.baseline_delta = abs(r.response_len - baseline.response_len)
                if r.baseline_delta > 200 or r.status_code != baseline.status_code:
                    r.classification = "ANOMALY"
                    r.suspicious = True
                else:
                    r.classification = "VARIANT"

            results.append(r)

            color = (
                Fore.MAGENTA if r.classification == "BASELINE"
                else Fore.YELLOW if r.suspicious
                else Fore.GREEN if r.success
                else Fore.RED
            )

            print(f"{color}[{r.classification}] "
                  f"{r.status_code} {r.response_time:.2f}s "
                  f"Δ={r.baseline_delta} "
                  f"{r.payload[:50]}")

    pentester.close()
    return results


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["graphql", "cypher"], required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--payload-file", type=Path, required=True)
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--rate-limit", type=float, default=0.1)
    p.add_argument("--user")
    p.add_argument("--password")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    init_colors(not args.no_color)
    logger = Logger(logging.DEBUG if args.verbose else logging.INFO)

    payloads = [l.strip() for l in args.payload_file.read_text().splitlines() if l.strip()]

    config = TestConfig(
        mode=args.mode,
        url=args.url,
        headers={"Content-Type": "application/json"},
        timeout=args.timeout,
        workers=args.workers,
        rate_limit=args.rate_limit,
        auth=(args.user, args.password) if args.user else None,
    )

    run_tests(config, payloads, logger)
    return 0


if __name__ == "__main__":
    sys.exit(main())
