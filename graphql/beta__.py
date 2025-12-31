#!/usr/bin/env python3
"""
pentest_tool.py — Enhanced concurrent GraphQL & Cypher injection pentester
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
from dataclasses import dataclass, asdict
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
    status_code: int
    response_time: float
    response_snippet: str
    error: Optional[str] = None
    suspicious: bool = False

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
    rate_limit: float = 0.1     # global rate limit (seconds)
    auth: Optional[Tuple[str, str]] = None

    def __post_init__(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        if not urlparse(self.url).netloc:
            raise ValueError("Invalid URL")


# ──────────────────────────────────────────────────────────────────────────────
# Logger (thread-safe, sanitized)
# ──────────────────────────────────────────────────────────────────────────────
class Logger:
    SENSITIVE_HEADERS = {"authorization", "x-api-key", "api-key", "token"}

    def __init__(self, level: int = logging.INFO):
        self.logger = logging.getLogger("pentest_tool")
        self.logger.setLevel(level)
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                "%H:%M:%S",
            ))
            self.logger.addHandler(h)
        self._lock = threading.Lock()

    def _sanitize(self, msg: str) -> str:
        for h in self.SENSITIVE_HEADERS:
            msg = re.sub(
                rf"({h}\s*[:=]\s*)(\S+)",
                r"\1***",
                msg,
                flags=re.IGNORECASE,
            )
        return msg

    def info(self, msg: str) -> None:
        with self._lock:
            self.logger.info(self._sanitize(msg))

    def debug(self, msg: str) -> None:
        with self._lock:
            self.logger.debug(self._sanitize(msg))

    def error(self, msg: str) -> None:
        with self._lock:
            self.logger.error(self._sanitize(msg))


# ──────────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────────
def load_payloads(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(path)

    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payloads = json.loads(text)
        if not isinstance(payloads, list):
            raise ValueError("JSON payload file must contain a list")
    else:
        payloads = [l.strip() for l in text.splitlines() if l.strip()]

    if not payloads:
        raise ValueError("No valid payloads found")
    return payloads


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


# ──────────────────────────────────────────────────────────────────────────────
# Base Pentester
# ──────────────────────────────────────────────────────────────────────────────
class BasePentester:
    def __init__(self, config: TestConfig, logger: Logger):
        self.config = config
        self.logger = logger
        self.session = create_session()
        self._last_request = 0.0
        self._lock = threading.Lock()

    def _rate_limit(self) -> None:
        with self._lock:
            delta = time.time() - self._last_request
            if delta < self.config.rate_limit:
                time.sleep(self.config.rate_limit - delta)
            self._last_request = time.time()

    def close(self) -> None:
        self.session.close()


# ──────────────────────────────────────────────────────────────────────────────
# GraphQL Pentester
# ──────────────────────────────────────────────────────────────────────────────
class GraphQLPentester(BasePentester):
    def introspect(self) -> bool:
        query = {"query": "query{__schema{queryType{name}}}"}
        try:
            self._rate_limit()
            r = self.session.post(
                self.config.url,
                json=query,
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            j = r.json()
            return "__schema" in j.get("data", {})
        except Exception:
            return False

    def test_payload(self, payload: str) -> TestResult:
        start = time.time()
        try:
            self._rate_limit()
            r = self.session.post(
                self.config.url,
                json={"query": payload},
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            snippet = r.text[:300].replace("\n", " ")
            suspicious = any(i in snippet.lower() for i in GRAPHQL_INDICATORS)
            return TestResult(
                "graphql", payload, r.status_code,
                time.time() - start, snippet, suspicious=suspicious
            )
        except Exception as e:
            return TestResult(
                "graphql", payload, -1,
                time.time() - start, "", error=str(e)
            )


# ──────────────────────────────────────────────────────────────────────────────
# Cypher Pentester
# ──────────────────────────────────────────────────────────────────────────────
class CypherPentester(BasePentester):
    def __init__(self, config: TestConfig, logger: Logger):
        super().__init__(config, logger)
        if not self.config.url.endswith("/db/neo4j/tx/commit"):
            self.config.url = self.config.url.rstrip("/") + "/db/neo4j/tx/commit"

    def test_payload(self, payload: str) -> TestResult:
        start = time.time()
        try:
            self._rate_limit()
            r = self.session.post(
                self.config.url,
                json={"statements": [{"statement": payload}]},
                auth=self.config.auth,
                headers={"Content-Type": "application/json"},
                timeout=self.config.timeout,
            )
            data = r.json()
            snippet = json.dumps(data)[:300]
            suspicious = any(i in snippet.lower() for i in CYPHER_INDICATORS)
            return TestResult(
                "cypher", payload, r.status_code,
                time.time() - start, snippet, suspicious=suspicious
            )
        except Exception as e:
            return TestResult(
                "cypher", payload, -1,
                time.time() - start, "", error=str(e)
            )


# ──────────────────────────────────────────────────────────────────────────────
# Results Manager
# ──────────────────────────────────────────────────────────────────────────────
class ResultsManager:
    def __init__(self):
        self.results: List[TestResult] = []
        self._lock = threading.Lock()

    def add(self, r: TestResult) -> None:
        with self._lock:
            self.results.append(r)

    def finalize(self) -> None:
        self.results.sort(
            key=lambda r: (not r.suspicious, not r.success, -r.response_time)
        )


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────
def run_tests(config: TestConfig, payloads: List[str], logger: Logger) -> ResultsManager:
    rm = ResultsManager()
    pentester = (
        GraphQLPentester(config, logger)
        if config.mode == "graphql"
        else CypherPentester(config, logger)
    )

    if config.mode == "graphql":
        logger.info("GraphQL introspection: "
                    f"{'open' if pentester.introspect() else 'blocked'}")

    baseline_len: Optional[int] = None

    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        futures = {pool.submit(pentester.test_payload, p): p for p in payloads}
        for f in as_completed(futures):
            r = f.result()

            if baseline_len is None and r.response_snippet:
                baseline_len = len(r.response_snippet)
            elif baseline_len and abs(len(r.response_snippet) - baseline_len) > 200:
                r.suspicious = True

            rm.add(r)

            preview = r.payload.replace("\n", "\\n")[:60]
            color = Fore.YELLOW if r.suspicious else Fore.GREEN if r.success else Fore.RED
            print(f"{color}[{r.mode.upper()}] {r.status_code} "
                  f"{r.response_time:.2f}s — {preview}")

    pentester.close()
    rm.finalize()
    return rm


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

    payloads = load_payloads(args.payload_file)
    headers = {"Content-Type": "application/json"}

    config = TestConfig(
        mode=args.mode,
        url=args.url,
        headers=headers,
        timeout=args.timeout,
        workers=args.workers,
        rate_limit=args.rate_limit,
        auth=(args.user, args.password) if args.user and args.password else None,
    )

    run_tests(config, payloads, logger)
    return 0


if __name__ == "__main__":
    sys.exit(main())
