#!/usr/bin/env python3

import argparse
import concurrent.futures
import httpx
import json
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

MCP_PROTOCOL_VERSION = "2024-11-05"

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}

INJECTION_PATTERNS = re.compile(
    r"(ignore previous|jailbreak|override instruction|system prompt)",
    re.IGNORECASE,
)

EXECUTION_PATTERNS = re.compile(
    r"(exec|subprocess|bash|eval|os\.system|command)",
    re.IGNORECASE,
)

EXFIL_PATTERNS = re.compile(
    r"(token|secret|credential|169\.254\.169\.254|/var/run/secrets)",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""


@dataclass
class TargetResult:
    url: str
    transport: str = "unknown"
    tools: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def add(self, check, severity, title, detail="", evidence=""):
        self.findings.append(
            Finding(check, severity, title, detail, evidence)
        )

    def risk_score(self):
        return sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)


# ─────────────────────────────────────────────────────────────
# Correct Single-Stream SSE MCP Session
# ─────────────────────────────────────────────────────────────

class MCPSession:
    def __init__(self, url, timeout=25, verbose=False, debug=False):
        self.verbose = verbose
        self.debug = debug
        self.timeout = timeout

        parsed = urlparse(url)
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.sse_url = self.base + "/sse"

        self.client = httpx.Client(timeout=timeout, verify=False)
        self.queue = queue.Queue()
        self._id = 0
        self._stop = threading.Event()
        self.post_url = None

        self._ready = threading.Event()

        self.listener = threading.Thread(
            target=self._listen,
            daemon=True,
        )
        self.listener.start()

        # Wait until endpoint is discovered
        if not self._ready.wait(timeout=timeout):
            self.post_url = None

    def log(self, msg):
        if self.verbose:
            print(f"[{self.base}] {msg}")

    def debug_log(self, msg):
        if self.debug:
            print(f"[DEBUG {self.base}] {msg}")

    def _listen(self):
        try:
            with self.client.stream(
                "GET",
                self.sse_url,
                headers={"Accept": "text/event-stream"},
            ) as resp:

                if resp.status_code != 200:
                    return

                event = None

                for raw in resp.iter_lines():
                    if self._stop.is_set():
                        break

                    line = raw.strip()

                    if line.startswith("event:"):
                        event = line[6:].strip()

                    elif line.startswith("data:"):
                        data = line[5:].strip()

                        # Extract endpoint first
                        if event == "endpoint" and not self.post_url:
                            endpoint = data
                            self.post_url = (
                                endpoint
                                if endpoint.startswith("http")
                                else self.base + endpoint
                            )
                            self.log(f"Session established: {self.post_url}")
                            self._ready.set()

                        else:
                            try:
                                msg = json.loads(data)
                                self.queue.put(msg)
                                self.debug_log(f"SSE recv: {msg}")
                            except Exception:
                                pass

                        event = None

        except Exception as e:
            self.debug_log(f"SSE listener error: {e}")

    def _next_id(self):
        self._id += 1
        return self._id

    def call(self, method, params=None):
        if not self.post_url:
            return None

        rid = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": rid,
            "method": method,
            "params": params or {},
        }

        self.debug_log(f"POST {payload}")

        try:
            r = self.client.post(self.post_url, json=payload)
            if r.status_code not in (200, 202, 204):
                return None
        except Exception:
            return None

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                msg = self.queue.get(timeout=0.5)
                if msg.get("id") == rid:
                    return msg
            except queue.Empty:
                pass

        return None

    def notify_initialized(self):
        try:
            self.client.post(
                self.post_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "initialized",
                    "params": {},
                },
            )
        except Exception:
            pass

    def close(self):
        self._stop.set()
        self.client.close()


# ─────────────────────────────────────────────────────────────
# Enumeration
# ─────────────────────────────────────────────────────────────

def enumerate_server(session, result):
    session.log("Initializing MCP session")

    resp = session.call(
        "initialize",
        {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-audit", "version": "standalone"},
        },
    )

    if not resp or "result" not in resp:
        result.add("init", "HIGH", "Initialize failed")
        return

    session.log("Initialize successful")
    result.add("auth", "HIGH", "Unauthenticated initialize accepted")

    session.notify_initialized()
    time.sleep(1.5)

    for attempt in range(3):
        tools = session.call("tools/list")
        if tools and "result" in tools:
            result.tools = tools["result"].get("tools", [])
            session.log(f"Discovered {len(result.tools)} tools")
            break
        time.sleep(1)

    # Rug pull detection
    tools2 = session.call("tools/list")
    if tools2 and "result" in tools2:
        names1 = {t["name"] for t in result.tools}
        names2 = {t["name"] for t in tools2["result"].get("tools", [])}
        if names1 != names2:
            result.add(
                "rug_pull",
                "HIGH",
                "Tool list changed between calls",
                detail=f"{names1} -> {names2}",
            )


# ─────────────────────────────────────────────────────────────
# Security Checks
# ─────────────────────────────────────────────────────────────

def run_checks(result):
    tool_names = set()

    for tool in result.tools:
        name = tool.get("name", "")
        desc = tool.get("description", "")
        tool_names.add(name.lower())

        if INJECTION_PATTERNS.search(desc):
            result.add("prompt_injection", "CRITICAL",
                       f"Injection pattern in tool '{name}'")

        if EXECUTION_PATTERNS.search(desc):
            result.add("code_execution", "CRITICAL",
                       f"Execution capability in tool '{name}'")

        if EXFIL_PATTERNS.search(desc):
            result.add("exfiltration", "HIGH",
                       f"Secret access indicator in tool '{name}'")

        if not tool.get("inputSchema"):
            result.add("schema", "MEDIUM",
                       f"No input schema for tool '{name}'")

    # Shadowing
    common_names = {"run", "exec", "shell", "read", "write", "list"}
    shadowed = tool_names & common_names
    if shadowed:
        result.add("shadowing", "HIGH",
                   f"Tool shadowing common names: {shadowed}")

    # Multi-vector detection
    checks_hit = {f.check for f in result.findings}
    dangerous = {"prompt_injection", "code_execution", "exfiltration"}
    if len(checks_hit & dangerous) >= 2:
        result.add("multi_vector", "CRITICAL",
                   "Multiple attack vectors present")


# ─────────────────────────────────────────────────────────────
# Scan Logic
# ─────────────────────────────────────────────────────────────

def scan_target(url, args):
    result = TargetResult(url)

    session = MCPSession(
        url,
        timeout=args.timeout,
        verbose=args.verbose,
        debug=args.debug,
    )

    if not session.post_url:
        result.add("transport", "HIGH", "SSE negotiation failed")
        return result

    result.transport = "SSE"

    enumerate_server(session, result)
    run_checks(result)

    session.close()
    return result


# ─────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────

def print_report(results):
    print("\n=== MCP Audit Report ===\n")

    for r in results:
        print("────────────────────────────────────────")
        print(f"Target: {r.url}")
        print(f"Transport: {r.transport}")
        print(f"Tools: {len(r.tools)}")
        print(f"Risk Score: {r.risk_score()}")
        print(f"Findings: {len(r.findings)}")

        for f in r.findings:
            print(f"  [{f.severity}] {f.check} → {f.title}")

        print()


def write_json(results, path):
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [
            {
                "url": r.url,
                "risk_score": r.risk_score(),
                "findings": [f.__dict__ for f in r.findings],
            }
            for r in results
        ],
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def expand_port_range(host_range):
    host, ports = host_range.split(":")
    start, end = map(int, ports.split("-"))
    return [f"http://{host}:{p}" for p in range(start, end + 1)]


def main():
    parser = argparse.ArgumentParser(description="Standalone MCP Security Scanner")
    parser.add_argument("--targets", nargs="+")
    parser.add_argument("--port-range")
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--json")

    args = parser.parse_args()

    targets = args.targets or []

    if args.port_range:
        targets += expand_port_range(args.port_range)

    if not targets:
        print("No targets specified.")
        return

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:
        futures = [
            executor.submit(scan_target, t, args)
            for t in targets
        ]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    print_report(results)

    if args.json:
        write_json(results, args.json)


if __name__ == "__main__":
    main()
