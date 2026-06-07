#!/usr/bin/env python3
"""
mcp-audit v4.1 — Hardened Universal MCP + DVMCP Security Scanner ..beta..

Install:
    pip install httpx rich

Usage:
    python3 mcp_audit.py --targets http://localhost:2266
    python3 mcp_audit.py --port-range localhost:9001-9010 --verbose
    python3 mcp_audit.py --port-range localhost:9001-9010 --debug --json report.json
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import gzip
import json
import os
import queue
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from rich import box
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
debug_console = Console(stderr=True, style="dim")

# ════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════

MCP_PROTOCOL_VERSION = "2024-11-05"
MCP_INIT_PARAMS = {
    "protocolVersion": MCP_PROTOCOL_VERSION,
    "capabilities": {},
    "clientInfo": {"name": "mcp-audit", "version": "4.1"},
}

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

ATTACK_CHAIN_PATTERNS = [
    ("prompt_injection", "code_execution"),
    ("prompt_injection", "token_theft"),
    ("code_execution", "token_theft"),
    ("code_execution", "remote_access"),
    ("indirect_injection", "token_theft"),
    ("indirect_injection", "remote_access"),
    ("tool_poisoning", "token_theft"),
]

SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

SSE_PATHS = ["/sse", "/mcp/sse", "/v1/sse", "/stream", "/events", ""]
POST_PATHS = ["/mcp", "/rpc", "/jsonrpc", "/v1/mcp", "/messages", ""]

VERBOSE = False
DEBUG = False

GLOBAL_K8S_FINDINGS: list[Finding] = []

# ════════════════════════════════════════════════════════════════
# Detection patterns
# ════════════════════════════════════════════════════════════════

INJECTION_PATTERNS = [
    r"ignore\s+(previous|prior|above|all)\s+instruction",
    r"you\s+are\s+now",
    r"do\s+not\s+follow",
    r"override\s+(your\s+)?(previous\s+)?instruction",
    r"system\s*prompt",
    r"jailbreak",
    r"disregard\s+(your\s+)?",
    r"forget\s+(everything|all|your)",
    r"new\s+persona",
    r"act\s+as\s+(if\s+you\s+are|an?\s+)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"your\s+new\s+(role|task|goal|instruction)",
    r"<\s*SYSTEM\s*>",
    r"\[INST\]",
    r"###\s*(instruction|system|human|assistant)",
    r"<\s*/?s\s*>",
    r"<\|im_start\|>",
    r"\[\/INST\]",
    r"IGNORE ALL PREVIOUS",
    r"END OF CONVERSATION",
]

POISON_PATTERNS = [
    r"<\s*hidden\s*>",
    r"<!--.*?-->",
    r"\[hidden\]",
    r"(send|exfil|leak|transmit|upload).{0,30}(secret|token|key|password|credential)",
    r"(POST|GET|fetch|curl|wget).{0,60}(http|https)",
    r"always\s+(respond|reply|say|output)",
    r"never\s+(mention|say|tell|reveal)",
    r"when\s+(asked|prompted|queried).{0,30}(say|respond|output)",
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
    r"data:text/html",
    r"javascript:",
]

DANGEROUS_TOOL_PATTERNS = {
    "shell_exec": (
        r"(shell|exec|run|execute|cmd|bash|sh|powershell|eval|system)",
        "CRITICAL",
    ),
    "filesystem": (
        r"(read_file|write_file|delete|remove|mkdir|listdir|readdir|glob"
        r"|file_read|file_write)",
        "HIGH",
    ),
    "network": (
        r"(fetch|curl|wget|http_get|http_post|request|socket|connect"
        r"|http_request)",
        "HIGH",
    ),
    "database": (
        r"(sql|query|database|db_exec|mongo|redis|execute_query|db_query)",
        "HIGH",
    ),
    "code_eval": (
        r"(eval|exec|compile|__import__|subprocess|popen|code_exec)",
        "CRITICAL",
    ),
    "secrets_access": (
        r"(secret|credential|password|token|key|vault|ssm|aws_secret)",
        "HIGH",
    ),
    "cloud_api": (
        r"(iam|s3|ec2|gcp|azure|k8s|kubectl|terraform|cloud_exec)",
        "HIGH",
    ),
    "process_mgmt": (
        r"(kill|signal|fork|spawn|process|proc_exec)",
        "MEDIUM",
    ),
}

TOKEN_THEFT_PATTERNS = [
    r"(provide|give|send|include|pass).{0,30}(token|credential|password|secret|key|auth)",
    r"(authorization|bearer|api.?key|access.?token)",
    r"(forward|relay|proxy|tunnel|send).{0,30}(to|via|through).{0,30}(http|https|url|endpoint)",
    r"/var/run/secrets",
    r"kubernetes\.io/serviceaccount",
    r"KUBECONFIG|\.kube/config",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"instance-data\.ec2\.internal",
    r"imds",
]

CODE_EXEC_PATTERNS = [
    r"(subprocess|popen|system|exec|eval|compile)\s*\(",
    r"(os\.system|os\.popen|os\.execv)",
    r"(shell\s*=\s*True)",
    r"(bash|sh|zsh|pwsh|cmd\.exe)\s+-c",
    r"(python|node|ruby|perl|php)\s+-[ce]",
    r"`[^`]+`",
    r"\$\([^\)]+\)",
    r"&&\s*(rm|dd|mkfs|wget|curl|nc|socat)",
    r">(>?)\s*/dev/(null|tcp|udp)",
]

RAC_PATTERNS = {
    "reverse_shell": (
        r"(nc|ncat|socat|netcat|bash\s+-i|/dev/tcp|reverse.?shell)",
        "CRITICAL",
    ),
    "port_forward": (
        r"(port.?forward|tunnel|socks|proxy\s+port)",
        "HIGH",
    ),
    "remote_desktop": (
        r"(vnc|rdp|teamviewer|anydesk|screenshare)",
        "HIGH",
    ),
    "c2_beacon": (
        r"(beacon|c2|command.and.control|meterpreter|cobalt.?strike|sliver|havoc)",
        "CRITICAL",
    ),
    "network_scan": (
        r"(nmap|masscan|zmap|shodan|port.?scan|host.?discovery)",
        "HIGH",
    ),
    "data_exfil": (
        r"(exfil|exfiltrat|data.?transfer|upload.{0,20}(s3|ftp|http))",
        "HIGH",
    ),
}

SHADOW_TARGETS = {
    "ls", "cat", "echo", "read", "write", "open", "close", "get", "set",
    "list", "search", "find", "help", "info", "status", "ping", "run",
    "execute", "create", "delete", "update", "fetch", "send", "post",
    "memory_read", "memory_write", "file_read", "file_write",
    "web_search", "browser", "calculator", "send_email", "send_message",
    "think", "plan", "act", "observe", "reflect",
}

# ════════════════════════════════════════════════════════════════
# Logging helpers
# ════════════════════════════════════════════════════════════════


def dbg(msg: str):
    if DEBUG:
        debug_console.print(f"[dim][DBG] {msg}[/dim]")


def vrb(msg: str):
    if VERBOSE or DEBUG:
        console.print(f"  [dim]│ {msg}[/dim]")


# ════════════════════════════════════════════════════════════════
# Data models
# ════════════════════════════════════════════════════════════════


@dataclass
class Finding:
    target: str
    check: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""


@dataclass
class TargetResult:
    url: str
    transport: str = "unknown"
    server_info: dict = field(default_factory=dict)
    tools: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    prompts: list = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str = ""

    def add(
        self,
        check: str,
        severity: str,
        title: str,
        detail: str = "",
        evidence: str = "",
    ) -> Finding:
        f = Finding(self.url, check, severity, title, detail, evidence)
        self.findings.append(f)
        color = SEV_COLOR.get(severity, "white")
        vrb(f"[{color}]{severity}[/{color}] {check} → {title}")
        return f

    def risk_score(self) -> int:
        return sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)


# ════════════════════════════════════════════════════════════════
# JSON-RPC helper
# ════════════════════════════════════════════════════════════════


def _jrpc(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params or {},
    }


# ════════════════════════════════════════════════════════════════
# SSE probe
# ════════════════════════════════════════════════════════════════


def _probe_sse_path(base: str, path: str, timeout: float = 6.0) -> bool:
    url = base + path
    result: list[bool] = [False]
    done = threading.Event()

    def _try():
        try:
            with httpx.Client(
                verify=False, timeout=httpx.Timeout(timeout, connect=4.0)
            ) as c:
                with c.stream(
                    "GET", url, headers={"Accept": "text/event-stream"}
                ) as resp:
                    ct = resp.headers.get("content-type", "")
                    if resp.status_code == 200 and "text/event-stream" in ct:
                        result[0] = True
                    done.set()
                    for _ in zip(resp.iter_bytes(chunk_size=64), range(3)):
                        pass
        except Exception as exc:
            dbg(f"  {path} probe error: {exc}")
        finally:
            done.set()

    t = threading.Thread(target=_try, daemon=True)
    t.start()
    done.wait(timeout=timeout + 1)
    return result[0]


# ════════════════════════════════════════════════════════════════
# MCP Sessions
# ════════════════════════════════════════════════════════════════


class MCPSession:
    def __init__(self, base: str, sse_path: str, timeout: float = 25.0):
        self.base = base
        self.sse_url = base + sse_path
        self.post_url: str = ""
        self.timeout = timeout
        self._req_id = 0
        self._q: queue.Queue[dict] = queue.Queue()
        self._stop = threading.Event()
        self._endpoint_ready = threading.Event()
        self._client = httpx.Client(
            verify=False, timeout=timeout, follow_redirects=True
        )
        self._listener = threading.Thread(
            target=self._listen, daemon=True, name=f"sse-{base}"
        )
        self._listener.start()

    def _listen(self):
        dbg(f"SSE listener starting → {self.sse_url}")
        try:
            with self._client.stream(
                "GET",
                self.sse_url,
                headers={"Accept": "text/event-stream"},
            ) as resp:
                dbg(f"SSE connected, status={resp.status_code}")
                event_type = "message"
                for raw in resp.iter_lines():
                    if self._stop.is_set():
                        break
                    line = raw.strip()
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        if event_type == "endpoint" and data:
                            self.post_url = (
                                data
                                if data.startswith("http")
                                else self.base + data
                            )
                            dbg(f"SSE endpoint → {self.post_url}")
                            self._endpoint_ready.set()
                        elif event_type != "endpoint" and data:
                            try:
                                msg = json.loads(data)
                                dbg(f"SSE←  {json.dumps(msg)[:200]}")
                                self._q.put(msg)
                            except json.JSONDecodeError:
                                pass
                        event_type = "message"
        except Exception as e:
            dbg(f"SSE listener error: {e}")
        finally:
            self._endpoint_ready.set()

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return self._endpoint_ready.wait(timeout=timeout)

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        wait = timeout or self.timeout
        for attempt in range(retries + 1):
            self._req_id += 1
            payload = _jrpc(method, params, self._req_id)
            dbg(
                f"→ POST [{attempt}] {method} id={self._req_id}"
                f" → {self.post_url}"
            )
            try:
                r = self._client.post(
                    self.post_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                dbg(f"  POST status={r.status_code}")
                if r.status_code not in (200, 202, 204):
                    if attempt < retries:
                        time.sleep(0.5)
                        continue
                    return None
            except Exception as e:
                dbg(f"  POST error: {e}")
                if attempt < retries:
                    time.sleep(0.5)
                    continue
                return None

            deadline = time.time() + wait
            pending: list[dict] = []
            while time.time() < deadline:
                try:
                    msg = self._q.get(timeout=0.3)
                    if isinstance(msg, dict) and msg.get("id") == self._req_id:
                        for m in pending:
                            self._q.put(m)
                        dbg(f"← matched id={self._req_id}")
                        return msg
                    pending.append(msg)
                except queue.Empty:
                    pass
            for m in pending:
                self._q.put(m)
            dbg(
                f"  timeout waiting for id={self._req_id} (attempt {attempt})"
            )
            if attempt < retries:
                time.sleep(1.0)
        return None

    def notify(self, method: str, params: dict | None = None):
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        dbg(f"→ notify {method}")
        try:
            self._client.post(
                self.post_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
        except Exception as e:
            dbg(f"  notify error: {e}")

    def raw_get(self, path: str, **kw) -> httpx.Response | None:
        try:
            return self._client.get(urljoin(self.base, path), **kw)
        except Exception:
            return None

    def close(self):
        self._stop.set()
        try:
            self._client.close()
        except Exception:
            pass


class _HTTPSession(MCPSession):
    """Plain HTTP POST fallback (no SSE)."""

    def __init__(self, base: str, post_url: str, timeout: float = 25.0):
        self.base = base
        self.sse_url = ""
        self.post_url = post_url
        self.timeout = timeout
        self._req_id = 0
        self._stop = threading.Event()
        self._client = httpx.Client(
            verify=False, timeout=timeout, follow_redirects=True
        )

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        for attempt in range(retries + 1):
            self._req_id += 1
            dbg(f"→ HTTP POST [{attempt}] {method}")
            try:
                r = self._client.post(
                    self.post_url,
                    json=_jrpc(method, params, self._req_id),
                    headers={"Content-Type": "application/json"},
                    timeout=timeout or self.timeout,
                )
                if r.status_code == 200:
                    data = r.json()
                    dbg(f"← {json.dumps(data)[:200]}")
                    return data
            except Exception as e:
                dbg(f"  HTTP error: {e}")
                if attempt < retries:
                    time.sleep(0.5)
        return None

    def notify(self, method: str, params: dict | None = None):
        try:
            self._client.post(
                self.post_url,
                json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params or {},
                },
                timeout=5,
            )
        except Exception:
            pass

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════
# Transport detection
# ════════════════════════════════════════════════════════════════


def detect_transport(
    url: str, connect_timeout: float = 25.0
) -> MCPSession | None:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    hint = parsed.path.rstrip("/") or None

    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    for p in ([hint] if hint else []) + SSE_PATHS:
        if p is not None and p not in seen_paths:
            seen_paths.add(p)
            ordered_paths.append(p)

    vrb(f"Trying SSE paths: {ordered_paths}")

    for sse_path in ordered_paths:
        dbg(f"  probing SSE {sse_path!r}")
        if not _probe_sse_path(base, sse_path, timeout=6.0):
            dbg(f"  {sse_path!r} → not SSE, skipping")
            continue

        dbg(f"  {sse_path!r} → SSE confirmed, opening persistent session")
        session = MCPSession(base, sse_path, timeout=connect_timeout)

        if session.wait_ready(timeout=12.0) and session.post_url:
            vrb(f"SSE negotiated: {sse_path!r} → {session.post_url}")
            return session

        dbg(f"  No endpoint event on {sse_path!r}, closing")
        session.close()

    vrb("SSE not detected — trying plain HTTP POST fallback")
    client = httpx.Client(verify=False, timeout=8, follow_redirects=True)

    seen_post: set[str] = set()
    ordered_post: list[str] = []
    for p in ([hint] if hint else []) + POST_PATHS:
        if p is not None and p not in seen_post:
            seen_post.add(p)
            ordered_post.append(p)

    for path in ordered_post:
        post_url = base + path
        try:
            r = client.post(
                post_url,
                json=_jrpc("initialize", MCP_INIT_PARAMS),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            dbg(f"  HTTP probe {path!r} → {r.status_code} body={r.text[:80]}")
            is_jsonrpc_body = "jsonrpc" in r.text or "JSON-RPC" in r.text
            is_jsonrpc_error = r.status_code in (400, 422) and (
                is_jsonrpc_body
                or "method" in r.text
                or "error" in r.text.lower()
            )
            if (r.status_code == 200 and is_jsonrpc_body) or is_jsonrpc_error:
                vrb(f"HTTP transport detected: {post_url}")
                client.close()
                return _HTTPSession(base, post_url, timeout=connect_timeout)
        except Exception as e:
            dbg(f"  HTTP probe {path!r} error: {e}")

    for sse_path in ["/sse", ""]:
        for post_path in ["/messages", "/mcp"]:
            post_url = base + post_path
            try:
                r = client.post(
                    post_url,
                    json=_jrpc("initialize", MCP_INIT_PARAMS),
                    headers={"Content-Type": "application/json"},
                    timeout=4,
                )
                if r.status_code in (400, 404, 422):
                    dbg(
                        f"  Heuristic: {post_path} → {r.status_code},"
                        f" retrying with forced SSE on {sse_path!r}"
                    )
                    session = MCPSession(
                        base, sse_path, timeout=connect_timeout
                    )
                    if session.wait_ready(timeout=10.0) and session.post_url:
                        vrb(
                            f"Heuristic SSE match: {sse_path!r}"
                            f" → {session.post_url}"
                        )
                        client.close()
                        return session
                    session.close()
            except Exception:
                pass

    client.close()
    return None


# ════════════════════════════════════════════════════════════════
# Enumeration
# ════════════════════════════════════════════════════════════════


def enumerate_server(session: MCPSession, result: TargetResult):
    t0 = time.time()
    vrb("Sending initialize...")
    resp = session.call("initialize", MCP_INIT_PARAMS, retries=3)

    if not resp or "result" not in resp:
        result.add(
            "init",
            "HIGH",
            "No response to MCP initialize",
            "Server did not respond to initialize handshake",
        )
        result.timings["enumerate"] = time.time() - t0
        return

    r = resp["result"]
    result.server_info = r
    info = r.get("serverInfo", {})
    caps = r.get("capabilities", {})
    vrb(
        f"Server: {info.get('name','?')} v{info.get('version','?')}"
        f" caps={list(caps.keys())}"
    )

    result.add(
        "auth",
        "HIGH",
        "Unauthenticated MCP initialize accepted",
        f"Server '{info.get('name','?')}' v{info.get('version','?')} "
        f"accepted initialize with no credentials",
        evidence=json.dumps(r, indent=2)[:500],
    )

    session.notify("notifications/initialized")
    time.sleep(0.5)

    for attempt in range(3):
        tr = session.call("tools/list", timeout=15, retries=2)
        if tr and "result" in tr:
            result.tools = tr["result"].get("tools", [])
            vrb(f"  → {len(result.tools)} tools")
            break
        vrb(f"  tools/list attempt {attempt+1} failed")
        time.sleep(1)

    rr = session.call("resources/list", timeout=15, retries=2)
    if rr and "result" in rr:
        result.resources = rr["result"].get("resources", [])
        vrb(f"  → {len(result.resources)} resources")

    pr = session.call("prompts/list", timeout=15, retries=2)
    if pr and "result" in pr:
        result.prompts = pr["result"].get("prompts", [])
        vrb(f"  → {len(result.prompts)} prompts")

    result.timings["enumerate"] = time.time() - t0

    if DEBUG:
        for t in result.tools:
            dbg(f"  tool: {t.get('name')} — {t.get('description','')[:80]}")


# ════════════════════════════════════════════════════════════════
# Timing helper
# ════════════════════════════════════════════════════════════════


def _time_check(name: str, result: TargetResult):
    class _T:
        def __enter__(self):
            self.t0 = time.time()
            vrb(f"Check: {name}...")
            return self

        def __exit__(self, *_):
            result.timings[name] = time.time() - self.t0

    return _T()


# ════════════════════════════════════════════════════════════════
# Security checks
# ════════════════════════════════════════════════════════════════


def check_prompt_injection(result: TargetResult):
    with _time_check("prompt_injection", result):

        def _scan(text: str, location: str):
            for pat in INJECTION_PATTERNS:
                if re.search(pat, text, re.IGNORECASE):
                    result.add(
                        "prompt_injection",
                        "CRITICAL",
                        "Prompt injection payload detected",
                        f"Location: {location}",
                        evidence=f"Pattern: {pat}\nText: {text[:300]}",
                    )
                    return

        for tool in result.tools:
            name = tool.get("name", "")
            _scan(tool.get("description", ""), f"tool description: '{name}'")
            _scan(name, f"tool name: '{name}'")
            for prop, pdef in (
                tool.get("inputSchema", {}).get("properties", {}).items()
            ):
                _scan(
                    pdef.get("description", ""),
                    f"tool '{name}' param '{prop}'",
                )

        for r in result.resources:
            _scan(
                r.get("description", ""),
                f"resource '{r.get('uri','')}'",
            )
            _scan(r.get("name", ""), f"resource name '{r.get('uri','')}'")

        for p in result.prompts:
            _scan(
                p.get("description", ""),
                f"prompt '{p.get('name','')}'",
            )
            _scan(p.get("name", ""), "prompt name")


def check_tool_poisoning(result: TargetResult):
    with _time_check("tool_poisoning", result):
        for tool in result.tools:
            name = tool.get("name", "")
            full = tool.get("description", "") + " " + json.dumps(
                tool.get("inputSchema", {})
            )

            for pat in POISON_PATTERNS:
                if re.search(pat, full, re.IGNORECASE | re.DOTALL):
                    result.add(
                        "tool_poisoning",
                        "CRITICAL",
                        f"Tool poisoning indicator in '{name}'",
                        f"Pattern: {pat}",
                        evidence=full[:400],
                    )
                    break

            for ch in tool.get("description", ""):
                if ord(ch) in range(0x200B, 0x2010) or ord(ch) == 0xFEFF:
                    result.add(
                        "tool_poisoning",
                        "CRITICAL",
                        f"Invisible Unicode in tool '{name}'",
                        "Possible hidden instructions via Unicode steganography",
                        evidence=repr(tool["description"][:200]),
                    )
                    break


def check_excessive_permissions(result: TargetResult):
    with _time_check("excessive_permissions", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = tool.get("description", "").lower()
            combined = f"{name} {desc}"

            for category, (pattern, severity) in DANGEROUS_TOOL_PATTERNS.items():
                if re.search(pattern, combined, re.IGNORECASE):
                    result.add(
                        "excessive_permissions",
                        severity,
                        f"Dangerous capability [{category}]: '{tool['name']}'",
                        tool.get("description", "")[:200],
                        evidence=f"Pattern: {pattern}",
                    )

            schema = tool.get("inputSchema", {})
            if schema.get("type") == "object":
                props = schema.get("properties", {})
                if not props and not schema.get("required"):
                    result.add(
                        "excessive_permissions",
                        "MEDIUM",
                        f"Tool '{tool['name']}' has no input schema",
                        "Accepts arbitrary input with no validation",
                    )
                for pname, pdef in props.items():
                    if not pdef.get("type"):
                        result.add(
                            "excessive_permissions",
                            "LOW",
                            f"Untyped param '{pname}' in '{tool['name']}'",
                        )


def check_rug_pull(session: MCPSession, result: TargetResult):
    with _time_check("rug_pull", result):
        vrb("  Rug-pull: fetching tools/list twice...")
        first = session.call("tools/list", timeout=15)
        time.sleep(2)
        second = session.call("tools/list", timeout=15)

        if not first or not second:
            vrb("  Rug-pull: could not get two listings")
            return

        t1 = {t["name"]: t for t in first.get("result", {}).get("tools", [])}
        t2 = {
            t["name"]: t for t in second.get("result", {}).get("tools", [])
        }

        added = set(t2) - set(t1)
        removed = set(t1) - set(t2)

        if added:
            result.add(
                "rug_pull",
                "HIGH",
                f"Rug pull: {len(added)} tool(s) appeared after initial listing",
                f"New: {sorted(added)}",
            )
        if removed:
            result.add(
                "rug_pull",
                "HIGH",
                f"Rug pull: {len(removed)} tool(s) disappeared",
                f"Removed: {sorted(removed)}",
            )

        for name in set(t1) & set(t2):
            if t1[name].get("description") != t2[name].get("description"):
                result.add(
                    "rug_pull",
                    "CRITICAL",
                    f"Rug pull: tool '{name}' description changed between calls",
                    f"Before: {t1[name].get('description','')[:150]}\n"
                    f"After:  {t2[name].get('description','')[:150]}",
                )


def check_tool_shadowing(
    all_results: list[TargetResult], result: TargetResult
):
    with _time_check("tool_shadowing", result):
        my_names = {t["name"].lower() for t in result.tools}

        shadows = my_names & SHADOW_TARGETS
        if shadows:
            result.add(
                "tool_shadowing",
                "HIGH",
                f"Tool shadowing: redefines common name(s): {sorted(shadows)}",
            )

        for other in all_results:
            if other.url == result.url:
                continue
            dupes = my_names & {t["name"].lower() for t in other.tools}
            if dupes:
                result.add(
                    "tool_shadowing",
                    "MEDIUM",
                    f"Name collision with {other.url}: {sorted(dupes)}",
                )


def check_indirect_injection(session: MCPSession, result: TargetResult):
    with _time_check("indirect_injection", result):
        for resource in result.resources:
            uri = resource.get("uri", "")
            vrb(f"  Reading resource: {uri}")
            try:
                resp = session.call(
                    "resources/read", {"uri": uri}, timeout=15
                )
                if not resp or "result" not in resp:
                    continue
                for content in resp["result"].get("contents", []):
                    text = content.get("text", "") or content.get("blob", "")
                    if not text:
                        continue
                    for pat in INJECTION_PATTERNS + POISON_PATTERNS:
                        if re.search(
                            pat, text, re.IGNORECASE | re.DOTALL
                        ):
                            result.add(
                                "indirect_injection",
                                "CRITICAL",
                                f"Indirect prompt injection in resource '{uri}'",
                                f"Pattern: {pat}",
                                evidence=text[:400],
                            )
                            break
                    for u in re.findall(r"https?://[^\s'\"<>]+", text):
                        if any(
                            kw in u
                            for kw in [
                                "webhook",
                                "ngrok",
                                "burp",
                                "requestbin",
                                "pipedream",
                                "canarytokens",
                                "interactsh",
                            ]
                        ):
                            result.add(
                                "indirect_injection",
                                "HIGH",
                                f"Exfiltration URL in resource '{uri}'",
                                evidence=u,
                            )
            except Exception as e:
                dbg(f"  resource read error {uri}: {e}")


def check_token_theft(result: TargetResult):
    with _time_check("token_theft", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + json.dumps(tool.get("inputSchema", {}))
            )

            for pat in TOKEN_THEFT_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    result.add(
                        "token_theft",
                        "CRITICAL",
                        f"Token theft pattern in tool '{name}'",
                        f"Pattern: {pat}",
                        evidence=combined[:300],
                    )
                    break

            for pname in tool.get("inputSchema", {}).get("properties", {}):
                if any(
                    kw in pname.lower()
                    for kw in [
                        "token",
                        "secret",
                        "password",
                        "credential",
                        "key",
                        "auth",
                    ]
                ):
                    result.add(
                        "token_theft",
                        "HIGH",
                        f"Tool '{name}' accepts credential param: '{pname}'",
                    )


def check_code_execution(result: TargetResult):
    with _time_check("code_execution", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + json.dumps(tool.get("inputSchema", {}))
            )

            for pat in CODE_EXEC_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    result.add(
                        "code_execution",
                        "CRITICAL",
                        f"Code execution indicator in tool '{name}'",
                        f"Pattern: {pat}",
                        evidence=combined[:300],
                    )
                    break

            for pname in tool.get("inputSchema", {}).get("properties", {}):
                if any(
                    kw in pname.lower()
                    for kw in [
                        "command",
                        "cmd",
                        "code",
                        "script",
                        "payload",
                        "exec",
                        "query",
                        "expression",
                        "statement",
                    ]
                ):
                    result.add(
                        "code_execution",
                        "HIGH",
                        f"Tool '{name}' has execution-like param: '{pname}'",
                    )


def check_remote_access(result: TargetResult):
    with _time_check("remote_access", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = name + " " + tool.get("description", "")
            for category, (pattern, severity) in RAC_PATTERNS.items():
                if re.search(pattern, combined, re.IGNORECASE):
                    result.add(
                        "remote_access",
                        severity,
                        f"Remote access [{category}]: '{name}'",
                        tool.get("description", "")[:200],
                        evidence=f"Pattern: {pattern}",
                    )


def check_schema_risks(result: TargetResult):
    with _time_check("schema_risks", result):
        for tool in result.tools:
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            name = tool.get("name", "")
            for pname, pdef in props.items():
                if "command" in pname.lower():
                    result.add(
                        "schema_risk",
                        "CRITICAL",
                        f"Command parameter '{pname}' in tool '{name}'",
                    )
                if pdef.get("type") == "string" and not pdef.get("maxLength"):
                    result.add(
                        "schema_risk",
                        "MEDIUM",
                        f"Unbounded string param '{pname}' in tool '{name}'",
                        "No maxLength constraint — injection surface",
                    )
                if pdef.get("type") == "object" and not pdef.get(
                    "properties"
                ):
                    result.add(
                        "schema_risk",
                        "MEDIUM",
                        f"Freeform object param '{pname}' in tool '{name}'",
                        "Accepts arbitrary nested structure",
                    )


def check_multi_vector(result: TargetResult):
    with _time_check("multi_vector", result):
        checks_hit = {f.check for f in result.findings}
        dangerous = {
            "prompt_injection",
            "tool_poisoning",
            "token_theft",
            "code_execution",
            "remote_access",
            "indirect_injection",
        }
        hit = checks_hit & dangerous
        if len(hit) >= 2:
            result.add(
                "multi_vector",
                "CRITICAL",
                f"Multi-vector attack: {len(hit)} categories active",
                f"Vectors: {sorted(hit)}",
            )
        if (
            {"prompt_injection", "indirect_injection", "tool_poisoning"}
            & checks_hit
            and {"token_theft", "remote_access"} & checks_hit
        ):
            result.add(
                "multi_vector",
                "CRITICAL",
                "Attack chain: injection + exfiltration vector present",
            )


def check_attack_chains(result: TargetResult):
    with _time_check("attack_chains", result):
        checks = {f.check for f in result.findings}
        for a, b in ATTACK_CHAIN_PATTERNS:
            if a in checks and b in checks:
                result.add(
                    "attack_chain",
                    "CRITICAL",
                    f"Attack chain: {a} → {b}",
                    "Two linked vulnerability classes detected in sequence",
                )


def check_protocol_robustness(session: MCPSession, result: TargetResult):
    with _time_check("protocol_robustness", result):
        resp = session.call("nonexistent/method/xyz", timeout=8)
        if resp and "error" not in resp:
            result.add(
                "protocol_robustness",
                "MEDIUM",
                "Server returned success for unknown JSON-RPC method",
                "Should return -32601 Method Not Found",
            )
        resp = session.call("tools/call", timeout=8)
        if resp and "result" in resp:
            result.add(
                "protocol_robustness",
                "MEDIUM",
                "Server returned result for tools/call with no params",
            )


def check_sse_security(base: str, sse_path: str, result: TargetResult):
    with _time_check("sse_security", result):
        client = httpx.Client(verify=False, timeout=8)
        try:
            with client.stream(
                "GET",
                base + sse_path,
                headers={"Accept": "text/event-stream"},
                timeout=httpx.Timeout(6.0, connect=3.0),
            ) as r:
                ct = r.headers.get("content-type", "")
                if "text/event-stream" in ct:
                    result.add(
                        "sse_security",
                        "HIGH",
                        "SSE stream accessible without authentication",
                        f"GET {sse_path} returned event-stream with no credentials",
                    )
        except Exception as e:
            dbg(f"  SSE unauth check error: {e}")

        try:
            with client.stream(
                "GET",
                base + sse_path,
                headers={
                    "Accept": "text/event-stream",
                    "Origin": "https://evil.example.com",
                },
                timeout=httpx.Timeout(6.0, connect=3.0),
            ) as r:
                acao = r.headers.get("access-control-allow-origin", "")
                if acao in ("*", "https://evil.example.com"):
                    result.add(
                        "sse_security",
                        "HIGH",
                        f"SSE CORS misconfiguration: ACAO={acao}",
                    )
        except Exception as e:
            dbg(f"  CORS check error: {e}")

        try:
            r = client.post(
                base + "/messages",
                json=_jrpc("initialize", MCP_INIT_PARAMS),
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://evil.example.com",
                },
                follow_redirects=False,
                timeout=5,
            )
            if r.status_code in (200, 202, 307):
                result.add(
                    "sse_security",
                    "MEDIUM",
                    "MCP messages endpoint accepts cross-origin POST",
                    f"Status {r.status_code} with evil Origin header",
                )
        except Exception as e:
            dbg(f"  CSRF check error: {e}")

        client.close()


def detect_cross_shadowing(results: list[TargetResult]):
    tool_map: dict[str, list[str]] = defaultdict(list)
    for r in results:
        for t in r.tools:
            tool_map[t["name"]].append(r.url)
    for name, servers in tool_map.items():
        if len(servers) > 1:
            for r in results:
                if r.url in servers:
                    r.add(
                        "cross_shadowing",
                        "MEDIUM",
                        f"Tool '{name}' exists on {len(servers)} servers",
                        f"Servers: {servers}",
                    )


# ════════════════════════════════════════════════════════════════
# K8s checks
# ════════════════════════════════════════════════════════════════


def _k8s_get(path: str, token: str) -> dict | None:
    import ssl
    import urllib.request

    req = urllib.request.Request(
        f"https://kubernetes.default{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _scan_helm(sname: str, obj: Any, path: str):
    if isinstance(obj, dict):
        for k, v in obj.items():
            np = f"{path}.{k}" if path else k
            if isinstance(v, str):
                if "PRIVATE KEY" in v:
                    GLOBAL_K8S_FINDINGS.append(
                        Finding(
                            target="k8s",
                            check="helm_secrets",
                            severity="CRITICAL",
                            title=f"Private key in Helm values: {sname} → {np}",
                        )
                    )
                elif any(
                    s in k.lower()
                    for s in ["password", "secret", "token", "apikey"]
                ):
                    GLOBAL_K8S_FINDINGS.append(
                        Finding(
                            target="k8s",
                            check="helm_secrets",
                            severity="HIGH",
                            title=f"Credential in Helm values: {sname} → {np}",
                        )
                    )
            else:
                _scan_helm(sname, v, np)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _scan_helm(sname, item, f"{path}[{i}]")


def run_k8s_checks(namespace: str):
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if not os.path.exists(token_path):
        console.print("[dim]  No SA token — skipping K8s checks[/dim]")
        return

    with open(token_path) as f:
        token = f.read().strip()

    console.print(f"\n[bold]── K8s Internal Checks (ns={namespace}) ──[/bold]")

    for name, path in [
        ("secrets", f"/api/v1/namespaces/{namespace}/secrets"),
        ("configmaps", f"/api/v1/namespaces/{namespace}/configmaps"),
        ("pods", f"/api/v1/namespaces/{namespace}/pods"),
    ]:
        data = _k8s_get(path, token)
        if data:
            count = len(data.get("items", []))
            sev = "HIGH" if name == "secrets" else "INFO"
            GLOBAL_K8S_FINDINGS.append(
                Finding(
                    target="k8s",
                    check="rbac",
                    severity=sev,
                    title=f"SA can read {name} ({count} items) in {namespace}",
                )
            )

    secrets_data = _k8s_get(
        f"/api/v1/namespaces/{namespace}/secrets", token
    )
    if secrets_data:
        for secret in secrets_data.get("items", []):
            if secret.get("type") != "helm.sh/release.v1":
                continue
            sname = secret["metadata"]["name"]
            b64 = secret.get("data", {}).get("release", "")
            if not b64:
                continue
            try:
                decoded = gzip.decompress(
                    base64.b64decode(base64.b64decode(b64))
                )
                _scan_helm(
                    sname,
                    json.loads(decoded).get("chart", {}).get("values", {}),
                    "",
                )
            except Exception:
                pass


# ════════════════════════════════════════════════════════════════
# Per-target orchestrator
# ════════════════════════════════════════════════════════════════


def scan_target(
    url: str,
    all_results: list[TargetResult],
    args: argparse.Namespace,
) -> TargetResult:
    result = TargetResult(url=url)
    t_start = time.time()
    console.print(f"\n[bold cyan]▶ {url}[/bold cyan]")

    session = detect_transport(url, connect_timeout=args.timeout)

    if not session:
        console.print(f"  [red]✗[/red] No MCP transport found on {url}")
        result.transport = "none"
        result.add(
            "transport",
            "HIGH",
            "No MCP endpoint found",
            "Tried SSE + HTTP POST on common paths",
        )
        result.timings["total"] = time.time() - t_start
        return result

    transport_label = (
        "SSE"
        if isinstance(session, MCPSession) and session.sse_url
        else "HTTP"
    )
    result.transport = transport_label
    console.print(
        f"  [green]✓[/green] Transport={transport_label}"
        f"  post_url={session.post_url}"
    )

    if session.sse_url:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        sse_path = urlparse(session.sse_url).path
        check_sse_security(base, sse_path, result)

    enumerate_server(session, result)
    console.print(
        f"  [dim]Tools={len(result.tools)} "
        f"Resources={len(result.resources)} "
        f"Prompts={len(result.prompts)}[/dim]"
    )

    if result.tools and VERBOSE:
        for t in result.tools:
            vrb(f"  tool: {t.get('name')} — {t.get('description','')[:60]}")

    check_prompt_injection(result)
    check_tool_poisoning(result)
    check_excessive_permissions(result)
    check_rug_pull(session, result)
    check_tool_shadowing(all_results, result)
    check_indirect_injection(session, result)
    check_token_theft(result)
    check_code_execution(result)
    check_remote_access(result)
    check_schema_risks(result)
    check_protocol_robustness(session, result)
    check_multi_vector(result)
    check_attack_chains(result)

    session.close()
    result.timings["total"] = time.time() - t_start
    console.print(
        f"  [dim]Done in {result.timings['total']:.1f}s  "
        f"findings={len(result.findings)}  score={result.risk_score()}[/dim]"
    )
    return result


# ════════════════════════════════════════════════════════════════
# Parallel runner
# ════════════════════════════════════════════════════════════════


def run_parallel(
    urls: list[str], args: argparse.Namespace
) -> list[TargetResult]:
    results: list[TargetResult] = []
    lock = threading.Lock()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    task = progress.add_task(
        f"Scanning {len(urls)} target(s)", total=len(urls)
    )

    with progress:

        def worker(url: str):
            with lock:
                snapshot = list(results)
            r = scan_target(url, snapshot, args)
            with lock:
                results.append(r)
            progress.advance(task)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.workers
        ) as ex:
            futures = [ex.submit(worker, u) for u in urls]
            concurrent.futures.wait(futures)

    return results


# ════════════════════════════════════════════════════════════════
# Reporting
# ════════════════════════════════════════════════════════════════


def print_report(results: list[TargetResult]):
    console.print("\n")
    console.rule("[bold]MCP AUDIT v4.1 — REPORT[/bold]")

    all_findings = (
        [f for r in results for f in r.findings] + GLOBAL_K8S_FINDINGS
    )

    if not all_findings:
        console.print("[green]  No vulnerabilities found.[/green]")
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f = sorted(
        all_findings, key=lambda f: sev_order.get(f.severity, 5)
    )

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Target", style="cyan", no_wrap=True)
    table.add_column("Check", style="white")
    table.add_column("Sev", style="bold", no_wrap=True, width=8)
    table.add_column("Finding", style="white")

    for f in sorted_f:
        color = SEV_COLOR.get(f.severity, "white")
        table.add_row(
            f.target.replace("http://", ""),
            f.check,
            Text(f.severity, style=color),
            f.title,
        )
    console.print(table)

    console.print("\n[bold]Per-Target Summary[/bold]")
    ranked = sorted(results, key=lambda r: r.risk_score(), reverse=True)
    pt = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    pt.add_column("Target", style="cyan")
    pt.add_column("Transport")
    pt.add_column("Tools", justify="right")
    pt.add_column("Findings", justify="right")
    pt.add_column("Score", justify="right", style="bold")
    pt.add_column("Time", justify="right")

    for r in ranked:
        score = r.risk_score()
        color = (
            "bold red"
            if score >= 20
            else "red"
            if score >= 10
            else "yellow"
            if score >= 5
            else "green"
        )
        pt.add_row(
            r.url.replace("http://", ""),
            r.transport,
            str(len(r.tools)),
            str(len(r.findings)),
            Text(str(score), style=color),
            f"{r.timings.get('total', 0):.1f}s",
        )
    console.print(pt)

    if VERBOSE and results:
        console.print("\n[bold]Check Timing Breakdown[/bold]")
        for r in ranked[:3]:
            console.print(f"  [cyan]{r.url}[/cyan]")
            for check, elapsed in sorted(
                r.timings.items(), key=lambda x: x[1], reverse=True
            ):
                bar = "█" * int(elapsed * 10)
                console.print(f"    {check:<25} {elapsed:.2f}s {bar}")

    counts = Counter(f.severity for f in all_findings)
    console.print(
        f"\n  [bold red]CRITICAL: {counts['CRITICAL']}[/bold red]  |  "
        f"[red]HIGH: {counts['HIGH']}[/red]  |  "
        f"[yellow]MEDIUM: {counts['MEDIUM']}[/yellow]  |  "
        f"[cyan]LOW: {counts['LOW']}[/cyan]"
    )

    chain_findings = [f for f in all_findings if f.check == "attack_chain"]
    if chain_findings:
        console.print("\n[bold red]Attack Chains Detected:[/bold red]")
        for f in chain_findings:
            console.print(
                f"  [bold red]⚠[/bold red]  {f.title} ({f.target})"
            )


def write_json(results: list[TargetResult], path: str):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "severity_counts": dict(
                Counter(
                    f.severity for r in results for f in r.findings
                )
            ),
        },
        "targets": [
            {
                "url": r.url,
                "transport": r.transport,
                "risk_score": r.risk_score(),
                "tools": [t.get("name") for t in r.tools],
                "timings": r.timings,
                "findings": [
                    {
                        "check": f.check,
                        "severity": f.severity,
                        "title": f.title,
                        "detail": f.detail,
                        "evidence": f.evidence,
                    }
                    for f in r.findings
                ],
            }
            for r in results
        ],
        "k8s_findings": [
            {
                "check": f.check,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in GLOBAL_K8S_FINDINGS
        ],
    }
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    console.print(f"\n[green]JSON report written → {path}[/green]")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════


def expand_port_range(spec: str) -> list[str]:
    m = re.match(r"^(.+):(\d+)-(\d+)$", spec)
    if not m:
        raise ValueError(f"Invalid port range spec: {spec!r}")
    host, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    if end < start:
        raise ValueError(f"End port {end} < start port {start}")
    return [f"http://{host}:{p}" for p in range(start, end + 1)]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcp-audit v4.1 — MCP Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--targets",
        nargs="+",
        metavar="URL",
        help="One or more MCP target URLs",
    )
    p.add_argument(
        "--port-range",
        metavar="HOST:START-END",
        help="Scan a port range, e.g. localhost:9001-9010",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=25.0,
        metavar="SEC",
        help="Per-target connection timeout (default: 25)",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=4,
        metavar="N",
        help="Parallel scan workers (default: 4)",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (very noisy)",
    )
    p.add_argument(
        "--json",
        metavar="FILE",
        dest="json_out",
        help="Write JSON report to FILE",
    )
    p.add_argument(
        "--k8s-namespace",
        metavar="NS",
        default="default",
        help="Kubernetes namespace for internal checks (default: default)",
    )
    p.add_argument(
        "--no-k8s",
        action="store_true",
        help="Skip Kubernetes internal checks",
    )
    return p.parse_args()


def main():
    global VERBOSE, DEBUG

    args = parse_args()
    VERBOSE = args.verbose
    DEBUG = args.debug

    # Build URL list
    urls: list[str] = []

    if args.targets:
        urls.extend(args.targets)

    if args.port_range:
        try:
            urls.extend(expand_port_range(args.port_range))
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)

    if not urls:
        console.print(
            "[red]Error: specify --targets or --port-range[/red]"
        )
        sys.exit(1)

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    urls = deduped

    console.print(
        Panel(
            f"[bold cyan]mcp-audit v4.1[/bold cyan]\n"
            f"Targets : {len(urls)}\n"
            f"Workers : {args.workers}\n"
            f"Timeout : {args.timeout}s\n"
            f"Verbose : {VERBOSE}  Debug: {DEBUG}\n"
            f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="MCP Security Scanner",
            border_style="cyan",
        )
    )

    # Optional K8s checks (runs locally inside a pod)
    if not args.no_k8s:
        run_k8s_checks(args.k8s_namespace)

    # Run scans
    if len(urls) == 1:
        results = [scan_target(urls[0], [], args)]
    else:
        results = run_parallel(urls, args)

    # Cross-target analysis
    detect_cross_shadowing(results)

    # Report
    print_report(results)

    if args.json_out:
        write_json(results, args.json_out)

    # Exit code: 1 if any CRITICAL or HIGH findings
    all_findings = [f for r in results for f in r.findings]
    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
