#!/usr/bin/env python3
"""
mcp-audit v2: Universal MCP Security Scanner ..(beta)..
============================================
Covers DVMCP challenge categories + K8s/infra checks.

Supports:
  - HTTP + SSE MCP transports (auto-detected)
  - Multiple targets in parallel
  - Detection-only mode (no active exploitation)

Install deps:
    pip install httpx rich "pyjwt[crypto]"

Usage:
    python3 mcp_audit.py \
        --targets http://localhost:2266 \
        --port-range localhost:9001-9010 \
        --workers 5 \
        --json dvmcp_report.json
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import queue
import re
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

console = Console()

SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Data classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    target:   str
    check:    str
    severity: str
    title:    str
    detail:   str = ""
    evidence: str = ""

@dataclass
class TargetResult:
    url:         str
    transport:   str  = "unknown"
    server_info: dict = field(default_factory=dict)
    tools:       list = field(default_factory=list)
    resources:   list = field(default_factory=list)
    prompts:     list = field(default_factory=list)
    findings:    list = field(default_factory=list)

    def add(self, check: str, severity: str, title: str,
            detail: str = "", evidence: str = ""):
        self.findings.append(Finding(
            target=self.url, check=check, severity=severity,
            title=title, detail=detail, evidence=evidence,
        ))

GLOBAL_K8S_FINDINGS: list[Finding] = []

# ═══════════════════════════════════════════════════════════════════════════════
#  Transport — SSE session-based MCP
# ═══════════════════════════════════════════════════════════════════════════════

MCP_INIT_PARAMS = {
    "protocolVersion": "2024-11-05",
    "capabilities":   {},
    "clientInfo":     {"name": "mcp-audit", "version": "2.0"},
}

SSE_PATHS  = ["/sse", "/mcp/sse", "/v1/sse", "/stream", "/events", ""]
POST_PATHS = ["/mcp", "/rpc", "/jsonrpc", "/v1/mcp", ""]


def _jrpc(method: str, params: dict | None = None, req_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "method": method, "params": params or {}}


class MCPSession:
    """
    SSE-based MCP session.

    Protocol:
      1. GET /sse  →  server emits:
             event: endpoint
             data: /messages/?session_id=<uuid>
      2. POST /messages/?session_id=<uuid>  →  JSON-RPC request
      3. Response arrives on the SSE stream as a JSON data event
         matching the request id.
    """

    def __init__(self, base: str, sse_path: str, post_url: str,
                 timeout: float = 20.0):
        self.base     = base
        self.sse_url  = base + sse_path
        self.post_url = post_url          # already includes session_id
        self.timeout  = timeout
        self._req_id  = 0
        self._q: queue.Queue[dict] = queue.Queue()
        self._stop    = threading.Event()
        self._client  = httpx.Client(verify=False, timeout=timeout,
                                     follow_redirects=True)
        self._listener = threading.Thread(target=self._listen, daemon=True)
        self._listener.start()
        time.sleep(0.2)   # let listener settle

    # ── SSE listener ──────────────────────────────────────────────────────────

    def _listen(self):
        try:
            with self._client.stream(
                "GET", self.sse_url,
                headers={"Accept": "text/event-stream"},
            ) as resp:
                event_type = "message"
                for raw_line in resp.iter_lines():
                    if self._stop.is_set():
                        break
                    line = raw_line.strip()
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        if event_type != "endpoint" and data:
                            try:
                                self._q.put(json.loads(data))
                            except json.JSONDecodeError:
                                pass
                        event_type = "message"
        except Exception:
            pass

    # ── JSON-RPC call ─────────────────────────────────────────────────────────

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def call(self, method: str, params: dict | None = None,
             timeout: float | None = None) -> dict | None:
        req_id  = self._next_id()
        payload = _jrpc(method, params, req_id)
        wait    = timeout or self.timeout

        try:
            r = self._client.post(
                self.post_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            # 202 Accepted is normal for SSE-based MCP
            if r.status_code not in (200, 202, 204):
                return None
        except Exception:
            return None

        # Wait for matching response on SSE stream
        deadline = time.time() + wait
        pending: list[dict] = []
        while time.time() < deadline:
            try:
                msg = self._q.get(timeout=0.3)
                if isinstance(msg, dict) and msg.get("id") == req_id:
                    # Re-queue anything we skipped
                    for m in pending:
                        self._q.put(m)
                    return msg
                pending.append(msg)
            except queue.Empty:
                pass

        for m in pending:
            self._q.put(m)
        return None

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


# ── Transport detection ───────────────────────────────────────────────────────

def _get_session_url(base: str, sse_path: str,
                     client: httpx.Client) -> str | None:
    """
    Open SSE stream, read the first `endpoint` event, return the POST URL.
    Returns None if no endpoint event arrives within 5 s.
    """
    result: list[str] = []
    done   = threading.Event()

    def _read():
        try:
            with client.stream(
                "GET", base + sse_path,
                headers={"Accept": "text/event-stream"},
                timeout=8,
            ) as resp:
                if resp.status_code != 200:
                    done.set()
                    return
                ct = resp.headers.get("content-type", "")
                if "text/event-stream" not in ct:
                    done.set()
                    return
                event_type = "message"
                for raw in resp.iter_lines():
                    line = raw.strip()
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:") and event_type == "endpoint":
                        data = line[5:].strip()
                        # data is a path like /messages/?session_id=...
                        full = data if data.startswith("http") \
                               else base + data
                        result.append(full)
                        done.set()
                        return
                    if done.is_set():
                        return
        except Exception:
            done.set()

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    done.wait(timeout=6)
    return result[0] if result else None


def detect_transport(url: str) -> MCPSession | None:
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    hint   = parsed.path.rstrip("/") or None   # e.g. "/sse" if user passed it

    client = httpx.Client(verify=False, timeout=8, follow_redirects=True)

    paths = ([hint] if hint else []) + \
            [p for p in SSE_PATHS if p != hint]

    for sse_path in paths:
        post_url = _get_session_url(base, sse_path, client)
        if post_url:
            client.close()
            return MCPSession(base, sse_path, post_url)

    # ── Fallback: plain HTTP POST (no SSE) ───────────────────────────────────
    for path in POST_PATHS:
        post_url = base + path
        try:
            r = client.post(
                post_url,
                json=_jrpc("initialize", MCP_INIT_PARAMS),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if r.status_code in (200, 400, 422) and "jsonrpc" in r.text:
                client.close()
                # Wrap in a thin shim that reuses the same interface
                return _HTTPSession(base, post_url)
        except Exception:
            continue

    client.close()
    return None


class _HTTPSession(MCPSession):
    """Plain HTTP POST fallback (no SSE)."""

    def __init__(self, base: str, post_url: str, timeout: float = 20.0):
        # Don't call super().__init__ — no SSE thread needed
        self.base     = base
        self.sse_url  = ""
        self.post_url = post_url
        self.timeout  = timeout
        self._req_id  = 0
        self._stop    = threading.Event()
        self._client  = httpx.Client(verify=False, timeout=timeout,
                                     follow_redirects=True)

    def call(self, method: str, params: dict | None = None,
             timeout: float | None = None) -> dict | None:
        self._req_id += 1
        try:
            r = self._client.post(
                self.post_url,
                json=_jrpc(method, params, self._req_id),
                headers={"Content-Type": "application/json"},
                timeout=timeout or self.timeout,
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  Enumeration
# ═══════════════════════════════════════════════════════════════════════════════

def enumerate_server(session: MCPSession, result: TargetResult):
    resp = session.call("initialize", MCP_INIT_PARAMS)
    if not resp or "result" not in resp:
        result.add("init", "HIGH",
                   "No response to MCP initialize",
                   "Server did not respond to initialize handshake")
        return

    r = resp["result"]
    result.server_info = r
    info = r.get("serverInfo", {})
    caps = r.get("capabilities", {})

    result.add("auth", "HIGH",
               "Unauthenticated MCP initialize accepted",
               f"Server '{info.get('name','?')}' v{info.get('version','?')} "
               f"accepted initialize with no credentials",
               evidence=json.dumps(r, indent=2)[:500])

    # Notify server we're initialized
    session.call("notifications/initialized", {})

    # Tools
    tr = session.call("tools/list", timeout=15)
    if tr and "result" in tr:
        result.tools = tr["result"].get("tools", [])

    # Resources
    rr = session.call("resources/list", timeout=15)
    if rr and "result" in rr:
        result.resources = rr["result"].get("resources", [])

    # Prompts
    pr = session.call("prompts/list", timeout=15)
    if pr and "result" in pr:
        result.prompts = pr["result"].get("prompts", [])


# ═══════════════════════════════════════════════════════════════════════════════
#  Security checks
# ═══════════════════════════════════════════════════════════════════════════════

# ── Patterns ──────────────────────────────────────────────────────────────────

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
]

DANGEROUS_TOOL_PATTERNS = {
    "shell_exec":     (r"(shell|exec|run|execute|cmd|bash|sh|powershell|eval)",        "CRITICAL"),
    "filesystem":     (r"(read_file|write_file|delete|remove|mkdir|listdir|readdir|glob)", "HIGH"),
    "network":        (r"(fetch|curl|wget|http_get|http_post|request|socket|connect)",  "HIGH"),
    "database":       (r"(sql|query|database|db_exec|mongo|redis|execute_query)",       "HIGH"),
    "code_eval":      (r"(eval|exec|compile|__import__|subprocess|popen)",              "CRITICAL"),
    "secrets_access": (r"(secret|credential|password|token|key|vault|ssm|aws)",         "HIGH"),
    "cloud_api":      (r"(iam|s3|ec2|gcp|azure|k8s|kubectl|terraform)",                "HIGH"),
    "process_mgmt":   (r"(kill|signal|fork|spawn|process)",                             "MEDIUM"),
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
]

RAC_PATTERNS = {
    "reverse_shell":  (r"(nc|ncat|socat|netcat|bash\s+-i|/dev/tcp)",                   "CRITICAL"),
    "port_forward":   (r"(port.?forward|tunnel|socks|proxy\s+port)",                    "HIGH"),
    "remote_desktop": (r"(vnc|rdp|teamviewer|anydesk|screenshare)",                     "HIGH"),
    "c2_beacon":      (r"(beacon|c2|command.and.control|meterpreter|cobalt.?strike)",   "CRITICAL"),
    "network_scan":   (r"(nmap|masscan|zmap|shodan|port.?scan|host.?discovery)",        "HIGH"),
    "data_exfil":     (r"(exfil|exfiltrat|data.?transfer|upload.{0,20}(s3|ftp|http))", "HIGH"),
}

SHADOW_TARGETS = {
    "ls", "cat", "echo", "read", "write", "open", "close", "get", "set",
    "list", "search", "find", "help", "info", "status", "ping", "run",
    "execute", "create", "delete", "update", "fetch", "send", "post",
    "memory_read", "memory_write", "file_read", "file_write",
    "web_search", "browser", "calculator", "send_email", "send_message",
    "think", "plan", "act", "observe", "reflect",
}

# ── Check 1 & 6: Prompt injection ─────────────────────────────────────────────

def check_prompt_injection(result: TargetResult):
    def _scan(text: str, location: str):
        for pat in INJECTION_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                result.add("prompt_injection", "CRITICAL",
                           "Prompt injection payload detected",
                           f"Location: {location}",
                           evidence=f"Pattern: {pat}\nText: {text[:300]}")
                return

    for tool in result.tools:
        name = tool.get("name", "")
        _scan(tool.get("description", ""), f"tool description: '{name}'")
        _scan(name, f"tool name: '{name}'")
        for prop, pdef in tool.get("inputSchema", {}).get("properties", {}).items():
            _scan(pdef.get("description", ""),
                  f"tool '{name}' param '{prop}'")

    for r in result.resources:
        _scan(r.get("description", ""), f"resource '{r.get('uri','')}'")
        _scan(r.get("name", ""),        f"resource name '{r.get('uri','')}'")

    for p in result.prompts:
        _scan(p.get("description", ""), f"prompt '{p.get('name','')}'")
        _scan(p.get("name", ""),        f"prompt name")


# ── Check 2: Tool poisoning ───────────────────────────────────────────────────

def check_tool_poisoning(result: TargetResult):
    for tool in result.tools:
        name     = tool.get("name", "")
        full     = tool.get("description", "") + " " + \
                   json.dumps(tool.get("inputSchema", {}))

        for pat in POISON_PATTERNS:
            if re.search(pat, full, re.IGNORECASE | re.DOTALL):
                result.add("tool_poisoning", "CRITICAL",
                           f"Tool poisoning indicator in '{name}'",
                           f"Pattern: {pat}",
                           evidence=full[:400])
                break

        # Unicode invisible chars
        for ch in tool.get("description", ""):
            if ord(ch) in range(0x200B, 0x2010) or ord(ch) == 0xFEFF:
                result.add("tool_poisoning", "CRITICAL",
                           f"Invisible Unicode in tool '{name}'",
                           "Possible hidden instructions via Unicode steganography",
                           evidence=repr(tool["description"][:200]))
                break


# ── Check 3: Excessive permissions ────────────────────────────────────────────

def check_excessive_permissions(result: TargetResult):
    for tool in result.tools:
        name     = tool.get("name", "").lower()
        desc     = tool.get("description", "").lower()
        combined = f"{name} {desc}"

        for category, (pattern, severity) in DANGEROUS_TOOL_PATTERNS.items():
            if re.search(pattern, combined, re.IGNORECASE):
                result.add("excessive_permissions", severity,
                           f"Dangerous capability [{category}]: '{tool['name']}'",
                           tool.get("description", "")[:200],
                           evidence=f"Pattern: {pattern}")

        schema = tool.get("inputSchema", {})
        if schema.get("type") == "object":
            props = schema.get("properties", {})
            if not props and not schema.get("required"):
                result.add("excessive_permissions", "MEDIUM",
                           f"Tool '{tool['name']}' has no input schema",
                           "Accepts arbitrary input with no validation")
            for pname, pdef in props.items():
                if not pdef.get("type"):
                    result.add("excessive_permissions", "LOW",
                               f"Untyped param '{pname}' in '{tool['name']}'")


# ── Check 4: Rug pull ─────────────────────────────────────────────────────────

def check_rug_pull(session: MCPSession, result: TargetResult):
    first  = session.call("tools/list", timeout=15)
    time.sleep(2)
    second = session.call("tools/list", timeout=15)

    if not first or not second:
        return

    t1 = {t["name"]: t for t in first.get("result",  {}).get("tools", [])}
    t2 = {t["name"]: t for t in second.get("result", {}).get("tools", [])}

    added   = set(t2) - set(t1)
    removed = set(t1) - set(t2)

    if added:
        result.add("rug_pull", "HIGH",
                   f"Rug pull: {len(added)} tool(s) appeared after initial listing",
                   f"New: {sorted(added)}")
    if removed:
        result.add("rug_pull", "HIGH",
                   f"Rug pull: {len(removed)} tool(s) disappeared",
                   f"Removed: {sorted(removed)}")

    for name in set(t1) & set(t2):
        if t1[name].get("description") != t2[name].get("description"):
            result.add("rug_pull", "CRITICAL",
                       f"Rug pull: tool '{name}' description changed between calls",
                       f"Before: {t1[name].get('description','')[:150]}\n"
                       f"After:  {t2[name].get('description','')[:150]}")


# ── Check 5: Tool shadowing ───────────────────────────────────────────────────

def check_tool_shadowing(all_results: list[TargetResult],
                         result: TargetResult):
    my_names = {t["name"].lower() for t in result.tools}

    shadows = my_names & SHADOW_TARGETS
    if shadows:
        result.add("tool_shadowing", "HIGH",
                   f"Tool shadowing: redefines common name(s): {sorted(shadows)}")

    for other in all_results:
        if other.url == result.url:
            continue
        dupes = my_names & {t["name"].lower() for t in other.tools}
        if dupes:
            result.add("tool_shadowing", "MEDIUM",
                       f"Name collision with {other.url}: {sorted(dupes)}")


# ── Check 6: Indirect injection via resource content ─────────────────────────

def check_indirect_injection(session: MCPSession, result: TargetResult):
    for resource in result.resources:
        uri = resource.get("uri", "")
        try:
            resp = session.call("resources/read", {"uri": uri}, timeout=15)
            if not resp or "result" not in resp:
                continue
            for content in resp["result"].get("contents", []):
                text = content.get("text", "") or content.get("blob", "")
                if not text:
                    continue
                for pat in INJECTION_PATTERNS + POISON_PATTERNS:
                    if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                        result.add("indirect_injection", "CRITICAL",
                                   f"Indirect prompt injection in resource '{uri}'",
                                   f"Pattern: {pat}",
                                   evidence=text[:400])
                        break
                # Exfil URLs
                for u in re.findall(r'https?://[^\s\'"<>]+', text):
                    if any(kw in u for kw in [
                        "webhook", "ngrok", "burp", "requestbin",
                        "pipedream", "canarytokens", "interactsh",
                    ]):
                        result.add("indirect_injection", "HIGH",
                                   f"Exfiltration URL in resource '{uri}'",
                                   evidence=u)
        except Exception:
            continue


# ── Check 7: Token theft ──────────────────────────────────────────────────────

def check_token_theft(result: TargetResult):
    for tool in result.tools:
        name     = tool.get("name", "")
        combined = name + " " + tool.get("description", "") + " " + \
                   json.dumps(tool.get("inputSchema", {}))

        for pat in TOKEN_THEFT_PATTERNS:
            if re.search(pat, combined, re.IGNORECASE):
                result.add("token_theft", "CRITICAL",
                           f"Token theft pattern in tool '{name}'",
                           f"Pattern: {pat}",
                           evidence=combined[:300])
                break

        for pname in tool.get("inputSchema", {}).get("properties", {}):
            if any(kw in pname.lower() for kw in
                   ["token", "secret", "password", "credential", "key", "auth"]):
                result.add("token_theft", "HIGH",
                           f"Tool '{name}' accepts credential param: '{pname}'")


# ── Check 8: Code execution ───────────────────────────────────────────────────

def check_code_execution(result: TargetResult):
    for tool in result.tools:
        name     = tool.get("name", "")
        combined = name + " " + tool.get("description", "") + " " + \
                   json.dumps(tool.get("inputSchema", {}))

        for pat in CODE_EXEC_PATTERNS:
            if re.search(pat, combined, re.IGNORECASE):
                result.add("code_execution", "CRITICAL",
                           f"Code execution indicator in tool '{name}'",
                           f"Pattern: {pat}",
                           evidence=combined[:300])
                break

        for pname in tool.get("inputSchema", {}).get("properties", {}):
            if any(kw in pname.lower() for kw in
                   ["command", "cmd", "code", "script", "payload",
                    "exec", "query", "expression", "statement"]):
                result.add("code_execution", "HIGH",
                           f"Tool '{name}' has execution-like param: '{pname}'")


# ── Check 9: Remote access ────────────────────────────────────────────────────

def check_remote_access(result: TargetResult):
    for tool in result.tools:
        name     = tool.get("name", "")
        combined = name + " " + tool.get("description", "")
        for category, (pattern, severity) in RAC_PATTERNS.items():
            if re.search(pattern, combined, re.IGNORECASE):
                result.add("remote_access", severity,
                           f"Remote access [{category}]: '{name}'",
                           tool.get("description", "")[:200],
                           evidence=f"Pattern: {pattern}")


# ── Check 10: Multi-vector ────────────────────────────────────────────────────

def check_multi_vector(result: TargetResult):
    checks_hit = {f.check for f in result.findings}
    dangerous  = {
        "prompt_injection", "tool_poisoning", "token_theft",
        "code_execution", "remote_access", "indirect_injection",
    }
    hit = checks_hit & dangerous

    if len(hit) >= 2:
        result.add("multi_vector", "CRITICAL",
                   f"Multi-vector attack: {len(hit)} categories active",
                   f"Vectors: {sorted(hit)}")

    if ({"prompt_injection", "indirect_injection", "tool_poisoning"} & checks_hit
            and {"token_theft", "remote_access"} & checks_hit):
        result.add("multi_vector", "CRITICAL",
                   "Attack chain: injection + exfiltration vector present")


# ── SSE-specific checks ───────────────────────────────────────────────────────

def check_sse_security(base: str, sse_path: str, result: TargetResult):
    client = httpx.Client(verify=False, timeout=8)

    # Unauth access
    try:
        r = client.get(base + sse_path,
                       headers={"Accept": "text/event-stream"}, timeout=5)
        if "text/event-stream" in r.headers.get("content-type", ""):
            result.add("sse_security", "HIGH",
                       "SSE stream accessible without authentication",
                       f"GET {sse_path} returned event-stream with no credentials")
    except Exception:
        pass

    # CORS wildcard
    try:
        r = client.get(base + sse_path, headers={
            "Accept": "text/event-stream",
            "Origin": "https://evil.example.com",
        }, timeout=5)
        acao = r.headers.get("access-control-allow-origin", "")
        if acao in ("*", "https://evil.example.com"):
            result.add("sse_security", "HIGH",
                       f"SSE CORS misconfiguration: ACAO={acao}")
    except Exception:
        pass

    # CSRF on messages endpoint
    try:
        r = client.post(base + "/messages",
                        json=_jrpc("initialize", MCP_INIT_PARAMS),
                        headers={
                            "Content-Type": "application/json",
                            "Origin": "https://evil.example.com",
                        },
                        follow_redirects=False,
                        timeout=5)
        if r.status_code in (200, 202, 307):
            result.add("sse_security", "MEDIUM",
                       "MCP messages endpoint accepts cross-origin POST",
                       f"Status {r.status_code} with evil Origin header")
    except Exception:
        pass

    client.close()


# ── Protocol robustness ───────────────────────────────────────────────────────

def check_protocol_robustness(session: MCPSession, result: TargetResult):
    resp = session.call("nonexistent/method/xyz", timeout=8)
    if resp and "error" not in resp:
        result.add("protocol_robustness", "MEDIUM",
                   "Server returned success for unknown JSON-RPC method",
                   "Should return -32601 Method Not Found")

    resp = session.call("tools/call", timeout=8)
    if resp and "result" in resp:
        result.add("protocol_robustness", "MEDIUM",
                   "Server returned result for tools/call with no params")


# ═══════════════════════════════════════════════════════════════════════════════
#  K8s checks (internal)
# ═══════════════════════════════════════════════════════════════════════════════

def _k8s_get(path: str, token: str) -> dict | None:
    import ssl
    import urllib.request
    req = urllib.request.Request(
        f"https://kubernetes.default{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return json.loads(r.read())
    except Exception:
        return None


def run_k8s_checks(namespace: str):
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if not os.path.exists(token_path):
        console.print("[dim]  No SA token — skipping K8s checks[/dim]")
        return

    with open(token_path) as f:
        token = f.read().strip()

    console.print(f"\n[bold]── K8s Internal Checks (ns={namespace}) ──[/bold]")

    for name, path in [
        ("secrets",    f"/api/v1/namespaces/{namespace}/secrets"),
        ("configmaps", f"/api/v1/namespaces/{namespace}/configmaps"),
        ("pods",       f"/api/v1/namespaces/{namespace}/pods"),
    ]:
        data = _k8s_get(path, token)
        if data:
            count = len(data.get("items", []))
            sev   = "HIGH" if name == "secrets" else "INFO"
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="rbac", severity=sev,
                title=f"SA can read {name} ({count} items) in {namespace}",
            ))

    secrets_data = _k8s_get(
        f"/api/v1/namespaces/{namespace}/secrets", token)
    if secrets_data:
        for secret in secrets_data.get("items", []):
            if secret.get("type") != "helm.sh/release.v1":
                continue
            sname = secret["metadata"]["name"]
            b64   = secret.get("data", {}).get("release", "")
            if not b64:
                continue
            try:
                decoded = gzip.decompress(
                    base64.b64decode(base64.b64decode(b64)))
                _scan_helm(sname,
                           json.loads(decoded)
                               .get("chart", {}).get("values", {}), "")
            except Exception:
                pass


def _scan_helm(sname: str, obj: Any, path: str):
    if isinstance(obj, dict):
        for k, v in obj.items():
            np = f"{path}.{k}" if path else k
            if isinstance(v, str):
                if "PRIVATE KEY" in v:
                    GLOBAL_K8S_FINDINGS.append(Finding(
                        target="k8s", check="helm_secrets",
                        severity="CRITICAL",
                        title=f"Private key in Helm values: {sname} → {np}",
                    ))
                elif any(s in k.lower()
                         for s in ["password","secret","token","apikey"]):
                    GLOBAL_K8S_FINDINGS.append(Finding(
                        target="k8s", check="helm_secrets",
                        severity="HIGH",
                        title=f"Credential in Helm values: {sname} → {np}",
                    ))
            else:
                _scan_helm(sname, v, np)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _scan_helm(sname, item, f"{path}[{i}]")


# ═══════════════════════════════════════════════════════════════════════════════
#  Per-target orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

def scan_target(url: str, all_results: list[TargetResult]) -> TargetResult:
    result = TargetResult(url=url)
    console.print(f"\n[bold cyan]▶ Scanning {url}[/bold cyan]")

    session = detect_transport(url)
    if not session:
        console.print(f"  [red]✗[/red] No MCP session on {url}")
        result.transport = "none"
        result.add("transport", "HIGH", "No MCP endpoint found",
                   "Tried SSE and HTTP POST on common paths")
        return result

    result.transport = session.__class__.__name__
    console.print(
        f"  [green]✓[/green] Transport: "
        f"{'SSE' if isinstance(session, MCPSession) and session.sse_url else 'HTTP'} "
        f"→ {session.post_url}"
    )

    # SSE-specific checks
    if session.sse_url:
        parsed   = urlparse(url)
        base     = f"{parsed.scheme}://{parsed.netloc}"
        sse_path = urlparse(session.sse_url).path
        check_sse_security(base, sse_path, result)

    # Enumerate
    enumerate_server(session, result)
    console.print(
        f"  [dim]Tools: {len(result.tools)}  "
        f"Resources: {len(result.resources)}  "
        f"Prompts: {len(result.prompts)}[/dim]"
    )

    # Run all checks
    check_prompt_injection(result)
    check_tool_poisoning(result)
    check_excessive_permissions(result)
    check_rug_pull(session, result)
    check_tool_shadowing(all_results, result)
    check_indirect_injection(session, result)
    check_token_theft(result)
    check_code_execution(result)
    check_remote_access(result)
    check_protocol_robustness(session, result)
    check_multi_vector(result)

    session.close()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  Parallel runner
# ═══════════════════════════════════════════════════════════════════════════════

def run_parallel(urls: list[str],
                 max_workers: int = 5) -> list[TargetResult]:
    results: list[TargetResult] = []
    lock = threading.Lock()
    sem  = threading.Semaphore(max_workers)

    def worker(url: str):
        with sem:
            r = scan_target(url, results)
            with lock:
                results.append(r)

    threads = [threading.Thread(target=worker, args=(u,), daemon=True)
               for u in urls]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Reporting
# ═══════════════════════════════════════════════════════════════════════════════

def print_report(results: list[TargetResult]):
    console.print("\n")
    console.rule("[bold]AUDIT REPORT[/bold]")

    all_findings = ([f for r in results for f in r.findings]
                    + GLOBAL_K8S_FINDINGS)

    if not all_findings:
        console.print("[green]  No vulnerabilities found.[/green]")
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f  = sorted(all_findings,
                       key=lambda f: sev_order.get(f.severity, 5))

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Target",   style="cyan",  no_wrap=True)
    table.add_column("Check",    style="white")
    table.add_column("Sev",      style="bold",  no_wrap=True, width=8)
    table.add_column("Finding",  style="white")

    for f in sorted_f:
        color    = SEV_COLOR.get(f.severity, "white")
        sev_text = Text(f.severity, style=color)
        table.add_row(
            f.target.replace("http://", ""),
            f.check,
            sev_text,
            f.title,
        )

    console.print(table)

    counts = Counter(f.severity for f in all_findings)
    console.print(
        f"\n  [bold red]CRITICAL: {counts['CRITICAL']}[/bold red]  |  "
        f"[red]HIGH: {counts['HIGH']}[/red]  |  "
        f"[yellow]MEDIUM: {counts['MEDIUM']}[/yellow]  |  "
        f"[cyan]LOW: {counts['LOW']}[/cyan]"
    )


def write_json(results: list[TargetResult], path: str):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [
            {
                "url":        r.url,
                "transport":  r.transport,
                "tools":      [t.get("name") for t in r.tools],
                "findings": [
                    {"check": f.check, "severity": f.severity,
                     "title": f.title, "detail": f.detail,
                     "evidence": f.evidence}
                    for f in r.findings
                ],
            }
            for r in results
        ],
        "k8s_findings": [
            {"check": f.check, "severity": f.severity, "title": f.title}
            for f in GLOBAL_K8S_FINDINGS
        ],
    }
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    console.print(f"\n[green]  JSON report → {path}[/green]")


# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════

def expand_targets(args) -> list[str]:
    targets = list(args.targets or [])
    if args.port_range:
        m = re.match(r"(.+):(\d+)-(\d+)$", args.port_range)
        if m:
            host  = m.group(1)
            start = int(m.group(2))
            end   = int(m.group(3))
            targets += [f"http://{host}:{p}" for p in range(start, end + 1)]
        else:
            console.print("[red]Invalid --port-range. Use host:start-end[/red]")
    return targets


def main():
    parser = argparse.ArgumentParser(
        description="mcp-audit v2: Universal MCP Security Scanner")
    parser.add_argument("--targets",    nargs="+", metavar="URL")
    parser.add_argument("--port-range", metavar="HOST:START-END")
    parser.add_argument("--mode",
                        choices=["mcp", "internal", "full"], default="mcp")
    parser.add_argument("--namespace",  default="default")
    parser.add_argument("--workers",    type=int, default=5)
    parser.add_argument("--json",       metavar="FILE")
    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold cyan]mcp-audit v2[/bold cyan]  —  "
        "Universal MCP Security Scanner\n"
        "[dim]DVMCP challenges • SSE • HTTP • K8s • Multi-target[/dim]",
        border_style="cyan",
    ))

    targets = expand_targets(args)

    if args.mode in ("mcp", "full") and not targets:
        console.print("[red]Error: no targets. Use --targets or "
                      "--port-range[/red]")
        sys.exit(1)

    results: list[TargetResult] = []

    if args.mode in ("mcp", "full") and targets:
        console.print(f"\n[bold]Targets:[/bold] {len(targets)}")
        for t in targets:
            console.print(f"  [dim]{t}[/dim]")
        results = run_parallel(targets, max_workers=args.workers)

    if args.mode in ("internal", "full"):
        run_k8s_checks(args.namespace)

    print_report(results)

    if args.json:
        write_json(results, args.json)


if __name__ == "__main__":
    main()
