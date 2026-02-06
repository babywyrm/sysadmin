#!/usr/bin/env python3
import argparse
import json
import time
import uuid
import yaml
import requests
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Protocol, Tuple

# -----------------------------
# Models
# -----------------------------

@dataclass
class TargetTool:
    name: str
    url: str
    execute_path: str = "/execute"
    timeout_s: float = 10.0

@dataclass
class Targets:
    gateway: str
    tools: List[TargetTool]

@dataclass
class Finding:
    risk_id: str
    title: str
    severity: str              # INFO/LOW/MED/HIGH/CRIT
    target: str
    request: Dict[str, Any]
    evidence: Dict[str, Any]
    recommendation: str
    blue_team_signal: str

@dataclass
class RunConfig:
    authorized: bool
    config_path: str
    modules: List[str]
    out_json: Optional[str]
    out_md: Optional[str]
    timeout_s: float
    retries: int

# -----------------------------
# Auth
# -----------------------------

class AuthProvider(Protocol):
    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        ...

class StaticBearer(AuthProvider):
    """Use a provided token; no forging in the harness."""
    def __init__(self, token: str):
        self.token = token

    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

class OAuth2ClientCreds(AuthProvider):
    def __init__(self, token_url: str, client_id: str, client_secret: str, scope: Optional[str] = None):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self._token: Optional[str] = None

    def _fetch(self) -> str:
        data = {"grant_type": "client_credentials"}
        if self.scope:
            data["scope"] = self.scope
        r = requests.post(
            self.token_url,
            data=data,
            auth=(self.client_id, self.client_secret),
            timeout=10,
        )
        r.raise_for_status()
        j = r.json()
        return j["access_token"]

    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        if not self._token:
            self._token = self._fetch()
        return {"Authorization": f"Bearer {self._token}"}

class NoAuth(AuthProvider):
    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        return {}

# -----------------------------
# HTTP client with retries
# -----------------------------

class HttpClient:
    def __init__(self, base_headers: Dict[str, str], timeout_s: float, retries: int):
        self.s = requests.Session()
        self.base_headers = dict(base_headers)
        self.timeout_s = timeout_s
        self.retries = retries

    def request(self, method: str, url: str, *, headers: Optional[Dict[str, str]] = None, json_body: Any = None
               ) -> Tuple[requests.Response, float]:
        hdrs = dict(self.base_headers)
        if headers:
            hdrs.update(headers)

        # correlation for tracing in OBS plane
        hdrs.setdefault("X-Request-Id", str(uuid.uuid4()))
        hdrs.setdefault("X-MCP-Slayer", "true")

        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                start = time.time()
                r = self.s.request(method, url, headers=hdrs, json=json_body, timeout=self.timeout_s)
                dur = time.time() - start
                return r, dur
            except requests.RequestException as e:
                last_exc = e
                if attempt < self.retries:
                    time.sleep(0.5 * (2 ** attempt))
        raise last_exc  # type: ignore

# -----------------------------
# Module interface
# -----------------------------

class Module(Protocol):
    id: str
    name: str
    risk_id: str

    def run(self, ctx: "Context") -> List[Finding]:
        ...

@dataclass
class Context:
    cfg: Dict[str, Any]
    targets: Targets
    auth: AuthProvider
    http: HttpClient

# -----------------------------
# Example modules
# -----------------------------

class ConfusedDeputyModule:
    id = "confused-deputy"
    name = "Confused Deputy / Audience & Scope Binding"
    risk_id = "MCP-02"

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        for tool in ctx.targets.tools:
            url = tool.url.rstrip("/") + tool.execute_path
            r, dur = ctx.http.request("POST", url, json_body={"action": "list_all"})
            # Expectation: tools should NOT accept “gateway token” unless explicitly intended
            if r.status_code < 400:
                findings.append(Finding(
                    risk_id=self.risk_id,
                    title=f"Tool accepted caller token without clear audience/scope enforcement ({tool.name})",
                    severity="HIGH",
                    target=url,
                    request={"method": "POST", "body": {"action": "list_all"}},
                    evidence={"status": r.status_code, "duration_s": round(dur, 3), "snippet": r.text[:300]},
                    recommendation="Enforce per-tool audience binding + scopes; require TR/GW to mint per-tool tokens; validate aud/iss/scope at tool boundary.",
                    blue_team_signal="Detect same token/sub used across multiple tools; log aud/scope mismatch denials; alert on cross-tool token reuse."
                ))
        return findings

class PromptInjectionCanaryModule:
    id = "prompt-injection-canary"
    name = "Indirect Prompt Injection (Canary Execution)"
    risk_id = "MCP-01"

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        gw = ctx.targets.gateway.rstrip("/") + "/invoke"
        payloads = ctx.cfg.get("payloads", {}).get("injection", [])
        for p in payloads:
            r, dur = ctx.http.request("POST", gw, json_body={"prompt": p["string"]})
            canary = p.get("canary")
            if canary and canary in r.text:
                findings.append(Finding(
                    risk_id=self.risk_id,
                    title=f"Injected instruction appears to have executed (canary observed): {p.get('name','payload')}",
                    severity="CRIT",
                    target=gw,
                    request={"method": "POST", "body": {"prompt": "<redacted by design; use prompt_hash in prod>"}},
                    evidence={"status": r.status_code, "duration_s": round(dur, 3), "canary": canary, "snippet": r.text[:400]},
                    recommendation="Treat tool outputs as untrusted; instruction-strip/label; enforce tool action allowlists; add regression tests for this payload.",
                    blue_team_signal="Alert on canary strings in tool outputs; detect unusual tool chains triggered by untrusted content sources (RAG/docs/repos)."
                ))
        return findings

class JwtValidationModule:
    """
    Safe auth validation checks: verify server rejects missing/expired/bad-aud tokens.
    This harness does NOT generate forged tokens.
    """
    id = "jwt-validation"
    name = "JWT Validation (aud/iss/exp/signature enforcement)"
    risk_id = "MCP-12"

    def run(self, ctx: Context) -> List[Finding]:
        findings: List[Finding] = []
        # Use user-supplied test tokens (e.g., from your IdP) to validate rejections.
        jwt_tests = ctx.cfg.get("payloads", {}).get("jwt_tests", [])
        if not jwt_tests:
            return findings

        tool0 = ctx.targets.tools[0]
        url = tool0.url.rstrip("/") + tool0.execute_path

        for t in jwt_tests:
            headers = {"Authorization": f"Bearer {t['token']}"}
            r, dur = ctx.http.request("POST", url, headers=headers, json_body={"action": "whoami"})
            expected = t.get("expect_status", 401)
            if r.status_code != expected:
                findings.append(Finding(
                    risk_id=self.risk_id,
                    title=f"Unexpected JWT validation behavior ({t.get('name','test')})",
                    severity="HIGH",
                    target=url,
                    request={"method": "POST", "body": {"action": "whoami"}, "token_name": t.get("name")},
                    evidence={"status": r.status_code, "expected": expected, "duration_s": round(dur, 3), "snippet": r.text[:300]},
                    recommendation="Verify JWT signature, exp, nbf, iss, aud; enforce tool-specific aud; deny on any validation errors with generic messages.",
                    blue_team_signal="Alert on repeated 401/403 with invalid aud/iss/exp; rate-limit invalid token storms; log decision reasons (without leaking JWT details)."
                ))
        return findings

# -----------------------------
# Runner / Reporting
# -----------------------------

MODULES: Dict[str, Module] = {
    ConfusedDeputyModule.id: ConfusedDeputyModule(),
    PromptInjectionCanaryModule.id: PromptInjectionCanaryModule(),
    JwtValidationModule.id: JwtValidationModule(),
}

def load_targets(cfg: Dict[str, Any]) -> Targets:
    tools = []
    for t in cfg["targets"]["tools"]:
        tools.append(TargetTool(
            name=t["name"],
            url=t["url"],
            execute_path=t.get("execute_path", "/execute"),
            timeout_s=float(t.get("timeout_s", 10.0)),
        ))
    return Targets(gateway=cfg["targets"]["gateway"], tools=tools)

def init_auth(cfg: Dict[str, Any]) -> AuthProvider:
    a = cfg.get("auth", {"type": "none"})
    t = a.get("type", "none")
    if t == "jwt":
        return StaticBearer(a["token"])
    if t == "oauth2":
        return OAuth2ClientCreds(a["url"], a["id"], a["secret"], a.get("scope"))
    return NoAuth()

def to_markdown(findings: List[Finding]) -> str:
    lines = []
    lines.append("# MCP-SLAYER Findings\n")
    if not findings:
        lines.append("_No findings._\n")
        return "\n".join(lines)

    lines.append("| Risk | Severity | Title | Target | Blue Team Signal |\n")
    lines.append("|---|---|---|---|---|\n")
    for f in findings:
        lines.append(f"| {f.risk_id} | {f.severity} | {f.title} | `{f.target}` | {f.blue_team_signal} |\n")

    lines.append("\n## Details\n")
    for f in findings:
        lines.append(f"### {f.risk_id} — {f.title}\n")
        lines.append(f"- **Severity:** {f.severity}\n")
        lines.append(f"- **Target:** `{f.target}`\n")
        lines.append(f"- **Evidence:** `{json.dumps(f.evidence, ensure_ascii=False)}`\n")
        lines.append(f"- **Recommendation:** {f.recommendation}\n")
        lines.append(f"- **Blue Team Signal:** {f.blue_team_signal}\n")
        lines.append("")
    return "\n".join(lines)

def main():
    p = argparse.ArgumentParser(description="MCP-SLAYER — modular MCP/Agent security harness")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--modules", default="confused-deputy,prompt-injection-canary,jwt-validation",
                   help="comma-separated module IDs")
    p.add_argument("--out-json", default="slayer_findings.json")
    p.add_argument("--out-md", default="slayer_findings.md")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--authorized", action="store_true",
                   help="Required. Confirms you have authorization to test the specified targets.")
    args = p.parse_args()

    if not args.authorized:
        raise SystemExit("Refusing to run without --authorized (safety guard).")

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f)

    targets = load_targets(cfg)
    auth = init_auth(cfg)
    http = HttpClient(base_headers=auth.headers_for(), timeout_s=args.timeout, retries=args.retries)
    ctx = Context(cfg=cfg, targets=targets, auth=auth, http=http)

    mod_ids = [m.strip() for m in args.modules.split(",") if m.strip()]
    findings: List[Finding] = []

    for mid in mod_ids:
        mod = MODULES.get(mid)
        if not mod:
            print(f"[!] Unknown module: {mid}")
            continue
        print(f"[*] Running {mod.id} ({mod.risk_id}) — {mod.name}")
        findings.extend(mod.run(ctx))

    # Write outputs
    out = [asdict(f) for f in findings]
    with open(args.out_json, "w") as f:
        json.dump(out, f, indent=2)

    with open(args.out_md, "w") as f:
        f.write(to_markdown(findings))

    print(f"[*] Findings: {len(findings)}")
    print(f"[*] Wrote: {args.out_json}, {args.out_md}")

if __name__ == "__main__":
    main()
