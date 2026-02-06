#!/usr/bin/env python3
import argparse
import json
import os
import re
import time
import uuid
import yaml
import requests
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Protocol, Tuple


# -----------------------------
# Utilities: env interpolation
# -----------------------------

ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")

def _env_substitute(s: str) -> str:
    """
    Supports:
      ${VAR}
      ${VAR:-default}
    """
    def repl(m: re.Match) -> str:
        expr = m.group(1)
        if ":-" in expr:
            var, default = expr.split(":-", 1)
            return os.getenv(var, default)
        return os.getenv(expr, "")
    return ENV_PATTERN.sub(repl, s)

def resolve_env(obj: Any) -> Any:
    if isinstance(obj, str):
        return _env_substitute(obj)
    if isinstance(obj, list):
        return [resolve_env(x) for x in obj]
    if isinstance(obj, dict):
        return {k: resolve_env(v) for k, v in obj.items()}
    return obj


# -----------------------------
# Redaction helpers
# -----------------------------

def redact_headers(headers: Dict[str, str], header_names: List[str]) -> Dict[str, str]:
    redacted = dict(headers or {})
    header_set = {h.lower() for h in header_names}
    for k in list(redacted.keys()):
        if k.lower() in header_set:
            redacted[k] = "[REDACTED]"
    return redacted

def redact_json_fields(obj: Any, field_names: List[str]) -> Any:
    """
    Simple redaction: if a dict key matches any sensitive name (case-insensitive),
    replace its value. This is intentionally lightweight (no full JSONPath engine).
    """
    if not field_names:
        return obj
    sens = {f.lower() for f in field_names}

    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in sens:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_json_fields(v, field_names)
        return out
    if isinstance(obj, list):
        return [redact_json_fields(x, field_names) for x in obj]
    return obj


# -----------------------------
# Models
# -----------------------------

@dataclass
class TargetTool:
    name: str
    base_url: str
    execute_path: str = "/execute"
    auth_profile: Optional[str] = None
    labels: List[str] = None
    limits: Dict[str, Any] = None

    def __post_init__(self):
        if self.labels is None:
            self.labels = []
        if self.limits is None:
            self.limits = {}

@dataclass
class Targets:
    gateway_base_url: str
    gateway_invoke_path: str = "/invoke"
    gateway_health_path: str = "/healthz"
    tools: List[TargetTool] = None

    def __post_init__(self):
        if self.tools is None:
            self.tools = []

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
    tags: Dict[str, Any]

class AuthProvider(Protocol):
    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        ...


# -----------------------------
# Auth providers
# -----------------------------

class NoAuth:
    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        return {}

class StaticBearer:
    def __init__(self, token: str):
        self.token = token

    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

class OAuth2ClientCreds:
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
        r = requests.post(self.token_url, data=data, auth=(self.client_id, self.client_secret), timeout=10)
        r.raise_for_status()
        j = r.json()
        return j["access_token"]

    def headers_for(self, audience: Optional[str] = None) -> Dict[str, str]:
        if not self._token:
            self._token = self._fetch()
        return {"Authorization": f"Bearer {self._token}"}


# -----------------------------
# HTTP client with retries
# -----------------------------

class HttpClient:
    def __init__(
        self,
        base_headers: Dict[str, str],
        timeout_s: float,
        retries: int,
        backoff_base_s: float,
        verify_tls: bool,
        follow_redirects: bool,
    ):
        self.s = requests.Session()
        self.base_headers = dict(base_headers or {})
        self.timeout_s = timeout_s
        self.retries = retries
        self.backoff_base_s = backoff_base_s
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None,
    ) -> Tuple[requests.Response, float, Dict[str, str]]:
        hdrs = dict(self.base_headers)
        if headers:
            hdrs.update(headers)

        hdrs.setdefault("X-Request-Id", str(uuid.uuid4()))
        hdrs.setdefault("X-MCP-Slayer", "true")

        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                start = time.time()
                r = self.s.request(
                    method,
                    url,
                    headers=hdrs,
                    json=json_body,
                    timeout=self.timeout_s,
                    verify=self.verify_tls,
                    allow_redirects=self.follow_redirects,
                )
                dur = time.time() - start
                return r, dur, hdrs
            except requests.RequestException as e:
                last_exc = e
                if attempt < self.retries:
                    time.sleep(self.backoff_base_s * (2 ** attempt))
        raise last_exc  # type: ignore


# -----------------------------
# Context + modules
# -----------------------------

@dataclass
class Context:
    cfg: Dict[str, Any]
    targets: Targets
    auth_profiles: Dict[str, AuthProvider]
    default_auth_profile: str
    http: HttpClient
    run_tags: Dict[str, Any]
    redact_header_names: List[str]
    redact_json_field_names: List[str]
    payloads: Dict[str, List[Dict[str, Any]]]
    module_settings: Dict[str, Any]

def _severity_rank(s: str) -> int:
    order = {"INFO": 0, "LOW": 1, "MED": 2, "HIGH": 3, "CRIT": 4}
    return order.get((s or "INFO").upper(), 0)


class Module(Protocol):
    id: str
    name: str
    risk_id: str

    def run(self, ctx: Context) -> List[Finding]:
        ...


class ConfusedDeputyModule:
    id = "confused-deputy"
    name = "Confused Deputy / Audience & Scope Binding"
    risk_id = "MCP-02"

    def run(self, ctx: Context) -> List[Finding]:
        settings = ctx.module_settings.get(self.id, {})
        actions = settings.get("actions", ["list_all"])
        success_statuses = settings.get("success_statuses", [200, 201, 202])
        strict_2xx = bool(settings.get("strict_2xx_is_finding", True))

        findings: List[Finding] = []
        for tool in ctx.targets.tools:
            url = tool.base_url.rstrip("/") + tool.execute_path

            # Use the DEFAULT auth unless overridden by tool
            ap = tool.auth_profile or ctx.default_auth_profile
            auth = ctx.auth_profiles.get(ap, NoAuth())

            for action in actions:
                r, dur, sent_headers = ctx.http.request(
                    "POST",
                    url,
                    headers=auth.headers_for(),
                    json_body={"action": action},
                )

                is_success = (r.status_code in success_statuses) or (strict_2xx and 200 <= r.status_code < 300)
                if is_success:
                    findings.append(Finding(
                        risk_id=self.risk_id,
                        title=f"Tool accepted caller token without clear audience/scope enforcement ({tool.name})",
                        severity="HIGH",
                        target=url,
                        request={
                            "method": "POST",
                            "headers": redact_headers(sent_headers, ctx.redact_header_names),
                            "body": {"action": action},
                            "auth_profile": ap,
                        },
                        evidence={"status": r.status_code, "duration_s": round(dur, 3), "snippet": r.text[:300]},
                        recommendation="Enforce per-tool audience binding + tool-scoped tokens; validate aud/iss/scope at tool boundary; deny by default.",
                        blue_team_signal="Detect cross-tool token reuse (same sub/jti across multiple tools); alert on scope/audience mismatches.",
                        tags=ctx.run_tags
                    ))
        return findings


class PromptInjectionCanaryModule:
    id = "prompt-injection-canary"
    name = "Indirect Prompt Injection (Canary Execution)"
    risk_id = "MCP-01"

    def run(self, ctx: Context) -> List[Finding]:
        settings = ctx.module_settings.get(self.id, {})
        endpoint_ref = settings.get("endpoint", "gateway.invoke")
        require_canary = bool(settings.get("require_canary", True))

        if endpoint_ref != "gateway.invoke":
            # keep simple for now; can add more endpoint references later
            pass

        gw = ctx.targets.gateway_base_url.rstrip("/") + ctx.targets.gateway_invoke_path

        findings: List[Finding] = []
        pack = ctx.payloads.get("prompt_injection", [])
        for p in pack:
            canary = p.get("canary")
            prompt = p.get("prompt") or p.get("string")  # backward compat with earlier config

            if require_canary and not canary:
                continue

            # Gateway uses default auth profile
            auth = ctx.auth_profiles.get(ctx.default_auth_profile, NoAuth())

            r, dur, sent_headers = ctx.http.request(
                "POST",
                gw,
                headers=auth.headers_for(),
                json_body={"prompt": prompt},
            )

            if canary and canary in r.text:
                mapping = p.get("mapping", {})
                findings.append(Finding(
                    risk_id=mapping.get("risk_id", self.risk_id),
                    title=f"Injected instruction appears to have executed (canary observed): {p.get('name', p.get('id','payload'))}",
                    severity=mapping.get("severity", "CRIT"),
                    target=gw,
                    request={
                        "method": "POST",
                        "headers": redact_headers(sent_headers, ctx.redact_header_names),
                        "body": {"prompt": "[REDACTED_BY_DESIGN]"},
                    },
                    evidence={"status": r.status_code, "duration_s": round(dur, 3), "canary": canary, "snippet": r.text[:400]},
                    recommendation="Treat tool outputs as untrusted; instruction-strip/label; enforce tool action allowlists; add regression tests for this payload.",
                    blue_team_signal="Alert on canary strings; detect unusual tool chains triggered by untrusted content sources (RAG/docs/repos).",
                    tags=ctx.run_tags
                ))
        return findings


class JwtValidationModule:
    """
    Safe auth validation checks. You provide negative-test tokens (expired / wrong aud / etc).
    The harness verifies expected rejections; it does not generate forged tokens.
    """
    id = "jwt-validation"
    name = "JWT Validation (aud/iss/exp/signature enforcement)"
    risk_id = "MCP-12"

    def run(self, ctx: Context) -> List[Finding]:
        settings = ctx.module_settings.get(self.id, {})
        tests_from_pack = settings.get("tests_from_pack", "jwt_negative")

        tests = ctx.payloads.get(tests_from_pack, [])
        if not tests:
            return []

        # pick a tool endpoint (default: first tool)
        tool = ctx.targets.tools[0]
        url = tool.base_url.rstrip("/") + tool.execute_path

        findings: List[Finding] = []
        for t in tests:
            token = t.get("token", "")
            expected = int(t.get("expect_status", 401))
            name = t.get("name", t.get("id", "jwt_test"))

            headers = {"Authorization": f"Bearer {token}"} if token else {}
            r, dur, sent_headers = ctx.http.request("POST", url, headers=headers, json_body={"action": "whoami"})

            if r.status_code != expected:
                mapping = t.get("mapping", {})
                findings.append(Finding(
                    risk_id=mapping.get("risk_id", self.risk_id),
                    title=f"Unexpected JWT validation behavior ({name})",
                    severity=mapping.get("severity", "HIGH"),
                    target=url,
                    request={
                        "method": "POST",
                        "headers": redact_headers(sent_headers, ctx.redact_header_names),
                        "body": {"action": "whoami"},
                        "test": name,
                    },
                    evidence={"status": r.status_code, "expected": expected, "duration_s": round(dur, 3), "snippet": r.text[:300]},
                    recommendation="Verify JWT signature, exp/nbf, iss, aud; enforce tool-specific aud; deny on any validation errors with generic messages.",
                    blue_team_signal="Alert on spikes of invalid token rejections; log decision reasons without leaking token contents.",
                    tags=ctx.run_tags
                ))
        return findings


class DosRecursionModule:
    id = "dos-recursion"
    name = "Resource Exhaustion / Recursion Guard"
    risk_id = "MCP-14"

    def run(self, ctx: Context) -> List[Finding]:
        settings = ctx.module_settings.get(self.id, {})
        max_dur = float(settings.get("max_duration_s", 5.0))
        prompt = settings.get("prompt") or "Perform action X, take the result, and perform action X again. Repeat 100 times."

        gw = ctx.targets.gateway_base_url.rstrip("/") + ctx.targets.gateway_invoke_path
        auth = ctx.auth_profiles.get(ctx.default_auth_profile, NoAuth())

        r, dur, sent_headers = ctx.http.request("POST", gw, headers=auth.headers_for(), json_body={"prompt": prompt})

        findings: List[Finding] = []
        # This is a “guardrail verification”: if it takes too long or returns huge output, flag it.
        if dur > max_dur:
            findings.append(Finding(
                risk_id=self.risk_id,
                title=f"Potential missing recursion/timeout guard (duration {dur:.2f}s > {max_dur:.2f}s)",
                severity="MED",
                target=gw,
                request={
                    "method": "POST",
                    "headers": redact_headers(sent_headers, ctx.redact_header_names),
                    "body": {"prompt": "[REDACTED_BY_DESIGN]"},
                },
                evidence={"status": r.status_code, "duration_s": round(dur, 3), "snippet": r.text[:250]},
                recommendation="Add recursion/loop guards, max tool-call depth, and per-session budgets; enforce request timeouts at gateway and tool router.",
                blue_team_signal="Detect repeated tool-call patterns and long-running sessions; alert on budget overruns and throttling events.",
                tags=ctx.run_tags
            ))
        return findings


MODULES: Dict[str, Module] = {
    ConfusedDeputyModule.id: ConfusedDeputyModule(),
    PromptInjectionCanaryModule.id: PromptInjectionCanaryModule(),
    JwtValidationModule.id: JwtValidationModule(),
    DosRecursionModule.id: DosRecursionModule(),
}


# -----------------------------
# Config loading + normalization
# -----------------------------

def normalize_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts robust config. Also supports older shape:
      auth: {type, token/id/secret/url}
      targets: {gateway, tools:[{name,url}]}
      payloads: {injection:[...]}
    """
    cfg = cfg or {}
    # Backward compat: old 'targets.gateway'
    if "targets" in cfg and isinstance(cfg["targets"], dict) and "gateway" in cfg["targets"]:
        # old style
        old_targets = cfg["targets"]
        tools = old_targets.get("tools", [])
        cfg = {
            "version": 1,
            "run": {"authorized": False},
            "env": {},
            "reporting": {"outputs": [{"format": "json", "path": "out/findings.json"},
                                     {"format": "markdown", "path": "out/findings.md"}],
                          "redact": {"headers": ["Authorization", "Cookie", "X-Api-Key"], "json_fields": ["token","access_token","refresh_token"]}},
            "auth_profiles": {
                "default": "default",
                "profiles": _old_auth_to_profiles(cfg.get("auth", {})),
            },
            "targets": {
                "gateway": {"base_url": old_targets["gateway"], "invoke_path": "/invoke", "health_path": "/healthz"},
                "tools": [{"name": t["name"], "base_url": t["url"], "execute_path": "/execute"} for t in tools],
            },
            "payload_packs": {"enabled": ["prompt_injection"]},
            "payloads": {
                "prompt_injection": [
                    {"id": p.get("name", "payload"), "name": p.get("name", "payload"),
                     "prompt": p.get("string"), "canary": p.get("canary"),
                     "mapping": {"risk_id": "MCP-01", "severity": "CRIT"}}
                    for p in cfg.get("payloads", {}).get("injection", [])
                ]
            },
            "modules": {"enabled": ["confused-deputy", "prompt-injection-canary", "jwt-validation"],
                        "settings": {}}
        }
    return cfg

def _old_auth_to_profiles(a: Dict[str, Any]) -> Dict[str, Any]:
    t = (a or {}).get("type", "none")
    if t == "jwt":
        return {"default": {"type": "jwt_static", "token": a.get("token", "")}}
    if t == "oauth2":
        return {"default": {"type": "oauth2_client_credentials", "token_url": a.get("url", ""), "client_id": a.get("id",""), "client_secret": a.get("secret","")}}
    return {"default": {"type": "none"}}

def build_targets(cfg: Dict[str, Any]) -> Targets:
    t = cfg["targets"]
    gw = t["gateway"]
    tools = []
    for tool in t.get("tools", []):
        tools.append(TargetTool(
            name=tool["name"],
            base_url=tool["base_url"],
            execute_path=tool.get("execute_path", "/execute"),
            auth_profile=tool.get("auth_profile"),
            labels=tool.get("labels", []) or [],
            limits=tool.get("limits", {}) or {},
        ))
    return Targets(
        gateway_base_url=gw["base_url"],
        gateway_invoke_path=gw.get("invoke_path", "/invoke"),
        gateway_health_path=gw.get("health_path", "/healthz"),
        tools=tools
    )

def build_auth_profiles(cfg: Dict[str, Any]) -> Tuple[Dict[str, AuthProvider], str]:
    ap = cfg.get("auth_profiles", {})
    default_name = ap.get("default", "none")
    profiles = ap.get("profiles", {}) or {}

    built: Dict[str, AuthProvider] = {}
    for name, p in profiles.items():
        ptype = (p.get("type") or "none").lower()
        if ptype == "jwt_static":
            built[name] = StaticBearer(p.get("token", ""))
        elif ptype == "oauth2_client_credentials":
            built[name] = OAuth2ClientCreds(
                p["token_url"],
                p["client_id"],
                p["client_secret"],
                p.get("scope")
            )
        else:
            built[name] = NoAuth()

    if default_name not in built:
        built[default_name] = NoAuth()

    return built, default_name

def build_payloads(cfg: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    enabled_packs = set((cfg.get("payload_packs", {}) or {}).get("enabled", []) or [])
    all_payloads = cfg.get("payloads", {}) or {}
    # If no packs specified, include all payload sections
    if not enabled_packs:
        return {k: (v or []) for k, v in all_payloads.items()}

    return {k: (v or []) for k, v in all_payloads.items() if k in enabled_packs}

def markdown_report(findings: List[Finding]) -> str:
    lines = ["# MCP-SLAYER Findings\n"]
    if not findings:
        lines.append("_No findings._\n")
        return "\n".join(lines)

    findings_sorted = sorted(findings, key=lambda f: _severity_rank(f.severity), reverse=True)

    lines.append("| Risk | Severity | Title | Target | Blue Team Signal |\n")
    lines.append("|---|---|---|---|---|\n")
    for f in findings_sorted:
        lines.append(f"| {f.risk_id} | {f.severity} | {f.title} | `{f.target}` | {f.blue_team_signal} |\n")

    lines.append("\n## Details\n")
    for f in findings_sorted:
        lines.append(f"### {f.risk_id} — {f.title}\n")
        lines.append(f"- **Severity:** {f.severity}\n")
        lines.append(f"- **Target:** `{f.target}`\n")
        lines.append(f"- **Tags:** `{json.dumps(f.tags, ensure_ascii=False)}`\n")
        lines.append(f"- **Evidence:** `{json.dumps(f.evidence, ensure_ascii=False)}`\n")
        lines.append(f"- **Recommendation:** {f.recommendation}\n")
        lines.append(f"- **Blue Team Signal:** {f.blue_team_signal}\n")
        lines.append("")
    return "\n".join(lines)


# -----------------------------
# Main
# -----------------------------

def main():
    p = argparse.ArgumentParser(description="MCP-SLAYER — modular MCP/Agent security harness")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--modules", default=None, help="Override modules.enabled (comma-separated)")
    p.add_argument("--authorized", action="store_true", help="Required safety guard to run probes")
    args = p.parse_args()

    with open(args.config, "r") as f:
        raw = yaml.safe_load(f)

    raw = resolve_env(raw)
    cfg = normalize_config(raw)

    run = cfg.get("run", {}) or {}
    if not (args.authorized and bool(run.get("authorized", False))):
        raise SystemExit("Refusing to run without BOTH: --authorized and run.authorized: true in config.")

    # Reporting redaction config
    reporting = cfg.get("reporting", {}) or {}
    redact_cfg = reporting.get("redact", {}) or {}
    redact_header_names = (redact_cfg.get("headers") or [])
    # The robust sample used json_fields as JSONPath; we accept simple key names too.
    redact_json_field_names = []
    for x in (redact_cfg.get("json_fields") or []):
        # accept "$..token" style or "token"
        if isinstance(x, str) and x.startswith("$.."):
            redact_json_field_names.append(x.replace("$..", ""))
        elif isinstance(x, str):
            redact_json_field_names.append(x)

    # Build targets/auth/http
    targets = build_targets(cfg)
    auth_profiles, default_auth = build_auth_profiles(cfg)

    env = cfg.get("env", {}) or {}
    run_tags = {}
    run_tags.update(env.get("tags", {}) or {})
    run_tags["env"] = env.get("name", "unknown")
    run_tags["run_name"] = run.get("name", "run")

    http = HttpClient(
        base_headers=(env.get("base_headers", {}) or {}),
        timeout_s=float(run.get("timeout_s", 10.0)),
        retries=int(run.get("retries", 1)),
        backoff_base_s=float(run.get("backoff_base_s", 0.5)),
        verify_tls=bool(run.get("verify_tls", True)),
        follow_redirects=bool(run.get("follow_redirects", False)),
    )

    payloads = build_payloads(cfg)
    modules_cfg = cfg.get("modules", {}) or {}
    enabled_modules = modules_cfg.get("enabled", []) or []
    module_settings = modules_cfg.get("settings", {}) or {}

    if args.modules:
        enabled_modules = [m.strip() for m in args.modules.split(",") if m.strip()]

    ctx = Context(
        cfg=cfg,
        targets=targets,
        auth_profiles=auth_profiles,
        default_auth_profile=default_auth,
        http=http,
        run_tags=run_tags,
        redact_header_names=redact_header_names,
        redact_json_field_names=redact_json_field_names,
        payloads=payloads,
        module_settings=module_settings,
    )

    findings: List[Finding] = []
    for mid in enabled_modules:
        mod = MODULES.get(mid)
        if not mod:
            print(f"[!] Unknown module: {mid} (skipping)")
            continue
        print(f"[*] Running {mod.id} ({mod.risk_id}) — {mod.name}")
        findings.extend(mod.run(ctx))

    # Redact JSON evidence (and any nested fields) before writing artifacts
    findings_out = []
    for fnd in findings:
        d = asdict(fnd)
        d = redact_json_fields(d, ctx.redact_json_field_names)
        findings_out.append(d)

    # Write outputs
    for out in (reporting.get("outputs") or []):
        fmt = (out.get("format") or "").lower()
        path = out.get("path") or ""
        if not path:
            continue

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        if fmt == "json":
            with open(path, "w") as f:
                json.dump(findings_out, f, indent=2)
            print(f"[*] Wrote JSON: {path}")

        elif fmt in ("md", "markdown"):
            # markdown uses redacted findings objects converted back to Finding-ish
            md = markdown_report([Finding(**x) for x in findings_out])  # type: ignore
            with open(path, "w") as f:
                f.write(md)
            print(f"[*] Wrote Markdown: {path}")

        else:
            print(f"[!] Unsupported output format: {fmt} (skipping)")

    print(f"[*] Findings: {len(findings)}")


if __name__ == "__main__":
    main()
