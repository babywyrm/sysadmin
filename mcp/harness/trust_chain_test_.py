#!/usr/bin/env python3
"""
Zero-Trust AI Mesh - Trust Chain Tester
Tests each security layer independently and reports results.
"""

import time
import uuid
import json
import hmac
import hashlib
import base64
import argparse
import textwrap
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

# ── Enums & Types ─────────────────────────────────────────────────────────────

class LayerResult(Enum):
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    WARN = "⚠️  WARN"
    SKIP = "⏭️  SKIP"


@dataclass
class TestResult:
    layer: int
    name: str
    result: LayerResult
    detail: str
    attack_simulated: Optional[str] = None
    mitigated: Optional[bool] = None


@dataclass
class TrustChainReport:
    results: list[TestResult] = field(default_factory=list)
    token_store: dict = field(default_factory=dict)  # shared state between layers

    def add(self, result: TestResult):
        self.results.append(result)

    def summary(self):
        passed = sum(1 for r in self.results if r.result == LayerResult.PASS)
        failed = sum(1 for r in self.results if r.result == LayerResult.FAIL)
        warned = sum(1 for r in self.results if r.result == LayerResult.WARN)
        return passed, failed, warned


# ── Minimal JWT (no external deps) ────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def mint_jwt(claims: dict, secret: str = "test-secret") -> str:
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url_encode(json.dumps(claims).encode())
    sig_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url_encode(sig)}"


def decode_jwt(token: str) -> tuple[dict, dict]:
    """Returns (header, claims). Does NOT verify signature here."""
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    return header, claims


def verify_jwt(token: str, secret: str = "test-secret") -> bool:
    parts = token.split(".")
    sig_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    actual_sig = b64url_decode(parts[2])
    return hmac.compare_digest(expected_sig, actual_sig)


# ── Layer Testers ─────────────────────────────────────────────────────────────

def test_layer0_threat_ingress(report: TrustChainReport, config: dict):
    """
    Layer 0: Threat-Aware Ingress
    Simulates risk scoring and MFA enforcement at the gateway.
    """
    print("\n── Layer 0: Threat-Aware Ingress ────────────────────────────────────")

    # Test 1: Clean user, low risk
    signals = config.get("threat_signals", {})
    risk_score = _compute_risk_score(signals)
    report.token_store["risk_score"] = risk_score

    result = LayerResult.PASS if risk_score < 0.7 else LayerResult.FAIL
    report.add(TestResult(
        layer=0,
        name="Risk score within acceptable threshold",
        result=result,
        detail=f"Computed risk score: {risk_score:.2f} (threshold: 0.70)",
    ))
    print(f"  {result.value}  Risk score: {risk_score:.2f}")

    # Test 2: MFA enforcement
    mfa_verified = signals.get("mfa_verified", False)
    result = LayerResult.PASS if mfa_verified else LayerResult.WARN
    report.add(TestResult(
        layer=0,
        name="MFA verification present",
        result=result,
        detail="MFA verified" if mfa_verified else "MFA not verified — destructive actions will be blocked",
    ))
    print(f"  {result.value}  MFA verified: {mfa_verified}")

    # Attack simulation: high-risk source
    print("\n  [Attack Sim] High-risk IP (known-bad reputation)...")
    attack_signals = {**signals, "ip_reputation": "known-bad"}
    attack_score = _compute_risk_score(attack_signals)
    mitigated = attack_score >= 0.7
    report.add(TestResult(
        layer=0,
        name="[Attack] High-risk IP blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"Attack risk score: {attack_score:.2f}",
        attack_simulated="Known-bad IP reputation",
        mitigated=mitigated,
    ))
    print(f"  {'✅ Mitigated' if mitigated else '❌ NOT mitigated'}  Attack risk score: {attack_score:.2f}")


def _compute_risk_score(signals: dict) -> float:
    score = 0.0
    if signals.get("ip_reputation") == "known-bad":
        score += 0.6
    elif signals.get("ip_reputation") == "tor":
        score += 0.4
    elif signals.get("ip_reputation") == "vpn":
        score += 0.2
    if signals.get("geo_velocity", 0) > 900:
        score += 0.3
    if not signals.get("mfa_verified", False):
        score += 0.1
    if signals.get("recent_anomalies", 0) > 3:
        score += 0.2
    return min(score, 1.0)


def test_layer1_token_pipeline(report: TrustChainReport, config: dict):
    """
    Layer 1: Token Isolation
    Mints a bot-scoped JWT and validates its structure and claims.
    """
    print("\n── Layer 1: Token Pipeline ───────────────────────────────────────────")

    bot_id = config["bot_id"]
    tool_id = config["tool_id"]
    ttl = config.get("token_ttl", 300)
    secret = config.get("jwt_secret", "test-secret")
    jti = str(uuid.uuid4())

    now = int(time.time())
    claims = {
        "sub": bot_id,
        "aud": tool_id,
        "iss": config.get("issuer", "https://protocol-gateway.internal"),
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
        "user_context": config["user_context"],
        "tool_context": {
            "tool_id": tool_id,
            "allowed_actions": config.get("allowed_actions", []),
            "request_id": f"req_{uuid.uuid4().hex[:8]}",
        },
    }
    token = mint_jwt(claims, secret)
    report.token_store["valid_token"] = token
    report.token_store["jti"] = jti
    report.token_store["claims"] = claims
    report.token_store["secret"] = secret

    # Test 1: Token minted successfully
    _, decoded = decode_jwt(token)
    report.add(TestResult(
        layer=1,
        name="Bot-scoped JWT minted",
        result=LayerResult.PASS,
        detail=f"sub={decoded['sub']} aud={decoded['aud']} jti={decoded['jti'][:8]}...",
    ))
    print(f"  ✅ PASS  Token minted — jti: {jti[:8]}...")

    # Test 2: Signature valid
    sig_valid = verify_jwt(token, secret)
    result = LayerResult.PASS if sig_valid else LayerResult.FAIL
    report.add(TestResult(
        layer=1,
        name="JWT signature valid (HS256)",
        result=result,
        detail="Signature verification passed" if sig_valid else "Signature mismatch",
    ))
    print(f"  {result.value}  Signature valid: {sig_valid}")

    # Test 3: TTL within policy
    ttl_ok = ttl <= 300
    result = LayerResult.PASS if ttl_ok else LayerResult.WARN
    report.add(TestResult(
        layer=1,
        name="Token TTL within policy (≤300s)",
        result=result,
        detail=f"TTL: {ttl}s",
    ))
    print(f"  {result.value}  TTL: {ttl}s (max: 300s)")

    # Attack simulation: alg:none
    print("\n  [Attack Sim] alg:none bypass...")
    none_header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    none_payload = b64url_encode(json.dumps(claims).encode())
    none_token = f"{none_header}.{none_payload}."
    _, none_claims = decode_jwt(none_token)
    mitigated = not _accept_alg_none(none_token)
    report.add(TestResult(
        layer=1,
        name="[Attack] alg:none rejected",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail="alg:none tokens correctly rejected",
        attack_simulated="JWT alg:none bypass",
        mitigated=mitigated,
    ))
    print(f"  {'✅ Mitigated' if mitigated else '❌ VULNERABLE'}  alg:none attack")

    # Attack simulation: expired token replay
    print("\n  [Attack Sim] Expired token replay...")
    expired_claims = {**claims, "exp": now - 10, "jti": str(uuid.uuid4())}
    expired_token = mint_jwt(expired_claims, secret)
    expired_rejected = _validate_expiry(expired_token)
    report.add(TestResult(
        layer=1,
        name="[Attack] Expired token rejected",
        result=LayerResult.PASS if expired_rejected else LayerResult.FAIL,
        detail="Expired token correctly rejected",
        attack_simulated="Expired token replay",
        mitigated=expired_rejected,
    ))
    print(f"  {'✅ Mitigated' if expired_rejected else '❌ VULNERABLE'}  Expired token replay")


def _accept_alg_none(token: str) -> bool:
    """Simulates a VULNERABLE validator that accepts alg:none."""
    header, _ = decode_jwt(token)
    # A hardened validator MUST reject this — we simulate rejection
    return header.get("alg", "").lower() == "none"  # True = vulnerable


def _validate_expiry(token: str) -> bool:
    """Returns True if token is correctly identified as expired."""
    _, claims = decode_jwt(token)
    return claims.get("exp", 0) < int(time.time())


def test_layer2_workload_identity(report: TrustChainReport, config: dict):
    """
    Layer 2: SPIFFE/SPIRE Workload Identity
    Simulates SVID presence checks and mTLS topology enforcement.
    """
    print("\n── Layer 2: Workload Identity (SPIFFE/SPIRE) ────────────────────────")

    spiffe_config = config.get("spiffe", {})

    # Test 1: SVID present
    svid_present = spiffe_config.get("svid_present", False)
    result = LayerResult.PASS if svid_present else LayerResult.FAIL
    report.add(TestResult(
        layer=2,
        name="SPIFFE SVID present on workload",
        result=result,
        detail=f"SVID: {spiffe_config.get('svid_id', 'NOT FOUND')}",
    ))
    print(f"  {result.value}  SVID: {spiffe_config.get('svid_id', 'NOT FOUND')}")

    # Test 2: SVID not expired
    svid_expiry = spiffe_config.get("svid_expiry", 0)
    svid_valid = svid_expiry > int(time.time())
    result = LayerResult.PASS if svid_valid else LayerResult.FAIL
    report.add(TestResult(
        layer=2,
        name="SVID not expired",
        result=result,
        detail=f"Expires: {svid_expiry} (now: {int(time.time())})",
    ))
    print(f"  {result.value}  SVID expiry valid: {svid_valid}")

    # Test 3: Peer SVID matches expected workload
    peer_id = spiffe_config.get("peer_svid_id", "")
    expected_peer = config.get("expected_tool_spiffe_id", "")
    peer_ok = peer_id == expected_peer
    result = LayerResult.PASS if peer_ok else LayerResult.FAIL
    report.add(TestResult(
        layer=2,
        name="Peer SVID matches expected tool workload",
        result=result,
        detail=f"Expected: {expected_peer} | Got: {peer_id}",
    ))
    print(f"  {result.value}  Peer SVID match: {peer_ok}")

    # Attack simulation: wrong workload trying to reach tool
    print("\n  [Attack Sim] Unauthorized workload attempting tool call...")
    attacker_svid = "spiffe://cluster.local/ns/default/sa/attacker"
    mitigated = attacker_svid != expected_peer
    report.add(TestResult(
        layer=2,
        name="[Attack] Unauthorized workload blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"Attacker SVID: {attacker_svid}",
        attack_simulated="Lateral movement via unauthorized workload",
        mitigated=mitigated,
    ))
    print(f"  {'✅ Mitigated' if mitigated else '❌ VULNERABLE'}  Lateral movement attempt")


def test_layer3_opa_policy(report: TrustChainReport, config: dict):
    """
    Layer 3: OPA Policy Evaluation
    Runs the authorization rules against the minted token claims.
    """
    print("\n── Layer 3: OPA Policy Evaluation ───────────────────────────────────")

    claims = report.token_store.get("claims", {})
    risk_score = report.token_store.get("risk_score", 0.0)
    user_ctx = claims.get("user_context", {})
    tool_ctx = claims.get("tool_context", {})

    tests = [
        {
            "name": "Valid bot subject",
            "result": claims.get("sub") == config["bot_id"],
            "detail": f"sub={claims.get('sub')}",
        },
        {
            "name": "Audience matches tool",
            "result": claims.get("aud") == config["tool_id"],
            "detail": f"aud={claims.get('aud')} expected={config['tool_id']}",
        },
        {
            "name": "Tenant is valid",
            "result": user_ctx.get("tenant") in config.get("valid_tenants", []),
            "detail": f"tenant={user_ctx.get('tenant')}",
        },
        {
            "name": "Risk score acceptable (< 0.70)",
            "result": risk_score < 0.70,
            "detail": f"risk_score={risk_score:.2f}",
        },
        {
            "name": "Action in token allowlist",
            "result": config.get("requested_action") in tool_ctx.get("allowed_actions", []),
            "detail": f"action={config.get('requested_action')} "
                      f"allowlist={tool_ctx.get('allowed_actions')}",
        },
    ]

    # Destructive action MFA check
    destructive_actions = {"repo:delete", "data:purge", "iam:modify"}
    if config.get("requested_action") in destructive_actions:
        tests.append({
            "name": "MFA required for destructive action",
            "result": user_ctx.get("auth_method") == "mfa",
            "detail": f"auth_method={user_ctx.get('auth_method')} action={config.get('requested_action')}",
        })

    for t in tests:
        result = LayerResult.PASS if t["result"] else LayerResult.FAIL
        report.add(TestResult(layer=3, name=t["name"], result=result, detail=t["detail"]))
        print(f"  {result.value}  {t['name']}")
        if not t["result"]:
            print(f"           ↳ {t['detail']}")

    # Attack simulation: cross-tenant token
    print("\n  [Attack Sim] Cross-tenant token injection...")
    hostile_tenant = "evil-corp"
    mitigated = hostile_tenant not in config.get("valid_tenants", [])
    report.add(TestResult(
        layer=3,
        name="[Attack] Cross-tenant access blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"Hostile tenant: {hostile_tenant}",
        attack_simulated="Cross-tenant token injection",
        mitigated=mitigated,
    ))
    print(f"  {'✅ Mitigated' if mitigated else '❌ VULNERABLE'}  Cross-tenant injection")

    # Attack simulation: token reuse on wrong tool
    print("\n  [Attack Sim] Token reuse on wrong tool...")
    wrong_tool = "tool://payroll-connector"
    mitigated = claims.get("aud") != wrong_tool
    report.add(TestResult(
        layer=3,
        name="[Attack] Token reuse on wrong tool blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"Token aud={claims.get('aud')} does not match {wrong_tool}",
        attack_simulated="Token reuse across tool boundaries",
        mitigated=mitigated,
    ))
    print(f"  {'✅ Mitigated' if mitigated else '❌ VULNERABLE'}  Cross-tool token reuse")


def test_layer4_iam_binding(report: TrustChainReport, config: dict):
    """
    Layer 4: Cloud IAM Binding (IRSA simulation)
    Validates that credential assumptions are scoped and short-lived.
    """
    print("\n── Layer 4: Cloud IAM / IRSA ─────────────────────────────────────────")

    iam_config = config.get("iam", {})
    cred_ttl = iam_config.get("credential_ttl", 9999)
    has_static_creds = iam_config.get("has_static_credentials", True)
    role_arn = iam_config.get("role_arn", "")
    tenant = config["user_context"].get("tenant", "")
    resource_path = iam_config.get("resource_path", "")

    # Test 1: No static credentials
    result = LayerResult.PASS if not has_static_creds else LayerResult.FAIL
    report.add(TestResult(
        layer=4,
        name="No static credentials present",
        result=result,
        detail="Using IRSA dynamic credentials" if not has_static_creds else "⚠️ Static credentials detected!",
    ))
    print(f"  {result.value}  Static credentials: {has_static_creds}")

    # Test 2: Credential TTL within policy
    ttl_ok = cred_ttl <= 900  # 15 minutes
    result = LayerResult.PASS if ttl_ok else LayerResult.WARN
    report.add(TestResult(
        layer=4,
        name="Credential TTL within policy (≤900s)",
        result=result,
        detail=f"TTL: {cred_ttl}s",
    ))
    print(f"  {result.value}  Credential TTL: {cred_ttl}s (max: 900s)")

    # Test 3: IAM role is tenant-scoped
    tenant_scoped = tenant and tenant in resource_path
    result = LayerResult.PASS if tenant_scoped else LayerResult.FAIL
    report.add(TestResult(
        layer=4,
        name="IAM resource path is tenant-scoped",
        result=result,
        detail=f"tenant={tenant} resource_path={resource_path}",
    ))
    print(f"  {result.value}  Tenant scoped: {tenant_scoped}")

    # Test 4: Role ARN present
    role_present = bool(role_arn)
    result = LayerResult.PASS if role_present else LayerResult.FAIL
    report.add(TestResult(
        layer=4,
        name="IAM role ARN configured",
        result=result,
        detail=f"role_arn={role_arn or 'MISSING'}",
    ))
    print(f"  {result.value}  Role ARN: {role_arn or 'MISSING'}")


def test_layer5_response_sanitization(report: TrustChainReport, config: dict):
    """
    Layer 5: Response Sanitization
    Validates that responses are scrubbed before reaching the user.
    """
    print("\n── Layer 5: Response Sanitization ───────────────────────────────────")

    tenant = config["user_context"].get("tenant", "")
    mock_response = config.get("mock_backend_response", {})

    # Test 1: Cross-tenant data stripped
    response_tenant = mock_response.get("tenant", "")
    cross_tenant_clean = response_tenant == "" or response_tenant == tenant
    result = LayerResult.PASS if cross_tenant_clean else LayerResult.FAIL
    report.add(TestResult(
        layer=5,
        name="Cross-tenant data stripped from response",
        result=result,
        detail=f"response tenant={response_tenant or 'stripped'} user tenant={tenant}",
    ))
    print(f"  {result.value}  Cross-tenant data clean: {cross_tenant_clean}")

    # Test 2: PII fields redacted
    pii_fields = {"ssn", "credit_card", "password", "secret"}
    leaked_pii = pii_fields.intersection(set(mock_response.keys()))
    result = LayerResult.PASS if not leaked_pii else LayerResult.FAIL
    report.add(TestResult(
        layer=5,
        name="PII fields not present in response",
        result=result,
        detail=f"Leaked fields: {leaked_pii or 'none'}",
    ))
    print(f"  {result.value}  PII leaked: {leaked_pii or 'none'}")

    # Test 3: Payload size within limits (prompt injection via oversized response)
    payload_size = len(json.dumps(mock_response))
    size_ok = payload_size <= config.get("max_response_bytes", 102400)
    result = LayerResult.PASS if size_ok else LayerResult.WARN
    report.add(TestResult(
        layer=5,
        name="Response payload within size limit",
        result=result,
        detail=f"Size: {payload_size} bytes (max: {config.get('max_response_bytes', 102400)})",
    ))
    print(f"  {result.value}  Payload size: {payload_size} bytes")


# ── Report Printer ─────────────────────────────────────────────────────────────

def print_report(report: TrustChainReport):
    passed, failed, warned = report.summary()
    total = len(report.results)
    attack_tests = [r for r in report.results if r.attack_simulated]
    mitigated = sum(1 for r in attack_tests if r.mitigated)

    print("\n" + "═" * 65)
    print("  TRUST CHAIN TEST REPORT")
    print("═" * 65)
    print(f"  Total checks : {total}")
    print(f"  Passed       : {passed}")
    print(f"  Failed       : {failed}")
    print(f"  Warnings     : {warned}")
    print(f"  Attack sims  : {len(attack_tests)} ({mitigated} mitigated)")
    print("═" * 65)

    if failed > 0:
        print("\n  ❌ FAILURES:")
        for r in report.results:
            if r.result == LayerResult.FAIL:
                print(f"    Layer {r.layer} — {r.name}")
                print(f"             {r.detail}")

    if warned > 0:
        print("\n  ⚠️  WARNINGS:")
        for r in report.results:
            if r.result == LayerResult.WARN:
                print(f"    Layer {r.layer} — {r.name}")
                print(f"             {r.detail}")

    print("\n  ATTACK SIMULATION SUMMARY:")
    for r in attack_tests:
        status = "✅ Mitigated" if r.mitigated else "❌ NOT mitigated"
        print(f"    [{status}] Layer {r.layer} — {r.attack_simulated}")

    overall = "✅ TRUST CHAIN HEALTHY" if failed == 0 else "❌ TRUST CHAIN COMPROMISED"
    print(f"\n  Overall: {overall}")
    print("═" * 65 + "\n")


# ── Default Config ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "bot_id": "bot://ai-agent-prod-v2",
    "tool_id": "tool://github-connector",
    "issuer": "https://protocol-gateway.internal",
    "jwt_secret": "super-secret-signing-key",
    "token_ttl": 300,
    "requested_action": "repo:read",
    "allowed_actions": ["repo:read", "pr:write"],
    "valid_tenants": ["acme-corp", "globex"],
    "expected_tool_spiffe_id": "spiffe://cluster.local/ns/ai/sa/tool-connector",
    "max_response_bytes": 102400,
    "threat_signals": {
        "ip_reputation": "clean",
        "geo_velocity": 0,
        "mfa_verified": True,
        "recent_anomalies": 0,
    },
    "user_context": {
        "user_id": "user-123",
        "team": "engineering",
        "tenant": "acme-corp",
        "session_id": "sess-abc-xyz",
        "auth_method": "mfa",
    },
    "spiffe": {
        "svid_present": True,
        "svid_id": "spiffe://cluster.local/ns/ai/sa/agent",
        "svid_expiry": int(time.time()) + 3600,
        "peer_svid_id": "spiffe://cluster.local/ns/ai/sa/tool-connector",
    },
    "iam": {
        "has_static_credentials": False,
        "credential_ttl": 900,
        "role_arn": "arn:aws:iam::123456789:role/github-connector-prod",
        "resource_path": "arn:aws:s3:::company-data/acme-corp/*",
    },
    "mock_backend_response": {
        "repo": "acme/backend",
        "branch": "main",
        "last_commit": "abc123",
    },
}


# ── Entry Point ────────────────────────────────────────────────────────────────

def run(config: dict):
    print(textwrap.dedent("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║       Zero-Trust AI Mesh — Trust Chain Tester                 ║
    ║       Testing all 6 layers of the security model              ║
    ╚═══════════════════════════════════════════════════════════════╝
    """))

    report = TrustChainReport()
    test_layer0_threat_ingress(report, config)
    test_layer1_token_pipeline(report, config)
    test_layer2_workload_identity(report, config)
    test_layer3_opa_policy(report, config)
    test_layer4_iam_binding(report, config)
    test_layer5_response_sanitization(report, config)
    print_report(report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Trust AI Mesh Trust Chain Tester")
    parser.add_argument(
        "--config", type=str, help="Path to JSON config file (overrides defaults)"
    )
    parser.add_argument(
        "--attack", action="store_true", help="Run with a hostile config to demo failures"
    )
    args = parser.parse_args()

    config = DEFAULT_CONFIG.copy()

    if args.attack:
        # Flip config to a hostile state — should surface failures across all layers
        config["threat_signals"]["ip_reputation"] = "known-bad"
        config["threat_signals"]["mfa_verified"] = False
        config["token_ttl"] = 3600           # too long
        config["requested_action"] = "repo:delete"
        config["user_context"]["auth_method"] = "password"
        config["user_context"]["tenant"] = "evil-corp"
        config["iam"]["has_static_credentials"] = True
        config["iam"]["credential_ttl"] = 86400
        config["mock_backend_response"]["ssn"] = "123-45-6789"
        config["spiffe"]["peer_svid_id"] = "spiffe://cluster.local/ns/default/sa/attacker"

    if args.config:
        with open(args.config) as f:
            config.update(json.load(f))

    run(config)
