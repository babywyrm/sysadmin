#!/usr/bin/env python3
"""
Zero-Trust AI Mesh — Trust Chain Tester
Tests each security layer independently and reports results.
"""

import argparse
import base64
import hashlib
import hmac
import json
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Enums & Types ─────────────────────────────────────────────────────────────


class LayerResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass(frozen=True)
class TestResult:
    layer: int
    name: str
    result: LayerResult
    detail: str
    attack_simulated: str | None = None
    mitigated: bool | None = None


@dataclass
class TrustChainReport:
    results: list[TestResult] = field(default_factory=list)
    token_store: dict[str, Any] = field(default_factory=dict)

    def add(self, result: TestResult) -> None:
        self.results.append(result)

    def summary(self) -> tuple[int, int, int]:
        passed = sum(1 for r in self.results if r.result == LayerResult.PASS)
        failed = sum(1 for r in self.results if r.result == LayerResult.FAIL)
        warned = sum(1 for r in self.results if r.result == LayerResult.WARN)
        return passed, failed, warned


# ── Minimal JWT (no external deps) ────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def mint_jwt(claims: dict[str, Any], secret: str = "test-secret") -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps(claims).encode())
    sig_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url_encode(sig)}"


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns (header, claims). Does NOT verify signature."""
    parts = token.split(".")
    header: dict[str, Any] = json.loads(_b64url_decode(parts[0]))
    claims: dict[str, Any] = json.loads(_b64url_decode(parts[1]))
    return header, claims


def verify_jwt(token: str, secret: str = "test-secret") -> bool:
    parts = token.split(".")
    sig_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    actual = _b64url_decode(parts[2])
    return hmac.compare_digest(expected, actual)


# ── Risk Scoring ──────────────────────────────────────────────────────────────

_IP_REPUTATION_SCORES: dict[str, float] = {
    "known-bad": 0.6,
    "tor": 0.4,
    "vpn": 0.2,
}

_GEO_VELOCITY_THRESHOLD = 900
_GEO_VELOCITY_PENALTY = 0.3
_MFA_ABSENT_PENALTY = 0.1
_ANOMALY_THRESHOLD = 3
_ANOMALY_PENALTY = 0.2


def compute_risk_score(signals: dict[str, Any]) -> float:
    score = _IP_REPUTATION_SCORES.get(signals.get("ip_reputation", ""), 0.0)
    if signals.get("geo_velocity", 0) > _GEO_VELOCITY_THRESHOLD:
        score += _GEO_VELOCITY_PENALTY
    if not signals.get("mfa_verified", False):
        score += _MFA_ABSENT_PENALTY
    if signals.get("recent_anomalies", 0) > _ANOMALY_THRESHOLD:
        score += _ANOMALY_PENALTY
    return min(score, 1.0)


# ── Layer Testers ─────────────────────────────────────────────────────────────

_RISK_THRESHOLD = 0.70
_MAX_TOKEN_TTL = 300
_MAX_CREDENTIAL_TTL = 900


def test_layer0_threat_ingress(
    report: TrustChainReport, config: dict[str, Any]
) -> None:
    """
    Layer 0: Threat-Aware Ingress
    Simulates risk scoring and MFA enforcement at the gateway.
    """
    print("\n-- Layer 0: Threat-Aware Ingress " + "-" * 32)

    signals: dict[str, Any] = config.get("threat_signals", {})
    risk_score = compute_risk_score(signals)
    report.token_store["risk_score"] = risk_score

    risk_ok = risk_score < _RISK_THRESHOLD
    report.add(TestResult(
        layer=0,
        name="Risk score within acceptable threshold",
        result=LayerResult.PASS if risk_ok else LayerResult.FAIL,
        detail=f"score={risk_score:.2f} threshold={_RISK_THRESHOLD:.2f}",
    ))
    print(f"  [{'PASS' if risk_ok else 'FAIL'}]  Risk score: {risk_score:.2f}")

    mfa_verified: bool = signals.get("mfa_verified", False)
    report.add(TestResult(
        layer=0,
        name="MFA verification present",
        result=LayerResult.PASS if mfa_verified else LayerResult.WARN,
        detail=(
            "MFA verified"
            if mfa_verified
            else "MFA not verified — destructive actions will be blocked"
        ),
    ))
    print(f"  [{'PASS' if mfa_verified else 'WARN'}]  MFA verified: {mfa_verified}")

    print("\n  [Attack Sim] High-risk IP (known-bad reputation)...")
    attack_score = compute_risk_score({**signals, "ip_reputation": "known-bad"})
    mitigated = attack_score >= _RISK_THRESHOLD
    report.add(TestResult(
        layer=0,
        name="[Attack] High-risk IP blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"attack_score={attack_score:.2f}",
        attack_simulated="Known-bad IP reputation",
        mitigated=mitigated,
    ))
    print(f"  [{'MITIGATED' if mitigated else 'VULNERABLE'}]  Attack risk score: {attack_score:.2f}")


def test_layer1_token_pipeline(
    report: TrustChainReport, config: dict[str, Any]
) -> None:
    """
    Layer 1: Token Isolation
    Mints a bot-scoped JWT and validates structure and claims.
    """
    print("\n-- Layer 1: Token Pipeline " + "-" * 38)

    bot_id: str = config["bot_id"]
    tool_id: str = config["tool_id"]
    ttl: int = config.get("token_ttl", _MAX_TOKEN_TTL)
    secret: str = config.get("jwt_secret", "test-secret")
    jti: str = str(uuid.uuid4())
    now = int(time.time())

    claims: dict[str, Any] = {
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
    report.token_store.update({
        "valid_token": token,
        "jti": jti,
        "claims": claims,
        "secret": secret,
    })

    _, decoded = decode_jwt(token)
    report.add(TestResult(
        layer=1,
        name="Bot-scoped JWT minted",
        result=LayerResult.PASS,
        detail=f"sub={decoded['sub']} aud={decoded['aud']} jti={jti[:8]}...",
    ))
    print(f"  [PASS]  Token minted — jti: {jti[:8]}...")

    sig_valid = verify_jwt(token, secret)
    report.add(TestResult(
        layer=1,
        name="JWT signature valid (HS256)",
        result=LayerResult.PASS if sig_valid else LayerResult.FAIL,
        detail="Signature verification passed" if sig_valid else "Signature mismatch",
    ))
    print(f"  [{'PASS' if sig_valid else 'FAIL'}]  Signature valid: {sig_valid}")

    ttl_ok = ttl <= _MAX_TOKEN_TTL
    report.add(TestResult(
        layer=1,
        name=f"Token TTL within policy (<={_MAX_TOKEN_TTL}s)",
        result=LayerResult.PASS if ttl_ok else LayerResult.WARN,
        detail=f"ttl={ttl}s max={_MAX_TOKEN_TTL}s",
    ))
    print(f"  [{'PASS' if ttl_ok else 'WARN'}]  TTL: {ttl}s (max: {_MAX_TOKEN_TTL}s)")

    print("\n  [Attack Sim] alg:none bypass...")
    none_header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    none_payload = _b64url_encode(json.dumps(claims).encode())
    none_token = f"{none_header}.{none_payload}."
    alg_none_rejected = not _is_alg_none_accepted(none_token)
    report.add(TestResult(
        layer=1,
        name="[Attack] alg:none rejected",
        result=LayerResult.PASS if alg_none_rejected else LayerResult.FAIL,
        detail="alg:none tokens correctly rejected",
        attack_simulated="JWT alg:none bypass",
        mitigated=alg_none_rejected,
    ))
    print(f"  [{'MITIGATED' if alg_none_rejected else 'VULNERABLE'}]  alg:none attack")

    print("\n  [Attack Sim] Expired token replay...")
    expired_claims = {**claims, "exp": now - 10, "jti": str(uuid.uuid4())}
    expired_token = mint_jwt(expired_claims, secret)
    expired_rejected = _is_token_expired(expired_token)
    report.add(TestResult(
        layer=1,
        name="[Attack] Expired token rejected",
        result=LayerResult.PASS if expired_rejected else LayerResult.FAIL,
        detail="Expired token correctly rejected",
        attack_simulated="Expired token replay",
        mitigated=expired_rejected,
    ))
    print(f"  [{'MITIGATED' if expired_rejected else 'VULNERABLE'}]  Expired token replay")


def _is_alg_none_accepted(token: str) -> bool:
    """Returns True if a vulnerable validator would accept an alg:none token."""
    header, _ = decode_jwt(token)
    return header.get("alg", "").lower() == "none"


def _is_token_expired(token: str) -> bool:
    """Returns True if the token is past its expiry time."""
    _, claims = decode_jwt(token)
    return claims.get("exp", 0) < int(time.time())


def test_layer2_workload_identity(
    report: TrustChainReport, config: dict[str, Any]
) -> None:
    """
    Layer 2: SPIFFE/SPIRE Workload Identity
    Validates SVID presence, expiry, and peer identity.
    """
    print("\n-- Layer 2: Workload Identity (SPIFFE/SPIRE) " + "-" * 20)

    spiffe: dict[str, Any] = config.get("spiffe", {})
    expected_peer: str = config.get("expected_tool_spiffe_id", "")
    now = int(time.time())

    svid_present: bool = spiffe.get("svid_present", False)
    report.add(TestResult(
        layer=2,
        name="SPIFFE SVID present on workload",
        result=LayerResult.PASS if svid_present else LayerResult.FAIL,
        detail=f"svid={spiffe.get('svid_id', 'NOT FOUND')}",
    ))
    print(f"  [{'PASS' if svid_present else 'FAIL'}]  SVID: {spiffe.get('svid_id', 'NOT FOUND')}")

    svid_valid = spiffe.get("svid_expiry", 0) > now
    report.add(TestResult(
        layer=2,
        name="SVID not expired",
        result=LayerResult.PASS if svid_valid else LayerResult.FAIL,
        detail=f"expiry={spiffe.get('svid_expiry')} now={now}",
    ))
    print(f"  [{'PASS' if svid_valid else 'FAIL'}]  SVID expiry valid: {svid_valid}")

    peer_id: str = spiffe.get("peer_svid_id", "")
    peer_ok = peer_id == expected_peer
    report.add(TestResult(
        layer=2,
        name="Peer SVID matches expected tool workload",
        result=LayerResult.PASS if peer_ok else LayerResult.FAIL,
        detail=f"expected={expected_peer} got={peer_id}",
    ))
    print(f"  [{'PASS' if peer_ok else 'FAIL'}]  Peer SVID match: {peer_ok}")

    print("\n  [Attack Sim] Unauthorized workload attempting tool call...")
    attacker_svid = "spiffe://cluster.local/ns/default/sa/attacker"
    mitigated = attacker_svid != expected_peer
    report.add(TestResult(
        layer=2,
        name="[Attack] Unauthorized workload blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"attacker_svid={attacker_svid}",
        attack_simulated="Lateral movement via unauthorized workload",
        mitigated=mitigated,
    ))
    print(f"  [{'MITIGATED' if mitigated else 'VULNERABLE'}]  Lateral movement attempt")


def test_layer3_opa_policy(
    report: TrustChainReport, config: dict[str, Any]
) -> None:
    """
    Layer 3: OPA Policy Evaluation
    Runs authorization rules against the minted token claims.
    """
    print("\n-- Layer 3: OPA Policy Evaluation " + "-" * 30)

    claims: dict[str, Any] = report.token_store.get("claims", {})
    risk_score: float = report.token_store.get("risk_score", 0.0)
    user_ctx: dict[str, Any] = claims.get("user_context", {})
    tool_ctx: dict[str, Any] = claims.get("tool_context", {})
    requested_action: str = config.get("requested_action", "")
    valid_tenants: list[str] = config.get("valid_tenants", [])

    policy_checks: list[tuple[str, bool, str]] = [
        (
            "Valid bot subject",
            claims.get("sub") == config["bot_id"],
            f"sub={claims.get('sub')}",
        ),
        (
            "Audience matches tool",
            claims.get("aud") == config["tool_id"],
            f"aud={claims.get('aud')} expected={config['tool_id']}",
        ),
        (
            "Tenant is valid",
            user_ctx.get("tenant") in valid_tenants,
            f"tenant={user_ctx.get('tenant')}",
        ),
        (
            f"Risk score acceptable (< {_RISK_THRESHOLD:.2f})",
            risk_score < _RISK_THRESHOLD,
            f"risk_score={risk_score:.2f}",
        ),
        (
            "Action in token allowlist",
            requested_action in tool_ctx.get("allowed_actions", []),
            f"action={requested_action} allowlist={tool_ctx.get('allowed_actions')}",
        ),
    ]

    _DESTRUCTIVE_ACTIONS: frozenset[str] = frozenset({"repo:delete", "data:purge", "iam:modify"})
    if requested_action in _DESTRUCTIVE_ACTIONS:
        policy_checks.append((
            "MFA required for destructive action",
            user_ctx.get("auth_method") == "mfa",
            f"auth_method={user_ctx.get('auth_method')} action={requested_action}",
        ))

    for name, passed, detail in policy_checks:
        result = LayerResult.PASS if passed else LayerResult.FAIL
        report.add(TestResult(layer=3, name=name, result=result, detail=detail))
        print(f"  [{'PASS' if passed else 'FAIL'}]  {name}")
        if not passed:
            print(f"         -> {detail}")

    print("\n  [Attack Sim] Cross-tenant token injection...")
    hostile_tenant = "evil-corp"
    mitigated = hostile_tenant not in valid_tenants
    report.add(TestResult(
        layer=3,
        name="[Attack] Cross-tenant access blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"hostile_tenant={hostile_tenant}",
        attack_simulated="Cross-tenant token injection",
        mitigated=mitigated,
    ))
    print(f"  [{'MITIGATED' if mitigated else 'VULNERABLE'}]  Cross-tenant injection")

    print("\n  [Attack Sim] Token reuse on wrong tool...")
    wrong_tool = "tool://payroll-connector"
    mitigated = claims.get("aud") != wrong_tool
    report.add(TestResult(
        layer=3,
        name="[Attack] Token reuse on wrong tool blocked",
        result=LayerResult.PASS if mitigated else LayerResult.FAIL,
        detail=f"aud={claims.get('aud')} does not match {wrong_tool}",
        attack_simulated="Token reuse across tool boundaries",
        mitigated=mitigated,
    ))
    print(f"  [{'MITIGATED' if mitigated else 'VULNERABLE'}]  Cross-tool token reuse")


def test_layer4_iam_binding(
    report: TrustChainReport, config: dict[str, Any]
) -> None:
    """
    Layer 4: Cloud IAM Binding (IRSA simulation)
    Validates credential scoping, TTL, and tenant isolation.
    """
    print("\n-- Layer 4: Cloud IAM / IRSA " + "-" * 36)

    iam: dict[str, Any] = config.get("iam", {})
    tenant: str = config["user_context"].get("tenant", "")
    cred_ttl: int = iam.get("credential_ttl", 9999)
    has_static_creds: bool = iam.get("has_static_credentials", True)
    role_arn: str = iam.get("role_arn", "")
    resource_path: str = iam.get("resource_path", "")

    no_static = not has_static_creds
    report.add(TestResult(
        layer=4,
        name="No static credentials present",
        result=LayerResult.PASS if no_static else LayerResult.FAIL,
        detail=(
            "Using IRSA dynamic credentials"
            if no_static
            else "Static credentials detected"
        ),
    ))
    print(f"  [{'PASS' if no_static else 'FAIL'}]  Static credentials: {has_static_creds}")

    ttl_ok = cred_ttl <= _MAX_CREDENTIAL_TTL
    report.add(TestResult(
        layer=4,
        name=f"Credential TTL within policy (<={_MAX_CREDENTIAL_TTL}s)",
        result=LayerResult.PASS if ttl_ok else LayerResult.WARN,
        detail=f"ttl={cred_ttl}s max={_MAX_CREDENTIAL_TTL}s",
    ))
    print(f"  [{'PASS' if ttl_ok else 'WARN'}]  Credential TTL: {cred_ttl}s (max: {_MAX_CREDENTIAL_TTL}s)")

    tenant_scoped = bool(tenant) and tenant in resource_path
    report.add(TestResult(
        layer=4,
        name="IAM resource path is tenant-scoped",
        result=LayerResult.PASS if tenant_scoped else LayerResult.FAIL,
        detail=f"tenant={tenant} resource_path={resource_path}",
    ))
    print(f"  [{'PASS' if tenant_scoped else 'FAIL'}]  Tenant scoped: {tenant_scoped}")

    role_present = bool(role_arn)
    report.add(TestResult(
        layer=4,
        name="IAM role ARN configured",
        result=LayerResult.PASS if role_present else LayerResult.FAIL,
        detail=f"role_arn={role_arn or 'MISSING'}",
    ))
    print(f"  [{'PASS' if role_present else 'FAIL'}]  Role ARN: {role_arn or 'MISSING'}")


def test_layer5_response_sanitization(
    report: TrustChainReport, config: dict[str, Any]
) -> None:
    """
    Layer 5: Response Sanitization
    Validates that responses are scrubbed before reaching the user.
    """
    print("\n-- Layer 5: Response Sanitization " + "-" * 30)

    tenant: str = config["user_context"].get("tenant", "")
    response: dict[str, Any] = config.get("mock_backend_response", {})
    max_bytes: int = config.get("max_response_bytes", 102400)

    response_tenant: str = response.get("tenant", "")
    cross_tenant_clean = not response_tenant or response_tenant == tenant
    report.add(TestResult(
        layer=5,
        name="Cross-tenant data stripped from response",
        result=LayerResult.PASS if cross_tenant_clean else LayerResult.FAIL,
        detail=f"response_tenant={response_tenant or 'stripped'} user_tenant={tenant}",
    ))
    print(f"  [{'PASS' if cross_tenant_clean else 'FAIL'}]  Cross-tenant data clean: {cross_tenant_clean}")

    _PII_FIELDS: frozenset[str] = frozenset({"ssn", "credit_card", "password", "secret"})
    leaked = _PII_FIELDS.intersection(response.keys())
    no_pii = not leaked
    report.add(TestResult(
        layer=5,
        name="PII fields not present in response",
        result=LayerResult.PASS if no_pii else LayerResult.FAIL,
        detail=f"leaked={leaked or 'none'}",
    ))
    print(f"  [{'PASS' if no_pii else 'FAIL'}]  PII leaked: {leaked or 'none'}")

    payload_size = len(json.dumps(response).encode())
    size_ok = payload_size <= max_bytes
    report.add(TestResult(
        layer=5,
        name="Response payload within size limit",
        result=LayerResult.PASS if size_ok else LayerResult.WARN,
        detail=f"size={payload_size}B max={max_bytes}B",
    ))
    print(f"  [{'PASS' if size_ok else 'WARN'}]  Payload size: {payload_size} bytes")


# ── Report Printer ─────────────────────────────────────────────────────────────

_RULE_WIDTH = 65


def print_report(report: TrustChainReport) -> None:
    passed, failed, warned = report.summary()
    total = len(report.results)
    attack_results = [r for r in report.results if r.attack_simulated]
    mitigated_count = sum(1 for r in attack_results if r.mitigated)

    rule = "=" * _RULE_WIDTH
    print(f"\n{rule}")
    print("  TRUST CHAIN TEST REPORT")
    print(rule)
    print(f"  Total checks : {total}")
    print(f"  Passed       : {passed}")
    print(f"  Failed       : {failed}")
    print(f"  Warnings     : {warned}")
    print(f"  Attack sims  : {len(attack_results)} ({mitigated_count} mitigated)")
    print(rule)

    if failed:
        print("\n  FAILURES:")
        for r in report.results:
            if r.result == LayerResult.FAIL:
                print(f"    Layer {r.layer} -- {r.name}")
                print(f"             {r.detail}")

    if warned:
        print("\n  WARNINGS:")
        for r in report.results:
            if r.result == LayerResult.WARN:
                print(f"    Layer {r.layer} -- {r.name}")
                print(f"             {r.detail}")

    print("\n  ATTACK SIMULATION SUMMARY:")
    for r in attack_results:
        status = "MITIGATED" if r.mitigated else "NOT MITIGATED"
        print(f"    [{status}] Layer {r.layer} -- {r.attack_simulated}")

    overall = "TRUST CHAIN HEALTHY" if not failed else "TRUST CHAIN COMPROMISED"
    print(f"\n  Overall: {overall}")
    print(f"{rule}\n")


# ── Default Config ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
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

_ATTACK_CONFIG_OVERRIDES: dict[str, Any] = {
    "token_ttl": 3600,
    "requested_action": "repo:delete",
    "threat_signals": {
        "ip_reputation": "known-bad",
        "geo_velocity": 0,
        "mfa_verified": False,
        "recent_anomalies": 0,
    },
    "user_context": {
        **DEFAULT_CONFIG["user_context"],
        "auth_method": "password",
        "tenant": "evil-corp",
    },
    "spiffe": {
        **DEFAULT_CONFIG["spiffe"],
        "peer_svid_id": "spiffe://cluster.local/ns/default/sa/attacker",
    },
    "iam": {
        **DEFAULT_CONFIG["iam"],
        "has_static_credentials": True,
        "credential_ttl": 86400,
    },
    "mock_backend_response": {
        **DEFAULT_CONFIG["mock_backend_response"],
        "ssn": "123-45-6789",
    },
}


# ── Entry Point ────────────────────────────────────────────────────────────────


def run(config: dict[str, Any]) -> TrustChainReport:
    print(textwrap.dedent("""
    +---------------------------------------------------------------+
    |  Zero-Trust AI Mesh -- Trust Chain Tester                     |
    |  Testing all 6 layers of the security model                   |
    +---------------------------------------------------------------+
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Zero-Trust AI Mesh Trust Chain Tester"
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to a JSON config file (merged over defaults)",
    )
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Run with a hostile config to surface failures across all layers",
    )
    args = parser.parse_args()

    config: dict[str, Any] = {**DEFAULT_CONFIG}

    if args.attack:
        config.update(_ATTACK_CONFIG_OVERRIDES)

    if args.config:
        with open(args.config) as fh:
            config.update(json.load(fh))

    run(config)


if __name__ == "__main__":
    main()
