
# Zero-Trust AI Mesh — Trust Chain Tester

A self-contained test harness that validates each layer of a zero-trust
security model for AI agent-to-tool communication. No external dependencies
beyond the Python standard library.

---

## Overview

AI agents calling external tools (APIs, data connectors, cloud services) must
be held to the same security standards as human users — arguably stricter, given
their potential for automated, high-volume access. This tester simulates and
validates six independent security layers that together form a complete trust
chain.

Each layer is tested in isolation and produces a pass/fail/warn result. Attack
scenarios are embedded in each layer to verify that mitigations hold.

---

## Security Layers

| # | Layer                        | What It Validates                                              |
|---|------------------------------|----------------------------------------------------------------|
| 0 | Threat-Aware Ingress         | Risk scoring from IP reputation, geo-velocity, MFA signals     |
| 1 | Token Pipeline               | Bot-scoped JWT minting, signature, TTL, alg:none rejection     |
| 2 | Workload Identity            | SPIFFE/SPIRE SVID presence, expiry, and peer identity matching |
| 3 | OPA Policy Evaluation        | Tenant, audience, action allowlist, and MFA policy enforcement |
| 4 | Cloud IAM / IRSA             | No static creds, short-lived credentials, tenant-scoped ARNs   |
| 5 | Response Sanitization        | PII redaction, cross-tenant data stripping, payload size limit |

---

## Attack Simulations

Each layer includes one or more embedded attack scenarios. These are clearly
labelled `[Attack Sim]` in the output and summarised at the end of the report.

| Layer | Attack Simulated                        | Expected Outcome  |
|-------|-----------------------------------------|-------------------|
| 0     | Known-bad IP reputation                 | Risk score >= 0.70, request blocked |
| 1     | JWT `alg:none` bypass                   | Token rejected    |
| 1     | Expired token replay                    | Token rejected    |
| 2     | Unauthorized workload lateral movement  | SVID mismatch, blocked |
| 3     | Cross-tenant token injection            | Tenant not in allowlist, blocked |
| 3     | Token reuse across tool boundaries      | Audience mismatch, blocked |

---

## Requirements

- Python 3.10 or later (uses `X | Y` union syntax and `list[...]` / `dict[...]`
  built-in generics)
- No third-party packages

---

## Usage

### Run with defaults (healthy config)

```bash
python trust_chain_tester.py
```

All layers should pass. Attack simulations should all report `[MITIGATED]`.

### Run with hostile config (expect failures)

```bash
python trust_chain_tester.py --attack
```

Surfaces failures across all layers. Useful for verifying the tester itself
catches real misconfigurations.

### Run with a custom config file

```bash
python trust_chain_tester.py --config path/to/config.json
```

The JSON file is merged over the defaults — only the keys you provide are
overridden. See [Configuration](#configuration) for the full schema.

### Combine flags

```bash
python trust_chain_tester.py --attack --config overrides.json
```

Attack overrides are applied first, then the config file is merged on top.

---

## Configuration

All configuration is passed as a single JSON object. Below is the full schema
with the default values.

```json
{
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
    "mfa_verified": true,
    "recent_anomalies": 0
  },
  "user_context": {
    "user_id": "user-123",
    "team": "engineering",
    "tenant": "acme-corp",
    "session_id": "sess-abc-xyz",
    "auth_method": "mfa"
  },
  "spiffe": {
    "svid_present": true,
    "svid_id": "spiffe://cluster.local/ns/ai/sa/agent",
    "svid_expiry": 1713000000,
    "peer_svid_id": "spiffe://cluster.local/ns/ai/sa/tool-connector"
  },
  "iam": {
    "has_static_credentials": false,
    "credential_ttl": 900,
    "role_arn": "arn:aws:iam::123456789:role/github-connector-prod",
    "resource_path": "arn:aws:s3:::company-data/acme-corp/*"
  },
  "mock_backend_response": {
    "repo": "acme/backend",
    "branch": "main",
    "last_commit": "abc123"
  }
}
```

### Field reference

#### Top-level

| Field                    | Type            | Description                                                 |
|--------------------------|-----------------|-------------------------------------------------------------|
| `bot_id`                 | string          | Identity of the calling AI agent (`sub` in JWT)             |
| `tool_id`                | string          | Identity of the target tool (`aud` in JWT)                  |
| `issuer`                 | string          | JWT `iss` claim — the issuing protocol gateway              |
| `jwt_secret`             | string          | HMAC-SHA256 signing secret                                  |
| `token_ttl`              | integer (s)     | Token lifetime; must be <= 300s to pass policy              |
| `requested_action`       | string          | The action the agent is attempting                          |
| `allowed_actions`        | string[]        | Actions embedded in the token's `tool_context`              |
| `valid_tenants`          | string[]        | Tenants that OPA policy will accept                         |
| `expected_tool_spiffe_id`| string          | SPIFFE ID the tool's workload must present                  |
| `max_response_bytes`     | integer         | Maximum permitted response payload size                     |

#### `threat_signals`

| Field              | Type    | Description                                                       |
|--------------------|---------|-------------------------------------------------------------------|
| `ip_reputation`    | string  | `clean`, `vpn`, `tor`, or `known-bad`                             |
| `geo_velocity`     | integer | km/h implied by recent logins; > 900 triggers a risk penalty      |
| `mfa_verified`     | boolean | Whether the session completed MFA                                 |
| `recent_anomalies` | integer | Count of anomalies in the session window; > 3 triggers a penalty  |

#### `spiffe`

| Field          | Type    | Description                                      |
|----------------|---------|--------------------------------------------------|
| `svid_present` | boolean | Whether an SVID is available on the workload     |
| `svid_id`      | string  | The agent's own SPIFFE ID                        |
| `svid_expiry`  | integer | Unix timestamp of SVID expiry                    |
| `peer_svid_id` | string  | SPIFFE ID presented by the peer (tool) workload  |

#### `iam`

| Field                    | Type    | Description                                              |
|--------------------------|---------|----------------------------------------------------------|
| `has_static_credentials` | boolean | Must be `false` — static creds are a policy violation   |
| `credential_ttl`         | integer | Assumed credential lifetime; must be <= 900s            |
| `role_arn`               | string  | IAM role ARN assumed by the workload                    |
| `resource_path`          | string  | ARN of the scoped resource; must contain the tenant name |

---

## Policy Thresholds

These are the enforcement limits baked into the tester. They reflect
conservative defaults suitable for an agentic workload.

| Policy                     | Threshold      |
|----------------------------|----------------|
| Risk score block           | >= 0.70        |
| JWT TTL maximum            | 300 seconds    |
| Credential TTL maximum     | 900 seconds    |
| Max response payload       | 100 KB         |
| Destructive action MFA     | Required       |

### Risk score composition

| Signal                          | Penalty |
|---------------------------------|---------|
| IP reputation: `known-bad`      | +0.60   |
| IP reputation: `tor`            | +0.40   |
| IP reputation: `vpn`            | +0.20   |
| Geo-velocity > 900 km/h         | +0.30   |
| MFA not verified                | +0.10   |
| Recent anomalies > 3            | +0.20   |
| Maximum possible score          | 1.00    |

---

## Output Format

```text
+---------------------------------------------------------------+
|  Zero-Trust AI Mesh -- Trust Chain Tester                     |
|  Testing all 6 layers of the security model                   |
+---------------------------------------------------------------+

-- Layer 0: Threat-Aware Ingress --------------------------------
  [PASS]  Risk score: 0.00
  [PASS]  MFA verified: True
  [MITIGATED]  Attack risk score: 0.60

...

=================================================================
  TRUST CHAIN TEST REPORT
=================================================================
  Total checks : 24
  Passed       : 22
  Failed       : 0
  Warnings     : 2
  Attack sims  : 7 (7 mitigated)
=================================================================

  ATTACK SIMULATION SUMMARY:
    [MITIGATED] Layer 0 -- Known-bad IP reputation
    [MITIGATED] Layer 1 -- JWT alg:none bypass
    ...

  Overall: TRUST CHAIN HEALTHY
=================================================================
```

---

## Extending the Tester

### Adding a new policy check to an existing layer

Add an entry to the `policy_checks` list inside the relevant `test_layerN_*`
function. Each entry is a `(name, passed: bool, detail: str)` tuple.

### Adding a new layer

1. Write a `test_layer6_*(report, config)` function following the same pattern.
2. Add it to the `run()` function after `test_layer5_response_sanitization`.
3. Add any new config fields to `DEFAULT_CONFIG` and document them above.

### Adding a new attack simulation

Within any layer function, construct the hostile input, evaluate whether it
would be blocked, and call `report.add(TestResult(..., attack_simulated=...,
mitigated=...))`. It will automatically appear in the attack summary.

---

## Limitations

This is a **simulation harness**, not a live security scanner.

- JWT validation is a local HMAC check — it does not contact a real JWKS
  endpoint or validate certificate chains.
- SPIFFE/SPIRE checks simulate SVID presence via config values — no Workload
  API socket is contacted.
- OPA policy evaluation is reimplemented in Python — it does not run a real OPA
  instance or load Rego policies.
- IAM/IRSA checks simulate credential metadata — no AWS API calls are made.

For production use, replace each layer's test logic with calls to your actual
infrastructure (JWKS endpoint, SPIRE agent socket, OPA sidecar, AWS STS, etc.).

---



# 🗡️ MCP-SLAYER v3.0 ..beta edition..

### **Overview**
MCP-SLAYER is a specialized Red Team framework designed to audit **Model Context Protocol (MCP)** implementations. 

It maps directly to the **OWASP MCP Top 10**, providing automated validation of identity binding, egress controls, and context isolation.

---

### **Core Components**
1.  **`slayer.py`**: A high-concurrency, type-safe Python 3.11+ harness. 
    *   **Modular Architecture**: Plugin-based modules for Injection, SSRF, Auth, and Supply Chain.
    *   **Defense Validation**: Measures Blue Team detection rates and MTTR.
    *   **Cryptographic Integrity**: Findings are Ed25519-signed to ensure chain-of-custody.
    *   **Safety**: Features a "Safe-Word" kill switch (`REDSTOP`) to abort all active probes instantly.

2.  **`slayer-config.yaml`**: Enterprise-grade configuration.
    *   Defines Gateway and Tool-specific endpoints.
    *   Configures complex Auth Profiles (mTLS, JWT, Basic).
    *   Implements automated PII/Secret redaction for report safety.
    *   Enables SIEM streaming (Splunk/Elastic) for Purple Team exercises.

---

### **Practical Use Cases**

| Scenario | MCP Risk | SLAYER Module |
| :--- | :--- | :--- |
| **Identity Replay** | **MCP02** | Attempts to use a low-privilege Tool-A token to execute actions on an Admin Tool-B. |
| **Cloud Credential Theft**| **MCP05/08** | Injects URL payloads targeting Cloud Instance Metadata (AWS/GCP/Azure) via Agent prompts. |
| **Shadow Tool Detection**| **MCP09** | Scans internal subnets for unauthenticated or default-credentialed MCP servers. |
| **Context Bleed** | **MCP10** | Validates that Tenant-A cannot retrieve "memory" or vector embeddings belonging to Tenant-B. |
| **Prompt Injection** | **MCP06** | Tests if malicious tool-readable files (like a `README.md`) can hijack the Agent's system instructions. |

---

### **Quick Start**
```bash
# 1. Install dependencies
pip install aiohttp pydantic yaml cryptography

# 2. Validate configuration and authorization
python slayer.py --config slayer-config.yaml --authorized --verbose

# 3. Run specific audit modules
python slayer.py --modules confused-deputy,ssrf-metadata --output-formats json,markdown
```

### **Ethical Use**
This tool is for **authorized security testing only**. Use the `safe_word` configuration to ensure tests can be stopped by Ops teams if performance is impacted.
