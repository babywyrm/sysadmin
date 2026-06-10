# MCP Detection Catalog

High-signal detection rules for MCP and agent architectures. Each rule maps to
a playbook threat ID, OWASP category, and MCP-SHIELD module.

---

## Detection Index

| # | Detection | Severity | Threat ID | OWASP | Module |
|---|---|---|---|---|---|
| D01 | Audience Mismatch | High | MCP-T04 | MCP02 | Identity |
| D02 | Metadata IP Access (SSRF) | Critical | MCP-T06 | MCP05 | Network |
| D03 | Chunked High-Volume Output | High | MCP-T12 | MCP10 | Data |
| D04 | Secrets in Logs/Output | Critical | MCP-T07 | MCP01 | Data |
| D05 | Cross-Tenant Retrieval / Canary | Critical | MCP-T11 | MCP10 | Data |
| D06 | Recursive Tool Loop | Medium | MCP-T10 | MCP05 | Runtime |
| D07 | Prompt Injection in Tool Output | High | MCP-T02 | MCP06 | Guardrail |
| D08 | Unsigned Tool Registration | High | MCP-T08 | MCP03 | Toolchain |
| D09 | Token Replay (same JTI) | Critical | MCP-T04 | MCP01 | Identity |
| D10 | Agent Config Mutation | Critical | MCP-T09 | MCP04 | Toolchain |
| D11 | Destructive Action Without HITL | High | MCP-T10 | MCP05 | Runtime |
| D12 | Egress to Unknown Domain | Medium | MCP-T06 | MCP05 | Network |
| D13 | Audit Attribution Gap | Medium | MCP-T13 | MCP08 | Identity |
| D14 | Persistent Callback Registration | High | MCP-T14 | MCP09 | Toolchain |

---

## Detection Specifications

### D01 — Audience Mismatch

Token or internal request context intended for one tool is used against another.

```text
trigger:
  auth_audience != expected_audience_for_tool(tool_name)

data_sources:
  - gateway access logs
  - tool-level auth validation logs

severity: high
confidence: high (deterministic)

response:
  - hard-fail the request (403)
  - log with full request context
  - alert security ops
  - correlate with session_id for chain analysis
```

---

### D02 — Metadata IP Access (SSRF)

Any tool or agent workload attempts to reach cloud metadata endpoints.

```text
trigger:
  egress_dest_ip IN [169.254.169.254, 169.254.170.2, fd00:ec2::254]
  OR egress_dest_host == "metadata.google.internal"
  OR egress_dest_host MATCHES "metadata.azure.com"

data_sources:
  - network flow logs
  - fetch proxy logs
  - DNS query logs

severity: critical
confidence: high (deterministic)

response:
  - block at NetworkPolicy (should already be blocked)
  - alert immediately
  - investigate which tool/prompt triggered the fetch
  - rotate cloud credentials if any response was received
```

---

### D03 — Chunked High-Volume Output

Session sends many medium-sized outputs that bypass per-message payload caps.

```text
trigger:
  COUNT(tool_action WHERE action IN [
    "message.send", "email.send", "webhook.post",
    "issue.create", "comment.post"
  ]) BY session_id OVER 10m > THRESHOLD(15)

data_sources:
  - tool action audit logs

severity: high
confidence: medium (requires tuning per environment)

response:
  - rate-limit or suspend the session
  - review output content for sensitive data
  - check if DLP patterns were bypassed via chunking
```

---

### D04 — Secrets in Logs/Output

Credential-like patterns detected after redaction layer.

```text
trigger:
  secret_detector.match(field) == true
  WHERE field IN [log_message, tool_output, agent_response]

patterns:
  - AWS access key: AKIA[0-9A-Z]{16}
  - Private key header: -----BEGIN .* PRIVATE KEY-----
  - Generic high-entropy: shannon_entropy(token) > 4.5 AND length > 20
  - Bearer token: Bearer [A-Za-z0-9\-._~+/]+=*

data_sources:
  - application logs (post-redaction)
  - tool output audit stream
  - agent response logs

severity: critical
confidence: high (pattern-matched)

response:
  - immediately rotate the exposed credential
  - trace which tool produced the secret
  - patch the redaction gap
  - add to regression suite
```

---

### D05 — Cross-Tenant Retrieval / Canary Hit

A tenant's query retrieves another tenant's data, or a planted canary is accessed.

```text
trigger:
  (retrieved_document.tenant_id != request.tenant_id)
  OR (retrieved_content CONTAINS canary_string)

data_sources:
  - vector DB query logs with tenant context
  - RAG retrieval audit logs

severity: critical
confidence: high (deterministic for canaries, medium for tenant mismatch)

response:
  - block the retrieval result from reaching context
  - alert with full session trace
  - investigate tenant filter bypass
  - notify affected tenant if data was exposed
```

---

### D06 — Recursive Tool Loop

Agent repeatedly calls the same tool or tool sequence in a tight loop.

```text
trigger:
  COUNT(tool_call WHERE tool_name = X) BY session_id OVER 2m > THRESHOLD(10)
  OR repeated_sequence_detected(session_id, [tool_a, tool_b, tool_a, tool_b])

data_sources:
  - tool call audit logs

severity: medium (escalate to high if destructive tools involved)
confidence: medium

response:
  - terminate the session
  - log the loop pattern for analysis
  - check if the loop was prompt-induced (injection) or hallucination
```

---

### D07 — Prompt Injection in Tool Output

Tool response contains instruction-like patterns that could hijack agent reasoning.

```text
trigger:
  injection_classifier(tool_output) == suspicious
  WHERE patterns INCLUDE:
    - "ignore previous instructions"
    - "you are now"
    - "system: override"
    - "AGENT INSTRUCTION:"
    - HTML comment with directive verbs

data_sources:
  - tool output inspection layer (Layer 5 Prompt Guard)

severity: high
confidence: medium (requires tuning to reduce false positives)

response:
  - quarantine the tool output (do not inject into context)
  - alert with content hash for forensics
  - investigate the content source (which backend returned this?)
  - add pattern to scanner regression suite
```

---

### D08 — Unsigned Tool Registration

A tool is registered or updated without a valid signature.

```text
trigger:
  tool_registry.event == "register" OR tool_registry.event == "update"
  AND tool_manifest.signature_valid == false

data_sources:
  - tool registry audit logs

severity: high
confidence: high (deterministic)

response:
  - reject the registration
  - alert platform security
  - investigate who initiated the registration
  - check for compromise of registry credentials
```

---

### D09 — Token Replay (Same JTI)

The same JWT `jti` claim is seen more than once.

```text
trigger:
  jti_store.lookup(jwt.jti) == "already_seen"

data_sources:
  - JTI store (Redis/DynamoDB)
  - tool auth validation logs

severity: critical
confidence: high (deterministic)

response:
  - reject the request immediately
  - alert with source IP, tool, and session context
  - investigate how the token was captured/replayed
  - check for MitM or token exfiltration
```

---

### D10 — Agent Config Mutation

Agent's own configuration (system prompt, tool list, permissions) is modified.

```text
trigger:
  git.push TO repo IN [agent-config, ai-config, platform-ai]
  WHERE committer == agent_service_account
  OR tool_call(action="write", target MATCHES "*/system-prompt*")

data_sources:
  - git audit logs (GitHub/GitLab)
  - tool action audit logs

severity: critical
confidence: high

response:
  - revert the change immediately
  - suspend the agent session
  - investigate the injection vector that caused the write
  - verify agent service account has read-only access to config
```

---

### D11 — Destructive Action Without HITL

A destructive operation executes without human-in-the-loop confirmation.

```text
trigger:
  tool_action IN [
    "kubectl.delete", "kubectl.scale --replicas=0",
    "repo.delete", "branch.force-push",
    "incident.resolve", "deployment.rollback"
  ]
  AND hitl_confirmation == false

data_sources:
  - tool action audit logs with HITL metadata

severity: high
confidence: high (deterministic if HITL flag is logged)

response:
  - attempt to reverse the action if safe
  - alert incident response
  - investigate why the HITL gate was bypassed
```

---

### D12 — Egress to Unknown Domain

Tool makes outbound request to a domain not on the per-tool egress allowlist.

```text
trigger:
  egress_dest_host NOT IN tool_egress_allowlist[tool_name]
  AND egress_dest_host NOT IN global_allowlist

data_sources:
  - network flow logs
  - fetch proxy logs
  - DNS query logs

severity: medium (escalate if tool handles sensitive data)
confidence: high (deterministic against allowlist)

response:
  - block the request
  - log for analysis
  - check if the domain is attacker-controlled or a legitimate new dependency
```

---

### D13 — Audit Attribution Gap

A tool action is logged with agent service account identity but no user attribution.

```text
trigger:
  tool_action.user_id == null OR tool_action.user_id == ""
  AND tool_action.auth_subject MATCHES "bot://*"

data_sources:
  - tool action audit logs

severity: medium
confidence: medium (some automated flows legitimately lack user context)

response:
  - flag for review
  - investigate if user context propagation is broken
  - ensure the action can be traced back to an originating user session
```

---

### D14 — Persistent Callback Registration

A new webhook, callback URL, or scheduled trigger is registered by the agent.

```text
trigger:
  tool_action IN ["webhook.register", "callback.create", "schedule.create"]
  AND target_url NOT IN approved_callback_allowlist

data_sources:
  - tool action audit logs
  - webhook registry

severity: high
confidence: high (deterministic against allowlist)

response:
  - block the registration
  - alert platform security
  - investigate the prompt/context that triggered the registration
  - check for persistence-via-callback attack pattern (MCP-T14)
```

---

## Implementation Priority

Start with deterministic, high-confidence detections before behavioral analytics:

**Phase 1 (deploy immediately):**
- D01, D02, D04, D05, D09 — all deterministic, critical/high severity

**Phase 2 (tune and deploy):**
- D03, D06, D07, D08, D10, D11 — require threshold tuning or classifier

**Phase 3 (mature program):**
- D12, D13, D14 — require allowlist maintenance and operational maturity

---

## Telemetry Dependencies

All detections require the structured log fields defined in
`blue-team-structure.md` § Blue Team Telemetry Requirements. The minimum viable
fields are:

- `session_id`, `request_id`, `tenant_id`, `user_id`
- `tool_name`, `tool_action`, `auth_audience`, `auth_subject`
- `egress_dest_ip`, `egress_dest_host`
- `decision` (allow/deny), `decision_reason`
