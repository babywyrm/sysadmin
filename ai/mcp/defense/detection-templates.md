# Detection Templates — Splunk SPL & Elastic KQL

Production-ready query templates for the 14 detections in `detection-catalog.md`.
Each template assumes the structured log fields defined in
`blue-team-structure.md` § Blue Team Telemetry Requirements.

Adapt index names, field prefixes, and thresholds to your environment.

---

## D01 — Audience Mismatch

### Splunk SPL

```spl
index=mcp_gateway sourcetype=tool_auth
| where auth_audience != expected_audience
| stats count by session_id, tool_name, auth_audience, auth_subject, _time
| where count > 0
| sort -_time
```

### Elastic KQL

```kql
event_type: "tool_auth" AND NOT auth_audience: expected_audience
```

### Elastic Query DSL (alert rule)

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "tool_auth" } }
      ],
      "must_not": [
        { "script": {
            "script": "doc['auth_audience'].value == doc['expected_audience'].value"
        }}
      ]
    }
  }
}
```

---

## D02 — Metadata IP Access (SSRF)

### Splunk SPL

```spl
index=mcp_network sourcetype=egress_flow
| where cidrmatch("169.254.0.0/16", egress_dest_ip)
    OR egress_dest_host="metadata.google.internal"
    OR egress_dest_host="metadata.azure.com"
| table _time, session_id, tool_name, egress_dest_ip, egress_dest_host, agent_id
```

### Elastic KQL

```kql
egress_dest_ip: "169.254.169.254" OR egress_dest_ip: "169.254.170.2"
  OR egress_dest_host: "metadata.google.internal"
  OR egress_dest_host: "metadata.azure.com"
```

---

## D03 — Chunked High-Volume Output

### Splunk SPL

```spl
index=mcp_audit sourcetype=tool_action
  tool_action IN ("message.send", "email.send", "webhook.post", "issue.create", "comment.post")
| bin _time span=10m
| stats count as action_count by session_id, _time
| where action_count > 15
| sort -action_count
```

### Elastic KQL

```kql
tool_action: ("message.send" OR "email.send" OR "webhook.post" OR "issue.create")
```

With date histogram aggregation (alert threshold: >15 per 10m per session):

```json
{
  "aggs": {
    "by_session": {
      "terms": { "field": "session_id" },
      "aggs": {
        "per_window": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "10m" },
          "aggs": {
            "action_count": { "value_count": { "field": "tool_action" } }
          }
        }
      }
    }
  }
}
```

---

## D04 — Secrets in Logs/Output

### Splunk SPL

```spl
index=mcp_audit OR index=mcp_logs
| regex _raw="(AKIA[0-9A-Z]{16}|-----BEGIN\s\w+\sPRIVATE\sKEY-----|Bearer\s[A-Za-z0-9\-._~+/]{20,})"
| table _time, session_id, tool_name, source, _raw
| head 50
```

### Elastic KQL

```kql
message: /AKIA[0-9A-Z]{16}/ OR message: /BEGIN.*PRIVATE KEY/
  OR message: /Bearer [A-Za-z0-9\-._~+\/]{20,}/
```

---

## D05 — Cross-Tenant Retrieval / Canary

### Splunk SPL

```spl
index=mcp_retrieval sourcetype=vector_query
| where retrieved_tenant_id != tenant_id OR canary_hit="true"
| table _time, session_id, tenant_id, retrieved_tenant_id, user_id, canary_hit
```

### Elastic KQL

```kql
(NOT retrieved_tenant_id: *) OR canary_hit: true
```

With script filter for mismatch:

```json
{
  "query": {
    "bool": {
      "should": [
        { "term": { "canary_hit": true } },
        { "script": {
            "script": "doc['retrieved_tenant_id'].value != doc['tenant_id'].value"
        }}
      ]
    }
  }
}
```

---

## D06 — Recursive Tool Loop

### Splunk SPL

```spl
index=mcp_audit sourcetype=tool_action
| bin _time span=2m
| stats count as call_count, dc(tool_name) as unique_tools by session_id, _time
| where call_count > 10 AND unique_tools <= 2
| sort -call_count
```

### Elastic KQL

```kql
event_type: "tool_action"
```

Alert rule: aggregate by `session_id` over 2m window, trigger when count > 10
with cardinality of `tool_name` <= 2.

---

## D07 — Prompt Injection in Tool Output

### Splunk SPL

```spl
index=mcp_audit sourcetype=tool_output
| regex tool_output="(?i)(ignore previous|you are now|system:\s*override|AGENT INSTRUCTION)"
| table _time, session_id, tool_name, tool_output_hash, request_id
```

### Elastic KQL

```kql
tool_output: /(ignore previous|you are now|system:\s*override|AGENT INSTRUCTION)/
```

---

## D08 — Unsigned Tool Registration

### Splunk SPL

```spl
index=mcp_registry sourcetype=tool_registry
  (event="register" OR event="update") signature_valid="false"
| table _time, tool_name, tool_version, registrant, signature_valid
```

### Elastic KQL

```kql
event_type: "tool_registry" AND (event: "register" OR event: "update")
  AND signature_valid: false
```

---

## D09 — Token Replay (Same JTI)

### Splunk SPL

```spl
index=mcp_gateway sourcetype=tool_auth
| stats count by jwt_jti
| where count > 1
| lookup jti_first_seen jwt_jti OUTPUT first_seen_time, first_seen_tool
| table jwt_jti, count, first_seen_time, first_seen_tool
```

### Elastic KQL

```kql
event_type: "tool_auth"
```

Alert: aggregate on `jwt_jti`, trigger when doc_count > 1 for any JTI value.

---

## D10 — Agent Config Mutation

### Splunk SPL

```spl
index=mcp_audit sourcetype=tool_action
  (tool_action="write" target="*system-prompt*")
  OR (tool_action="git.push" target IN ("agent-config", "ai-config", "platform-ai"))
| table _time, session_id, agent_id, tool_action, target, auth_subject
```

### Elastic KQL

```kql
(tool_action: "write" AND target: *system-prompt*)
  OR (tool_action: "git.push" AND target: ("agent-config" OR "ai-config"))
```

---

## D11 — Destructive Action Without HITL

### Splunk SPL

```spl
index=mcp_audit sourcetype=tool_action
  tool_action IN ("kubectl.delete", "repo.delete", "branch.force-push",
                  "deployment.rollback", "incident.resolve")
  hitl_confirmation="false"
| table _time, session_id, tool_name, tool_action, user_id, agent_id
```

### Elastic KQL

```kql
tool_action: ("kubectl.delete" OR "repo.delete" OR "branch.force-push"
  OR "deployment.rollback") AND hitl_confirmation: false
```

---

## D12 — Egress to Unknown Domain

### Splunk SPL

```spl
index=mcp_network sourcetype=egress_flow
| lookup tool_egress_allowlist tool_name OUTPUT allowed_domains
| where NOT like(egress_dest_host, allowed_domains)
| table _time, session_id, tool_name, egress_dest_host, egress_dest_ip
```

### Elastic KQL

```kql
event_type: "egress_flow" AND NOT egress_dest_host: *
```

Note: Requires an enrichment pipeline or watcher that cross-references against
a maintained allowlist. The KQL above is a placeholder — real implementation
uses a terms lookup against the allowlist index.

---

## D13 — Audit Attribution Gap

### Splunk SPL

```spl
index=mcp_audit sourcetype=tool_action
  auth_subject="bot://*" (user_id="" OR NOT user_id=*)
| stats count by session_id, agent_id, tool_name, _time
| where count > 0
```

### Elastic KQL

```kql
auth_subject: bot\:\/\/* AND (NOT user_id: * OR user_id: "")
```

---

## D14 — Persistent Callback Registration

### Splunk SPL

```spl
index=mcp_audit sourcetype=tool_action
  tool_action IN ("webhook.register", "callback.create", "schedule.create")
| lookup approved_callbacks target_url OUTPUT approved
| where approved!="true"
| table _time, session_id, tool_action, target_url, agent_id
```

### Elastic KQL

```kql
tool_action: ("webhook.register" OR "callback.create" OR "schedule.create")
```

Alert: cross-reference `target_url` against approved callback allowlist index.
Trigger when URL is not in the allowlist.

---

## Deployment Notes

### Splunk

- Create a `mcp` app with the indexes: `mcp_gateway`, `mcp_audit`,
  `mcp_network`, `mcp_registry`, `mcp_retrieval`, `mcp_logs`
- Use HEC (HTTP Event Collector) for structured JSON ingestion
- Create correlation searches in ES (Enterprise Security) for alerting
- Lookups: `tool_egress_allowlist`, `approved_callbacks`, `jti_first_seen`

### Elastic

- Index pattern: `mcp-*` with component templates per source type
- Use detection rules in Elastic Security (SIEM)
- Enrichment policies for allowlist cross-referencing
- Alert actions: webhook to PagerDuty/Slack, or directly to kill switch API

### Shared Requirements

- All detections assume the telemetry fields from `blue-team-structure.md`
- Tune thresholds (D03, D06) per environment before enabling alerts
- Start with D01, D02, D04, D05, D09 (deterministic, high-confidence)
- Phase in behavioral detections (D03, D06, D07) after baseline tuning
