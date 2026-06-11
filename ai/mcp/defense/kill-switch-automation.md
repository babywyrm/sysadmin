# Kill Switch Automation

Executable triggers for the kill switches defined in `blue-team-structure.md`.
Each switch includes the manual command, an automation hook, and rollback
procedure.

---

## Architecture

```text
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐
│ Detection Alert │────►│ Automation Layer  │────►│ Kill Switch Action│
│ (D01–D14)       │     │ (webhook / script)│     │ (k8s / IAM / DNS) │
└─────────────────┘     └──────────────────┘     └───────────────────┘
                              │
                              ▼
                        ┌──────────────┐
                        │ Audit Log    │
                        │ + Slack/PD   │
                        └──────────────┘
```

Triggers can be invoked:
- **Manually** by an operator (kubectl, CLI, console)
- **Automatically** by a detection alert via webhook
- **Scheduled** as part of a drill (monthly kill switch test)

---

## KS-01: Tool Disable Switch

Immediately disable a specific MCP tool (Slack, email, browser, shell, etc.).

### Manual

```bash
# Disable a tool via the MCP gateway config
kubectl patch configmap mcp-gateway-config -n mcp-system \
  --type merge -p '{"data":{"disabled_tools":"slack,email,webhook"}}'

# Force rollout to pick up the change
kubectl rollout restart deployment/mcp-gateway -n mcp-system
```

### Automation Hook

```bash
#!/bin/bash
# kill-tool.sh <tool_name> [namespace]
TOOL="${1:?usage: kill-tool.sh <tool_name>}"
NS="${2:-mcp-system}"

CURRENT=$(kubectl get configmap mcp-gateway-config -n "$NS" \
  -o jsonpath='{.data.disabled_tools}')
NEW="${CURRENT:+$CURRENT,}$TOOL"

kubectl patch configmap mcp-gateway-config -n "$NS" \
  --type merge -p "{\"data\":{\"disabled_tools\":\"$NEW\"}}"
kubectl rollout restart deployment/mcp-gateway -n "$NS"

echo "[KS-01] Disabled tool: $TOOL (ns=$NS)" | tee -a /var/log/kill-switch.log
```

### Rollback

```bash
kubectl patch configmap mcp-gateway-config -n mcp-system \
  --type merge -p '{"data":{"disabled_tools":""}}'
kubectl rollout restart deployment/mcp-gateway -n mcp-system
```

---

## KS-02: Egress Lockdown

Default-deny all outbound traffic except a minimal allowlist.

### Manual

```bash
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-egress-deny
  namespace: mcp-tools
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
EOF
```

### Automation Hook

```bash
#!/bin/bash
# kill-egress.sh [namespace]
NS="${1:-mcp-tools}"

kubectl apply -f /opt/kill-switches/emergency-egress-deny.yaml -n "$NS"
echo "[KS-02] Egress locked down (ns=$NS)" | tee -a /var/log/kill-switch.log
```

### Rollback

```bash
kubectl delete networkpolicy emergency-egress-deny -n mcp-tools
```

---

## KS-03: Write-Action Gate

Force human approval for all destructive/write operations.

### Manual

```bash
kubectl set env deployment/mcp-gateway -n mcp-system \
  MCP_HITL_MODE=enforced \
  MCP_HITL_ACTIONS="*"
```

### Automation Hook

```bash
#!/bin/bash
# kill-writes.sh [namespace]
NS="${1:-mcp-system}"

kubectl set env deployment/mcp-gateway -n "$NS" \
  MCP_HITL_MODE=enforced MCP_HITL_ACTIONS="*"

echo "[KS-03] Write-action gate enforced (ns=$NS)" | tee -a /var/log/kill-switch.log
```

### Rollback

```bash
kubectl set env deployment/mcp-gateway -n mcp-system \
  MCP_HITL_MODE=selective \
  MCP_HITL_ACTIONS="kubectl.delete,repo.delete,deployment.rollback"
```

---

## KS-04: Session Breaker

Terminate sessions that trigger recursion, cost, or exfil heuristics.

### Manual

```bash
# Kill a specific session
curl -X POST https://mcp-gateway.internal/admin/sessions/kill \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"session_id": "sess_abc_xyz", "reason": "D06 recursive loop"}'
```

### Automation Hook

```bash
#!/bin/bash
# kill-session.sh <session_id> <reason>
SESSION="${1:?usage: kill-session.sh <session_id> <reason>}"
REASON="${2:-automated kill switch}"

curl -sX POST https://mcp-gateway.internal/admin/sessions/kill \
  -H "Authorization: Bearer $MCP_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"session_id\":\"$SESSION\",\"reason\":\"$REASON\"}"

echo "[KS-04] Session killed: $SESSION ($REASON)" | tee -a /var/log/kill-switch.log
```

### Rollback

Sessions are stateless — no rollback needed. User reconnects normally.

---

## KS-05: Emergency Token Revoke

Revoke signing keys, rotate JWKs, or invalidate all active sessions.

### Manual

```bash
# Rotate the JWT signing key (invalidates ALL tokens)
kubectl create secret generic mcp-jwt-signing-key \
  --from-literal=key="$(openssl rand -base64 64)" \
  -n mcp-system --dry-run=client -o yaml | kubectl apply -f -

# Restart gateway to pick up new key
kubectl rollout restart deployment/mcp-gateway -n mcp-system
```

### Automation Hook

```bash
#!/bin/bash
# kill-tokens.sh [namespace]
NS="${1:-mcp-system}"

NEW_KEY=$(openssl rand -base64 64)
kubectl create secret generic mcp-jwt-signing-key \
  --from-literal=key="$NEW_KEY" -n "$NS" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/mcp-gateway -n "$NS"

echo "[KS-05] JWT signing key rotated (ns=$NS)" | tee -a /var/log/kill-switch.log
```

### Rollback

No rollback — clients re-authenticate and receive new tokens automatically.

---

## KS-06: Registry Freeze

Prevent new tool registration or tool version updates.

### Manual

```bash
kubectl set env deployment/mcp-registry -n mcp-system \
  REGISTRY_READ_ONLY=true
```

### Automation Hook

```bash
#!/bin/bash
# kill-registry.sh [namespace]
NS="${1:-mcp-system}"

kubectl set env deployment/mcp-registry -n "$NS" REGISTRY_READ_ONLY=true
echo "[KS-06] Registry frozen (ns=$NS)" | tee -a /var/log/kill-switch.log
```

### Rollback

```bash
kubectl set env deployment/mcp-registry -n mcp-system REGISTRY_READ_ONLY=false
```

---

## KS-07: Retrieval Isolation Mode

Disable cross-document or broad RAG retrieval; require exact tenant filters.

### Manual

```bash
kubectl set env deployment/mcp-rag-service -n mcp-system \
  RAG_ISOLATION_MODE=strict \
  RAG_CROSS_TENANT=deny \
  RAG_MAX_RESULTS=5
```

### Automation Hook

```bash
#!/bin/bash
# kill-retrieval.sh [namespace]
NS="${1:-mcp-system}"

kubectl set env deployment/mcp-rag-service -n "$NS" \
  RAG_ISOLATION_MODE=strict RAG_CROSS_TENANT=deny RAG_MAX_RESULTS=5

echo "[KS-07] Retrieval isolation enforced (ns=$NS)" | tee -a /var/log/kill-switch.log
```

### Rollback

```bash
kubectl set env deployment/mcp-rag-service -n mcp-system \
  RAG_ISOLATION_MODE=normal RAG_CROSS_TENANT=allow RAG_MAX_RESULTS=50
```

---

## KS-08: Safe-Response Mode

Return summaries only; block raw tool output from reaching the user.

### Manual

```bash
kubectl set env deployment/mcp-gateway -n mcp-system \
  MCP_SAFE_RESPONSE=true \
  MCP_RAW_OUTPUT=deny
```

### Automation Hook

```bash
#!/bin/bash
# kill-raw-output.sh [namespace]
NS="${1:-mcp-system}"

kubectl set env deployment/mcp-gateway -n "$NS" \
  MCP_SAFE_RESPONSE=true MCP_RAW_OUTPUT=deny

echo "[KS-08] Safe-response mode enabled (ns=$NS)" | tee -a /var/log/kill-switch.log
```

### Rollback

```bash
kubectl set env deployment/mcp-gateway -n mcp-system \
  MCP_SAFE_RESPONSE=false MCP_RAW_OUTPUT=allow
```

---

## Webhook Integration

For automated trigger from SIEM alerts:

```json
{
  "webhook_url": "https://mcp-ops.internal/kill-switch",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer ${KS_WEBHOOK_TOKEN}",
    "Content-Type": "application/json"
  },
  "body": {
    "switch": "KS-01",
    "tool": "slack",
    "reason": "D03 alert: chunked exfil detected",
    "session_id": "sess_abc_xyz",
    "triggered_by": "splunk_correlation_search",
    "dry_run": false
  }
}
```

The receiving service validates the token, executes the script, logs the
action, and notifies via Slack/PagerDuty.

---

## Drill Schedule

| Drill | Frequency | Validates |
|---|---|---|
| KS-01 tool disable + rollback | Monthly | Tool governance pipeline |
| KS-02 egress lockdown | Monthly | NetworkPolicy enforcement |
| KS-04 session kill | Weekly (automated) | Session management |
| KS-05 token rotation | Quarterly | Auth resilience |
| KS-06 registry freeze | Monthly | Registry ACLs |

All drills should:
1. Announce in #security-ops before execution
2. Verify the switch takes effect (confirm tool is unreachable, etc.)
3. Verify rollback restores normal operation
4. Log elapsed time (target: <60s for any switch)
5. File a brief report noting any issues
