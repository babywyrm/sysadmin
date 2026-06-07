This document is designed for an internal engineering repository (e.g., `architecture/security/mcp-security-standard.md`). It integrates the dissection of the MCP RFC with practical Kubernetes/Istio implementation patterns.

---

# Hardening Model Context Protocol (MCP) in Enterprise EKS

**Status:** Production Standard  
**Version:** 1.1  
**Owner:** Security Architecture / Platform Engineering

## 1. Executive Summary
The Model Context Protocol (MCP) is a powerful standard for connecting AI agents to data and tools. However, the open nature of the RFC introduces significant risks: **Shadow Tool discovery**, **Identity Confusion**, and **Data Exfiltration**. 

This document outlines the mandatory security architecture for all MCP implementations within our EKS clusters using a **4-Layer Infrastructure-as-Code (IaC) defense model**.

---

## 2. RFC Dissection: Weaknesses vs. Hardened Requirements

The following table identifies core protocol weaknesses and our mandatory infrastructure-level remediations.

| RFC Component | Vulnerability | Attack Scenario | Infrastructure Fix |
| :--- | :--- | :--- | :--- |
| **Discovery** | Blind Trust | A server injects a `system_exec` tool into the LLM context. | **Wasm Tool Filtering** (Allowlist) |
| **Transport** | Unauthenticated RPC | An internal attacker calls MCP tool endpoints directly. | **Istio AuthorizationPolicy** (mTLS) |
| **Resources** | Path Traversal | LLM manipulated to read `file:///etc/shadow` via URI. | **SecurityContext Root-Jailing** |
| **Identity** | Static Credentials | MCP Server uses a global admin API key for all user requests. | **Token Exchange (OBO)** |
| **Egress** | Open Network | Malicious tool call sends sensitive JSON to an external URL. | **Istio ServiceEntry Lockdown** |

---

## 3. Reference Architecture (IaC)

We enforce security through Istio and AWS IRSA, treating the MCP server as an untrusted workload.

### Layer 1: Tool Execution Guard (Wasm Filter)
We intercept the JSON-RPC traffic. The RFC allows dynamic discovery; we enforce a **Static Allowlist**.

```yaml
# mcp-guard.yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: mcp-tool-guard
  namespace: ai-agents
spec:
  selector:
    matchLabels:
      app: github-mcp-server
  url: oci://internal-registry.io/mcp-guard-filter:v1
  pluginConfig:
    # Explicit tools approved for this agent
    tool_allowlist:
      - "search_code"
      - "get_pull_request"
    # Logic: Drops JSON-RPC calls where params.name not in allowlist
```

### Layer 2: Network & Access Control (Istio AuthZ)
The RFC is transport-agnostic. We wrap it in **Zero Trust mTLS** and restrict the "caller" identity.

```yaml
# mcp-authz.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: mcp-access-policy
  namespace: ai-agents
spec:
  selector:
    matchLabels:
      app: github-mcp-server
  action: ALLOW
  rules:
    - from:
        - source:
            # Only the Central AI Gateway can call MCP tools
            principals: ["cluster.local/ns/gateway/sa/ai-gateway"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/rpc", "/sse"]
```

### Layer 3: Identity & Cloud Jailing (AWS IRSA)
To solve "Identity Confusion," MCP servers must not use static IAM keys. They must use pod-level scoped roles.

```yaml
# mcp-iam.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: github-mcp-sa
  namespace: ai-agents
  annotations:
    # Role only allows Read access to specific repos in AWS CodeCommit
    eks.amazonaws.com/role-arn: arn:aws:iam::1234567890:role/mcp-scoped-github-reader
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: github-mcp-server
spec:
  template:
    spec:
      serviceAccountName: github-mcp-sa
      containers:
      - name: server
        image: custom-mcp-image:latest
        securityContext:
          readOnlyRootFilesystem: true  # RFC path traversal mitigation
          allowPrivilegeEscalation: false
          runAsNonRoot: true
```

### Layer 4: Egress Hardening (Data Exfiltration Prevention)
AI agents are prone to "Prompt Injection" leading to exfiltration. We use Istio to air-gap the MCP server, allowing it to talk *only* to the target API.

```yaml
# mcp-egress.yaml
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: external-api-allowlist
spec:
  hosts:
  - api.github.com
  location: MESH_EXTERNAL
  ports:
  - number: 443
    name: https
    protocol: TLS
  resolution: DNS
---
apiVersion: networking.istio.io/v1alpha3
kind: Sidecar
metadata:
  name: mcp-egress-lockdown
spec:
  workloadSelector:
    labels:
      app: github-mcp-server
  egress:
  - hosts:
    - "istio-system/*"
    - "ai-agents/api.github.com"  # ONLY Github endpoint is visible
```

---

## 4. Operational Best Practices

### A. Human-in-the-Loop (HITL) for Destructive Actions
Any tool listed in an MCP schema that includes `delete`, `update`, or `execute` prefixes must be flagged in the AI Gateway.
*   **Action:** The Gateway must pause execution and request a signed approval from the user's browser before forwarding the RPC call to the MCP server.

### B. Audit Traceability
Standard MCP logging is often opaque. We require JSON-RPC auditing.
*   **Standard:** All MCP request/response pairs must be logged to our centralized SIEM with the `User-Identity` injected by the Istio gateway.

### C. Resource URI Sanitization
MCP Servers must implement a URI validator.
*   **Requirement:** If an MCP server exposes a resource (e.g., `mcp://logs/`), it must use absolute path mapping and reject any URI containing `..` or `%2e%2e`.

---

## 5. Security Checklist for New MCP Deployment
1. [ ] Is the tool schema validated against an allowlist?
2. [ ] Does the service account follow the Principle of Least Privilege?
3. [ ] Is egress traffic restricted to the absolute minimum required domains?
4. [ ] Does high-risk tool execution require manual user approval?
5. [ ] Are all tool calls traceable to a specific human user ID?

---

##
##

**Appendix:**   ..(forthcoming)..
For implementation details of the Wasm filter code or IAM role construction, see:  
`./filters/README.md` and `./terraform/mcp-roles.tf`
