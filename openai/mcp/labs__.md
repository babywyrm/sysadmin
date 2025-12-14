
# 🧠 Model Context Protocol (MCP) as a Kubernetes Control Plane *(beta)*

## STRIDE Threat Model + MITRE ATT&CK Mapping

> **TL;DR**
> MCP is safe only when it behaves like a Kubernetes control plane API — not a tool runner.
> AI is untrusted input. Controllers are the blast radius. Defense-in-depth is mandatory.

---

## 1. Scope & System Boundary

### In Scope

* AI Models / Agents *(untrusted)*
* MCP Server (policy and validation)
* MCP Tool Registry
* MCP to Kubernetes interface
* Kubernetes API Server
* AI Controllers (reconcile loops)
* CRDs (`AIAction`, `AITool`)
* Audit and logging pipeline

### Out of Scope (Adjacent)

* Model training pipelines
* External SaaS LLM providers (assumed upstream)
* Human CI/CD workflows

---

## 2. MCP as a Kubernetes Control Plane (Architecture)

```mermaid
flowchart LR
    subgraph External
        LLM[External LLM Provider]
    end

    subgraph Cluster[Kubernetes Cluster]
        subgraph MCP[MCP Control Plane]
            MCPAPI[MCP Server]
            Registry[MCP Tool Registry]
        end

        subgraph AI[AI Layer]
            Agent[AI Model or Agent]
        end

        subgraph Control[Execution Layer]
            CRD[AIAction and AITool CRDs]
            Ctrl[AI Controllers]
            KAPI[Kubernetes API Server]
        end

        Audit[Audit and Logging Pipeline]
    end

    LLM --> Agent
    Agent --> MCPAPI
    MCPAPI --> Registry
    MCPAPI --> CRD
    CRD --> Ctrl
    Ctrl --> KAPI

    MCPAPI --> Audit
    Ctrl --> Audit
    KAPI --> Audit
```

**Key Insight**
Everything *before* MCP is hostile.
Everything *after* controllers has real infrastructure power.

---

## 3. STRIDE Overview

| Category               | Risk Theme                |
| ---------------------- | ------------------------- |
| Spoofing               | Identity impersonation    |
| Tampering              | Unauthorized modification |
| Repudiation            | Loss of accountability    |
| Information Disclosure | Data leakage              |
| Denial of Service      | Availability impact       |
| Elevation of Privilege | Unauthorized power        |

---

## 4. STRIDE Overlay on MCP

```mermaid
flowchart TB
    Agent[AI Agent]
    MCP[MCP Server]
    CRD[AIAction CRD]
    Ctrl[Controller]
    KAPI[Kubernetes API]

    Agent -->|Spoofing| MCP
    MCP -->|Tampering| CRD
    CRD -->|Repudiation| Ctrl
    MCP -->|Information Disclosure| Agent
    Ctrl -->|Denial of Service| Ctrl
    Ctrl -->|Elevation of Privilege| KAPI
```

---

## 5. Secure Execution Flow (Happy Path)

```mermaid
sequenceDiagram
    participant AI as AI Agent
    participant MCP as MCP Server
    participant VAL as Policy Validation
    participant API as Kubernetes API
    participant CTRL as Controller
    participant AUD as Audit Log

    AI->>MCP: Request action
    MCP->>VAL: Validate policy and scope
    VAL-->>MCP: Approved
    MCP->>API: Create AIAction CRD
    API->>AUD: Audit CRD creation
    CTRL->>API: Watch AIAction
    CTRL->>API: Reconcile action
    CTRL->>AUD: Audit execution
```

### Design Properties

* No direct model to Kubernetes API access
* MCP validates before CRD creation
* Controllers enforce final execution guardrails

---

## 6. STRIDE Failure Mode: CRD Tampering (T + E)

```mermaid
sequenceDiagram
    participant Attacker
    participant API as Kubernetes API
    participant CTRL as Controller

    Attacker->>API: Patch AIAction spec
    API-->>Attacker: Accepted
    CTRL->>API: Read modified spec
    CTRL->>CTRL: Execute unintended path
```

### Required Controls

* Admission webhooks
* Immutable CRDs after creation
* Strong typing (no string execution)
* No shell invocation

---

## 7. Denial of Service: Reconcile Storms

```mermaid
flowchart LR
    AI[AI Agent]
    MCP[MCP Server]
    CRD[AIAction]
    CTRL[Controller]
    API[Kubernetes API]

    AI --> MCP --> CRD --> CTRL --> CRD
    CTRL --> API --> CTRL
```

### Mitigations

* TTL on AIAction CRDs
* Retry caps and backoff
* Circuit breakers in controllers
* MCP rate limiting

---

## 8. Elevation of Privilege: Over-Privileged Controller

```mermaid
flowchart TB
    AI[AI Agent]
    MCP[MCP Server]
    CRD[AIAction]
    CTRL[Controller with broad RBAC]
    KAPI[Kubernetes API]

    AI --> MCP --> CRD --> CTRL --> KAPI
    KAPI --> KAPI
```

**Critical Insight**
Controllers define the actual blast radius — not MCP.

---

## 9. STRIDE to MITRE ATT&CK Mapping (Summary)

```mermaid
flowchart LR
    STRIDE[STRIDE Threats]
    ATTACK[MITRE ATTACK Cloud and Containers]
    DETECT[Detection and Controls]

    STRIDE --> ATTACK
    ATTACK --> DETECT

    DETECT --> SIEM[SIEM Rules]
    DETECT --> Falco[Falco and eBPF]
    DETECT --> Audit[Kubernetes Audit Logs]
```

**Outcome**
AI control-plane risks map cleanly to known ATT&CK techniques — not novel AI threats.

---

## 10. Red and Purple Team Exercise Chain

```mermaid
flowchart LR
    S[Spoof Identity]
    T[Tamper CRDs]
    I[Exfiltrate Data]
    D[Control Plane DoS]
    E[Controller Escape]

    S --> T --> I --> D --> E
```

This provides a ready-made CTF and purple-team roadmap.

---

## 11. STRIDE-Informed Design Rules

* ❌ No direct model to Kubernetes API access
* ❌ No shell execution
* ❌ No wildcard RBAC
* ❌ No implicit trust in tool descriptions
* ❌ No mutable post-validation state
* ❌ No unaudited execution paths

---

## 12. Executive Summary

> **Bottom Line**
> MCP is only safe when it behaves like a Kubernetes policy API — not a tool runner.

---

## 13. Repository Layout (Suggested)

```text
mcp-stride/
├── README.md
├── docs/
│   ├── stride-threat-model.md
│   ├── mitre-mapping.md
│   ├── diagrams.md
├── ctf/
│   ├── spoofing.md
│   ├── crd-tampering.md
│   ├── controller-escape.md
└── policies/
    ├── gatekeeper.yaml
    ├── kyverno.yaml
```

---

##
##
