
# 🧠 Model Context Protocol (MCP) as a Kubernetes Control Plane ..beta..

## STRIDE Threat Model + MITRE ATT&CK Mapping

> **TL;DR:** MCP is safe only when it behaves like a Kubernetes control plane API — not a tool runner.
> AI is *untrusted input*. Controllers are the *blast radius*. Defense-in-depth is mandatory.

---

## 1. Scope & System Boundary

### In Scope

* AI Models / Agents *(untrusted)*
* MCP Server (policy + validation)
* MCP Tool Registry
* MCP → Kubernetes Interface
* Kubernetes API Server
* AI Controllers (reconcile loops)
* CRDs (`AIAction`, `AITool`, etc.)
* Audit & logging pipeline

### Out of Scope (Adjacent)

* Model training pipelines
* External SaaS LLM providers (assumed upstream)
* Human CI/CD workflows

---

## 2. MCP as a Kubernetes Control Plane (Architecture)

```mermaid
flowchart LR
    subgraph External
        LLM[External LLM Provider<br/>(Untrusted)]
    end

    subgraph Cluster["Kubernetes Cluster"]
        subgraph MCP["MCP Control Plane"]
            MCPAPI[MCP Server<br/>Policy + Validation]
            Registry[MCP Tool Registry]
        end

        subgraph AI["AI Layer"]
            Agent[AI Model / Agent<br/>(Untrusted Input)]
        end

        subgraph Control["Execution Layer"]
            CRD[AIAction / AITool CRDs]
            Ctrl[AI Controllers<br/>(Reconcile Loops)]
            KAPI[Kubernetes API Server]
        end

        Audit[Audit & Logging Pipeline]
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

    style LLM fill:#ffe6e6
    style Agent fill:#ffe6e6
    style MCPAPI fill:#e6f0ff
    style Ctrl fill:#fff2cc
```

**Key Insight:**
Everything *before* MCP is hostile.
Everything *after* controllers is real infrastructure power.

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

    Agent -->|S: Identity Spoofing| MCP
    MCP -->|T: Policy / State Tampering| CRD
    CRD -->|R: Attribution Loss| Ctrl
    Ctrl -->|E: Privilege Escalation| KAPI
    MCP -->|I: Data Exposure| Agent
    Ctrl -->|D: Reconcile Storms| Ctrl

    style Agent fill:#f8d7da
    style MCP fill:#d1ecf1
    style Ctrl fill:#fff3cd
```

---

## 5. Secure Execution Flow (Happy Path)

```mermaid
sequenceDiagram
    participant AI as AI Agent
    participant MCP as MCP Server
    participant VAL as Policy Validator
    participant API as K8s API Server
    participant CTRL as Controller
    participant AUD as Audit Log

    AI->>MCP: Request Action
    MCP->>VAL: Validate Policy + Scope
    VAL-->>MCP: Approved
    MCP->>API: Create AIAction CRD
    API->>AUD: Audit: CRD Created
    CTRL->>API: Watch AIAction
    CTRL->>API: Reconcile (Scoped Action)
    CTRL->>AUD: Audit: Action Executed
```

**Design Properties**

* No direct model → Kubernetes API access
* MCP validates *before* CRD creation
* Controllers enforce final execution guardrails

---

## 6. STRIDE Failure Mode: CRD Tampering (T + E)

```mermaid
sequenceDiagram
    participant Attacker
    participant API as K8s API Server
    participant CTRL as Controller

    Attacker->>API: Patch AIAction.spec
    API-->>Attacker: 200 OK
    CTRL->>API: Read Modified Spec
    CTRL->>CTRL: Execute Dangerous Path
```

**Required Controls**

* Admission webhooks
* Immutable CRDs post-create
* Strong typing (no string execution)
* No shell invocation

---

## 7. Denial of Service: Reconcile Storms

```mermaid
flowchart LR
    AI[AI Agent]
    MCP[MCP]
    CRD[AIAction]
    CTRL[Controller]
    API[K8s API]

    AI --> MCP --> CRD --> CTRL --> CRD
    CTRL --> API --> CTRL

    style CTRL fill:#f8d7da
```

**Mitigations**

* TTL on AIAction CRDs
* Retry caps & backoff
* Circuit breakers in controllers
* MCP rate limiting

---

## 8. Elevation of Privilege: Over-Privileged Controller

```mermaid
flowchart TB
    AI[AI Agent]
    MCP[MCP]
    CRD[AIAction]
    CTRL[Controller<br/>cluster-admin]
    KAPI[K8s API]

    AI --> MCP --> CRD --> CTRL --> KAPI
    KAPI -->|Create ClusterRoleBinding| KAPI

    style CTRL fill:#f8d7da
```

**Critical Insight:**
Controllers define *actual* blast radius — not MCP.

---

## 9. STRIDE → MITRE ATT&CK Mapping (Summary)

```mermaid
flowchart LR
    STRIDE[S T R I D E]
    ATTACK[MITRE ATT&CK<br/>(Cloud + Containers)]
    DETECT[Detection & Controls]

    STRIDE --> ATTACK
    ATTACK --> DETECT

    DETECT --> SIEM[SIEM Rules]
    DETECT --> Falco[Falco / eBPF]
    DETECT --> Audit[K8s Audit Logs]
```

**Outcome:**
AI control-plane risks map cleanly to *known* ATT&CK techniques — not novel AI threats.

---

## 10. Red / Purple Team Exercise Chain

```mermaid
flowchart LR
    S[Spoof Identity]
    T[Tamper CRD]
    I[Exfiltrate Secrets]
    D[DoS Control Plane]
    E[Controller Escape]

    S --> T --> I --> D --> E
```

This provides a **ready-made CTF / purple-team roadmap**.

---

## 11. STRIDE-Informed Design Rules

* ❌ No direct model → Kubernetes API access
* ❌ No shell execution
* ❌ No wildcard RBAC
* ❌ No implicit trust in tool descriptions
* ❌ No mutable post-validation state
* ❌ No unaudited execution paths

---

## 12. Executive Summary (Slide-Ready)

```mermaid
flowchart TB
    AI[AI is Untrusted Input]
    MCP[MCP = Policy Gate]
    CTRL[Controllers = Power]
    K8s[Kubernetes Enforces]

    AI --> MCP --> CTRL --> K8s

    style AI fill:#f8d7da
    style MCP fill:#d1ecf1
    style CTRL fill:#fff3cd
```

> **Bottom Line:**
> MCP is only safe when it behaves like a Kubernetes policy API — not a tool runner.

---

## 13. Repository Suggestions (Optional)

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

##
##
