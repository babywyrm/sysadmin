
# STRIDE Threat Model

## Model Context Protocol (MCP) as a Kubernetes Control Plane

---

## 1. Scope & System Boundary

### In Scope

* AI Models / Agents
* MCP Server (policy + validation)
* MCP Tool Registry
* MCP → Kubernetes interface
* Kubernetes API Server
* AI Controllers (reconcile loops)
* CRDs (`AIAction`, `AITool`, etc.)
* Audit & logging pipeline

### Out of Scope (but adjacent)

* Model training pipelines
* External SaaS LLM providers (assumed upstream)
* Human CI/CD workflows

---

## 2. STRIDE Overview

| STRIDE Category            | Risk Theme                |
| -------------------------- | ------------------------- |
| **S**poofing               | Identity impersonation    |
| **T**ampering              | Unauthorized modification |
| **R**epudiation            | Lack of accountability    |
| **I**nformation Disclosure | Data leakage              |
| **D**enial of Service      | Availability impact       |
| **E**levation of Privilege | Unauthorized power        |

---

## 3. STRIDE Analysis by Component

---

## S — Spoofing Identity

### Threats

| Threat                  | Description                            |
| ----------------------- | -------------------------------------- |
| Model identity spoofing | Attacker impersonates trusted AI agent |
| MCP client spoofing     | Unauthorized service calls MCP         |
| Tool impersonation      | Fake or shadow tool registered         |

### Attack Examples

* Forged service account token calling MCP
* Replayed MCP requests from compromised pod
* Tool registry collision (“trusted-sounding” tool)

### Impact

* Unauthorized AI actions
* Policy bypass
* Loss of trust boundary

### Mitigations

* mTLS / SPIFFE identities
* Short-lived tokens
* Explicit model identity binding
* Immutable tool registry
* Mutual auth between MCP ↔ controllers

---

## T — Tampering with Data or State

### Threats

| Threat                     | Description                               |
| -------------------------- | ----------------------------------------- |
| CRD manipulation           | AIAction modified post-creation           |
| Policy tampering           | MCP policies altered                      |
| Controller logic injection | Malicious inputs reaching execution paths |

### Attack Examples

* Modifying `spec` after MCP validation
* Injecting executable strings into CRDs
* Policy config drift or overwrite

### Impact

* Arbitrary execution
* Infrastructure mutation
* Silent compromise

### Mitigations

* Admission control validation
* Read-only CRDs post-create (immutability)
* Strong typing (no stringly-typed execution)
* No shell execution in controllers
* GitOps-managed policies

---

## R — Repudiation

### Threats

| Threat           | Description                          |
| ---------------- | ------------------------------------ |
| Action denial    | Model denies having triggered action |
| Log evasion      | Actions performed without audit      |
| Attribution loss | Cannot trace actor or intent         |

### Attack Examples

* High-volume benign actions hiding malicious one
* Controller-only logs without model attribution
* Missing request correlation IDs

### Impact

* Incident response failure
* Compliance violations
* Undetected abuse

### Mitigations

* Mandatory reason fields
* Model identity stamped into CRDs
* Correlated request IDs
* Immutable audit logs
* Separate control-plane logging

---

## I — Information Disclosure

### Threats

| Threat               | Description                |
| -------------------- | -------------------------- |
| Secret leakage       | Model reads sensitive data |
| Context overexposure | Excessive read permissions |
| Output exfiltration  | AI response leaks data     |

### Attack Examples

* Reading ConfigMaps and reconstructing secrets
* Overly broad “observe cluster” tools
* Model echoing sensitive values in responses

### Impact

* Credential theft
* Lateral movement
* Data breach

### Mitigations

* Read/write separation
* Context redaction
* Explicit data classification
* No secret material in MCP context
* Output filtering / post-processing

---

## D — Denial of Service

### Threats

| Threat           | Description             |
| ---------------- | ----------------------- |
| Reconcile storms | Infinite AIAction loops |
| API saturation   | High-volume CR creation |
| Tool abuse       | Resource-heavy actions  |

### Attack Examples

* AIAction never reaching terminal state
* Prompt-induced action loops
* Malicious scaling oscillations

### Impact

* Control plane degradation
* Production outages
* Alert fatigue

### Mitigations

* Rate limits on MCP
* Reconcile backoff & caps
* TTL on AIAction CRDs
* Max retries enforced
* Circuit breakers in controllers

---

## E — Elevation of Privilege

### Threats

| Threat                      | Description                     |
| --------------------------- | ------------------------------- |
| Over-privileged controllers | Controllers exceed scope        |
| Tool privilege creep        | Tools gain more power over time |
| Policy gaps                 | MCP allows more than intended   |

### Attack Examples

* Controller with `*` permissions
* AIAction triggers unintended resource types
* Namespace escape via mis-scoped RBAC

### Impact

* Full cluster compromise
* Persistent backdoors
* Total trust failure

### Mitigations

* One-controller-per-action-type
* Least-privilege RBAC
* Namespace isolation
* Deny-by-default policies
* Human approval gates for high-risk actions

---

## 4. STRIDE Heat Map (Qualitative)

| Category        | Likelihood | Impact   | Risk         |
| --------------- | ---------- | -------- | ------------ |
| Spoofing        | Medium     | High     | **High**     |
| Tampering       | Medium     | Critical | **Critical** |
| Repudiation     | Low        | High     | **Medium**   |
| Info Disclosure | Medium     | High     | **High**     |
| DoS             | High       | Medium   | **High**     |
| Elevation       | Low        | Critical | **Critical** |

---

## 5. Key STRIDE Insights

### 5.1 MCP Is a Trust Concentrator

* Compromise of MCP ≈ policy bypass
* Must be hardened like an API server

### 5.2 Controllers Are the Real Blast Radius

* Controllers define *actual power*
* RBAC mistakes are catastrophic

### 5.3 AI Must Be Treated as Hostile Input

* STRIDE maps **directly** to prompt abuse
* Models are not trusted actors

---

## 6. STRIDE-Informed Design Rules

1. **No direct model → API access**
2. **No shell execution**
3. **No wildcard RBAC**
4. **No implicit trust in tool descriptions**
5. **No mutable post-validation state**
6. **No unaudited execution paths**

---

## 7. Mapping STRIDE → CTF Scenarios

| STRIDE | CTF Scenario         |
| ------ | -------------------- |
| S      | Model identity spoof |
| T      | CRD injection        |
| R      | Audit evasion        |
| I      | Secret exfiltration  |
| D      | Reconcile DoS        |
| E      | Controller escape    |

This gives you a **clean exercise plan** for red/purple teams.

---

## 8. Executive Summary (for reviewers)

> Applying STRIDE to MCP confirms that **the dominant risks are privilege escalation, tampering, and information disclosure**, all of which are mitigated by enforcing Kubernetes-native control-plane patterns and treating AI as untrusted input.

---

## 9. Bottom Line

> **MCP is only safe when it behaves like a policy API, not a tool runner.**

STRIDE validates that:

* Kubernetes is the right enforcement layer
* Controllers are the correct execution boundary
* Defense-in-depth is mandatory, not optional

---

##
##
