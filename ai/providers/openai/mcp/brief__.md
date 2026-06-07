
# Security Overview

## Model Context Protocol (MCP) as a Kubernetes-Native Control Plane

---

## 1. Executive Summary

This document describes the security architecture for deploying a **Model Context Protocol (MCP)** within a Kubernetes environment, with a particular focus on **controller-based execution** for AI-initiated actions.

The design intentionally treats AI systems as **untrusted decision engines** and leverages Kubernetes’ mature control-plane primitives (CRDs, controllers, RBAC, admission control, and audit logging) to enforce **deterministic, auditable, and policy-governed execution** of all AI-driven operations.

This approach aligns with modern Zero Trust principles and is suitable for regulated environments (SOC2, FedRAMP-aligned, enterprise internal platforms).

---

## 2. Threat Model Assumptions

### 2.1 Explicit Assumptions

| Area       | Assumption                                                                  |
| ---------- | --------------------------------------------------------------------------- |
| AI Models  | **Untrusted** — may hallucinate, misinterpret intent, or be prompt-injected |
| Inputs     | Potentially malicious (user input, external signals, poisoned context)      |
| Network    | East–west traffic is not inherently trusted                                 |
| Kubernetes | Control plane is trusted and hardened                                       |
| MCP        | Security enforcement point, not an execution engine                         |

> **Key Principle:**
> *Models may decide, but they must never directly act.*

---

## 3. Architectural Security Goals

1. **Prevent direct infrastructure mutation by AI**
2. **Constrain AI actions to pre-approved capabilities**
3. **Ensure every action is auditable and attributable**
4. **Limit blast radius of incorrect or malicious AI decisions**
5. **Enable policy enforcement independent of model behavior**
6. **Support gradual privilege escalation via explicit approval**

---

## 4. High-Level Architecture

```
┌────────────┐
│  AI Model  │
│ (Agent)    │
└─────┬──────┘
      │ MCP request (intent only)
      ▼
┌───────────────────────────┐
│ MCP Server (Control Plane)│
│                           │
│ - Tool registry           │
│ - Schema validation       │
│ - AuthN / AuthZ           │
│ - Policy enforcement      │
│ - Audit logging           │
└─────┬─────────────────────┘
      │ Creates CRDs
      ▼
┌───────────────────────────┐
│ Kubernetes API Server     │
│                           │
│ - RBAC                    │
│ - Admission controllers   │
│ - Policy engines          │
└─────┬─────────────────────┘
      │
      ▼
┌───────────────────────────┐
│ AI Controllers            │
│ (Reconcile Loops)         │
│                           │
│ - Idempotent execution    │
│ - Scoped permissions      │
│ - Status reporting        │
└───────────────────────────┘
```

---

## 5. Core Security Design Principles

### 5.1 Intent vs Execution Separation

AI systems **express intent**, not execution:

* MCP validates *what* the model wants to do
* Controllers decide *how* (or if) it happens

This prevents:

* Arbitrary API calls
* Privilege escalation via prompt injection
* Non-deterministic side effects

---

### 5.2 CRD-Based Mediation

All AI actions are represented as **Kubernetes Custom Resources**, such as:

```yaml
kind: AIAction
spec:
  action: ScaleDeployment
  target:
    namespace: prod
    name: frontend
  replicas: 6
  reason: "Traffic spike detected"
```

Security benefits:

* Declarative
* Diffable
* Reviewable
* Replayable
* Subject to policy enforcement

---

### 5.3 Controller-Driven Execution

Controllers:

* Are **idempotent**
* Use **minimal RBAC**
* Execute **exactly one class of action**
* Update status rather than returning raw execution output

This eliminates:

* Direct model → API coupling
* Action ambiguity
* Multi-step hidden execution

---

## 6. Authentication & Authorization

### 6.1 MCP Authentication

* Models authenticate to MCP using:

  * Service identity (SPIFFE / mTLS preferred)
  * Short-lived tokens
* No static credentials embedded in prompts or context

---

### 6.2 Authorization Model

Authorization is enforced at **three independent layers**:

| Layer             | Purpose                             |
| ----------------- | ----------------------------------- |
| MCP Tool Registry | What tools exist                    |
| MCP Policy Engine | Which model can request which tool  |
| Kubernetes RBAC   | What the controller can actually do |

> **Defense-in-depth:**
> A policy bypass at one layer does not grant execution.

---

## 7. Policy Enforcement

### 7.1 MCP-Level Policy

* Input schema validation
* Tool allowlists
* Argument bounds checking
* Context scoping (read-only vs mutable)

Example:

* Model may request scaling between 1–10 replicas
* Cannot specify namespaces outside its scope

---

### 7.2 Kubernetes Admission Control

AIAction CRDs are subject to:

* OPA Gatekeeper
* Kyverno
* ValidatingAdmissionPolicies

Example enforced rules:

* No production namespace mutation without approval label
* No deletion actions allowed
* Rate limits on AI-generated CRs

---

## 8. Auditability & Forensics

### 8.1 Action Attribution

Each AIAction includes:

* Model identity
* Request timestamp
* Source context
* Reason string

### 8.2 Audit Trails

Logged at:

* MCP request layer
* Kubernetes API server
* Controller reconciliation
* Status updates

This enables:

* Full action reconstruction
* Incident response
* Compliance reporting

---

## 9. Blast Radius Control

### 9.1 Namespace & Scope Isolation

* Controllers scoped to specific namespaces
* Tools bound to explicit resource types
* No wildcard permissions

### 9.2 Progressive Capability Model

AI capabilities can be staged:

1. Read-only observation
2. Advisory actions (recommendations only)
3. Limited write actions
4. Full automation (opt-in only)

---

## 10. Failure & Abuse Scenarios

| Scenario                 | Mitigation                          |
| ------------------------ | ----------------------------------- |
| Prompt injection         | Tool allowlists + schema validation |
| Hallucinated API calls   | CRD validation                      |
| Infinite action loops    | Rate limiting + reconcile guards    |
| Privilege escalation     | RBAC + admission control            |
| Malicious model behavior | Human approval gates                |

---

## 11. Why MCP-as-Controller Is Preferable to Direct Tooling

| Direct Tool Calls      | MCP + Controller        |
| ---------------------- | ----------------------- |
| Hard to audit          | Fully auditable         |
| Non-deterministic      | Deterministic           |
| Model holds power      | Platform holds power    |
| Difficult to roll back | Declarative rollback    |
| Poor compliance story  | Strong compliance story |

---

## 12. Compliance & Enterprise Readiness

This architecture aligns well with:

* SOC2 change tracking
* FedRAMP-style separation of duties
* PSIRT expectations
* Internal platform governance

It enables:

* Clear ownership boundaries
* Safe experimentation
* Controlled rollout of AI automation

---

## 13. Conclusion

Treating MCP as a **Kubernetes-native control plane** — with CRDs as the interface and controllers as the execution boundary — provides a **secure, auditable, and policy-driven foundation** for AI-assisted operations.

This design ensures:

* AI systems augment human operators
* The platform remains in control
* Security posture improves as automation increases

---

### One-Line Summary

> **MCP should govern AI intent, Kubernetes should enforce execution, and controllers should be the only actors with real power.**


##
##
