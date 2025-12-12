
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


# STRIDE → MITRE ATT&CK Mapping ..beta..

## Model Context Protocol (MCP) in Kubernetes

---

## 1. Purpose

This section maps identified **STRIDE threats** for the MCP-based AI control plane to relevant **MITRE ATT&CK techniques**, enabling:

* Structured adversary modeling
* Red / purple team exercise design
* Detection engineering alignment
* Risk traceability to industry-standard taxonomy

---

## 2. Mapping Scope

### Applies To

* MCP server
* MCP tool registry
* AI models / agents
* AIAction CRDs
* Kubernetes controllers
* Kubernetes API server
* Audit and policy layers

### ATT&CK Matrices Used

* **Enterprise ATT&CK**
* **Cloud (Kubernetes / Containers) ATT&CK**

---

## 3. STRIDE → MITRE ATT&CK Mapping Table

---

## S — Spoofing Identity

| STRIDE Threat               | MITRE Technique        | ID    | Relevance                                |
| --------------------------- | ---------------------- | ----- | ---------------------------------------- |
| Model identity spoofing     | Valid Accounts         | T1078 | Forged service accounts or stolen tokens |
| MCP client impersonation    | Token Impersonation    | T1134 | Reuse or abuse of MCP auth tokens        |
| Tool impersonation          | Masquerading           | T1036 | Malicious tools named like trusted tools |
| Service-to-service spoofing | Exploit Authentication | T1556 | Bypassing mTLS / weak auth               |

**Detection Signals**

* Unexpected service account usage
* Token reuse from new pod identities
* MCP calls outside normal workload graph

---

## T — Tampering with Data or State

| STRIDE Threat              | MITRE Technique                     | ID    | Relevance                    |
| -------------------------- | ----------------------------------- | ----- | ---------------------------- |
| CRD manipulation           | Modify Cloud Compute Infrastructure | T1578 | AIAction spec tampering      |
| Policy modification        | Modify System Configuration         | T1601 | MCP policy drift             |
| Controller logic injection | Command Injection                   | T1059 | Unsafe interpolation or exec |
| Tool registry poisoning    | Supply Chain Compromise             | T1195 | Malicious tool registration  |

**Detection Signals**

* CRDs modified after creation
* Policy changes outside GitOps
* Controllers executing unexpected paths

---

## R — Repudiation

| STRIDE Threat    | MITRE Technique                       | ID        | Relevance                         |
| ---------------- | ------------------------------------- | --------- | --------------------------------- |
| Action denial    | Obfuscated Files or Information       | T1027     | Loss of attribution clarity       |
| Log manipulation | Clear Windows Event Logs / Equivalent | T1070     | Log tampering or suppression      |
| Audit evasion    | Indicator Removal on Host             | T1070.004 | High-volume noise to hide actions |

**Detection Signals**

* Missing correlation IDs
* Unattributed AIActions
* Log gaps during activity spikes

---

## I — Information Disclosure

| STRIDE Threat         | MITRE Technique                      | ID        | Relevance                       |
| --------------------- | ------------------------------------ | --------- | ------------------------------- |
| Secret exfiltration   | Credentials from Configuration Files | T1552     | Reading ConfigMaps / env vars   |
| Excessive read access | Unsecured Credentials                | T1552.001 | Overbroad observe permissions   |
| AI output leakage     | Exfiltration Over Application Layer  | T1041     | Model leaking data in responses |
| Context overexposure  | Cloud Service Discovery              | T1526     | Mapping cluster internals       |

**Detection Signals**

* Read-heavy access patterns
* AI responses containing sensitive markers
* Unusual enumeration behavior

---

## D — Denial of Service

| STRIDE Threat       | MITRE Technique            | ID    | Relevance                          |
| ------------------- | -------------------------- | ----- | ---------------------------------- |
| Reconcile storms    | Endpoint Denial of Service | T1499 | Infinite controller loops          |
| API server overload | Network Denial of Service  | T1498 | Excessive CR creation              |
| Tool abuse          | Resource Hijacking         | T1496 | Scaling abuse / compute exhaustion |

**Detection Signals**

* High-frequency AIAction creation
* Controller retry storms
* Control-plane latency spikes

---

## E — Elevation of Privilege

| STRIDE Threat                        | MITRE Technique                   | ID        | Relevance                 |
| ------------------------------------ | --------------------------------- | --------- | ------------------------- |
| Over-privileged controllers          | Abuse Elevation Control Mechanism | T1548     | Wildcard RBAC             |
| Namespace escape                     | Escape to Host                    | T1611     | Controller breakout paths |
| Privilege escalation via policy gaps | Exploit Public-Facing Application | T1190     | MCP policy bypass         |
| Cluster-admin acquisition            | Valid Accounts (Cloud)            | T1078.004 | SA token escalation       |

**Detection Signals**

* RBAC changes involving controllers
* Unexpected access to cluster-scoped APIs
* Privileged operations from AI-triggered workflows

---

## 4. STRIDE → ATT&CK Heat Alignment

| STRIDE          | Dominant ATT&CK Tactics           |
| --------------- | --------------------------------- |
| Spoofing        | Initial Access, Credential Access |
| Tampering       | Defense Evasion, Persistence      |
| Repudiation     | Defense Evasion                   |
| Info Disclosure | Discovery, Exfiltration           |
| DoS             | Impact                            |
| Elevation       | Privilege Escalation              |

---

## 5. Red Team Exercise Mapping

| Exercise             | STRIDE | ATT&CK Focus |
| -------------------- | ------ | ------------ |
| Prompt Injection Lab | S, T   | T1078, T1190 |
| CRD Smuggling        | T, E   | T1059, T1548 |
| Tool Poisoning       | T      | T1195        |
| Secret Exfiltration  | I      | T1552, T1041 |
| Reconcile DoS        | D      | T1499        |
| Controller Escape    | E      | T1611        |

---

## 6. Detection Engineering Implications

This mapping enables:

* SIEM rule creation
* Falco / eBPF detection alignment
* Kubernetes audit policy tuning
* Threat hunting playbooks

Example:

> “Detect T1552 attempts via AIAction-generated read access across namespaces”

---

## 7. Executive Takeaway

> Mapping STRIDE to MITRE ATT&CK confirms that **AI control-plane risks align with known cloud attack patterns**, not novel unknowns — making them **detectable, testable, and governable** using existing security frameworks.

---

## 8. One-Line Summary (Attachment Friendly)

> **STRIDE analysis of MCP maps cleanly to MITRE ATT&CK cloud and container techniques, enabling standardized adversary simulation, detection, and governance of AI-driven infrastructure actions.**

---
