
# Cloud vs. Local LLM Inference: Enterprise Risk Analysis

## Executive Summary

Enterprise LLM agents increasingly touch sensitive systems — source control, identity, incident response, infrastructure, HR, finance, and customer data. Routing inference through an external provider expands your trust boundary. Keeping it local reduces third-party exposure but increases operational burden.

**Core principle: The model is never the security boundary.** Authorization, policy, tool validation, logging, and approval workflows must live outside the model regardless of where inference runs.

**Default recommendation:**

| Workflow Sensitivity | Recommended Mode |
|---|---|
| Public / low-sensitivity | Cloud (with controls) |
| Internal / confidential | Hybrid or local |
| Regulated / high-impact | Local strongly preferred |

---

## 1. The Fundamental Question

> What sensitive data and authority does the model receive, and whose control boundary does that reasoning cross?

Cloud inference sends prompts, retrieved context, tool results, and conversation history to a third party. That context routinely includes:

- Private source code and diffs
- Customer records and PII
- Employee and HR data
- Incident timelines and log snippets
- Vulnerability and security findings
- Infrastructure topology and IAM state
- Identity metadata and access relationships
- Financial records and contract terms

Local inference keeps this reasoning inside your control boundary — but does not automatically make it secure.

---

## 2. Architecture

### 2.1 Trust Boundary Comparison

```text
Cloud Inference
──────────────────────────────────────────────────
  [ Your Control Boundary                        ]
  User → Agent Orchestrator → Tools & Context
                    │
──────────────────── ↓ ───────────────────────────
          [ External LLM Provider ]
          Third-party processes your data
──────────────────────────────────────────────────

Local Inference
──────────────────────────────────────────────────
  [ Your Control Boundary                        ]
  User → Agent Orchestrator → Tools & Context
                    │
          [ Local Inference Service ]
          vLLM / TGI / SGLang / llama.cpp
  ────────────────────────────────────────────────
```

### 2.2 Controlled Cloud Inference

```text
User
 │
 ▼
Agent Gateway (AuthN/AuthZ)
 │
 ▼
Agent Orchestrator
 ├── Data classification & redaction
 ├── Prompt minimization
 ├── Context retrieval
 └── Tool-call validation
 │                    │
 ▼                    ▼
Egress Proxy      Policy Engine
(allowlist,       (OPA / Cedar)
 quotas,
 logging)
 │
 ▼
Approved Cloud Provider
(DPA/BAA, retention controls)
 │
 ▼
Orchestrator validates response
 │
 ▼
Tool execution (human approval for high-impact)
```

**Minimum controls:** approved vendor + DPA/BAA where required · no-retention configuration · workload identity (no static keys) · prompt minimization and redaction · egress restrictions · tool-call validation · human approval for high-impact actions

### 2.3 Secure Local Inference

```text
User
 │
 ▼
Agent Gateway (AuthN/AuthZ)
 │
 ▼
Agent Orchestrator
 ├── Prompt assembly
 ├── Context retrieval
 ├── Tool-call validation
 └── Audit logging
 │                    │
 ▼                    ▼
Local Inference    Policy Engine
Service            (OPA / Cedar)
(isolated NS,
 pinned digest,
 signed image)
 │
 ▼
Tool Servers
(least-privilege credentials, mTLS)
```

**Minimum controls:** isolated namespace · dedicated service identity · signed + pinned model artifacts · default-deny egress · network policies · mTLS between services · least-privilege tool credentials · patching and upgrade process

---

## 3. Risk Categories

### 3.1 Data Disclosure
Cloud inference creates a third-party data processing event for every prompt. Sensitive content — code, records, logs, identities — crosses an external boundary.

**Controls:** classify data before prompting · minimize and redact · never include raw secrets · restrict and audit logs · enforce retention limits

### 3.2 Prompt Injection
Untrusted content enters context from anywhere: tickets, PR comments, Slack messages, logs, documents, CRM notes, alert payloads. Cloud inference does not cause this. Local inference does not solve it.

**Controls:** treat retrieved content as untrusted · isolate instructions from data · allowlist tools · validate all tool arguments · enforce policy outside the model · require approval for high-risk actions

### 3.3 Tool Misuse
The real risk is agents with write access. Dangerous actions include:

- Granting Okta admin access
- Disabling or silencing alerts
- Restarting production services
- Merging PRs or rotating secrets
- Issuing refunds or exporting customer lists
- Creating firewall rules or modifying IAM

**Controls:** orchestrator mediates every tool call · user identity bound to tool permissions · read and write tools separated · dangerous actions require human approval · immutable audit logs

### 3.4 Credential Exposure
Cloud inference requires external API credentials. Local inference requires model registry, object storage, and service mesh credentials. Both are risks.

**Controls:** workload identity over static keys · least privilege · rotation · metadata service hardening · API usage monitoring

### 3.5 Compliance
Cloud inference may create data processing obligations depending on data type and jurisdiction:

- SOC 2 / ISO 27001
- HIPAA / HITECH
- GDPR / CCPA / CPRA
- PCI DSS
- FedRAMP
- Customer contractual commitments

**Controls:** vendor risk review · DPA/BAA where required · subprocessor review · documented data flows · region controls

### 3.6 Model Integrity
Cloud providers control model versions, guardrails, and updates. You may not know when behavior changes.

**Controls:** pin model versions · verify artifact digests · sign images · regression test on upgrades · maintain rollback plan

### 3.7 Egress and Exfiltration
Cloud inference requires outbound paths. A compromised workload may abuse those paths.

**Controls:** default-deny egress · VPC endpoints / PrivateLink where available · destination allowlists · quotas · anomaly detection

---

## 4. Risk Matrix

| Risk Area | Cloud | Local |
|---|---|---|
| Data crosses external boundary | ⚠️ Higher | ✅ Lower |
| Third-party processing | ⚠️ Higher | ✅ Lower |
| Provider logging/retention | ⚠️ Higher | ✅ Lower |
| Compliance burden (sensitive data) | ⚠️ Higher | ✅ Lower |
| Egress exfiltration surface | ⚠️ Higher | ✅ Lower (if restricted) |
| Model version verifiability | ⚠️ Lower | ✅ Higher (if pinned) |
| Prompt injection | ⚠️ Equal | ⚠️ Equal |
| Tool misuse without controls | ⚠️ Equal | ⚠️ Equal |
| Credential abuse | ⚠️ Medium-high | ⚠️ Medium |
| Operational complexity | ✅ Lower | ⚠️ Higher |
| Availability dependency | Provider SLA | Your infra |
| Supply-chain responsibility | Shared | Customer-owned |

---

## 5. Workflow Risk Guide

| Workflow | Systems | Recommended Mode | Key Risk |
|---|---|---|---|
| Public documentation bot | Public content | ☁️ Cloud OK | Low sensitivity |
| Internal wiki assistant | Confluence, Notion, Drive | 🔀 Hybrid/local | Document classification |
| Code assistant | GitHub, GitLab, Bitbucket | 🏠 Local preferred | Source code, secrets in diffs |
| PR review agent | GitHub, CI, Snyk, Semgrep | 🏠 Local preferred | Code, CI logs, PR comments |
| Incident response | PagerDuty, Datadog, Splunk, Slack | 🏠 Local preferred | Logs, outage details, customer impact |
| Identity / access | Okta, Entra ID, Google Workspace | 🏠 Local strongly | Privileged identity data |
| Infrastructure agent | AWS, GCP, Azure, Terraform | 🏠 Local strongly | IAM, topology, blast radius |
| Security triage | Wiz, CrowdStrike, Snyk, Tenable | 🏠 Local preferred | Vuln data, asset inventory |
| Customer support | Zendesk, Intercom, Salesforce | 🔀 Hybrid/local | PII, customer data |
| HR assistant | Workday, BambooHR, Greenhouse | 🏠 Local strongly | Employee privacy |
| Finance agent | Stripe, NetSuite, HubSpot | 🏠 Local preferred | Financial and contractual data |
| CRM / sales | Salesforce, HubSpot, Gong | 🔀 Hybrid | Varies by account sensitivity |
| Data warehouse | Snowflake, BigQuery, Redshift | 🏠 Local preferred | Query results may be regulated |
| Workflow automation | Jira, Slack, Linear, ServiceNow | 🔀 Hybrid/local | Write access scope |

---

## 6. Decision Framework

**Use local inference when any of the following are true:**
- Prompts include regulated, customer-confidential, or employee data
- Prompts include private source code or security findings
- Prompts include infrastructure topology or IAM state
- The agent can mutate identity, infrastructure, finance, or customer systems
- Provider contracts do not clearly permit the data type
- Model version integrity must be verifiable

**Cloud inference may be acceptable when:**
- Data is public or low-sensitivity
- Provider is approved with acceptable retention and training policies
- Prompts are minimized and redacted
- The agent has no dangerous write tools
- Egress is restricted and monitored
- Risk is formally accepted

**Hybrid inference may be appropriate when:**
- Sensitive data can be summarized or classified locally before cloud inference
- A policy engine decides per-request whether cloud routing is permitted
- Logs prove exactly what crossed the external boundary

---

## 7. Minimum Enterprise Policy

```text
1. Public and low-sensitivity data may use approved cloud inference providers.

2. Internal confidential data may use cloud inference only with vendor approval,
   prompt minimization, documented retention controls, and data-owner sign-off.

3. Regulated data, credentials, private source code, identity data, employee
   data, security findings, incident data, infrastructure state, and raw customer
   records require local/private inference unless a formal exception is approved.

4. No model may directly execute tools. All tool calls must be mediated by an
   orchestrator that enforces authorization, validates arguments, and produces
   an immutable audit record.

5. High-impact actions require explicit human approval: identity changes,
   production changes, customer-impacting actions, external communications,
   payment and refund actions, data exports, and deletions.

6. Prompt and tool-result logs are sensitive assets. They must be
   access-controlled, redacted where appropriate, encrypted at rest and
   in transit, and subject to defined retention limits.
```

---

## 8. Conclusion

**Cloud inference is not inherently unsafe. Local inference is not inherently secure. The difference is control.**

Cloud inference trades control for simplicity. That trade is acceptable for low-sensitivity workloads with strong compensating controls. For agents with access to identity, production infrastructure, source code, security findings, HR data, financial records, or incident response workflows, the operational overhead of local inference is the correct default.

**The recommended default for high-impact enterprise agents:**

> Local/private inference · tool policy enforced outside the model · restricted egress · least-privilege credentials · verified model artifacts · human approval for high-impact actions · immutable audit logs

##
##
