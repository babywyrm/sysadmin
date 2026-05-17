# Whitepaper: Risk Analysis for Cloud vs Local LLM Inference in Enterprise Agent Workflows

## Executive Summary

Enterprise LLM agents increasingly connect to sensitive business systems: source control, ticketing, identity, incident response, observability, cloud infrastructure, CRM, HRIS, finance, and document platforms. These agents may read confidential data, summarize internal events, reason over production incidents, or request tool calls that affect real systems.

A central architectural question is whether inference should run through an external managed provider, such as Amazon Bedrock, OpenAI, Anthropic, Google Vertex AI, Azure OpenAI, Cohere, Mistral, Databricks Mosaic AI, Together AI, Groq, Fireworks AI, or Replicate, or whether inference should run locally inside the organization’s own controlled environment.

This paper analyzes the security and compliance implications of that choice.

The key conclusion:

> Cloud inference expands the trust boundary. Local inference reduces third-party exposure but increases the burden of securely operating model infrastructure.

For low-sensitivity workflows, cloud inference can be acceptable with strong controls. For agents that access identity, infrastructure, source code, customer data, employee data, incident data, security findings, or regulated records, local/private inference should be preferred unless a formal risk review approves external processing.

---

## 1. Scope

This paper applies to LLM agents and copilots that interact with enterprise SaaS and infrastructure systems, including but not limited to:

### AI and inference providers

- Amazon Bedrock
- OpenAI
- Anthropic
- Google Vertex AI
- Azure OpenAI
- Cohere
- Mistral
- Databricks Mosaic AI
- Together AI
- Groq
- Fireworks AI
- Replicate
- Perplexity API

### Identity and access systems

- Okta
- Microsoft Entra ID
- Google Workspace
- OneLogin
- Ping Identity
- Duo
- Teleport
- Auth0
- WorkOS

### Source control and engineering systems

- GitHub
- GitLab
- Bitbucket
- Azure DevOps
- CircleCI
- Buildkite
- Jenkins
- Argo CD
- Harness
- LaunchDarkly
- Snyk
- Semgrep
- SonarQube
- Dependabot

### Ticketing, collaboration, and knowledge systems

- Jira
- Confluence
- Slack
- Microsoft Teams
- Notion
- ServiceNow
- Linear
- Asana
- Monday.com
- Zendesk
- Intercom
- Freshdesk
- Google Drive
- SharePoint
- Dropbox
- Box

### Incident, observability, and security systems

- PagerDuty
- Opsgenie
- Datadog
- New Relic
- Splunk
- Elastic
- Sentry
- Grafana
- Prometheus
- CloudWatch
- SentinelOne
- CrowdStrike
- Wiz
- Lacework
- Orca
- Tenable
- Qualys
- Rapid7
- Vanta
- Drata

### Cloud, infrastructure, and data systems

- AWS
- Azure
- Google Cloud
- Cloudflare
- Fastly
- Kubernetes
- Terraform Cloud
- Pulumi Cloud
- Snowflake
- Databricks
- BigQuery
- Redshift
- MongoDB Atlas
- Stripe
- NetSuite
- Salesforce
- HubSpot
- Workday
- BambooHR
- Greenhouse
- Lever

The goal is not to label any provider as insecure. The goal is to identify what happens when sensitive context and tool authority are routed through an LLM inference boundary.

---

## 2. Core Principle

The model should never be the security boundary.

Whether inference runs locally or in a managed cloud service, the system must enforce authorization, data-flow controls, policy decisions, logging, tool validation, and approval workflows outside the model.

The primary architectural question is:

> What sensitive data and authority does the model receive, and whose control boundary does that reasoning pass through?

---

## 3. Architecture Options

## 3.1 Cloud Inference

Cloud inference sends prompt data, retrieved context, conversation history, and tool results to an external model provider.

```text
+-------------------+
| User / Client     |
+---------+---------+
          |
          v
+-----------------------------+
| Enterprise Agent            |
| Orchestrator                |
| - prompt assembly           |
| - context retrieval         |
| - tool planning             |
+------+------+---------------+
       |      |
       |      v
       |  +-------------------------+
       |  | SaaS / Internal Tools   |
       |  | Jira, GitHub, Okta,     |
       |  | Slack, Datadog, etc.    |
       |  +-------------------------+
       |
       v
+-----------------------------+
| Egress / Internet /         |
| VPC Endpoint / Proxy        |
+-------------+---------------+
              |
              v
+-----------------------------+
| External LLM Provider       |
| Bedrock, OpenAI, Anthropic, |
| Vertex AI, Azure OpenAI     |
+-------------+---------------+
              |
              v
+-----------------------------+
| Model response /            |
| tool-call decision          |
+-------------+---------------+
              |
              v
+-----------------------------+
| Enterprise Agent            |
| validates and executes      |
| approved tool calls         |
+-----------------------------+
```

Data that may cross the external inference boundary:

- system prompts;
- tool schemas;
- user prompts;
- retrieved documents;
- ticket bodies;
- code diffs;
- log snippets;
- customer records;
- employee records;
- identity metadata;
- incident timelines;
- conversation history.

---

## 3.2 Local or Private Inference

Local/private inference keeps model processing within the organization’s own environment, assuming logging, telemetry, and model operations are also controlled.

```text
+-------------------+
| User / Client     |
+---------+---------+
          |
          v
+-----------------------------+
| Enterprise Agent            |
| Orchestrator                |
| - prompt assembly           |
| - context retrieval         |
| - tool planning             |
+------+------+---------------+
       |      |
       |      v
       |  +-------------------------+
       |  | SaaS / Internal Tools   |
       |  | Jira, GitHub, Okta,     |
       |  | Slack, Datadog, etc.    |
       |  +-------------------------+
       |
       v
+-----------------------------+
| Local Inference Service     |
| vLLM, TGI, SGLang, Triton,  |
| llama.cpp, private endpoint |
+-------------+---------------+
              |
              v
+-----------------------------+
| Model response /            |
| tool-call decision          |
+-------------+---------------+
              |
              v
+-----------------------------+
| Enterprise Agent            |
| validates and executes      |
| approved tool calls         |
+-----------------------------+
```

Local inference reduces third-party disclosure, but it does not eliminate risk. The organization must secure:

- Kubernetes or hosting environment;
- GPU nodes;
- model artifacts;
- inference runtime images;
- service accounts;
- logs and traces;
- internal network paths;
- model update process.

---

## 3.3 Trust Boundary Comparison

```text
Cloud inference:

+-------------------------------------------------------------+
| Organization Control Boundary                               |
|                                                             |
|  User -> Agent -> Tools -> Retrieved Sensitive Context      |
|                    |                                        |
+--------------------|----------------------------------------+
                     |
                     v
          +----------------------+
          | External LLM Provider|
          | Third-party boundary |
          +----------------------+

Local inference:

+-------------------------------------------------------------+
| Organization Control Boundary                               |
|                                                             |
|  User -> Agent -> Tools -> Retrieved Sensitive Context      |
|                    |                                        |
|                    v                                        |
|          +----------------------+                           |
|          | Local LLM Inference  |                           |
|          +----------------------+                           |
|                                                             |
+-------------------------------------------------------------+
```

The primary benefit of local inference is not that it is automatically secure. The benefit is that sensitive reasoning can remain inside the organization’s policy, logging, identity, network, and compliance boundary.

---

## 3.4 Controlled Cloud Inference Reference Architecture

```text
+-------------------+
| User / Client     |
+---------+---------+
          |
          v
+-------------------+
| Agent Gateway     |
| AuthN / AuthZ     |
+---------+---------+
          |
          v
+-----------------------------+
| Agent Orchestrator          |
| - data classification       |
| - prompt minimization       |
| - redaction                 |
| - context retrieval         |
| - tool-call validation      |
+------+------+---------------+
       |      |
       |      v
       |  +-------------------------+
       |  | Policy Engine           |
       |  | OPA / Cedar / Custom    |
       |  +-------------------------+
       |
       v
+-----------------------------+
| Egress Proxy / VPC Endpoint |
| destination allowlist       |
| quota controls              |
| request logging             |
+-------------+---------------+
              |
              v
+-----------------------------+
| Approved Cloud LLM Provider |
| contract + retention review |
+-------------+---------------+
              |
              v
+-----------------------------+
| Agent Orchestrator          |
| validates model output      |
| before tool execution       |
+-----------------------------+
```

Minimum controls:

- approved provider;
- vendor security review;
- DPA/BAA where applicable;
- no-retention or limited-retention configuration where available;
- workload identity instead of static API keys;
- prompt minimization and redaction;
- egress restrictions;
- tool-call validation;
- human approval for high-impact actions.

---

## 3.5 Secure Local Inference Reference Architecture

```text
+-------------------+
| User / Client     |
+---------+---------+
          |
          v
+-------------------+
| Agent Gateway     |
| AuthN / AuthZ     |
+---------+---------+
          |
          v
+-----------------------------+
| Agent Orchestrator          |
| - prompt assembly           |
| - context retrieval         |
| - tool-call validation      |
| - audit logging             |
+------+------+---------------+
       |      |
       |      v
       |  +-------------------------+
       |  | Policy Engine           |
       |  | OPA / Cedar / Custom    |
       |  +-------------------------+
       |
       v
+-----------------------------+
| Local Inference Service     |
| isolated namespace          |
| pinned model digest         |
| signed runtime image        |
+-------------+---------------+
              |
              v
+-----------------------------+
| Tool Servers                |
| Jira / GitHub / Okta /      |
| Datadog / ServiceNow / etc. |
| least-privilege credentials |
+-----------------------------+
```

Minimum controls:

- isolated namespace or environment;
- dedicated service accounts;
- signed model artifacts;
- pinned model and runtime digests;
- prompt-log controls;
- default-deny egress;
- Kubernetes network policies;
- mTLS between services;
- least-privilege tool credentials;
- upgrade and rollback process.

---

## 4. Common Enterprise Agent Flows and Risks

## 4.1 Engineering Copilot

Example flow:

```text
GitHub / GitLab / Bitbucket
  -> PR diff, comments, code owners, CI failures
  -> LLM
  -> review summary, suggested fix, tool call
```

Risks:

- private source code leaves the boundary;
- secrets accidentally included in diffs or logs may be sent to the model;
- dependency vulnerabilities may disclose internal exposure;
- prompt injection in issues, PR descriptions, or comments may manipulate the agent;
- write-capable GitHub/GitLab tokens may be abused.

Recommended stance:

- local/private inference preferred for private code;
- cloud inference only with approved vendor controls and redaction;
- write actions require explicit approval.

---

## 4.2 Incident Response Copilot

Example flow:

```text
PagerDuty / Opsgenie
  -> Datadog / New Relic / Splunk / CloudWatch / Sentry
  -> Slack / Teams incident channel
  -> LLM
  -> diagnosis, runbook selection, escalation, remediation suggestion
```

Risks:

- incident details may reveal customer impact, vulnerabilities, infrastructure names, or outage causes;
- logs can contain tokens, PII, IPs, session IDs, and internal URLs;
- model may recommend unsafe remediation;
- prompt injection can be planted in logs, alerts, or chat messages;
- tool calls may restart services, silence alerts, or escalate pages.

Recommended stance:

- local/private inference preferred;
- no direct production-changing actions without human approval;
- redact logs aggressively;
- separate diagnostic tools from mutating tools.

---

## 4.3 Identity and Access Assistant

Example flow:

```text
Okta / Entra ID / Google Workspace
  -> group membership, user profile, access request
  -> LLM
  -> approval recommendation or access change request
```

Risks:

- identity data and access relationships are highly sensitive;
- group membership can reveal privileged roles;
- prompt injection in access-request comments can manipulate decisions;
- agent may grant excessive access;
- compromised tool credentials can modify identity systems.

Recommended stance:

- local/private inference strongly preferred;
- enforce access policy outside the model;
- model may summarize, but should not approve independently;
- all access grants require deterministic policy and audit trail.

---

## 4.4 Customer Support Copilot

Example flow:

```text
Zendesk / Intercom / Freshdesk / Salesforce
  -> customer ticket, account data, chat history
  -> LLM
  -> summary, response draft, refund/escalation recommendation
```

Risks:

- PII, customer confidential data, payment references, and support history may be sent externally;
- customer-provided prompt injection is common;
- generated replies may disclose internal notes;
- CRM data may include regulated or contractual information;
- tool calls may modify customer records or issue credits.

Recommended stance:

- hybrid or local inference preferred for sensitive customers;
- cloud inference may be acceptable for low-sensitivity summaries with redaction;
- customer content must be treated as untrusted input;
- external sends require output filtering.

---

## 4.5 HR and Employee Data Assistant

Example flow:

```text
Workday / BambooHR / Greenhouse / Lever
  -> employee record, candidate notes, compensation, performance data
  -> LLM
  -> summary, routing, draft response
```

Risks:

- employee and candidate data has high privacy sensitivity;
- compensation, performance, medical accommodation, or disciplinary data may be exposed;
- generated outputs may create employment-law risk;
- access control mistakes can leak records across managers or teams.

Recommended stance:

- local/private inference strongly preferred;
- strict role-based access controls;
- no sensitive HR decisions made by the model;
- retention and logging must be tightly controlled.

---

## 4.6 Finance and Revenue Operations Agent

Example flow:

```text
Stripe / NetSuite / Salesforce / HubSpot
  -> invoices, payment events, customer ARR, contract notes
  -> LLM
  -> account summary, collections draft, renewal insight
```

Risks:

- financial data, customer contracts, tax details, and payment metadata may be exposed;
- PCI-adjacent data may enter prompts if controls are weak;
- model may generate incorrect financial statements or commitments;
- prompt injection in CRM notes can manipulate recommendations.

Recommended stance:

- local/private inference preferred for finance-sensitive workflows;
- never send payment card data to the model;
- use deterministic systems for calculations and approvals;
- model output should be advisory.

---

## 4.7 Security Triage Agent

Example flow:

```text
Wiz / CrowdStrike / Snyk / Semgrep / Tenable / Splunk
  -> vulnerability, alert, asset inventory, exploit context
  -> LLM
  -> severity summary, remediation plan, ticket creation
```

Risks:

- vulnerability data exposes attack paths;
- asset inventory reveals high-value targets;
- security logs may contain secrets or PII;
- malicious content in alerts or scanned files may trigger prompt injection;
- generated remediation could be unsafe or incomplete.

Recommended stance:

- local/private inference preferred;
- redact secrets and tokens;
- do not expose raw exploit details externally unless approved;
- validate remediation steps with policy and human review.

---

## 4.8 Cloud Infrastructure Agent

Example flow:

```text
AWS / Azure / GCP / Cloudflare / Terraform / Pulumi
  -> infrastructure state, IAM policy, logs, config
  -> LLM
  -> change recommendation or infrastructure action
```

Risks:

- infrastructure topology and IAM permissions are highly sensitive;
- tool credentials may permit destructive actions;
- model may suggest insecure changes;
- prompt injection in Terraform comments, tickets, or logs may influence actions;
- egress path to cloud inference may become an exfiltration channel.

Recommended stance:

- local/private inference strongly preferred;
- read-only mode by default;
- production changes require approval;
- IaC plans should be reviewed deterministically;
- enforce policy-as-code.

---

## 4.9 Data Warehouse and Analytics Agent

Example flow:

```text
Snowflake / BigQuery / Redshift / Databricks
  -> schema, query results, customer records
  -> LLM
  -> SQL generation, analysis, summary
```

Risks:

- raw query results may contain PII, PHI, financial data, or customer confidential data;
- schema names can reveal sensitive business operations;
- model-generated SQL may over-query or bypass intent;
- cloud inference may create additional data-processing obligations.

Recommended stance:

- local/private inference preferred for sensitive datasets;
- use row/column-level access controls;
- limit query result size;
- classify and redact data before prompting;
- execute generated SQL only after validation.

---

## 4.10 Document and Knowledge Assistant

Example flow:

```text
Google Drive / SharePoint / Box / Dropbox / Confluence / Notion
  -> documents, policies, meeting notes
  -> LLM
  -> answer, summary, synthesis
```

Risks:

- documents may contain legal, finance, HR, customer, roadmap, M&A, or board content;
- document permissions may be incorrectly expanded by the agent;
- prompt injection can be embedded in documents;
- cloud inference may expose confidential internal knowledge.

Recommended stance:

- hybrid or local inference depending on document classification;
- enforce source permissions at retrieval time;
- include citations and access checks;
- do not index or prompt with documents the user cannot access.

---

## 4.11 Sales and CRM Assistant

Example flow:

```text
Salesforce / HubSpot / Gong / ZoomInfo
  -> account notes, call transcripts, opportunity data
  -> LLM
  -> account summary, next steps, email draft
```

Risks:

- call transcripts and CRM notes may contain confidential customer information;
- account strategy and pricing terms may be exposed;
- generated outreach may violate policy or contractual constraints;
- customer-inserted text may influence agent behavior.

Recommended stance:

- cloud inference may be acceptable with approved vendor terms for lower-risk accounts;
- local/private inference preferred for strategic, regulated, or confidential accounts;
- external communications require review and filtering.

---

## 4.12 Workflow Automation Agent

Example flow:

```text
Slack / Teams / Jira / ServiceNow / Asana / Linear
  -> user request and task context
  -> LLM
  -> create ticket, update status, send message, trigger workflow
```

Risks:

- chat and ticket content can contain secrets, PII, or incident data;
- prompt injection in tickets/comments can trigger unwanted actions;
- model may act outside user intent;
- workflow tokens may span many systems.

Recommended stance:

- use least-privilege tools;
- restrict write actions;
- validate tool arguments;
- require approval for cross-system updates;
- classify data before sending to cloud inference.

---

## 5. Primary Risk Categories

## 5.1 Prompt and Data Disclosure

Cloud inference sends prompts, retrieved content, tool outputs, and conversation history to a third party. This may include:

- private code;
- customer records;
- employee data;
- incident timelines;
- vulnerability reports;
- internal URLs;
- identity metadata;
- logs containing secrets;
- financial records.

Local inference reduces third-party disclosure, but internal logs and traces can still leak sensitive prompts.

Controls:

- data classification;
- prompt minimization;
- redaction;
- no secrets in prompts;
- restricted logs;
- retention limits.

---

## 5.2 Credential Exposure

Cloud inference requires external API credentials or cloud IAM permissions. Local inference uses different credentials, such as model registry, object storage, service mesh, and internal API credentials.

Controls:

- workload identity over static keys;
- least privilege;
- credential rotation;
- metadata service hardening;
- restricted pod exec;
- API usage monitoring.

---

## 5.3 Prompt Injection

Prompt injection can occur anywhere untrusted text enters the context:

- Jira tickets;
- GitHub issues;
- PR comments;
- Slack messages;
- customer support tickets;
- log lines;
- documents;
- CRM notes;
- web pages;
- alert payloads.

Cloud inference may add provider-side logging exposure. Local inference does not solve prompt injection by itself.

Controls:

- treat retrieved content as untrusted;
- isolate instructions from data;
- use allowlisted tools;
- validate tool arguments;
- enforce policy outside the model;
- require approval for high-risk actions.

---

## 5.4 Tool Misuse

The highest-risk systems are not just chatbots; they are agents with tools.

Examples of dangerous tool actions:

- grant Okta admin access;
- disable an alert;
- restart a production service;
- merge a PR;
- rotate a secret;
- send a customer email;
- issue a refund;
- run a SQL query;
- create a firewall rule;
- export a customer list.

Controls:

- model cannot directly execute tools;
- orchestrator mediates every tool call;
- user identity is bound to tool permissions;
- dangerous actions require human approval;
- read-only and write tools are separated;
- audit logs are immutable.

---

## 5.5 Provider Logging and Compliance

Cloud inference may create data-processing events involving a third party. Depending on the data, this can affect:

- SOC 2;
- ISO 27001;
- HIPAA;
- GDPR;
- CCPA/CPRA;
- FedRAMP;
- PCI DSS;
- financial services requirements;
- customer contractual commitments.

Controls:

- vendor risk review;
- DPA/BAA where required;
- retention and logging review;
- region controls;
- subprocessors review;
- documented data flows.

---

## 5.6 Model Integrity and Change Control

Cloud providers may control model versions, system layers, guardrails, routing, and updates. Local inference allows stronger pinning and verification, but only if implemented.

Controls:

- version pinning;
- model artifact digests;
- signed artifacts;
- approved model upgrade process;
- regression tests;
- rollback plan.

---

## 5.7 Egress and Exfiltration

Cloud inference requires outbound paths to model providers. A compromised workload may abuse those paths for unauthorized data transfer or cost abuse.

Controls:

- default-deny egress;
- VPC endpoints or PrivateLink where available;
- egress proxy;
- destination allowlists;
- quotas;
- anomaly detection.

---

## 6. Data Flow Risk Diagram

The main risk increase with cloud inference is that sensitive context crosses an external processing boundary.

```text
Cloud inference sensitive-data path:

+-------------+       +-------------+       +------------------+
| SaaS / Tool | ----> | Agent       | ----> | External LLM     |
| GitHub      |       | Orchestrator|       | Provider         |
| Okta        |       |             |       |                  |
| Jira        |       | Context:    |       | Receives:        |
| Datadog     |       | tickets     |       | prompts          |
| Workday     |       | logs        |       | tool results     |
| Salesforce  |       | code        |       | history          |
+-------------+       | identities  |       | metadata         |
                      +-------------+       +------------------+
                              |
                              v
                      +---------------+
                      | Tool Actions  |
                      | after model   |
                      | response      |
                      +---------------+
```

```text
Local inference sensitive-data path:

+-------------+       +-------------+       +------------------+
| SaaS / Tool | ----> | Agent       | ----> | Local Inference  |
| GitHub      |       | Orchestrator|       | Service          |
| Okta        |       |             |       |                  |
| Jira        |       | Context:    |       | Receives same    |
| Datadog     |       | tickets     |       | sensitive data,  |
| Workday     |       | logs        |       | but inside       |
| Salesforce  |       | code        |       | control boundary |
+-------------+       | identities  |       +------------------+
                      +-------------+
                              |
                              v
                      +---------------+
                      | Tool Actions  |
                      | after policy  |
                      | validation    |
                      +---------------+
```

---

## 7. Comparative Risk Matrix

| Risk Area | Cloud Inference | Local/Private Inference |
|---|---:|---:|
| Prompt leaves direct control boundary | Higher | Lower |
| Third-party processing | Higher | Lower |
| Provider logging/retention exposure | Higher | Lower |
| Prompt injection | High | High |
| Tool misuse | High without controls | High without controls |
| Credential abuse | Medium/high | Medium |
| Egress exfiltration | Higher | Lower if restricted |
| Model version verifiability | Lower | Higher if pinned |
| Compliance burden for sensitive data | Higher | Lower |
| Operational complexity | Lower | Higher |
| Availability dependency | Provider-dependent | Infrastructure-dependent |
| Supply-chain responsibility | Shared/provider-heavy | Customer-heavy |

---

## 8. Recommended Inference Modes by Workflow

| Workflow | Recommended Mode | Rationale |
|---|---|---|
| Public documentation chatbot | Cloud acceptable | Low sensitivity |
| Internal wiki assistant | Hybrid/local | Depends on document classification |
| Private code assistant | Local preferred | Source code and secrets risk |
| PR review agent | Local preferred | Code, diffs, CI logs, comments |
| Incident response copilot | Local preferred | Logs, outage details, customer impact |
| Identity/access assistant | Local strongly preferred | Privileged identity data/actions |
| Production infrastructure agent | Local strongly preferred | High blast radius |
| Security triage agent | Local preferred | Vulnerability and asset data |
| Customer support copilot | Hybrid/local | PII and customer data |
| HR assistant | Local strongly preferred | Employee privacy risk |
| Finance/revenue agent | Local preferred | Financial and contractual data |
| CRM/sales assistant | Hybrid/cloud depending sensitivity | Account confidentiality varies |
| Data warehouse agent | Local preferred | Query results may be regulated |
| Workflow automation bot | Hybrid/local | Depends on tools and write access |

---

## 9. Minimum Controls for Cloud Inference

Cloud inference should require:

- approved provider and contract;
- DPA/BAA if applicable;
- clear retention and logging terms;
- data classification before prompt submission;
- prompt minimization and redaction;
- no secrets or raw credentials in prompts;
- least-privilege API/IAM credentials;
- restricted egress path;
- quotas and anomaly detection;
- tool-call validation outside the model;
- human approval for high-impact actions;
- audit logging with sensitive-field redaction.

---

## 10. Minimum Controls for Local Inference

Local/private inference should require:

- isolated namespace or environment;
- dedicated inference service identity;
- pinned model artifacts;
- signed model and container images;
- digest verification;
- restricted model registry access;
- prompt-log controls;
- default-deny egress;
- network policies;
- mTLS between services;
- least-privilege tool credentials;
- patching and upgrade process;
- monitoring and capacity planning;
- regression testing for model/tool behavior.

---

## 11. Decision Framework

Use local/private inference by default when any of the following are true:

- prompts include regulated data;
- prompts include customer confidential data;
- prompts include employee data;
- prompts include private source code;
- prompts include incident response data;
- prompts include security findings;
- prompts include infrastructure topology;
- the agent can mutate identity, infrastructure, finance, or customer systems;
- provider contracts do not clearly permit the data flow;
- model version integrity must be verifiable.

Cloud inference may be acceptable when:

- data is public or low-sensitivity;
- the provider is approved;
- retention and training policies are acceptable;
- prompts are minimized or redacted;
- the agent has no dangerous tools;
- egress is restricted and monitored;
- the business accepts the residual risk.

Hybrid inference may be appropriate when:

- sensitive raw data can be summarized locally;
- only sanitized context is sent to cloud inference;
- a policy engine decides whether cloud inference is allowed;
- logs prove which data crossed the boundary.

---

## 12. Example Enterprise Policy

```text
1. Public and low-sensitivity data may use approved cloud inference providers.

2. Internal confidential data may use cloud inference only with vendor approval,
   prompt minimization, retention controls, and data-owner approval.

3. Restricted data, regulated data, credentials, private source code, identity
   data, employee data, security findings, incident response data, production
   infrastructure data, and raw customer records must use local/private
   inference unless an exception is approved.

4. No model may directly execute tools. All tool calls must be mediated by an
   orchestrator that enforces authorization, validates arguments, and logs
   decisions.

5. High-impact actions require human approval. These include identity changes,
   production changes, customer-impacting actions, external communications,
   payment/refund actions, data exports, and deletion operations.

6. Prompt and tool-result logs are sensitive. They must be access-controlled,
   redacted where possible, encrypted, and subject to retention limits.
```

---

## 13. Conclusion

Cloud inference is not inherently unsafe, and local inference is not inherently secure. The difference is control.

Cloud inference adds third-party processing, provider logging and retention considerations, external credentials, egress paths, and limited visibility into model integrity. These risks may be acceptable for low-sensitivity workloads with strong controls.

Local inference keeps prompts, tool results, and model reasoning closer to the organization’s control boundary. This can materially simplify risk management for sensitive enterprise agents. However, it requires disciplined operations around Kubernetes, inference runtimes, model artifacts, credentials, logs, monitoring, and supply chain.

For high-impact agents touching identity, production infrastructure, customer records, source code, security findings, HR data, finance systems, or incident response workflows, the recommended default is:

> Use local/private inference, enforce tool policy outside the model, restrict egress, apply least privilege, verify model artifacts, and require human approval for high-impact actions.

The final principle:

> The model can assist with reasoning, summarization, and recommendations, but authorization and control must remain deterministic, auditable, and outside the model.
