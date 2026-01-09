# Purple Team Exercise Framework (PTEF) – 2026 Edition ..(initial)..

*A cloud-native, identity-centric, AI-assisted framework for modern Red, Blue, and Purple Team operations.*

---

## Executive Summary

A **Purple Team** is a coordinated collaboration between **Cyber Threat Intelligence (CTI)**, **Red Team**, and **Blue Team (SOC, Detection Engineering, DFIR, Threat Hunting)** functions designed to continuously validate and improve defensive capabilities.

The **Purple Team Exercise Framework (PTEF)** defines a maturity-driven path from:

| Stage | Description |
|------|-------------|
| Ad-Hoc Purple Exercises | One-off Red vs Blue validation |
| Operationalized Purple Teaming | Repeatable, CI-driven, metrics-based |
| Dedicated Purple Team | Continuous adversary emulation and detection engineering |

The **2025 Edition** reflects modern reality:
- Cloud-native and Kubernetes-first environments
- Identity-centric Zero Trust architectures
- Detection-as-Code and CI/CD pipelines
- eBPF-based runtime telemetry
- AI-assisted detection engineering
- PTaaS-driven automation

> **Core principle:** Purple Teaming exists to improve *measurable security outcomes*, not to run attacks for their own sake.

---

## Goals & Objectives

Purple Team Exercises aim to:

- Foster collaboration across CTI, Red, and Blue teams
- Validate detection and response capabilities against real-world TTPs
- Identify gaps in people, process, and technology
- Embed security testing into DevSecOps pipelines
- Measure and report progress using risk-based metrics

---

## Methodology Overview

PTEF builds on established adversary-centric frameworks while extending them for **cloud, identity, and automation**.

### Foundational Frameworks

- MITRE ATT&CK (Enterprise & Cloud)
- MITRE D3FEND
- NIST Cybersecurity Framework (CSF) 2.0
- Cloud Security Alliance Cloud Controls Matrix (CCM)
- Lockheed Martin Cyber Kill Chain
- Pyramid of Pain
- Threat-Based Penetration Testing (CBEST, TIBER-ID, iCAST)

---

## 2025 Modern Enhancements

### Cloud-Native & DevSecOps Integration

| Capability | Implementation |
|----------|----------------|
| CI/CD Purple Runs | GitHub Actions, GitLab CI |
| IaC Attack Testing | Terraform misconfiguration TTPs |
| Runtime Telemetry | eBPF (Falco, Tracee, Pixie) |
| Ephemeral Targets | Namespaced cloud and cluster labs |

---

### Automation & Orchestration

```mermaid
flowchart LR
    A[Purple Exercise Trigger] --> B[PTaaS Execution]
    B --> C[Telemetry & Alerts]
    C --> D[SIEM / XDR]
    D --> E[SOAR Playbooks]
    E --> F[Detection / Config Update]
    F --> G[Automated Retest]
````

---

### AI-Augmented Detection Engineering

| Use Case             | Guardrails                   |
| -------------------- | ---------------------------- |
| Sigma / EQL drafting | Human-in-the-loop review     |
| ATT&CK mapping       | Deterministic ID validation  |
| Alert summarization  | Evidence-linked output       |
| Gap analysis         | Risk-weighted prioritization |

---

### Zero Trust & Identity-Centric TTPs

Identity is the **primary attack surface** in cloud environments.

| Scenario                  | Example                 |
| ------------------------- | ----------------------- |
| Workload identity abuse   | AWS IRSA token theft    |
| SaaS auth abuse           | OAuth mis-scoping       |
| Conditional Access bypass | MFA enforcement testing |
| Service mesh identity     | mTLS / JWT replay       |

---

## Criticality, Timing, and Responsiveness

Purple Team engagements **must be paced by risk**. Not all exercises are equal, and prioritization is mandatory to preserve signal and trust.

---

## Purple Team vs Incident Response

Purple Teaming **does not replace Incident Response (IR)**. It *feeds* IR maturity.

| Aspect        | Incident Response | Purple Team                      |
| ------------- | ----------------- | -------------------------------- |
| Trigger       | Real compromise   | Simulated adversary              |
| Objective     | Contain & recover | Validate & improve               |
| Time pressure | Immediate         | Risk-calibrated                  |
| Output        | Postmortem        | Detection & control improvements |

> Purple Team activity must never obscure or delay a real incident response.

---

## Purple Team Criticality Tiers

Each engagement **must be classified before execution**.

| Tier   | Name             | Description                      | Example                              |
| ------ | ---------------- | -------------------------------- | ------------------------------------ |
| **P0** | Mission-Critical | High-impact, realistic adversary | CI/CD compromise, cloud IAM takeover |
| **P1** | High-Risk        | Likely attacker paths            | IRSA abuse, token theft              |
| **P2** | Moderate         | Common attacker behavior         | Credential spray, LOLBins            |
| **P3** | Low-Risk         | Hygiene / validation             | Parser tuning, alert checks          |

---

## Timing & Response Expectations (Purple SLOs)

| Tier   | Detection Validation | Blue Review | Detection Fix | Retest     |
| ------ | -------------------- | ----------- | ------------- | ---------- |
| **P0** | ≤ 15 min             | ≤ 30 min    | ≤ 24 hrs      | ≤ 48 hrs   |
| **P1** | ≤ 30 min             | ≤ 4 hrs     | ≤ 3 days      | ≤ 7 days   |
| **P2** | ≤ 24 hrs             | ≤ 2 days    | ≤ 1 sprint    | Next cycle |
| **P3** | Best effort          | Best effort | Backlog       | Backlog    |

Failure to meet these targets is a **maturity signal**, not a fault.

---

## Phase-Based Responsiveness Model

```mermaid
flowchart TD
    A[Engagement Planned] --> B[Criticality Assigned]
    B --> C{Tier}
    C -->|P0 / P1| D[Accelerated Purple Loop]
    C -->|P2 / P3| E[Standard Purple Loop]
```

---

## Accelerated Purple Loop (P0 / P1)

```mermaid
flowchart LR
    A[Live Emulation] --> B[Immediate Telemetry Review]
    B --> C[Real-Time Blue Validation]
    C --> D[Hot Detection Fix]
    D --> E[Automated Retest]
    E --> F[Executive Summary]
```

**Characteristics**

* Live coordination / war room
* Detection engineers on standby
* Near-real-time metrics
* Executive visibility

---

## Standard Purple Loop (P2 / P3)

```mermaid
flowchart LR
    A[Scheduled Emulation] --> B[Telemetry Collected]
    B --> C[Async Review]
    C --> D[Detection Backlog]
    D --> E[CI/CD Fix]
    E --> F[Next-Cycle Retest]
```

**Characteristics**

* Sprint-based remediation
* Batched improvements
* Trend-focused metrics

---

## Risk Inputs for Criticality Assignment

| Factor               | Example            |
| -------------------- | ------------------ |
| Asset sensitivity    | IAM, CI/CD, auth   |
| Blast radius         | Org-wide vs scoped |
| Adversary realism    | APT-aligned        |
| Detection confidence | Known blind spots  |
| Regulatory exposure  | PCI, HIPAA, GDPR   |

---

## Purple Team Escalation Rules

```mermaid
flowchart TD
    A[Purple Activity Detected] --> B{Expected?}
    B -->|Yes| C[Continue Exercise]
    B -->|No| D[Pause Immediately]
    D --> E[IR Triage]
    E --> F{Real Incident?}
    F -->|Yes| G[IR Takes Control]
    F -->|No| H[Resume Purple]
```

---

## Metrics & Reporting

### Purple-Ops Score

```
Purple-Ops Score =
(MTTD + MTTR + True Positive Rate) × Risk Weight
```

Metrics must be **segmented by tier**, not averaged.

---

## Roles & Responsibilities

| Role                  | Responsibility         |
| --------------------- | ---------------------- |
| Executive Sponsor     | Risk ownership         |
| Purple Team Lead      | Coordination & metrics |
| CTI                   | TTP sourcing           |
| Red Team              | Emulation              |
| Blue Team             | Detection & response   |
| Detection Engineering | Rule lifecycle         |
| Automation            | CI/CD & SOAR           |

---

## Purple Team Exercise Lifecycle

```mermaid
flowchart TD
    A[CTI Intake] --> B[Planning & Scoping]
    B --> C[Technical Preparation]
    C --> D[Tabletop Exercise]
    D --> E[Live Emulation]
    E --> F[Detection Validation]
    F --> G[Detection Engineering]
    G --> H[Automated Retest]
    H --> I[Metrics & Reporting]
```

---

## Operationalized Purple Teaming

```mermaid
flowchart LR
    A[CTI Feed] --> B[TTP Backlog]
    B --> C[Scheduled Emulation]
    C --> D[Detection Validation]
    D --> E[SOAR Remediation]
    E --> F[Regression Testing]
```

---

## Dedicated Purple Team Model

### Roles

* Purple Team Engineers
* Detection Engineers
* CTI Analysts
* Automation Architects

### Ownership

* Emulation catalog
* Detection backlog
* Prompt libraries
* Cloud labs

---

## Purple Team Maturity Model (PTMM)

```mermaid
quadrantChart
    title Purple Team Maturity Model
    x-axis Detection Understanding --> Creation
    y-axis Threat Understanding --> Creation
    quadrant-1 Autonomous Purple Teaming
    quadrant-2 Threat-Aware DevOps
    quadrant-3 Ad-Hoc Purple Exercises
    quadrant-4 Operationalized Purple Teaming
```

---

## Templates

| Template        | Purpose              |
| --------------- | -------------------- |
| Planning Agenda | CI/CD-aware kickoff  |
| CTI Mapping     | ATT&CK + D3FEND      |
| Detection Rule  | Sigma / EQL scaffold |
| Metrics Sheet   | Purple-Ops scoring   |

---

## FAQ

**Does AI replace detection engineers?**
No. AI accelerates drafting; humans own correctness.

**Is PTaaS mandatory?**
No, but API-driven emulation is strongly recommended.

---

## Contributors

Original PTEF authors and community contributors
(Orchilles, Peacock, and others)

---

```

```

##
##

# Purple Team Exercise Framework (PTEF) – 2025 Edition

This document defines how to build and mature a Purple Team program from ad-hoc Purple Team Exercises, to Operationalized Purple Teaming,
to building a Dedicated Purple Team. It integrates modern cloud-native, AI-driven, and identity-centric practices that have emerged as best practices in 2025.

<p align="center"> <img src="./images/PurpleTeamProgram_2025.png" /> </p>

# Table of Contents
1. [Executive Summary](#executive-summary)
2. [Goals and Objectives](#goals-and-objectives)
3. [Methodology](#methodology)
   1. [Industry & Regulatory Frameworks](#industry--regulatory-frameworks)
   2. [2025 Modern Enhancements](#2025-modern-enhancements)
4. [Roles and Responsibilities](#roles-and-responsibilities)
5. [Planning](#planning)
6. [Technical Preparation](#technical-preparation)
7. [Cyber Threat Intelligence](#cyber-threat-intelligence)
8. [Purple Team Exercise Execution](#purple-team-exercise-execution)
9. [Operationalized Purple Team](#operationalized-purple-team)
10. [Dedicated Purple Team](#dedicated-purple-team)
11. [Lessons Learned](#lessons-learned)
12. [Purple Team Maturity Model](#purple-team-maturity-model)
13. [Templates](#templates)
14. [FAQ](#faq)
15. [Contributors](#contributors)

---

## Executive Summary

A Purple Team is a coordinated collaboration of Cyber Threat Intelligence (CTI), Red Team, and Blue Team (SOC, Hunt, DFIR) functions to test, measure, and improve an organization’s cyber defenses. By combining adversary emulation with continuous feedback and modern tooling, organizations can accelerate their security maturity across people, process, and technology.

Advancements in cloud-native architectures, AI-driven detection engineering, and identity-centric zero trust have reshaped how Purple Team operations are conducted. The 2025 Edition of the PTEF ensures your program leverages: CI/CD integrations, eBPF telemetry, LLM-assisted playbooks, PTaaS platforms, and identity-based attack testing.

---

## Goals and Objectives

Purple Team Exercises aim to:

- Foster a collaborative security culture across CTI, Red, and Blue teams
- Validate detection and response capabilities against real-world TTPs
- Identify gaps in people, processes, and technology for continuous improvement
- Embed security testing into DevSecOps pipelines for proactive resilience
- Measure and report on security performance using risk-based and AI-augmented metrics

---

## Methodology

Building on established frameworks (Kill Chain, MITRE ATT&CK, regulatory standards), the PTEF 2025 Edition adds cloud-native, AI-augmented, and identity-centric practices:

### Industry & Regulatory Frameworks

- **Lockheed Martin Cyber Kill Chain**
- **MITRE ATT&CK Enterprise & Cloud**
- **David Bianco’s Pyramid of Pain**
- **CSA Cloud Controls Matrix (CCM)**
- **MITRE D3FEND**
- **NIST Cybersecurity Framework (CSF) 2.0**
- **TIBER-ID (EU 2024)**
- **ISAC Threat-Based Penetration Testing Guidelines (e.g. CBEST, iCAST)**

### 2025 Modern Enhancements

#### Cloud-Native & DevSecOps Integration

- **CI/CD Embedding**: Define pipeline stages (GitHub Actions, GitLab CI) to automatically trigger Purple Team runs on pull requests or nightly schedules.
- **eBPF Telemetry**: Deploy Falco, Tracee, or Pixie agents to capture in-kernel events for container and serverless workloads, ensuring high-fidelity observability.
- **Infrastructure-as-Code Testing**: Integrate IaC security scans (Checkov, Terraform-compliance) into the adversary emulation plan to test misconfiguration TTPs early.

#### Automation & Orchestration

- **PTaaS Platforms**: Use AttackIQ Cloud, SafeBreach, or SCYTHE Cloud for API-driven execution of adversary playbooks, enabling self-service and scheduling.
- **CI/CD–SOAR Loops**: Automate the flow: exercise job → detection alert → SOAR runbook triggered → remediation action → retest.
- **Auto-Remediation Playbooks**: Pre-build workflows in Cortex XSOAR or Splunk Phantom to automatically adjust rulesets or block indicators post-exercise.

#### AI-Augmented Detection Engineering

- **LLM-Assisted Playbooks**: Generate initial Sigma or EQL detection rules from TTP descriptions using LLM prompts, then refine via human review.
- **Anomaly Detection Models**: Incorporate ML-based baseline profiling in SIEM/XDR to detect deviations during simulated attacks (e.g. anomalous process behavior or network patterns).
- **Automated ATT&CK/D3FEND Mapping**: Leverage tools that ingest CTI feeds and annotate techniques with both ATT&CK IDs and D3FEND countermeasure IDs.

#### Extended Framework Coverage

- **MITRE D3FEND**: Align detection engineering efforts with documented defensive techniques and countermeasures.
- **Cloud-Specific Matrices**: Reference MITRE ATT&CK Cloud (e.g., AWS, Azure, GCP) and CSA CCM controls for comprehensive coverage of cloud-native TTPs.
- **Regulatory Mappings**: Maintain crosswalks between NIST CSF 2.0, TIBER-ID, and industry-specific compliance standards (PCI-DSS, HIPAA, GDPR).

#### Zero Trust & Identity-Centric TTPs

- **Identity Attacks**: Emulate AWS IRSA compromise, Azure AD workload identity misuse, and Kubernetes OIDC token theft to validate continuous authorization.
- **Conditional Access Testing**: Execute scenarios to test Azure Conditional Access, Okta Adaptive MFA, and Google BeyondCorp policies.
- **Service Mesh Enforcement**: Validate Istio and Linkerd mTLS, JWT, and LWT policies by simulating identity spoofing or token replay.

#### Modern Metrics & Reporting

- **Purple-Ops Score**: Composite metric combining Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), and True Positive Rate (TPR).
- **Real-Time Dashboards**: Stream exercise telemetry into BI tools (PowerBI, Apache Superset) for live scorecards and trend analysis.
- **Risk-Based Prioritization**: Tag TTPs by risk (Likelihood × Impact) and track remediation velocity (time-to-fix per TTP).

#### Maturity Model Refresh

Expand the Purple Team Maturity Model (PTMM) axes to include:

1. **AI-Empowered** (automation, LLM) – from manual to fully automated, LLM-assisted workflows.
2. **Cloud-First** (containers, serverless) – from traditional on-prem to fully cloud-native and IaC-driven teams.

Define two strategic capability paths:

- **Threat-Aware DevOps**: Embedding purple tests into Agile sprints and pull requests.
- **Autonomous Purple Teaming**: Self-service emulation catalog with scheduled runs and automated remediation.

---

## Roles and Responsibilities

(As defined in original PTEF, covering Sponsors, Exercise Coordinator, CTI, Red, Blue, DFIR, SOC, Hunt Teams, etc.)

---

## Planning

- **Kickoff & Pitch**: Include CI/CD pipeline prerequisites and IaC module availability.
- **Planning Meetings**: Assign action items for container telemetry, PTaaS onboarding, and LLM integration.
- **Logistics**: Ensure test cloud accounts, cluster namespaces, and PTaaS workspaces are provisioned.
- **Metrics Definition**: Agree on Purple-Ops score thresholds, BI dashboard endpoints, and risk tags.

---

## Technical Preparation

- **Target Systems**: Provision cloud and on-prem hosts via Terraform; deploy EDR, Falco agents, and CI runners.
- **Security Tools**: Validate SIEM/XDR, SOAR connectivity, and PTaaS API access tokens.
- **Accounts & Identities**: Create service accounts (AWS IRSA, Azure Managed Identities) and baseline credentials.
- **Attack Infrastructure**: Configure PTaaS environments, external redirectors, and credential theft traps in cloud labs.

---

## Cyber Threat Intelligence

- **Data Sources**: Ingest CTI feeds into an LLM-enabled parser to extract new TTPs and update ATT&CK mapping.
- **Adversary Profiles**: Generate tables of TTPs with automated mapping to MITRE ATT&CK Cloud and D3FEND.
- **Table-Top Exercises**: Use collaborative docs (e.g. Lucidchart, Miro) with live annotation of expected observables and detection points.

---

## Purple Team Exercise Execution

1. **Present Adversary & TTPs**: Include slides or notebooks showing CI/CD pipeline steps, IaC misconfig scans, and telemetry dashboards.
2. **Table-Top Discussion**: Annotate expected logs, alerts, and SOAR playbook triggers in chatops channels.
3. **Live Emulation**: Use PTaaS UI or CLI to execute playbooks; share pipeline logs and Falco alerts.
4. **Detection Validation**: Blue Team reviews SIEM/XDR, dashboards, and anomaly alerts; record MTTD.
5. **Detection Engineering**: LLM-assisted rule creation, deploy updates via CI/CD; automatically trigger re-emulation.
6. **Metrics Capture**: Record Purple-Ops score, remediation velocity, and risk reduction.

---

## Tracking Exercise

- **Automated Ticketing**: Post exercise results and LLM-generated summaries into Jira or ServiceNow via API.
- **Collaboration Platforms**: Archive chatops transcripts, dashboard screenshots, and pipeline logs in a central repo.

---

## Operationalized Purple Team

- **New TTP Intake**: CTI updates flow into LLM parser → technique extraction → detection backlog ticket.
- **Organize & Prioritize**: Tag TTPs by risk and schedule PTaaS runs as part of sprint cycles.
- **Emulate & Validate**: Automated nightly emulation jobs with pre- and post-tests in CI/CD.
- **Issue Remediation**: SOAR playbooks triggered for rule updates or config changes; verification runs.

---

## Dedicated Purple Team

- **Roles**: Dedicated Purple Team Engineers, Detection Engineers, CTI Analysts, Automation Architects.
- **Responsibilities**: Maintain emulation catalog, dashboard integrity, LLM prompt library, and cloud lab environments.

---

## Lessons Learned

- **Feedback Loop**: Use retrospective tools (e.g. Parabol) to capture action items, assign owners, set deadlines.
- **Retesting**: Schedule automated reruns for recalibrated detections and track regression rates.

---

## Purple Team Maturity Model

Visualize a 2D matrix with axes:
- **Threat Understanding** (Deployment → Creation)
- **Detection Understanding** (Deployment → Creation)
- **AI-Empowered** layered gradient
- **Cloud-First** layered gradient

Define milestones in each quadrant, e.g., “CI-driven emulations” at mid-cloud axis, “LLM-assisted detection” at mid-AI axis.

---

## Templates

- **Planning Agenda**: Add Terraform module links, PTaaS workspace URLs, and LLM prompt examples.
- **CTI Mapping**: CSV template for TTP → ATT&CK Cloud → D3FEND → Risk tags.
- **Detection Rule**: Sigma/EQL rule scaffold with LLM prompt placeholders.

---

## FAQ

1. **PTaaS Licensing Costs**: Estimate per-emulation pricing and ROI calculations.
2. **LLM Hallucinations**: Mitigation strategies—human-in-the-loop review and prompt engineering.
3. **Conditional Access Testing Tools**: List open-source and commercial tools (e.g. Pester for PowerShell, MSAL automation).

---

## Contributors

- Original PTEF Authors (Orchilles, Peacock, etc.)

```
