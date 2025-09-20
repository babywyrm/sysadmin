# PSIRT Incident Response Process (Flyover)

```mermaid
flowchart TD
    %% Detection
    A[🔎 Detection] --> B{Classify Severity}
    B -->|SEV1: Active Exploit| C[🚨 Incident Commander Assigned]
    B -->|SEV2/3: Vuln or Misconfig| C
    B -->|SEV4: Low Risk| Z[📋 Track for backlog]

    %% Roles
    C --> D[👥 Assign Roles]
    D --> D1[Incident Commander]
    D --> D2[Scribe]
    D --> D3[Tech Leads (Sec/Cloud/CI-CD)]
    D --> D4[Researcher(s)]
    D --> D5[Support & Comms Liaison]

    %% Blast Radius
    D --> E{Blast Radius Analysis}
    E --> E1[Affected Accounts & Regions]
    E --> E2[Customer/Data Impact]
    E --> E3[CI/CD Artifacts or Pipelines]
    E --> E4[Network/VPC Scope]
    E --> E5[Exposure Duration]

    %% Scoring
    E --> F[📊 Blast Radius Score (BRS)]
    F --> G{Prioritization Framework}

    %% Prioritization & Buckets
    G -->|BRS ≥ 100| H1[🔴 Critical Now]
    G -->|50 ≤ BRS < 100| H2[🟠 Short-Term]
    G -->|20 ≤ BRS < 50| H3[🟡 Medium-Term]
    G -->|< 20| H4[Backlog]

    %% Remediation
    H1 --> I[⚡ Containment Actions]
    H2 --> I
    H3 --> I
    H4 --> J[📌 Track & Monitor]

    I --> K[🔧 Remediation & Recovery]
    K --> K1[Patch / Hotfix]
    K --> K2[Secrets Rotation]
    K --> K3[Infra Hardening]
    K --> K4[Pipeline Security]

    %% Communication
    C --> L[📢 Communication Cadence]
    L --> L1[Engineering updates: 30m]
    L --> L2[IC Stakeholder updates: 60m]
    L --> L3[Exec Brief: 2-4h]
    L --> L4[External Messaging: Legal+PR]

    %% Closure
    K --> M[✅ Closure & Lessons Learned]
    M --> M1[After-Action Report]
    M --> M2[Rotation/Burnout Check]
    M --> M3[Feed into PSIRT Intake]
