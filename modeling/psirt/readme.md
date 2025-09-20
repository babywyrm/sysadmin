# PSIRT Incident Response Process (Flyover)

```mermaid
flowchart TD
    %% Detection
    A[Detection] --> B{Classify Severity}
    B -->|SEV1: Active Exploit| C[Incident Commander Assigned]
    B -->|SEV2-3: Vulnerability or Misconfiguration| C
    B -->|SEV4: Low Risk| Z[Track for backlog]

    %% Roles
    C --> D[Assign Roles]
    D --> D1[Incident Commander]
    D --> D2[Scribe]
    D --> D3[Tech Leads - Security, Cloud, CI_CD]
    D --> D4[Researchers]
    D --> D5[Support and Comms Liaison]

    %% Blast Radius
    D --> E{Blast Radius Analysis}
    E --> E1[Affected Accounts and Regions]
    E --> E2[Customer or Data Impact]
    E --> E3[CI_CD Artifacts or Pipelines]
    E --> E4[Network and VPC Scope]
    E --> E5[Exposure Duration]

    %% Scoring
    E --> F[Blast Radius Score (BRS)]
    F --> G{Prioritization Framework}

    %% Prioritization & Buckets
    G -->|BRS >= 100| H1[Critical Now]
    G -->|50-99| H2[Short-Term]
    G -->|20-49| H3[Medium-Term]
    G -->|< 20| H4[Backlog]

    %% Remediation
    H1 --> I[Containment Actions]
    H2 --> I
    H3 --> I
    H4 --> J[Track and Monitor]

    I --> K[Remediation and Recovery]
    K --> K1[Patch or Hotfix]
    K --> K2[Secrets Rotation]
    K --> K3[Infrastructure Hardening]
    K --> K4[Pipeline Security]

    %% Communication
    C --> L[Communication Cadence]
    L --> L1[Engineering updates every 30m]
    L --> L2[IC Stakeholder updates every 60m]
    L --> L3[Executive Brief every 2-4h]
    L --> L4[External Messaging via Legal and PR]

    %% Closure
    K --> M[Closure and Lessons Learned]
    M --> M1[After-Action Report]
    M --> M2[Rotation and Burnout Check]
    M --> M3[Feed into PSIRT Intake]

