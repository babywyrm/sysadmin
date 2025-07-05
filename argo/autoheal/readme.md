
```

┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SECURE IMAGE PROMOTION PIPELINE                         │
│                        (Immutable Images + Hash Consistency)                    │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Developer      │    │   Feature        │    │  Main Branch    │
│  Commits Code   │───▶│   Branch PR      │───▶│  Merge Trigger  │
│                 │    │  + Dockerfile    │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │  BUILD ONCE     │
                                               │  CI Pipeline    │
                                               │  • Unit Tests   │
                                               │  • Build Image  │
                                               │  • Generate     │
                                               │    SHA256 Hash  │
                                               └─────────────────┘
                                                        │
                       ┌────────────────────────────────┼────────────────────────────────┐
                       │                 GOLDEN IMAGE CREATION                           │
                       │                                │                                │
                       ▼                                ▼                                ▼
            ┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
            │  STAGE 1        │              │  STAGE 2        │              │  STAGE 3        │
            │  Initial Scan   │              │  Deep Security  │              │  Final Approval │
            │  • Trivy SAST   │─────────────▶│  • Aqua Full    │─────────────▶│  • Compliance   │
            │  • Basic CVE    │              │  • Malware      │              │  • Sign Image   │
            │  • Secrets      │              │  • Compliance   │              │  • Attestation  │
            │  • License      │              │  • SBOM Gen     │              │  • Provenance   │
            └─────────────────┘              └─────────────────┘              └─────────────────┘
                     │                                │                                │
                     ▼                                ▼                                ▼
               [SCAN PASSED]                   [DEEP SCAN PASSED]                [APPROVED]
                     │                                │                                │
                     └────────────────────────────────┼────────────────────────────────┘
                                                      │
                                                      ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                            GOLDEN REGISTRY                                     │
│                     (Single Source of Truth)                                   │
├────────────────────────────────────────────────────────────────────────────────┤
│  🏆 GOLDEN ECR/ARTIFACTORY                                                    │
│  registry.company.com/app-name:1.2.3                                          │
│  └─ SHA256: a1b2c3d4e5f6...                                                   │
│  └─ Signed: ✓ (Cosign)                                                        │
│  └─ Scanned: ✓ (Aqua + Trivy)                                                 │
│  └─ SBOM: ✓ (Attached)                                                        │
│  └─ Attestation: ✓ (SLSA Level 3)                                             │
│  └─ Compliance: ✓ (CIS, NIST, PCI)                                            │
│                                                                               │
│  📋 IMMUTABLE TAGS:                                                           │
│  • registry.company.com/app-name:1.2.3                                        │
│  • registry.company.com/app-name:sha256-a1b2c3d4e5f6...                       │
│  • registry.company.com/app-name:latest-secure                                │
└───────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                          KARGO PROMOTION PIPELINE                              │
│                     (Same Hash Across All Environments)                        │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  DEV ENVIRONMENT          STAGING ENVIRONMENT         PRODUCTION ENVIRONMENT  │
│  ┌─────────────────┐      ┌─────────────────┐         ┌─────────────────┐     │
│  │ Auto Promotion  │─────▶│ Auto Promotion  │────────▶│ Manual Gate     │     │
│  │                 │      │                 │         │                 │     │
│  │ Image:          │      │ Image:          │         │ Image:          │     │
│  │ SHA: a1b2c3d4   │      │ SHA: a1b2c3d4   │         │ SHA: a1b2c3d4   │     │
│  │ ✓ Same Hash     │      │ ✓ Same Hash     │         │ ✓ Same Hash     │     │
│  │                 │      │                 │         │                 │     │
│  │ Tests:          │      │ Tests:          │         │ Validations:    │     │
│  │ • Unit Tests    │      │ • E2E Tests     │         │ • Approval      │     │
│  │ • Smoke Tests   │      │ • Perf Tests    │         │ • Canary Ready  │     │
│  │ • Runtime Scan  │      │ • Security Test │         │ • Rollback Plan │     │
│  └─────────────────┘      └─────────────────┘         └─────────────────┘     │
│         │                          │                          │               │
└───────────────────────────────────────────────────────────────────────────────┘
          │                          │                          │
          ▼                          ▼                          ▼
┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
│   K3S/K8S       │        │   K3S/K8S       │        │   EKS/K8S       │
│   DEV CLUSTER   │        │  STAGE CLUSTER  │        │  PROD CLUSTER   │
│                 │        │                 │        │                 │
│ Pulls Image:    │        │ Pulls Image:    │        │ Pulls Image:    │
│ SHA: a1b2c3d4   │        │ SHA: a1b2c3d4   │        │ SHA: a1b2c3d4   │
│ FROM: Golden    │        │ FROM: Golden    │        │ FROM: Golden    │
│ Registry        │        │ Registry        │        │ Registry        │
└─────────────────┘        └─────────────────┘        └─────────────────┘
          │                          │                          │
          ▼                          ▼                          ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ARGOCD DEPLOYMENT                                       │
│                    (Hash Verification & Drift Detection)                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │ DEV ArgoCD      │    │ STAGING ArgoCD  │    │ PROD ArgoCD     │            │
│  │ • Sync Policy   │    │ • Sync Policy   │    │ • Sync Policy   │            │
│  │ • Hash Check    │    │ • Hash Check    │    │ • Hash Check    │            │
│  │ • Auto Heal     │    │ • Auto Heal     │    │ • Manual Sync   │            │
│  │ • Prune         │    │ • Prune         │    │ • Backup Before │            │
│  │                 │    │                 │    │ • Blue/Green    │            │
│  │ Expected SHA:   │    │ Expected SHA:   │    │ Expected SHA:   │            │
│  │ a1b2c3d4e5f6    │    │ a1b2c3d4e5f6    │    │ a1b2c3d4e5f6    │            │
│  │                 │    │                 │    │                 │            │
│  │ Actual SHA:     │    │ Actual SHA:     │    │ Actual SHA:     │            │
│  │ a1b2c3d4e5f6 ✓  │    │ a1b2c3d4e5f6 ✓  │    │ a1b2c3d4e5f6 ✓  │            │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘            │
└───────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        RUNTIME SECURITY LAYER                                   │
│                      (Continuous Image Validation)                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐               │
│  │ Aqua Enforcer   │  │ Image Validator │  │ Admission Ctrl  │               │
│  │ • Runtime Check │  │ • SHA256 Verify │  │ • Policy Check  │               │
│  │ • Drift Monitor │  │ • Signature Val │  │ • Image Source  │               │
│  │ • Compliance    │  │ • Registry Auth │  │ • Hash Match    │               │
│  │ • Behavior      │  │ • SBOM Verify   │  │ • Attestation   │               │
│  │                 │  │                 │  │                 │               │
│  │ Running SHA:    │  │ Expected SHA:   │  │ Allowed SHA:    │               │
│  │ a1b2c3d4e5f6 ✓  │  │ a1b2c3d4e5f6 ✓  │  │ a1b2c3d4e5f6 ✓  │               │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘               │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                    CONTINUOUS MONITORING & VALIDATION                          │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐               │
│  │ Image Tracking  │  │ Vulnerability   │  │ Compliance      │               │
│  │ • Hash History  │  │ • New CVEs      │  │ • Policy Drift  │               │
│  │ • Deployment    │  │ • CVSS Scores   │  │ • Benchmark     │               │
│  │ • Rollback      │  │ • Patch Avail   │  │ • Attestation   │               │
│  │ • Audit Trail   │  │ • Risk Score    │  │ • Cert Expiry   │               │
│  │                 │  │                 │  │                 │               │
│  │ All Envs SHA:   │  │ Current Risk:   │  │ Compliance:     │               │
│  │ a1b2c3d4e5f6 ✓  │  │ Low (Score: 2)  │  │ 98% (Passing)   │               │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘               │
└──────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────┐
│                           RENOVATION CYCLE                                     │
│                    (Automated Security Updates)                                │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────┐                    ┌─────────────────┐                   │
│  │ Renovate Bot    │───── Triggers ────▶│ New Build       │                   │
│  │ • Base Image    │                    │ • New SHA       │                   │
│  │ • Dependencies  │                    │ • Security Scan │                   │
│  │ • CVE Patches   │                    │ • New Golden    │                   │
│  │ • Auto PR       │                    │ • Replaces Old  │                   │
│  │                 │                    │                 │                   │
│  │ Detected:       │                    │ New SHA:        │                   │
│  │ • CVE-2024-1234 │                    │ b2c3d4e5f6a1    │                   │
│  │ • High Severity │                    │ • Secure        │                   │
│  │ • Patch Avail   │                    │ • Tested        │                   │
│  └─────────────────┘                    └─────────────────┘                   │
│                                                  │                            │
│                                                  ▼                            │
│                                         ┌─────────────────┐                   │
│                                         │ Automatic       │                   │
│                                         │ Propagation     │                   │
│                                         │ • Dev First     │                   │
│                                         │ • Staging Test  │                   │
│                                         │ • Prod Approval │                   │
│                                         │ • Same SHA      │                   │
│                                         │ • Zero Downtime │                   │
│                                         └─────────────────┘                   │
└───────────────────────────────────────────────────────────────────────────────┘

```

```mermaid
flowchart TD
    A[👨‍💻 Developer] --> B[🔀 Git Push]
    B --> C[🏗️ CI/CD Build]
    C --> D[🔒 Security Scan]
    D --> E[🏆 Golden Registry<br/>SHA: abc123...]
    
    E --> F[🚀 Kargo Promotion]
    F --> G[🔧 Dev<br/>SHA: abc123...]
    G --> H[🎯 Staging<br/>SHA: abc123...]
    H --> I[🏭 Production<br/>SHA: abc123...]
    
    I --> J[🎯 ArgoCD Deploy]
    J --> K[🛡️ Runtime Security]
    K --> L[📊 Monitoring]
    
    M[🔄 Renovate] --> B
    L --> M
    
    %% Same Hash Emphasis
    N[🔑 Same SHA256 Hash<br/>Across All Environments] 
    G -.-> N
    H -.-> N
    I -.-> N
    
    %% Security Gates
    O[🛡️ Multi-Stage Security]
    D --> O
    O --> |Stage 1: Quick Scan| P[📊 Trivy + Secrets]
    O --> |Stage 2: Deep Scan| Q[🔬 Aqua + Compliance]
    O --> |Stage 3: Approval| R[👤 Manual + Signing]
    
    P --> E
    Q --> E
    R --> E
    
    classDef golden fill:#ffd700,stroke:#333,stroke-width:3px
    classDef security fill:#ff9999,stroke:#333,stroke-width:2px
    classDef environment fill:#99ccff,stroke:#333,stroke-width:2px
    classDef hash fill:#90EE90,stroke:#333,stroke-width:2px
    
    class E golden
    class D,K,O,P,Q,R security
    class G,H,I,J environment
    class N hash
```


```mermaid
flowchart TD
  %% === SECTION: DEV & CI ===
  A1[👨‍💻 Developer Commits Code] --> A2[🔀 Feature Branch PR<br/>+ Dockerfile]
  A2 --> A3[📥 Merge to Main<br/>Triggers CI]

  A3 --> B1[🏗️ CI Pipeline:<br/>• Unit Tests<br/>• Build Image<br/>• Generate SHA256]

  %% === SECTION: MULTI-STAGE SECURITY ===
  B1 --> C1[🔍 Stage 1: Trivy<br/>• SAST, CVEs, Secrets, License]
  C1 --> C2[🧪 Stage 2: Aqua<br/>• Malware, Compliance, SBOM]
  C2 --> C3[✅ Stage 3: Approval<br/>• Manual Sign + Attestation]

  C3 --> D1[🏆 Golden Registry<br/>registry.company.com/app:1.2.3<br/>SHA: a1b2c3d4...<br/>Signed: ✓, Scanned: ✓, SBOM: ✓]

  %% === SECTION: PROMOTION PIPELINE ===
  D1 --> E1[🚀 Kargo Promote to DEV<br/>SHA: a1b2c3d4...<br/>• Unit, Smoke, Runtime Scan]
  E1 --> E2[🚀 Promote to STAGING<br/>SHA: a1b2c3d4...<br/>• E2E, Perf, Security]
  E2 --> E3[🛑 Manual Gate to PROD<br/>SHA: a1b2c3d4...<br/>• Approval, Canary, Rollback Plan]

  %% === SECTION: CLUSTER DEPLOYMENTS ===
  E1 --> F1[☸️ DEV K3s Pull<br/>FROM Golden<br/>SHA: a1b2c3d4...]
  E2 --> F2[☸️ STAGE K3s Pull<br/>FROM Golden<br/>SHA: a1b2c3d4...]
  E3 --> F3[☸️ PROD EKS Pull<br/>FROM Golden<br/>SHA: a1b2c3d4...]

  %% === SECTION: ARGOCD ===
  F1 --> G1[🤖 ArgoCD DEV<br/>• Auto Sync, Hash Check<br/>Expected SHA: a1b2c3d4...]
  F2 --> G2[🤖 ArgoCD STAGE<br/>• Auto Sync, Hash Check<br/>Expected SHA: a1b2c3d4...]
  F3 --> G3[🤖 ArgoCD PROD<br/>• Manual Sync, Backup<br/>Expected SHA: a1b2c3d4...]

  %% === SECTION: RUNTIME SECURITY ===
  G1 --> H1[🛡️ Aqua Enforcer<br/>• Runtime Check, Drift<br/>Running SHA: a1b2c3d4...]
  G2 --> H2[🔐 Validator<br/>• Signature, Attestation, SBOM]
  G3 --> H3[✅ Admission Ctrl<br/>• Policy & Source Check<br/>Allowed SHA: a1b2c3d4...]

  %% === SECTION: MONITORING ===
  H1 --> I1[📊 Monitoring:<br/>• Image History, CVEs<br/>• Risk Score: Low<br/>• Compliance: 98%]
  H2 --> I1
  H3 --> I1

  %% === SECTION: RENOVATE ===
  I1 --> J1[🔄 Renovate Bot<br/>• CVE-2024-1234, Patch Available]
  J1 --> J2[🔁 Auto PR + New Build<br/>New SHA: b2c3d4e5...]

  J2 --> B1

```
