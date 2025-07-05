┌─────────────────────────────────────────────────────────────────────────────────┐
│                            SECURE GITOPS PIPELINE                              │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Developer      │    │   Feature        │    │  Main Branch    │
│  Commits Code   │───▶│   Branch PR      │───▶│  (Source Repo)  │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  PR Security    │    │  CI Pipeline    │
                       │  Scan & Gates   │    │  Build & Test   │
                       │  • Code Scan    │    │  • Unit Tests   │
                       │  • SAST/DAST    │    │  • Integration  │
                       │  • Secrets      │    │  • Security     │
                       └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Renovate Bot   │    │  Container       │    │   Image         │
│  Dependencies   │    │  Registry        │    │   Scanning      │
│  • Helm Charts  │───▶│  (Harbor/ECR)    │───▶│   (Aqua)        │
│  • Base Images  │    │                  │    │   • CVE Scan    │
│  • Libraries    │    │                  │    │   • Malware     │
└─────────────────┘    └──────────────────┘    │   • Secrets     │
         │                       │             │   • Compliance  │
         ▼                       ▼             └─────────────────┘
┌─────────────────┐    ┌──────────────────┐              │
│  Config Repo    │    │  Manifest        │              │
│  Auto-Update    │    │  Generation      │              │
│  • Image Tags   │◀───│  • Kustomize     │              │
│  • Charts       │    │  • Helm          │              │
│  • Configs      │    │  • Validation    │              │
└─────────────────┘    └──────────────────┘              │
         │                                               │
         ▼                                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KARGO PROMOTION PIPELINE                    │
├─────────────────────────────────────────────────────────────────┤
│  DEV STAGE          STAGING STAGE         PRODUCTION STAGE     │
│  ┌─────────────┐    ┌─────────────┐       ┌─────────────┐      │
│  │ Auto Deploy │───▶│ Auto Deploy │──────▶│ Manual Gate │      │
│  │ • Fast Fail │    │ • E2E Tests │       │ • Approval  │      │
│  │ • Unit Test │    │ • Perf Test │       │ • Rollback  │      │
│  │ • Sec Scan  │    │ • Sec Scan  │       │ • Canary    │      │
│  └─────────────┘    └─────────────┘       └─────────────┘      │
│         │                   │                      │           │
└─────────────────────────────────────────────────────────────────┘
          │                   │                      │
          ▼                   ▼                      ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   K3S/K8S       │  │   K3S/K8S       │  │   EKS/K8S       │
│   DEV CLUSTER   │  │  STAGE CLUSTER  │  │  PROD CLUSTER   │
└─────────────────┘  └─────────────────┘  └─────────────────┘
          │                   │                      │
          ▼                   ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ARGOCD DEPLOYMENT                          │
├─────────────────────────────────────────────────────────────────┤
│  • Health Checks     • Self-Healing      • Rollback Ready     │
│  • Drift Detection   • Resource Pruning  • Blue/Green         │
│  • Sync Policies     • Hooks & Waves     • Progressive        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RUNTIME SECURITY LAYER                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │    Aqua     │  │    OPA      │  │   Falco     │  │ Network │ │
│  │  Enforcer   │  │ Gatekeeper  │  │  Runtime    │  │ Policy  │ │
│  │ • Workload  │  │ • Policies  │  │ • Behavior  │  │ • Micro │ │
│  │   Protection│  │ • Admission │  │ • Anomaly   │  │   Seg   │ │
│  │ • Compliance│  │ • Mutation  │  │ • Threats   │  │ • Zero  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  │  Trust  │ │
│                                                     └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   MONITORING & FEEDBACK                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │ Prometheus  │  │   Grafana   │  │ AlertManager│  │  Slack/ │ │
│  │ • Metrics   │  │ • Dashboards│  │ • Incidents │  │ Teams   │ │
│  │ • Health    │  │ • Security  │  │ • Escalation│  │ • PagerD│ │
│  │ • SLOs      │  │ • Compliance│  │ • Runbooks  │  │ • Jira  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
