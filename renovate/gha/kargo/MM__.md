
```mermaid
flowchart TD

  subgraph "1. Dependency Update (Renovate)"
    DEP1[cron schedule weekly at 01:00 UTC] --> DEP2[Run renovate/renovate-action@v38]
    DEP2 --> DEP3[Renovate updates deps and opens PR]
  end

  subgraph "2. Pull-Request CI Checks"
    DEP3 --> CI1[Checkout source code]
    CI1 --> CI2[Setup runtime environment (Node/Python/Java/etc.)]
    CI2 --> CI3[Run unit tests]
    CI3 -- fail --> CI_FAIL_TESTS[Block PR: fix unit tests]
    CI3 -- pass --> CI4[Run service health check]
    CI4 -- fail --> CI_FAIL_SERVICE[Block PR: fix service startup]
    CI4 -- pass --> CI5[Proceed to build]
  end

  subgraph "3. Build & Vulnerability Scan"
    CI5 --> BS1[Build Docker image tagged with SHA]
    BS1 --> BS2[Run vulnerability scan using Trivy]
    BS2 -- CVEs found --> BS_FAIL_CVES[Block PR: patch CVEs]
    BS2 -- no CVEs --> BS3[Tag image and push to container registry]
  end

  subgraph "4. Deploy to Dev Environment"
    BS3 --> DEV1[Update Dev manifest in GitOps repo]
    DEV1 --> DEV2[Argo CD detects change and syncs]
    DEV2 --> DEV3[Kargo applies manifests to EKS Dev]
    DEV3 --> DEV4[Run post-deploy smoke tests]
    DEV4 -- fail --> DEV_FAIL[Auto-rollback via Argo CD]
    DEV4 -- pass --> DEV_OK[Dev environment healthy]
  end

  subgraph "5. Promote to Staging Environment"
    DEV_OK --> STG1[Manual approval to promote]
    STG1 --> STG2[Update Staging manifest in GitOps repo]
    STG2 --> STG3[Argo CD sync to EKS Staging]
    STG3 --> STG4[Run Staging integration tests]
    STG4 -- fail --> STG_FAIL[Alert and rollback]
    STG4 -- pass --> STG_OK[Staging environment healthy]
  end

  subgraph "6. Promote to Production Environment"
    STG_OK --> PR1[Manual approval to promote to Production]
    PR1 --> PR2[Update Production manifest in GitOps repo]
    PR2 --> PR3[Argo CD sync to EKS Production]
    PR3 --> PR4[Run Production smoke tests and canary checks]
    PR4 -- fail --> PR_FAIL[Alert and rollback]
    PR4 -- pass --> PR_OK[Production is live]
  end
```
##
##

```
flowchart TD
  %% 1. Dependency Update (Renovate)
  subgraph A["1. Dependency Update (Renovate)"]
    A1["Schedule: weekly @ 01:00 UTC"] --> A2["Run renovate/renovate-action@v38"]
    A2 --> A3["Renovate updates deps & opens PR"]
  end

  %% 2. Pull-Request CI Checks
  subgraph B["2. PR CI Checks"]
    A3 --> B1["Checkout code"]
    B1 --> B2["Set up runtime (Node/Python/Java…)"]
    B2 --> B3["Run unit tests"]
    B3 -- fail --> B8["Block PR: fix tests"]
    B3 -- pass --> B4["Start service health check"]
    B4 -- fail --> B9["Block PR: fix service"]
    B4 -- pass --> B5["Proceed to build"]
  end

  %% 3. Build & Vulnerability Scan
  subgraph C["3. Build & Vulnerability Scan"]
    B5 --> C1["Build Docker image (app:SHA)"]
    C1 --> C2["Run Trivy scan"]
    C2 -- "CVE-2021-1234, CVE-2022-2345 detected" --> C4["Block & comment PR: patch CVEs"]
    C2 -- pass --> C3["Tag image → push to ECR"]
  end

  %% 4. Dev Deployment via GitOps (Argo CD / Kargo)
  subgraph D["4. Deploy to Dev (EKS Dev)"]
    C3 --> D1["Update Dev k8s manifest (image:SHA) in gitops-repo"]
    D1 --> D2["Argo CD detects change & syncs"]
    D2 --> D3["Apply via Kargo CLI on EKS Dev"]
    D3 --> D4["Run post-deploy smoke tests"]
    D4 -- fail --> D5["Auto-rollback via Argo CD"]
    D4 -- pass --> D6["Dev is healthy"]
  end

  %% 5. Promote to Staging
  subgraph E["5. Promote to Staging (EKS Staging)"]
    D6 --> E1["Manual approval required"]
    E1 --> E2["Update manifest in staging gitops-repo"]
    E2 --> E3["Argo CD sync → EKS Staging"]
    E3 --> E4["Run staging integration tests"]
    E4 -- fail --> E5["Alert & rollback"]
    E4 -- pass --> E6["Staging is healthy"]
  end

  %% 6. Promote to Production
  subgraph F["6. Promote to Production (EKS Prod)"]
    E6 --> F1["Manual approval required"]
    F1 --> F2["Update manifest in prod gitops-repo"]
    F2 --> F3["Argo CD sync → EKS Prod"]
    F3 --> F4["Run prod smoke & canary checks"]
    F4 -- fail --> F5["Alert & rollback"]
    F4 -- pass --> F6["Production is live"]
  end
