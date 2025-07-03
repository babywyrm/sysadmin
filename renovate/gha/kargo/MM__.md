
```mermaid
flowchart TB

  subgraph "1. Dependency Update (Renovate)"
    A1["🗓️ cron: weekly @ 01:00 UTC"] 
      --> A2["🔄 Run renovate/renovate-action@v38"]
    A2 --> A3["📦 Renovate updates deps and opens PR"]
  end

  subgraph "2. CI Pipeline on PR"
    A3 --> B1["👷 Checkout code"]
    B1 --> B2["🐍 Setup runtime (Node/Python/Java/etc.)"]
    B2 --> B3{"🔍 Vulnerability scan (Trivy)"}
    B3 -- "✔️ Pass" --> B4["🚀 Push tagged image to registry"]
    B3 -- "❌ Fail" --> B5["🛑 Block PR merge: fix vulnerabilities"]
  end

  subgraph "3. Merge & Deploy to Dev"
    B4 --> C1["🔀 Merge PR to main"]
    C1 --> C2["⚙️ Run kargo-apply.yml via GitHub Actions"]
    C2 --> C3["📡 Kargo applies manifests to EKS Dev"]
    C3 --> C4["🧪 Run Dev integration tests"]
    C4 -- "❌ Fail" --> C5["🚨 Alert and rollback"]
    C4 -- "✔️ Pass" --> C6["✅ Dev environment healthy"]
  end

  subgraph "4. Promote to Staging"
    C6 --> D1["🛂 Manual approval gate"]
    D1 --> D2["📋 Update Staging manifest in GitOps repo"]
    D2 --> D3["🔁 Argo CD syncs to EKS Staging"]
    D3 --> D4["🧪 Run Staging integration tests"]
    D4 -- "❌ Fail" --> D5["🚨 Alert and rollback"]
    D4 -- "✔️ Pass" --> D6["✅ Staging environment healthy"]
  end

  subgraph "5. Promote to Production"
    D6 --> E1["🛂 Manual approval gate"]
    E1 --> E2["📋 Update Prod manifest in GitOps repo"]
    E2 --> E3["🔁 Argo CD syncs to EKS Production"]
    E3 --> E4["🧪 Run Prod smoke and canary tests"]
    E4 -- "❌ Fail" --> E5["🚨 Alert and rollback"]
    E4 -- "✔️ Pass" --> E6["🎉 Production is live"]
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
