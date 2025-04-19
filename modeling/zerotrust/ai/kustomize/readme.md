

```
kustomize/
├── base/
│   ├── deployment.yaml
│   ├── serviceaccount.yaml
│   ├── configmap.yaml
│   ├── networkpolicy.yaml
│   ├── mapping-ambassador.yaml
│   └── kustomization.yaml
└── overlays/
    └── prod/
        ├── kustomization.yaml
        └── patch‑deployment.yaml
```


```
```
base/kustomization.yaml

```
resources:
  - deployment.yaml
  - serviceaccount.yaml
  - configmap.yaml
  - networkpolicy.yaml
  - mapping-ambassador.yaml

```
overlays/prod/kustomization.yaml

```
resources:
  - ../../base
patchesStrategicMerge:
  - patch-deployment.yaml




```
overlays/prod/patch-deployment.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: brain-api
spec:
  replicas: 4                # override to 4 in prod
  template:
    spec:
      containers:
      - name: brain-api
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "1"
            memory: "2Gi"




```


# Combining Helm and Kustomize for Zero‑Trust AI/ML Microservices on EKS

A technical guide to packaging, customizing, and deploying a Zero‑Trust AI/ML inference service (`brain-api`) on Amazon EKS using both Helm and Kustomize.

---

## Table of Contents

1. [Introduction](#introduction)  
2. [Why Use Both Helm and Kustomize?](#why-use-both-helm-and-kustomize)  
3. [Workflow A: Render‑Then‑Patch](#workflow-a-render-then-patch)  
4. [Workflow B: Kustomize Helm Inflator](#workflow-b-kustomize-helm-inflator)  
5. [Key Considerations & Best Practices](#key-considerations--best-practices)  
6. [CI/CD Pipeline Integration](#cicd-pipeline-integration)  
7. [Quick Reference Commands](#quick-reference-commands)  

---

## Introduction

Deploying a complex, Zero‑Trust microservice on Kubernetes often requires:

- **Parameterized, reusable manifests** (Helm charts)  
- **Environment‑specific overlays** (dev, staging, prod)  

Helm excels at packaging and templating; Kustomize excels at patching and overlaying. Together, they enable:

- **DRY**: Don’t Repeat Yourself — keep common templates in one place  
- **Separation of concerns**: Chart authors maintain application logic; operators manage per‑environment patches  

---

## Why Use Both Helm and Kustomize?

| Feature              | Helm                                    | Kustomize                               |
|----------------------|-----------------------------------------|-----------------------------------------|
| Templating           | Go‑template engine + `values.yaml`      | None (YAML as code)                     |
| Package management   | Chart dependencies, versioning          | N/A                                     |
| Overlays             | Limited (subcharts, conditionals)       | Native overlays, patches, generators    |
| GitOps friendliness  | Requires rendering step or plugin       | Native support in tools like Argo CD    |
| Secret management    | `helm secrets` plugins, external tools  | `secretGenerator`, SealedSecrets, ExternalSecrets |

**Combining** them provides:

1. **Helm** for core templating, shared across teams  
2. **Kustomize** for environment‑specific tweaks without chart forks  

---

## Workflow A: Render‑Then‑Patch

1. **Render** your Helm chart to plain YAML  
   ```bash
   helm template zero‑trust-brain-chart \
     --values values.yaml \
     --output-dir rendered
   ```

2. **Base**: treat `rendered/` as `kustomize/base/`  
   ```text
   kustomize/base/
   └── rendered/
        ├ deployment.yaml
        ├ serviceaccount.yaml
        ├ configmap.yaml
        ├ networkpolicy.yaml
        └ mapping-ambassador.yaml
   ```

3. **Create** `kustomization.yaml` in `kustomize/base/`:
   ```yaml
   resources:
     - rendered/
   ```

4. **Overlay** in `kustomize/overlays/prod/`:
   ```yaml
   resources:
     - ../../base
   patchesStrategicMerge:
     - patch-deployment.yaml
   ```

5. **Deploy**:
   ```bash
   kubectl apply -k kustomize/overlays/prod
   ```

> **Pros:**  
> - You see the exact YAML Helm generated.  
> - Easy to debug both layers.

> **Cons:**  
> - You must regenerate base when chart changes.  
> - Base directory can grow large.

---

## Workflow B: Kustomize Helm Inflator

Leverage Kustomize v4+’s built‑in Helm support to keep charts and overlays in Git without checking in rendered YAML.

1. **Base** `kustomize/base/kustomization.yaml`:
   ```yaml
   helmCharts:
     - name: zero-trust-brain
       chart: ../../zero-trust-brain-chart
       version: 0.1.0
       releaseName: brain-api
       valuesFile: values.yaml

   resources: []
   ```

2. **Overlay** same as Workflow A:
   ```yaml
   # overlays/prod/kustomization.yaml
   resources:
     - ../../base
   patchesStrategicMerge:
     - patch-deployment.yaml
   ```

3. **Deploy**:
   ```bash
   kubectl apply -k kustomize/overlays/prod
   ```

> **Pros:**  
> - Single “kustomize build” step.  
> - No rendered YAML in repo.

> **Cons:**  
> - Rendered output hidden behind Kustomize plugin.  
> - Less transparent during debugging.

---

## Key Considerations & Best Practices

1. **Secret Management**  
   - Use Kustomize `secretGenerator` or SealedSecrets to avoid putting secrets in Helm `values.yaml`.  
   - ExternalSecrets controller can fetch from AWS Secrets Manager or Vault.

2. **Version Pinning**  
   - Pin your Helm CLI and Kustomize versions in CI.  
   - In inflator mode, specify `chartVersion` in kustomization.

3. **Dry‑Run & Linting**  
   - `helm lint zero-trust-brain-chart`  
   - `kustomize build kustomize/base | kubeval`  

4. **GitOps Integration**  
   - Argo CD supports both Helm charts and Kustomize overlays:  
     - Use two Applications or a single Kustomize Application with Helm generator.  
   - FluxCD also supports HelmRelease + Kustomization.

---

## CI/CD Pipeline Integration

```yaml
# Example GitHub Actions snippet

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Helm & Kustomize
        uses: azure/setup-kubectl@v3
        with:
          version: '1.27.0'
      - uses: xboxsetup/setup-helm@v1
        with:
          version: '3.12.0'
      - name: Setup Kustomize
        run: |
          curl -sSL https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v4.8.2/kustomize_v4.8.2_linux_amd64.tar.gz \
            | tar xz -C /usr/local/bin

      - name: Helm Lint
        run: helm lint zero-trust-brain-chart

      - name: Render Helm (if using Workflow A)
        run: helm template zero-trust-brain-chart --values values.yaml --output-dir rendered

      - name: Kustomize Build & Deploy
        run: |
          kubectl apply -k kustomize/overlays/${{ matrix.env }}

```

---

## Quick Reference Commands

| Task                               | Command                                                                     |
|------------------------------------|-----------------------------------------------------------------------------|
| **Lint Helm chart**                | `helm lint zero-trust-brain-chart`                                          |
| **Render Helm chart**              | `helm template zero-trust-brain-chart -f values.yaml > rendered/app.yaml`   |
| **Build Kustomize base**           | `kustomize build kustomize/base`                                            |
| **Build & apply prod overlay**     | `kubectl apply -k kustomize/overlays/prod`                                  |
| **Build (Helm Inflator)**          | `kustomize build kustomize/base`                                            |

---

> **Summary:**  
> - **Helm** drives your application template, versions, and packaging.  
> - **Kustomize** applies environment‑specific patches, secrets, and overlays.  
> - Choose **Render‑Then‑Patch** for transparency, or **Helm Inflator** for DRYness.  
> - Integrate both in your CI/CD for fully automated, GitOps‑friendly Zero‑Trust deployments.
```
