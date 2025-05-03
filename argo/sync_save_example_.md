

# Argo CD Sync Waves: A How-To Guide

## Overview

Argo CD applies manifests in a deterministic sequence to ensure dependencies are created before dependents. 

**Sync waves** let you explicitly group and order resources within that sequence—perfect for things like CRDs, ExternalSecrets, or any manifest that another object relies on.

---

## 1. What Is a Sync Wave?

* **Wave = an integer** you assign to a resource via annotation
* **Negative → early**; **zero (default)** → normal; **positive → late**
* Argo CD sorts and applies resources by:

  1. Pre-sync hooks
  2. Sync-wave (low → high)
  3. Kubernetes Kind order (Namespace, CRD, Secret, ServiceAccount, Deployment, …)
  4. Name (alphabetical)
  5. Post-sync hooks

*Default wave is 0 for all non-hook manifests.*

---

## 2. Annotating a Manifest

Add this under `metadata.annotations`:

```yaml
metadata:
  annotations:
    argocd.argoproj.io/sync-wave: "<N>"
```

* Replace `<N>` with your chosen integer
* Quotes are required for negative numbers (e.g. `"-1"`)

---

## 3. Common Wave Patterns

|   Wave   | When to Use                                           |
| :------: | ----------------------------------------------------- |
| `-10…-1` | Early resources (CRDs, Namespaces, SecretStores)      |
|    `0`   | Main workloads (Helm charts, Deployments)             |
|  `1…10`  | Cleanup/late tasks (post-deploy scripts, CR removals) |

---

## 4. Example: ExternalSecret → Helm Chart

**Goal:** Ensure `ExternalSecret` creates a Kubernetes Secret before the Helm chart references it.

```yaml
# external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-creds
  annotations:
    argocd.argoproj.io/sync-wave: "-1"    # wave −1 = apply first
spec:
  secretStoreRef:
    name: aws-store
    kind: SecretStore
  target:
    name: db-creds
  data:
    - secretKey: username
      remoteRef:
        key: /prod/db/username
    - secretKey: password
      remoteRef:
        key: /prod/db/password
```

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

helmCharts:
- name: my-app
  repo: https://example.com/charts
  version: 1.2.3
  valuesFile: values.yaml

resources:
- external-secret.yaml
```

```yaml
# values.yaml
database:
  existingSecret: db-creds
  existingSecretUsernameKey: username
  existingSecretPasswordKey: password
```

> **Result:**
>
> 1. Argo CD applies `external-secret.yaml` at wave −1.
> 2. The ExternalSecrets operator writes the `db-creds` Secret.
> 3. Argo CD renders & applies the Helm chart (wave 0), which can now safely reference `db-creds`.

---

## 5. Advanced Scenarios

### 5.1 Multiple Dependency Layers

If you have three layers—CRD → SecretStore → ExternalSecret → Helm chart—you might assign waves like:

| Resource           | Wave |
| ------------------ | :--: |
| CRD definitions    | `-3` |
| SecretStore CR     | `-2` |
| ExternalSecret CRs | `-1` |
| Helm charts        |  `0` |

### 5.2 Post-Sync Cleanup

For jobs that should run **after** everything else, use positive waves or post-sync hooks:

```yaml
metadata:
  annotations:
    argocd.argoproj.io/sync-wave: "1"           # after all wave 0 resources
    argocd.argoproj.io/hook: PostSync           # optional post-sync hook
```

---

## 6. Best Practices

* **Group by function**: Pick wave ranges (e.g. −5 to −1) for distinct dependency tiers.
* **Keep them simple**: Don’t over-engineer—only annotate when default ordering isn’t enough.
* **Document your ranges**: In your repo’s README, map each wave range to its purpose.
* **Health checks**: If you’ve enabled Argo CD health checks, it will wait for wave −1 resources to become healthy before proceeding to 0.

---

## 7. Troubleshooting

1. **“Secret not found” errors**

   * Verify the ExternalSecret CR is annotated with a lower wave than the chart.
2. **Resources stuck pending**

   * Check Argo CD’s resource tree UI to see the wave assignments.
3. **Out-of-order application**

   * Confirm you’re not mixing sync-wave with incompatible hooks; hooks have their own phases.

---

