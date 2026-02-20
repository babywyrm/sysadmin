# Registering Rancher-Managed Clusters in Argo CD ..beta..

## Why `argocd cluster add` Fails with Rancher

Rancher's default kubeconfig points to its **authentication proxy** (`https://<rancher>/k8s/clusters/<id>`) rather than the downstream cluster API directly. Argo CD's `argocd cluster add` tries to install a ServiceAccount and use its token — but the Rancher auth proxy **rejects service account tokens**; it only accepts **Rancher API tokens**.

The fix: skip `argocd cluster add` entirely and create the cluster secret manually.

---

## Prerequisites

| What | Why |
|---|---|
| Rancher local user account | Used to generate a Rancher API token |
| Rancher API token (no scope) | Bearer token for Argo CD auth |
| Cluster Owner role on target cluster(s) | Cluster Member is insufficient — ArgoCD needs to list all resource types |
| Rancher TLS CA cert (if private CA) | Required for TLS verification |

> **Role note:** Multiple users have confirmed that **Cluster Member is not enough**. Assign **Cluster Owner** to the service account, then narrow down permissions later.

---

## Step 1 — Create a Rancher Service Account

1. In Rancher UI: **Users & Authentication → Users → Create**
2. Username: `service-argocd`, assign **Standard User** global role
3. Log in as that user and go to **API & Keys → Add Key**
   - Scope: **No Scope**
   - Copy the token — it looks like `token-xxxxx:yyyyyyyyyyyyyyyyyyy`

---

## Step 2 — Grant Cluster Access

For **every cluster** Argo CD will manage (including the one Argo CD runs on):

**Rancher UI → Cluster → Cluster Members → Add**
- User: `service-argocd`
- Role: **Cluster Owner**

---

## Step 3 — Get the Cluster ID and CA Data

**Cluster ID:** Rancher UI → Cluster Management → your cluster → Related Resources → find the **Mgmt Cluster** object. The name is your cluster ID (e.g. `c-m-abcdefgh`).

**CA Data:** Extract from the Rancher-provided kubeconfig for that cluster:

```bash
# Get the caData field (already base64-encoded)
kubectl config view --raw \
  --context=<rancher-context> \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}'
```

> **Important:** This must be the CA for the **Rancher endpoint**, not the downstream cluster's CA. If Rancher uses a public trusted CA, you can omit `caData` and set `"insecure": false`.

---

## Step 4 — Create the Cluster Secret

```yaml
# cluster-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: rancher-cluster-prod
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: prod
  server: https://<rancher-hostname>/k8s/clusters/<cluster-id>
  config: |
    {
      "bearerToken": "token-xxxxx:yyyyyyyyyyyyyyyyyyy",
      "tlsClientConfig": {
        "insecure": false,
        "caData": "<base64-encoded-rancher-CA-cert>"
      }
    }
```

Apply it to the Argo CD namespace:

```bash
kubectl apply -n argocd -f cluster-secret.yaml
```

---

## Step 5 — Verify

```bash
argocd cluster list
```

Expected output:

```text
SERVER                                          NAME   VERSION  STATUS
https://<rancher>/k8s/clusters/<cluster-id>    prod   1.28     Successful
https://kubernetes.default.svc                         1.28     Successful
```

> **Note:** Status may show `Unknown` until Argo CD has an application deployed to the cluster. To verify credentials without deploying, see the [Argo CD cluster credentials troubleshooting guide](https://argo-cd.readthedocs.io/en/stable/operator-manual/troubleshooting/#cluster-credentials).

If the cluster appears registered but shows no `Successful` status in the CLI, **restart the Argo CD pods**:

```bash
kubectl rollout restart deployment -n argocd
```

---

## Troubleshooting

### `x509: certificate signed by unknown authority`

You're using the wrong CA. The `caData` must be the CA that signed the **Rancher server's TLS certificate**, not the downstream cluster's internal CA.

```bash
# Inspect what cert Rancher is actually serving
openssl s_client -connect <rancher-hostname>:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 "Issuer:"

# Then base64-encode the correct root CA PEM
base64 -w0 rancher-ca.pem
```

As a temporary diagnostic (not for production), set `"insecure": true` and omit `caData`. If that works, your `caData` is the problem.

### `serviceaccounts is forbidden` / resource listing errors

The Rancher user needs **Cluster Owner**, not Cluster Member. Update the role in Rancher UI and re-test.

### Cluster shows as registered in UI but sync fails with "not configured"

Restart Argo CD pods — this is a known cache initialization issue when a secret is applied while Argo CD is running:

```bash
kubectl rollout restart deployment -n argocd
```

---

## Namespace-Scoped Registration (Optional)

To restrict Argo CD to specific namespaces instead of cluster-wide access:

```yaml
stringData:
  name: prod
  server: https://<rancher-hostname>/k8s/clusters/<cluster-id>
  namespaces: namespace1,namespace2
  config: |
    {
      "bearerToken": "token-xxxxx:yyyyyyyyyyyyyyyyyyy",
      "tlsClientConfig": {
        "insecure": false,
        "caData": "<base64-encoded-ca>"
      }
    }
```

---

## Summary

```text
argocd cluster add  ✗  (uses SA tokens — rejected by Rancher proxy)
kubectl apply       ✓  (uses Rancher API token — works)
```

| Setting | Value |
|---|---|
| `server` | `https://<rancher>/k8s/clusters/<cluster-id>` |
| `bearerToken` | Rancher API token (no scope) |
| `caData` | Rancher server's CA (base64, not downstream cluster CA) |
| User role | Cluster Owner on all target clusters |
| Token scope | No Scope (not cluster-scoped) |

##
#
https://gist.github.com/janeczku/b16154194f7f03f772645303af8e9f80
#
https://gist.github.com/devops-school/7dbba2adb3933071dc15d44a82c4cd5c
#
##

