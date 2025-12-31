# 🐐 Kubernetes Pentest Quick Wins  
## In-Cluster API Recon & Privilege Mapping Reference

> **Authorized use only.**  
> Practical field guide for Kubernetes API reconnaissance, RBAC assessment, and configuration discovery from an **in-cluster attacker perspective**.  
> Companion to `kubernetes-api-pentest.sh`.

---

## 🔧 Setup (In-Cluster Context)

These commands assume execution **inside a Pod** with a mounted ServiceAccount token.

```bash
TOKEN=$(< /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(< /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc.cluster.local"
AUTH="-H Authorization: Bearer $TOKEN"
````

---

## 🧭 Phase 1 — Initial Recon (Establish Ground Truth)

| Goal            | Why It Matters               | kubectl                      | curl                                                                             |
| --------------- | ---------------------------- | ---------------------------- | -------------------------------------------------------------------------------- |
| Cluster version | Identify CVEs & feature set  | `kubectl version`            | `curl -sk $AUTH $APISERVER/version`                                              |
| API health      | Confirm API reachability     | `kubectl get --raw /healthz` | `curl -sk $AUTH $APISERVER/healthz`                                              |
| API surface     | Discover available resources | `kubectl api-resources`      | `curl -sk $AUTH $APISERVER/api/v1`                                               |
| Identity        | Determine current SA context | `kubectl config view`        | `curl -sk $AUTH $APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts/default` |

**Decision point:**
If the API is reachable → continue.
If not → investigate networking / proxy / DNS first.

---

## 🗺 Phase 2 — Namespace Enumeration (Blast Radius)

| Goal                | Why                     | kubectl                           | curl                                                      |
| ------------------- | ----------------------- | --------------------------------- | --------------------------------------------------------- |
| List namespaces     | Determine cluster scope | `kubectl get ns`                  | `curl -sk $AUTH $APISERVER/api/v1/namespaces`             |
| Names only          | Fast targeting          | `kubectl get ns -o name`          | `jq -r '.items[].metadata.name'`                          |
| kube-system details | High-value infra        | `kubectl describe ns kube-system` | `curl -sk $AUTH $APISERVER/api/v1/namespaces/kube-system` |

⚠️ **If you can read `kube-system`, escalation risk is high.**

---

## 🔑 Phase 3 — RBAC Assessment (Privilege Reality)

### What can this token do?

```bash
kubectl auth can-i --list
```

Raw API equivalent:

```bash
curl -sk $AUTH -H "Content-Type: application/json" \
  -X POST $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -d '{"spec":{"resourceAttributes":{"verb":"*","resource":"*"}}}'
```

### High-value RBAC objects

| Object              | Why                               |
| ------------------- | --------------------------------- |
| ClusterRoles        | Look for wildcards, secrets, exec |
| ClusterRoleBindings | Cluster-wide power                |
| ServiceAccounts     | Token escalation paths            |

```bash
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin")'
```

🔥 **Any ServiceAccount bound to `cluster-admin` = full cluster compromise**

---

## 🔐 Phase 4 — Secret & Config Harvesting

| Target     | Why                        |
| ---------- | -------------------------- |
| Secrets    | Tokens, credentials, certs |
| ConfigMaps | Often contain passwords    |
| SA tokens  | Lateral movement           |

```bash
kubectl get secrets -A
kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token
```

Search ConfigMaps for sensitive data:

```bash
kubectl get cm -A -o json | \
  jq '.items[] |
      select(.data|to_entries[]?.value|
      test("password|token|key|secret";"i"))'
```

---

## 🧱 Phase 5 — Pod Recon (Escape & Lateral Movement)

| Finding             | Risk                    |
| ------------------- | ----------------------- |
| `privileged: true`  | Container escape        |
| `hostNetwork: true` | Bypass network policy   |
| `hostPID: true`     | Host process visibility |
| `hostPath` volumes  | Host filesystem access  |

```bash
kubectl get pods -A -o json | \
  jq '.items[] |
     select(.spec.hostNetwork==true or
            .spec.hostPID==true or
            .spec.volumes[]?.hostPath)'
```

---

## 🧨 Phase 6 — Execution & Lateral Movement

### Check permissions first

```bash
kubectl auth can-i create pods/exec
kubectl auth can-i create pods/portforward
```

### Exec into a pod (if allowed)

```bash
kubectl exec -it <pod> -- /bin/sh
```

Raw API (SPDY):

```text
POST /api/v1/namespaces/{ns}/pods/{pod}/exec
```

⚠️ **Exec + secrets + writable pods = persistence path**

---

## 🖥 Phase 7 — Node Recon (If Allowed)

```bash
kubectl get nodes
kubectl get node <node> -o yaml
```

Node access almost always implies **host-level impact**.

---

## 🌐 Phase 8 — Network & Exposure

| Object          | Why                       |
| --------------- | ------------------------- |
| Services        | Internal topology         |
| Endpoints       | Backend IPs               |
| Ingress         | External exposure         |
| NetworkPolicies | Flat vs segmented network |

```bash
kubectl get svc -A
kubectl get ep -A
kubectl get netpol -A
```

---

## 🧠 Phase 9 — Persistence & Long-Lived Access

| Mechanism  | Why                  |
| ---------- | -------------------- |
| PVCs       | Survive pod restarts |
| CronJobs   | Scheduled execution  |
| DaemonSets | Node-level foothold  |

```bash
kubectl get cronjobs -A
kubectl get daemonsets -A
```

---

## 💎 High-Value One-Liners

```bash
# List all readable secrets by namespace
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}');
do kubectl get secrets -n $ns 2>/dev/null; done
```

```bash
# ServiceAccounts with cluster-wide bindings
kubectl get clusterrolebindings -o json | \
 jq '.items[] | select(.subjects[]?.kind=="ServiceAccount")'
```

---

## 🧬 Methodology Summary

1. Can I reach the API?
2. What namespaces are visible?
3. What RBAC do I actually have?
4. Are secrets readable?
5. Can I exec or create pods?
6. Can I persist or reach the node?

If **any** answer is “yes” → escalate carefully.

---

## ⚠️ Stealth & Safety Notes

* Throttle requests: `sleep $((RANDOM % 5 + 1))`
* Match kubectl User-Agent:
  `kubectl/v1.29.0 (linux/amd64)`
* Check permissions before actions
* **Authorized testing only**

---

## 🧰 Companion Script

**`kubernetes-api-pentest.sh`**

Features:

* Safe read-only enumeration
* Graceful handling of 403s / 404s
* Optional `--deep` mode
* Per-namespace JSON output

```bash
# quick scan
bash kubernetes-api-pentest.sh

# full deep read
bash kubernetes-api-pentest.sh --deep
```

---

## 📜 Disclaimer

This guide is intended **only** for environments where you have explicit authorization.
Unauthorized access to Kubernetes clusters is illegal.
```



```
# BFF script
```
#!/usr/bin/env bash
#
# kubernetes-api-pentest.sh
#
# Read-only Kubernetes API enumeration from an in-cluster context.
# Companion to: Kubernetes Pentest Quick Wins
#
# Authorized use only.
#

set -euo pipefail

# -------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------

SA_TOKEN_FILE="/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_NS_FILE="/var/run/secrets/kubernetes.io/serviceaccount/namespace"
APISERVER="https://kubernetes.default.svc.cluster.local"

if [[ ! -r "$SA_TOKEN_FILE" ]]; then
  echo "[!] No serviceaccount token found — not running in cluster?"
  exit 1
fi

TOKEN=$(<"$SA_TOKEN_FILE")
NAMESPACE=$(<"$SA_NS_FILE" 2>/dev/null || echo "unknown")
AUTH=(-H "Authorization: Bearer $TOKEN")

OUTDIR="./k8s-pentest-output"
TS=$(date +%Y%m%dT%H%M%S)
HOST=$(hostname 2>/dev/null || echo "unknown")
DEST="$OUTDIR/${HOST}.${TS}"

mkdir -p "$DEST"

log() {
  echo "[*] $*" | tee -a "$DEST/summary.txt"
}

api() {
  local path="$1"
  curl -sk "${AUTH[@]}" "$APISERVER$path"
}

safe_api() {
  local name="$1"
  local path="$2"

  log "Fetching $name"
  if ! api "$path" >"$DEST/$name.json" 2>/dev/null; then
    echo "{}" >"$DEST/$name.json"
  fi
}

# -------------------------------------------------------------------
# Phase 1 — Initial Recon
# -------------------------------------------------------------------

log "Phase 1: Initial Recon"

safe_api "version" "/version"
safe_api "healthz" "/healthz"
safe_api "api-v1-root" "/api/v1"

# -------------------------------------------------------------------
# Phase 2 — Namespace Enumeration
# -------------------------------------------------------------------

log "Phase 2: Namespace Enumeration"

safe_api "namespaces" "/api/v1/namespaces"

jq -r '.items[].metadata.name' "$DEST/namespaces.json" \
  >"$DEST/namespace-list.txt" 2>/dev/null || true

# -------------------------------------------------------------------
# Phase 3 — RBAC
# -------------------------------------------------------------------

log "Phase 3: RBAC"

safe_api "serviceaccounts-current-ns" \
  "/api/v1/namespaces/$NAMESPACE/serviceaccounts"

safe_api "roles" "/apis/rbac.authorization.k8s.io/v1/roles"
safe_api "rolebindings" "/apis/rbac.authorization.k8s.io/v1/rolebindings"
safe_api "clusterroles" "/apis/rbac.authorization.k8s.io/v1/clusterroles"
safe_api "clusterrolebindings" "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"

# Identify cluster-admin bindings
jq '.items[] | select(.roleRef.name=="cluster-admin")' \
  "$DEST/clusterrolebindings.json" \
  >"$DEST/cluster-admin-bindings.json" 2>/dev/null || true

# -------------------------------------------------------------------
# Phase 4 — Secrets & ConfigMaps
# -------------------------------------------------------------------

log "Phase 4: Secrets & ConfigMaps"

safe_api "secrets-all" "/api/v1/secrets"
safe_api "configmaps-all" "/api/v1/configmaps"

# -------------------------------------------------------------------
# Phase 5 — Pods
# -------------------------------------------------------------------

log "Phase 5: Pods"

safe_api "pods-all" "/api/v1/pods"

jq '.items[] |
    select(.spec.hostNetwork==true or
           .spec.hostPID==true or
           .spec.volumes[]?.hostPath)' \
  "$DEST/pods-all.json" \
  >"$DEST/high-risk-pods.json" 2>/dev/null || true

# -------------------------------------------------------------------
# Phase 6 — Workloads
# -------------------------------------------------------------------

log "Phase 6: Workloads"

safe_api "deployments" "/apis/apps/v1/deployments"
safe_api "daemonsets" "/apis/apps/v1/daemonsets"
safe_api "statefulsets" "/apis/apps/v1/statefulsets"
safe_api "jobs" "/apis/batch/v1/jobs"
safe_api "cronjobs" "/apis/batch/v1/cronjobs"

# -------------------------------------------------------------------
# Phase 7 — Network
# -------------------------------------------------------------------

log "Phase 7: Network"

safe_api "services" "/api/v1/services"
safe_api "endpoints" "/api/v1/endpoints"
safe_api "networkpolicies" "/apis/networking.k8s.io/v1/networkpolicies"
safe_api "ingresses" "/apis/networking.k8s.io/v1/ingresses"

# -------------------------------------------------------------------
# Phase 8 — Nodes (if allowed)
# -------------------------------------------------------------------

log "Phase 8: Nodes"

safe_api "nodes" "/api/v1/nodes"

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------

log "Enumeration complete"
log "Namespace: $NAMESPACE"
log "Output directory: $DEST"

echo
echo "[+] Results written to $DEST"
echo "[+] Review cluster-admin-bindings.json and high-risk-pods.json first"
```
