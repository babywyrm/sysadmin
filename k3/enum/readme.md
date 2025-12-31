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
##
##
