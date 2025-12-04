

# 02 — Setup & Operational Variables  
### Mi Familia · Core Environment Setup for Kubernetes / k3s Pentesting

This module defines **all essential variables, helpers, user-agents, timing controls, and baseline operational behavior** used across the entire Kubernetes/k3s pentest workflow.

The goal:  
Make enumeration **predictable**, **stealthy**, and **repeatable**.

---

# 🔧 1. Required Environment Variables

Every in-cluster pod has a ServiceAccount token mounted automatically:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc.cluster.local"
````

Verify:

```bash
echo "Namespace: $NAMESPACE"
echo "Token length: $(echo -n $TOKEN | wc -c)"
```

---

# 🧭 2. User-Agent Spoofing (Stealth)

Kubernetes API audit logs record User-Agent strings.
Using `curl` defaults is suspicious.
Using kubectl-like UAs blends into normal cluster traffic.

```bash
UA="kubectl/v1.29.0 (linux/amd64)"
```

Define a stealth alias:

```bash
alias kcurl='curl -sk -H "Authorization: Bearer $TOKEN" -H "User-Agent: $UA"'
```

All subsequent examples assume `kcurl`.

---

# 💠 3. Universal Curl Templates

**List a resource:**

```bash
kcurl "$APISERVER/apis/<group>/<version>/namespaces/<ns>/<resource>"
```

**Get one item:**

```bash
kcurl "$APISERVER/apis/<group>/<version>/namespaces/<ns>/<resource>/<name>" | jq .
```

**Core API listing:**

```bash
kcurl "$APISERVER/api/v1/<resource>"
```

---

# ⏱️ 4. Timing Controls (Anti-Detection)

To avoid burst activity patterns in API audit logs:

```bash
random_sleep() {
  sleep $((RANDOM % 5 + 2))
}
```

Throttled wrapper function:

```bash
kscan() {
  random_sleep
  kcurl "$1"
}
```

---

# 🔐 5. Disable TLS Verification (In-Cluster Safe)

Pods often use cluster-local CA bundles that `curl` doesn’t trust:

```bash
curl -sk   # s = silent, k = ignore TLS validation
```

---

# 📦 6. Optional Tools (If jq is missing)

BusyBox containers lack jq.
Define a barebones JSON expander:

```bash
jqless() {
  sed 's/[{}]/\n/g' | sed 's/", "/\n/g'
}
```

Example usage:

```bash
kcurl "$APISERVER/api/v1/pods" | jqless
```

---

# 🧯 7. k3s-Specific Setup

k3s uses its own embedded containerd and directory layout.

**containerd socket:**

```bash
CTR="ctr --address /run/k3s/containerd/containerd.sock"
```

**Cluster state directory:**

```
/var/lib/rancher/k3s/server/
```

Critical for node-level or cluster-level escalation.

---

# 🧩 8. Enhanced Helper Commands

### List all API groups:

```bash
kcurl "$APISERVER/apis" | jq -r '.groups[].name'
```

### Check projected token expiration (Bound ServiceAccount Tokens):

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$HOSTNAME" \
 | jq '.spec.volumes[]?.projected.sources[]?.serviceAccountToken'
```

---

# 📚 9. Full Setup Snippet (Copy/Paste Anytime)

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc.cluster.local"
UA="kubectl/v1.29.0 (linux/amd64)"

alias kcurl='curl -sk -H "Authorization: Bearer $TOKEN" -H "User-Agent: $UA"'

random_sleep() { sleep $((RANDOM % 5 + 2)); }

CTR="ctr --address /run/k3s/containerd/containerd.sock"
```

---

# 🧡 10. Real-World Notes

* Many modern clusters rotate ServiceAccount tokens frequently.
* Istio/Envoy sidecars may rewrite or capture traffic.
* Kubernetes audit logs *always* see UA, IP, verb, resource, and subresource.
* Cloud-managed clusters may add additional webhook-based admission logs.

---

This module sets the foundation for all enumeration, RBAC testing, secret extraction, lateral movement, and breakout techniques in subsequent sections.

```

---
