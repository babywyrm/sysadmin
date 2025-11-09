
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

##
##


```
#!/usr/bin/env bash
# pod-enum.sh — lightweight pod enumerator (read-only)
# Usage: bash pod-enum.sh
# Output: ./k8s-pod-enumeration/<hostname>.<ts>/*.txt

set -uo pipefail

OUTDIR="./k8s-pod-enumeration"
TS=$(date +%Y%m%dT%H%M%S)
HOST=$(hostname 2>/dev/null || echo "unknown-host")
DEST="$OUTDIR/${HOST}.${TS}"
mkdir -p "$DEST"

# helper: run command, save stdout+stderr
run() {
  local name="$1"; shift
  printf "=== %s ===\n" "$name" | tee -a "$DEST/summary.txt"
  {
    printf "\$ %s\n\n" "$*"
    "$@" 2>&1
  } | tee "$DEST/${name}.txt"
  printf "\n\n" >> "$DEST/summary.txt"
}

# safe helper to try commands that may not exist
try() {
  command -v "$1" >/dev/null 2>&1 || return 1
  run "$2" "$@"
}

# Basic system / identity
run "date" date
run "whoami" whoami
run "id" id
run "hostname" hostname -f || hostname
run "uname" uname -a
run "uptime" uptime || true

# Filesystem, mounts, capabilities
run "pwd" pwd
run "ls-root" ls -la /
run "mounts" cat /proc/self/mounts
run "cgroups" cat /proc/1/cgroup || true
try cat "resolv.conf" /etc/resolv.conf
try cat "hosts" /etc/hosts

# Environment, shell, creds
run "env" env | sort
run "shells" echo "$SHELL"
run "passwd-file" ls -la /etc/passwd || true
run "sudoers" ls -la /etc/sudoers* 2>/dev/null || true

# Processes & users
try ps "ps-aux" aux
try ss "ss-users" -tunap || try netstat "netstat-list" -tunap
run "groups" groups || true
run "getent_passwd" getent passwd || true

# Network info
try ip "ip-address" address
try ip "ip-route" route
run "arp" arp -a 2>/dev/null || true

# Search for obvious secrets-ish files (read-only, shallow)
run "find-common-keys" find / -xdev -maxdepth 3 -type f \( -iname "*id_rsa*" -o -iname "*.pem" -o -iname "*.key" -o -iname "*.crt" \) -print 2>/dev/null || true
run "find-etc" find /etc -maxdepth 2 -type f -iname "*conf*" -print 2>/dev/null || true

# Kubernetes in-cluster cues (service account)
SA_TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_NS="/var/run/secrets/kubernetes.io/serviceaccount/namespace"
KUB_API="https://kubernetes.default.svc.cluster.local"

if [ -r "$SA_TOKEN" ]; then
  run "sa-namespace" cat "$SA_NS"
  # don't print token to terminal; write masked file but allow user to inspect file if needed
  printf "service account token present (saved to %s/token.txt but masked)\n" "$DEST" | tee -a "$DEST/summary.txt"
  # save token but mask middle for quick inspection
  TOKEN=$(sed -n '1p' "$SA_TOKEN" 2>/dev/null || true)
  if [ -n "$TOKEN" ]; then
    echo "${TOKEN:0:8}...${TOKEN: -8}" > "$DEST/token.txt"
    chmod 600 "$DEST/token.txt"
  fi

  # try safe read-only API calls (version + namespaces + current SA)
  if command -v curl >/dev/null 2>&1; then
    run "k8s-version" curl -ks --header "Authorization: Bearer $TOKEN" "$KUB_API/version"
    run "k8s-namespaces" curl -ks --header "Authorization: Bearer $TOKEN" "$KUB_API/api/v1/namespaces" | head -n 200
    # list serviceaccounts in current namespace (if namespace file exists)
    if [ -r "$SA_NS" ]; then
      NS=$(cat "$SA_NS")
      run "k8s-serviceaccounts" curl -ks --header "Authorization: Bearer $TOKEN" "$KUB_API/api/v1/namespaces/$NS/serviceaccounts" || true
      run "k8s-pods-ns" curl -ks --header "Authorization: Bearer $TOKEN" "$KUB_API/api/v1/namespaces/$NS/pods" | jq -r '.items[]?.metadata.name' 2>/dev/null || true
    fi
  else
    echo "curl not present — skipping in-cluster API queries" | tee -a "$DEST/summary.txt"
  fi
else
  echo "no serviceaccount token readable at $SA_TOKEN" | tee -a "$DEST/summary.txt"
fi

# Common app/runtime probes (languages & package managers)
try python3 "python-info" --version
try python3 "pip-list" -m pip list --format=columns 2>/dev/null || true
try node "node-version" --version
try npm "npm-list" ls --depth=0 2>/dev/null || true
try java "java-version" -version

# Containers / docker info (inside container these are usually not present)
run "container-runtime-proc" ls -la /proc/1 || true
run "container-runtime-cgroup" cat /proc/1/cgroup 2>/dev/null || true

# Pod filesystem quick read for interesting local files (non-destructive)
for f in /var/log /etc /home /root /opt; do
  if [ -d "$f" ]; then
    run "ls-$(basename $f)" ls -la "$f" 2>/dev/null || true
  fi
done

# Lightweight local discovery searches (fast, shallow)
run "shallow-find-home" find / -xdev -maxdepth 3 -path "*/home/*" -type f -iname "*config*" -print 2>/dev/null || true

# Short summary
{
  echo "host: $HOST"
  echo "timestamp: $TS"
  echo "output: $DEST"
  echo "note: read-only enumeration. do not run on clusters without authorization."
} >> "$DEST/summary.txt"

printf "\nComplete. Output saved to: %s\n\n" "$DEST"

```

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
    
