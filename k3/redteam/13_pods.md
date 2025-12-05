
# 📄 **13_pods.md**

### *Phase 4 — Pod Reconnaissance, Privilege Analysis & Escape Pathing*

**Mi Familia Edition — Kubernetes / k3s Pentest Diary**

---

````markdown
# 13 — Pod Reconnaissance & Privilege Escalation
### Phase 4: Understanding Execution Context & Escape Opportunities

Once inside a pod, **everything hinges on your environment**:
- privileges  
- mounted volumes  
- kernel namespaces  
- runtime configuration  
- node identity  
- service account  
- network policies  
- node relationships  

This module provides the complete professional playbook for pod-level security analysis and root-to-node escalation.

---

# 🧭 1. Identify Pod Identity & Basic Context

### Pod name:
```bash
HOSTPOD=$(hostname)
````

### Pod metadata:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$HOSTPOD" | jq .
```

Extract:

* pod name
* namespace
* serviceAccount
* node name
* volumes
* init containers
* annotations (CRITICAL)
* container args (leak creds)

---

# 🎖️ 2. ServiceAccount & Token Analysis

### Current SA:

```bash
SA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
```

### Token:

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token | wc -c
```

### Mounted token metadata:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"
```

Weak SAs = early root cause of most cluster compromises.

---

# 🧩 3. Container SecurityContext Analysis (Privilege Detection)

Retrieve container security context:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$HOSTPOD" \
 | jq '.spec.containers[].securityContext'
```

### Critical indicators:

| Setting                          | Meaning                         | Risk                  |
| -------------------------------- | ------------------------------- | --------------------- |
| `privileged: true`               | Full root access to host kernel | 🔥 Critical           |
| `allowPrivilegeEscalation: true` | Enables CAP_SYS_ADMIN abuses    | 🔥 High               |
| `hostPID: true`                  | Sees host processes             | 🔥 High               |
| `hostIPC: true`                  | Can snoop IPC                   | High                  |
| `hostNetwork: true`              | Direct host networking          | High                  |
| `runAsUser: 0`                   | Container running as root       | Medium–High           |
| `capabilities.add`               | Extra kernel capabilities       | Critical if SYS_ADMIN |

### Check capabilities:

```bash
grep Cap /proc/self/status
```

### If you see `CapEff` containing:

* `SYS_ADMIN`
* `NET_ADMIN`
* `SYS_PTRACE`

→ **You have a node breakout path.**

---

# 🪓 4. HostPath Volume Analysis (Node Takeover)

List volumes:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$HOSTPOD" \
 | jq '.spec.volumes'
```

Check for:

```
hostPath:
  path: /
hostPath:
  path: /var/run/docker.sock
hostPath:
  path: /run/containerd/containerd.sock
hostPath:
  path: /etc
hostPath:
  path: /var/lib/kubelet
```

These represent **immediate node compromise**.

### Quick test:

```bash
ls /host || true
```

If `/host` exists, you likely have host mounts.

---

# 🔌 5. Container Runtime Access (Docker, containerd, CRI-O)

### Check runtime socket mounts:

```bash
find / -name '*dock*sock' 2>/dev/null
find / -name 'containerd.sock' 2>/dev/null
```

If accessible →
You can create containers **on the host itself**.

Example:

* Docker socket → root
* containerd → namespace override
* CRI → run privileged pod → host root

---

# 🧿 6. Node Identity Leakage

### Show node name:

```bash
NODE=$(kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$HOSTPOD" | jq -r '.spec.nodeName')
```

### Node metadata:

```bash
kcurl "$APISERVER/api/v1/nodes/$NODE"
```

Node metadata reveals:

* OS version
* kernel version
* cloud provider
* container runtime
* CVE surface
* user data

Example exploits:

* containerd unprivileged breakout
* runc escape CVEs
* kernel privilege escalation

---

# 🔥 7. Environment Variable Credential Extraction

List everything:

```bash
env | sort
```

Look for:

* database URLs
* cloud role ARNs
* OAuth client secrets
* JWT signing keys
* API tokens

Search patterns:

```bash
env | grep -Ei "key|token|secret|pass|auth|aws|gcp|azure"
```

---

# 📦 8. Filesystem Credential & Config Harvesting

Search common locations:

```bash
find / -maxdepth 4 -type f -iname "*config*" 2>/dev/null
```

Check:

* `/etc`
* `/var/run/secrets`
* app directories under `/opt`, `/var/lib`, `/app`
* mounted config volumes

Look for:

* `.env` files
* JSON/YAML config
* kubeconfigs
* git credentials

### Check if kubeconfig exists:

```bash
ls -la ~/.kube/config 2>/dev/null
```

Sometimes CI/CD and operator pods mount **admin kubeconfigs**.
This is one of the highest-value findings in real clusters.

---

# 🔭 9. Init Container Recon (often overlooked)

Init containers often:

* access host resources
* run privileged workloads
* fetch secrets
* execute bootstrap scripts

List init containers:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$HOSTPOD" \
 | jq '.spec.initContainers'
```

Check for:

* SSH keys
* Git deploy keys
* Privileged setup scripts
* Docker/CRI interactions

---

# 🔁 10. Pod-to-Pod Lateral Movement

### List pods in namespace:

```bash
kcurl "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" | jq -r '.items[].metadata.name'
```

### Try exec:

If allowed:

```bash
kubectl exec -n $NAMESPACE -it <pod> -- sh
```

### Login pivot vector:

Pods with:

* vault-agent
* db-migration scripts
* CI/CD runners
* sidecars
  contain credentials & tokens.

---

# 🛰️ 11. Network Recon From Within the Pod

### Show IP addresses:

```bash
ip a
```

### Show routes:

```bash
ip route
```

### DNS enumeration:

```bash
cat /etc/resolv.conf
```

### Check metadata (cloud providers):

AWS:

```bash
curl -s http://169.254.169.254/latest/meta-data/
```

GCP:

```bash
curl -s http://metadata.google.internal/
```

Azure:

```bash
curl -s -H "Metadata: true" http://169.254.169.254/metadata/instance
```

If reachable →
You may steal:

* IAM roles
* Tokens
* Cloud secrets
* Credentials for other workloads

---

# 🧱 12. NetworkPolicy Weakness Detection

Check namespace policies:

```bash
kcurl "$APISERVER/apis/networking.k8s.io/v1/namespaces/$NAMESPACE/networkpolicies"
```

If empty →
“**Flat network**” → unrestricted lateral movement.

Test outbound egress:

```bash
nc -vz 10.0.0.0/8 80
```

Test in-cluster east-west:

```bash
curl -s http://<service-name>.<namespace>.svc.cluster.local
```

---

# 🧨 13. Pod Escape Opportunities (Node Takeover Matrix)

Perform systematic checks:

| Escape Vector        | Test                                       |
| -------------------- | ------------------------------------------ |
| Privileged container | check `securityContext.privileged == true` |
| HostPID              | check `.spec.hostPID`                      |
| HostNetwork          | check `.spec.hostNetwork`                  |
| CAP_SYS_ADMIN        | check `/proc/self/status`                  |
| Docker socket        | `/var/run/docker.sock` exists              |
| containerd sock      | `/run/containerd/containerd.sock`          |
| Writable hostPath    | mount with write perms                     |
| Unsafe sysctls       | check `.spec.securityContext.sysctls`      |
| AppArmor disabled    | `/proc/self/attr/current`                  |
| Seccomp disabled     | `grep Seccomp /proc/self/status`           |

If ANY of these are positive →
You have at least **partial node access**.

Multiple positive indicators →
**full node compromise is likely.**

---

# 🧨 14. Pod Risk Grading (Professional Audit Criteria)

| Severity     | Indicators                                           |
| ------------ | ---------------------------------------------------- |
| **Critical** | Privileged, hostPath, CAP_SYS_ADMIN, containerd.sock |
| **High**     | hostNetwork, hostPID, env creds, mounted secrets     |
| **Medium**   | runs as root, writable config volumes                |
| **Low**      | restricted SCC/PSP, no mounts                        |

---

# 🛑 15. Anti-Forensics: Reduce Noise While Enumerating

### Limit audit log noise:

```bash
sleep $((RANDOM % 4 + 2))
```

### Mimic kubelet or kubectl:

```bash
-H "User-Agent: kubelet/v1.29.0"
```

### Only hit endpoints that matter:

Avoid bulk-listing unless needed.

---

# 🔥 16. High-Value One-Liners

### List all privileged pods:

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'
```

### List all pods with hostPath volumes:

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq -r '.items[] | select(.spec.volumes[]?.hostPath) | .metadata.name'
```

### Identify all pods running as root:

```bash
kcurl "$APISERVER/api/v1/pods" \
 | jq -r '.items[] | select(.spec.containers[].securityContext.runAsUser == 0) | .metadata.name'
```

### Check for dangerous capabilities:

```bash
grep Cap /proc/self/status
```

---

# 🎯 17. Summary

Pod-level reconnaissance is where you uncover:

* privilege boundaries
* breakout vectors
* identity weaknesses
* environment credential leaks
* node relationships
* runtime capabilities
* lateral movement paths
* misconfigurations in operators & CI/CD

This phase produces **your first true privilege-escalation decision tree.**

##
##
