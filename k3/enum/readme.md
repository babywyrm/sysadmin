# Kubernetes API Resource Map (v1.31+)

## Core API Group (`/api/v1`)
```
/api/v1/
├── namespaces/                          # Namespace management
├── pods/                                # Pod resources  
├── services/                            # Service definitions
├── endpoints/                           # Service endpoints
├── configmaps/                          # ConfigMap storage
├── secrets/                             # Secret storage
├── persistentvolumes/                   # PV resources
├── persistentvolumeclaims/             # PVC resources
├── serviceaccounts/                     # ServiceAccount definitions
└── nodes/                               # Node information
```

## Apps API Group (`/apis/apps/v1`)
```
/apis/apps/v1/
├── deployments/                         # Deployment resources
├── replicasets/                         # ReplicaSet resources
├── daemonsets/                          # DaemonSet resources
└── statefulsets/                        # StatefulSet resources
```

## RBAC API Group (`/apis/rbac.authorization.k8s.io/v1`)
```
/apis/rbac.authorization.k8s.io/v1/
├── roles/                               # Namespace-scoped permissions
├── rolebindings/                        # Role assignments (namespace)
├── clusterroles/                        # Cluster-wide permissions  
└── clusterrolebindings/                 # ClusterRole assignments
```

## Key CTF Target Endpoints

### **Secrets** (High Value)
```bash
# All secrets in current namespace
GET /api/v1/namespaces/{namespace}/secrets

# All secrets cluster-wide (requires permissions)
GET /api/v1/secrets

# Specific secret
GET /api/v1/namespaces/{namespace}/secrets/{secret-name}
```

### **ServiceAccount Tokens**
```bash
# ServiceAccount info
GET /api/v1/namespaces/{namespace}/serviceaccounts/{sa-name}

# Associated secrets (tokens)
GET /api/v1/namespaces/{namespace}/secrets?fieldSelector=type=kubernetes.io/service-account-token
```

### **ConfigMaps** (Config Data)
```bash
# All ConfigMaps
GET /api/v1/namespaces/{namespace}/configmaps

# Specific ConfigMap  
GET /api/v1/namespaces/{namespace}/configmaps/{configmap-name}
```

### **RBAC Discovery**
```bash
# What can I do? (Self-assessment)
POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews

# Role permissions
GET /apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles

# Cluster roles (high privilege)
GET /apis/rbac.authorization.k8s.io/v1/clusterroles
```

### **Pod/Container Info**
```bash
# Current pod info
GET /api/v1/namespaces/{namespace}/pods/{pod-name}

# Pod logs (potential secrets)
GET /api/v1/namespaces/{namespace}/pods/{pod-name}/log

# Execute commands
POST /api/v1/namespaces/{namespace}/pods/{pod-name}/exec
```

## Common CTF Attack Paths

### 1. **Initial Recon**
```bash
# Discovery
GET /api/v1/namespaces
GET /apis/rbac.authorization.k8s.io/v1/clusterroles

# Self-assessment  
POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews
```

### 2. **Secret Extraction**
```bash
# Find secrets
GET /api/v1/secrets

# Extract ServiceAccount tokens
GET /api/v1/namespaces/kube-system/secrets
GET /api/v1/namespaces/default/secrets
```

### 3. **Privilege Escalation**
```bash
# Find privileged roles
GET /apis/rbac.authorization.k8s.io/v1/clusterroles

# Check bindings
GET /apis/rbac.authorization.k8s.io/v1/clusterrolebindings
```

## API Server Access Methods

### **From Pod (ServiceAccount)**
```bash
# Token location
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# API server endpoint
https://kubernetes.default.svc.cluster.local
# or
https://10.43.0.1  # Service IP
```

### **Authentication Headers**
```bash
curl -H "Authorization: Bearer ${TOKEN}" \
     -k https://kubernetes.default.svc.cluster.local/api/v1/secrets
```


##
##
