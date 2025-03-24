# Comprehensive K3s Security Hardening Guide 2024-2025

#Beta Edition 

## Overview
This enhanced guide provides comprehensive security hardening measures for K3s clusters, incorporating modern security practices and CIS benchmark controls.

## Version Compatibility Matrix
| Rancher Version | CIS Benchmark | Kubernetes | Notes |
|-----------------|---------------|------------|--------|
| Rancher v2.7    | v1.23         | K8s v1.23  | Legacy Support |
| Rancher v2.7    | v1.24         | K8s v1.24  | Extended Support |
| Rancher v2.7    | v1.7          | K8s v1.25-1.26 | Current Standard |
| Rancher v2.8+   | v1.8          | K8s v1.27+ | Modern Features |

## 1. Host-Level Security

### 1.1 System Hardening
```bash
# Create dedicated system user
sudo useradd -r -s /sbin/nologin k3s-user

# Set restrictive directory permissions
sudo mkdir -p /etc/k3s
sudo chown -R k3s-user:k3s-user /etc/k3s
sudo chmod 700 /etc/k3s

# Configure kernel parameters
cat << EOF | sudo tee /etc/sysctl.d/90-kubelet.conf
vm.panic_on_oom=0
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
kernel.keys.root_maxkeys=1000000
kernel.keys.root_maxbytes=25000000
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv6.conf.all.forwarding=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF

sudo sysctl --system
```

### 1.2 Security Modules
```bash
# Enable and configure AppArmor
sudo systemctl enable apparmor
sudo systemctl start apparmor

# Configure SELinux (if used instead of AppArmor)
sudo setenforce 1
sudo sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
```

## 2. Kubernetes Security Configuration

### 2.1 Enhanced Pod Security Standards
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "restricted"
      enforce-version: "latest"
      audit: "restricted"
      audit-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces: [kube-system]
```

### 2.2 Modern Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### 2.3 Enhanced API Server Security
```yaml
spec:
  rkeConfig:
    machineGlobalConfig:
      kube-apiserver-arg:
        # Authentication and Authorization
        - authentication-token-webhook-config-file=/etc/k3s/webhook-config.yaml
        - authorization-mode=Node,RBAC
        - enable-admission-plugins=NodeRestriction,PodSecurityPolicy,ServiceAccount,AlwaysPullImages
        
        # Audit Configuration
        - audit-policy-file=/var/lib/rancher/k3s/server/audit.yaml
        - audit-log-path=/var/lib/rancher/k3s/server/logs/audit.log
        - audit-log-maxage=30
        - audit-log-maxbackup=10
        - audit-log-maxsize=100
        
        # Security Settings
        - encryption-provider-config=/etc/k3s/encryption-config.yaml
        - tls-min-version=VersionTLS12
        - tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        - secure-port=6443
        - profiling=false
```

## 3. Runtime Security

### 3.1 Container Security Context
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: secure-container
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      readOnlyRootFilesystem: true
```

### 3.2 Resource Limits
```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
spec:
  limits:
  - default:
      cpu: 500m
      memory: 512Mi
    defaultRequest:
      cpu: 200m
      memory: 256Mi
    type: Container
```

## 4. Monitoring and Logging

### 4.1 Enhanced Audit Policy
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: RequestResponse
  resources:
  - group: "authentication.k8s.io"
    resources: ["*"]
- level: Request
  resources:
  - group: ""
    resources: ["pods"]
  namespaces: ["kube-system"]
```

### 4.2 Prometheus Monitoring
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: k3s-monitoring
spec:
  endpoints:
  - interval: 30s
    port: metrics
  selector:
    matchLabels:
      k8s-app: k3s
```

## 5. Encryption Configuration

### 5.1 Secrets Encryption
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base64-encoded-key>
    - identity: {}
```

## Best Practices and Recommendations

1. **Regular Updates**
   - Keep K3s and all components up to date
   - Subscribe to security advisories
   - Implement automated update policies

2. **Access Control**
   - Implement RBAC strictly
   - Use service accounts with minimal permissions
   - Regular audit of access permissions

3. **Network Security**
   - Use private networks for cluster communication
   - Implement mutual TLS (mTLS)
   - Regular network policy reviews

4. **Monitoring**
   - Implement comprehensive logging
   - Use security scanning tools
   - Regular security audits

5. **Backup and Recovery**
   - Regular encrypted backups
   - Tested disaster recovery plan
   - Documented recovery procedures

## Important Notes
- Test all configurations in a non-production environment
- Regular security assessments
- Keep documentation updated
- Monitor security mailing lists and updates
- Implement change management procedures

## References
- CIS Kubernetes Benchmark
- NIST Kubernetes Security Guide
- Kubernetes Security Best Practices
- K3s Official Documentation
