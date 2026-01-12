# K3s + Helm Installation & Bootstrap Guide

Quick bootstrap scripts for installing K3s, Helm, and optional components like NATS and Rancher.

**Designed for:**
- CTF labs
- Homelabs
- Single-node Kubernetes setups
- Lightweight cloud VMs

---

## Option 1: Install K3s (Official Script)

```bash
curl -sfL https://get.k3s.io | sh -
```

### Configure kubectl

```bash
mkdir -p $HOME/.kube
sudo cp /etc/rancher/k3s/k3s.yaml $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
chmod 600 $HOME/.kube/config
```

### Verify Installation

```bash
kubectl get nodes
kubectl get pods -n kube-system
```

---

## Option 2: Install K3s using k3sup (Recommended)

k3sup installs K3s over SSH and automatically configures your kubeconfig.

### Install k3sup

```bash
curl -sLS https://get.k3sup.dev | sh
sudo install k3sup /usr/local/bin/
```

### Install K3s on Local Machine

```bash
k3sup install --local
```

### Install K3s on Remote Server

```bash
k3sup install \
  --ip <SERVER_IP> \
  --user <SSH_USER> \
  --ssh-key ~/.ssh/id_rsa
```

kubeconfig will be written to `~/.kube/config` automatically.

**Verify:**

```bash
kubectl get nodes
```

---

## Storage Class (Local Path)

K3s typically installs local-path-provisioner automatically.

**Verify:**

```bash
kubectl get storageclass
```

**If missing, install manually:**

```bash
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
```

---

## Install Helm

```bash
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

**Verify:**

```bash
helm version
helm repo update
```

---

## Example: Install NATS with Helm

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

helm install nats bitnami/nats \
  --namespace demo \
  --create-namespace \
  --set auth.enabled=true \
  --set auth.user=admin \
  --set auth.password=admin1234
```

**Check deployment:**

```bash
helm list -n demo
kubectl get svc -n demo
```

**Port-forward for local access:**

```bash
kubectl port-forward svc/nats 4222 -n demo
```

**Delete deployment:**

```bash
helm uninstall nats -n demo
```

---

## Firewall Configuration (UFW + K3s)

Allow K3s pod network traffic through UFW:

```bash
sudo ufw allow in on cni0 from 10.42.0.0/16 comment "K3s pod network"
```

---

## Quick Bootstrap Script (K3s + Rancher)

This script installs K3s, cert-manager, and Rancher via the embedded Helm controller.

**k3s_rancher_bootstrap.sh:**

```bash
#!/bin/sh
set -e

echo "Installing K3s..."
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.30.0+k3s1" sh -

PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

echo "Downloading cert-manager CRDs..."
wget -q -P /var/lib/rancher/k3s/server/manifests/ \
  https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.crds.yaml

cat > /var/lib/rancher/k3s/server/manifests/rancher.yaml << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: cattle-system
---
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: cert-manager
  namespace: kube-system
spec:
  targetNamespace: cert-manager
  repo: https://charts.jetstack.io
  chart: cert-manager
  version: v1.14.0
  helmVersion: v3
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: rancher
  namespace: kube-system
spec:
  targetNamespace: cattle-system
  repo: https://releases.rancher.com/server-charts/latest
  chart: rancher
  set:
    hostname: $PUBLIC_IP.sslip.io
    replicas: 1
    bootstrapPassword: "admin"
  helmVersion: v3
EOF

echo "Rancher will be available shortly at: https://$PUBLIC_IP.sslip.io"
```

**Make executable and run:**

```bash
chmod +x k3s_rancher_bootstrap.sh
./k3s_rancher_bootstrap.sh
```

**Verify Rancher deployment:**

```bash
kubectl get pods -n cattle-system
kubectl get pods -n cert-manager
```

---

## Updates and Maintenance

### Upgrade K3s

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.30.0+k3s1" sh -
```

Replace version string with desired release from [K3s releases](https://github.com/k3s-io/k3s/releases).

### Verify Upgrade

```bash
kubectl get nodes
k3s --version
```

### Upgrade Helm Charts

```bash
helm repo update
helm list -A
helm upgrade <release-name> <chart> -n <namespace>
```

### Backup K3s Configuration

```bash
sudo cp -r /var/lib/rancher/k3s /backup/k3s-$(date +%Y%m%d)
sudo cp /etc/rancher/k3s/k3s.yaml /backup/kubeconfig-$(date +%Y%m%d)
```

### Check for Available Updates

```bash
kubectl get nodes -o wide
kubectl version --short
```

---

## Security Basics

### Secure kubeconfig Permissions

```bash
chmod 600 $HOME/.kube/config
```

### Enable Pod Security Standards

Create a namespace with restricted pod security:

```bash
kubectl create namespace secure-ns
kubectl label namespace secure-ns pod-security.kubernetes.io/enforce=restricted
```

### Network Policies

Example deny-all network policy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

Apply:

```bash
kubectl apply -f network-policy.yaml
```

### Disable Anonymous Auth (if needed)

Edit `/etc/rancher/k3s/config.yaml`:

```yaml
kube-apiserver-arg:
- "anonymous-auth=false"
```

Restart K3s:

```bash
sudo systemctl restart k3s
```

### Regular Security Updates

```bash
sudo apt update && sudo apt upgrade -y
```

### Audit Logging

Enable audit logging in `/etc/rancher/k3s/config.yaml`:

```yaml
kube-apiserver-arg:
- "audit-log-path=/var/log/k3s-audit.log"
- "audit-log-maxage=30"
- "audit-log-maxbackup=10"
- "audit-log-maxsize=100"
```

### RBAC Best Practices

- Use least-privilege service accounts
- Avoid using default service accounts for workloads
- Review cluster role bindings regularly:

```bash
kubectl get clusterrolebindings
kubectl get rolebindings -A
```

### Secret Management

Use sealed secrets or external secret management:

```bash
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets sealed-secrets/sealed-secrets -n kube-system
```

### Monitor CVEs

Subscribe to K3s security advisories:
- https://github.com/k3s-io/k3s/security/advisories

---

## References

- K3s: https://k3s.io
- k3sup: https://github.com/alexellis/k3sup
- Helm: https://helm.sh
- Rancher: https://rancher.com
- K3s Security Hardening: https://docs.k3s.io/security/hardening-guide
