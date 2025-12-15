# 🚀 K3s + Helm Install & Bootstrap Guide, Mini 

This repo may or may not contain **quick bootstrap scripts** for installing **K3s**, **Helm**, and optional components like **NATS** and **Rancher**.

Designed for:
- CTF labs
- Homelabs
- Single‑node Kubernetes setups
- Lightweight cloud VMs

---

## 📦 Option 1: Install K3s (Official Script)

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

### Verify

```bash
kubectl get nodes
kubectl get pods -n kube-system
```

---

## 📦 Option 2: Install K3s using k3sup (Recommended)

`k3sup` installs K3s over SSH and automatically configures your kubeconfig.

### Install k3sup

```bash
curl -sLS https://get.k3sup.dev | sh
sudo install k3sup /usr/local/bin/
```

### Install K3s on local machine

```bash
k3sup install --local
```

### Install K3s on a remote server

```bash
k3sup install \
  --ip <SERVER_IP> \
  --user <SSH_USER> \
  --ssh-key ~/.ssh/id_rsa
```

✅ kubeconfig will be written to `~/.kube/config` automatically

Verify:

```bash
kubectl get nodes
```

---

## 📦 Storage Class (Local Path)

K3s usually installs this automatically.

Verify:

```bash
kubectl get storageclass
```

If missing:

```bash
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
```

---

## 📦 Install Helm

```bash
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

Verify:

```bash
helm version
helm repo update
```

---

## 📦 Example: Install NATS with Helm

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

Check:

```bash
helm list -n demo
kubectl get svc -n demo
```

Port‑forward:

```bash
kubectl port-forward svc/nats 4222 -n demo
```

Delete:

```bash
helm uninstall nats -n demo
```

---

## 🔥 Firewall Fix (UFW + K3s DNS)

```bash
sudo ufw allow in on cni0 from 10.42.0.0/16 comment "K3s pod network"
```

---

# ⚡ Quick Bootstrap Script (K3s + Rancher)

This script installs:
- K3s
- cert‑manager
- Rancher (via embedded Helm controller)

### 📜 `k3s_helm_install.sh`

```sh
#!/bin/sh
set -e

echo "Installing K3s"
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.19.5+k3s2" sh -

PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

echo "Downloading cert-manager CRDs"
wget -q -P /var/lib/rancher/k3s/server/manifests/ \
  https://github.com/jetstack/cert-manager/releases/download/v0.15.0/cert-manager.crds.yaml

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
  labels:
    certmanager.k8s.io/disable-validation: "true"
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
  version: v0.15.0
  helmVersion: v3
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: rancher
  namespace: kube-system
spec:
  targetNamespace: cattle-system
  repo: https://releases.rancher.com/server-charts/latest/
  chart: rancher
  set:
    hostname: $PUBLIC_IP.xip.io
    replicas: 1
  helmVersion: v3
EOF

echo "✅ Rancher will be available shortly"
echo "🌐 https://$PUBLIC_IP.xip.io"
```

Make executable:

```bash
chmod +x k3s_helm_install.sh
./k3s_helm_install.sh
```

---

## ✅ Verify Rancher

```bash
kubectl get pods -n cattle-system
kubectl get pods -n cert-manager
```

---

## 📚 References

- K3s: https://k3s.io
- k3sup: https://github.com/alexellis/k3sup
- Helm: https://helm.sh
- Rancher: https://rancher.com

##
##

##
#
https://gist.githubusercontent.com/icebob/958b6aeb0703dc24f436ee8945f0794f/raw/6c1c1843c307a2e3d3c49bd41fff8af1ae98ad12/k3s_helm_install.sh
#
##

```
# Install K3S
curl -sfL https://get.k3s.io | sh -

# Copy k3s config
mkdir $HOME/.kube
sudo cp /etc/rancher/k3s/k3s.yaml $HOME/.kube/config
sudo chmod 644 $HOME/.kube/config

# Check K3S 
kubectl get pods -n kube-system

# Create Storage class
# kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
# kubectl get storageclass

# Download & install Helm
curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get > install-helm.sh
chmod u+x install-helm.sh
./install-helm.sh

# Link Helm with Tiller
kubectl -n kube-system create serviceaccount tiller
kubectl create clusterrolebinding tiller --clusterrole cluster-admin --serviceaccount=kube-system:tiller
helm init --service-account tiller

# Check Helm
helm repo update
helm search postgres

# Install NATS with Helm
# https://hub.helm.sh/charts/bitnami/nats
helm install --name nats --namespace demo \
	--set auth.enabled=true,auth.user=admin,auth.password=admin1234 \
	stable/nats
	
# Check
helm list
kubectl svc -n demo

# Create a port forward to NATS (blocking the terminal)
kubectl port-forward svc/nats-client 4222 -n demo

# Delete NATS
helm delete nats

# Working DNS with ufw  https://github.com/rancher/k3s/issues/24#issuecomment-515003702
# sudo ufw allow in on cni0 from 10.42.0.0/16 comment "K3s rule"


```
# Quick Bootstrap...


##
#
https://gist.github.com/dkeightley/77aa969adea4fa6163e174bf5d39146c
#
##

```
#!/bin/sh
echo "Installing K3S"
curl  -sfL https://get.k3s.io  | INSTALL_K3S_VERSION="v1.19.5+k3s2" sh -

PUBLIC_IP=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)

echo "Downlading cert-manager CRDs"
wget -q -P /var/lib/rancher/k3s/server/manifests/ https://github.com/jetstack/cert-manager/releases/download/v0.15.0/cert-manager.crds.yaml

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
  labels:
    certmanager.k8s.io/disable-validation: "true"
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
  version: v0.15.0
  helmVersion: v3
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: rancher
  namespace: kube-system
spec:
  targetNamespace: cattle-system
  repo: https://releases.rancher.com/server-charts/latest/
  chart: rancher
  set:
    hostname: $PUBLIC_IP.xip.io
    replicas: 1
  helmVersion: v3
EOF

echo "Rancher should be booted up in a few mins"

