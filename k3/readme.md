
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

