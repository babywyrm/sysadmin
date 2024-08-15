
##
#
https://gist.githubusercontent.com/icebob/958b6aeb0703dc24f436ee8945f0794f/raw/6c1c1843c307a2e3d3c49bd41fff8af1ae98ad12/k3s_helm_install.sh
#
##

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

