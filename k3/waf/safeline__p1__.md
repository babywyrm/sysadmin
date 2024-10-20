
##
#
https://dev.to/carrie_luo1/deploying-high-availability-safeline-waf-on-k3spart-1-3iab
#
https://systemweakness.com/deploying-high-availability-safeline-waf-on-k3s-part-2-fb366aee20eb
#
##

Deploying High Availability SafeLine WAF on K3s(Part 1)
#
cybersecurity
#
opensource
#
k3s
Chaitin Tech’s SafeLine open-source WAF (Web Application Firewall) is a simple, powerful, and user-friendly free WAF.

Image description

Based on industry-leading semantic detection technology, it acts as a reverse proxy to protect your website from hacker attacks.

At the time of writing, the official open-source version and the professional edition do not support HA (High Availability) and cluster mode deployment.

Due to the necessity of deploying in a production environment, the architecture must at least support HA. Since the official version does not support it, I found a deployment solution in the community using HelmChart in a K8S cluster.

After a month of testing and deploying the open-source version, the final solution was to deploy using HelmChart on a k3s cluster, using the official images without any modifications.

However, SafeLine WAF running in the k3s cluster can only have one POD replica. Multiple replicas can cause some functionality issues, such as the control panel homepage not showing access count changes, normal business forwarding but failing to detect and block intrusion behaviors.

Currently, this document only enables the WAF service to run on multiple nodes in a k3s cluster. If a node fails, the services on that node will automatically switch to other nodes, but it does not achieve multi-POD replica load balancing.

SafeLine WAF Official Website: https://waf.chaitin.com/
SafeLine WAF Official GitHub: https://github.com/chaitin/SafeLine
Third-Party HelmChart Repository: https://github.com/jangrui/charts
Third-Party HelmChart Source Repository: https://github.com/jangrui/SafeLine
Personal Tencent Coding HelmChart Repository: https://g-otkk6267-helm.pkg.coding.net/Charts/safeline
Preparation Before Deployment
Prepare three servers with 4C8G configurations;
for production environments, it is recommended to use 8C16G or higher.
The operating system is Ubuntu 22.04, and these servers will form the k3s cluster on which SafeLine WAF will be deployed. The configuration information is as follows:

Hostname	IP Address	Role
```
waf-lan-k3s-master	192.168.1.9	k3s master node
waf-lan-k3s-node1	192.168.1.7	k3s node1
waf-lan-k3s-node2	192.168.1.8	k3s node2
```
Deploying k3s Cluster
Deploying the k3s Master Node

Deploy the master node service using a script.
Install k3s version corresponding to k8s-1.28.8, disabling the built-in Traefik gateway and local-storage.

curl -sfL https://rancher-mirror.rancher.cn/k3s/k3s-install.sh | INSTALL_K3S_MIRROR=cn INSTALL_K3S_VERSION=v1.28.8+k3s1 sh -s - --disable traefik --disable local-storage
Check cluster information:

kubectl get nodes -owide
kubectl get pod -A
Refer to the official documentation for deployment:

Quick Start
Configuration
For upgradeable k3s versions, check: k3s Release Channels
After installation, the following utilities are available: kubectl, crictl, ctr, k3s-killall.sh, and k3s-uninstall.sh.

Adjusting the Cluster kubeconfig File

The default kubeconfig file path for k3s is:

ls -l /etc/rancher/k3s/k3s.yaml
Fix the absence of /root/.kube/config file:

echo "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml" >> /etc/profile
source /etc/profile
mkdir -p /root/.kube/
ln -sf /etc/rancher/k3s/k3s.yaml /root/.kube/config
cat /root/.kube/config
Taint the Master Node to Make it Unschedulable

kubectl taint nodes waf-lan-k3s-master node-role.kubernetes.io/control-plane:NoSchedule
kubectl describe nodes waf-lan-k3s-master | grep Taints
Output:

Taints:             node-role.kubernetes.io/control-plane:NoSchedule
Configuring Private Registry Information in k3s Cluster

The default containerd configuration for docker images in k3s lacks private registry addresses. Add the custom private registry information in /etc/rancher/k3s/registries.yaml on the master node.

Example registries.yaml (Note: the passwords in this file are not real):
```
mirrors:
  "docker.io":
    endpoint:
    - "http://192.168.1.138:5000"
    - "https://tshf4sa5.mirror.aliyuncs.com"
  "harbor.scmttec.com":
    endpoint:
    - "https://harbor.scmttec.com"
configs:
  "harbor.scmttec.com":
  auth:
    username: "robot$pull_image"
    password: "b9RCmoH5vN5ZA0"
  tls:
    insecure_skip_verify: false
```

After saving the file, restart the k3s service to apply the configuration:

systemctl restart k3s
Installing Helm Tool
Download and install the Helm tool from the official website.
```
Download page: https://github.com/helm/helm/releases
Download link: https://get.helm.sh/helm-v3.12.0-linux-amd64.tar.gz
wget https://get.helm.sh/helm-v3.12.0-linux-amd64.tar.gz
tar zxf helm-v3.12.0-linux-amd64.tar.gz
cp ./linux-amd64/helm /usr/local/bin/
rm -rf ./linux-amd64/    # Remove the extracted directory
Configuring Auto-completion for Helm and Kubectl Commands
echo "source <(kubectl completion bash)" >> /etc/profile  # Add kubectl command auto-completion
echo "source <(helm completion bash)" >> /etc/profile    # Add helm command auto-completion
source /etc/profile     # Apply changes immediately
Checking if Helm Commands are Working
helm list -n kube-system
```
Expected output:
```
NAME            NAMESPACE       REVISION        UPDATED                                 STATUS          CHART                           APP VERSION
traefik         kube-system     1               2023-05-29 06:39:26.751316258 +0000 UTC deployed        traefik-21.2.1+up21.2.0         v2.9.10
traefik-crd     kube-system     1               2023-05-29 06:39:22.816811082 +0000 UTC deployed        traefik-crd-21.2.1+up21.2.0     v2.9.10
```

Deploying k3s Node Services
Retrieve the Token from the k3s Master Node

Before deploying the k3s-node services, which are the k3s-agent services, you need to retrieve the token file from the k3s-server service. The token file is located at /var/lib/rancher/k3s/server/token on the master node. Execute the following command on the master node to get the token value:

cat /var/lib/rancher/k3s/server/token
Expected output:

K10f890abb83ce8cdf8b5dbeff8edb628d10cc53c23fa9f56152db0cf22454546bf::server:fec37548170a2affec1e3ebd1fdf708d
Install k3s-Agent Services Using the Official Script

The k3s official script for installing the k3s-agent services can be run via curl, specifying the master node's IP address and the token value during installation. Execute the following command on the two node servers:

curl -sfL https://rancher-mirror.rancher.cn/k3s/k3s-install.sh | INSTALL_K3S_MIRROR=cn INSTALL_K3S_VERSION=v1.28.8+k3s1 K3S_URL=https://192.168.1.9:6443 K3S_TOKEN=K10f890abb83ce8cdf8b5dbeff8edb628d10cc53c23fa9f56152db0cf22454546bf::server:fec37548170a2affec1e3ebd1fdf708d sh -
After executing, check the status of the new nodes on the master node:

kubectl get nodes -owide
Expected output:

NAME                 STATUS   ROLES                  AGE   VERSION        INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION      CONTAINER-RUNTIME
waf-lan-k3s-master   Ready    control-plane,master   17d   v1.28.8+k3s1   192.168.1.9   <none>        Ubuntu 22.04.1 LTS   5.15.0-69-generic   containerd://1.7.11-k3s2
waf-lan-k3s-node2    Ready    <none>                 17d   v1.28.8+k3s1   192.168.1.8   <none>        Ubuntu 22.04.1 LTS   5.15.0-69-generic   containerd://1.7.11-k3s2
waf-lan-k3s-node1    Ready    <none>                 17d   v1.28.8+k3s1   192.168.1.7   <none>        Ubuntu 22.04.1 LTS   5.15.0-69-generic   containerd://1.7.11-k3s2
So far, the basic services of the k3s cluster have been successfully deployed!

To be continued...
