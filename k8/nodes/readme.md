# Multiplatform (`amd64` and `arm`) Kubernetes cluster setup
#

# https://gist.githubusercontent.com/squidpickles/dda268d9a444c600418da5e1641239af/raw/38450f734d4d9f6a4c5f6b2690b7f5fe349771ae/README.md

##
##

The [official guide](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/) for setting up Kubernetes using `kubeadm` works well for clusters of one architecture. But, the main problem that crops up is the `kube-proxy` image defaults to the architecture of the master node (where `kubeadm` was run in the first place).

This causes issues when `arm` nodes join the cluster, as they will try to execute the `amd64` version of `kube-proxy`, and will fail.

It turns out that the pod running `kube-proxy` is configured using a [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/). With a small edit to the configuration, it's possible to create multiple DaemonSets—one for each architecture.

## Steps
Follow the instructions at https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/ for setting up the master node. I've been using [Weave Net](https://www.weave.works/oss/net/) as the network plugin; it seems to work well across architectures, and was easy to set up. Just be careful that you pass through an `IPALLOC_RANGE` to the Weave configuration that matches your `--pod-network-cidr`, if you used that in your `kubeadm init`. *Stop once you have the network plugin installed, before you add any nodes.*

My workflow looks like:
```bash
sudo kubeadm init --pod-network-cidr 10.244.0.0/16
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')&env.IPALLOC_RANGE=10.244.0.0/16"
```
Now, edit the `kube-proxy` DaemonSet by running
```bash
kubectl edit daemonset kube-proxy --namespace=kube-system
```
I made the following change:
```diff
--- daemonset-orig.yaml	2018-01-27 00:16:15.319098008 -0800
+++ daemonset-amd64.yaml	2018-01-27 00:15:37.839511917 -0800
@@ -47,6 +47,8 @@
           readOnly: true
       dnsPolicy: ClusterFirst
       hostNetwork: true
+      nodeSelector:
+        kubernetes.io/arch: amd64
       restartPolicy: Always
       schedulerName: default-scheduler
       securityContext: {}
```
You'll need to add the following to the configuration under `spec: template: spec:`
```yaml
nodeSelector:
    kubernetes.io/arch: amd64
```
While you're still in the editor, copy the configuration file somewhere you can find it, and name it `daemonset-arm.yaml`; you'll be creating another one for `arm` nodes. Save and exit, and your changes will be applied.

You'll need to remove some of the metadata fields from the file. The main thing to note is the changes to the `name` (in `metadata`), the container `image`, and the `nodeSelector`:
```diff
--- daemonset-amd64.yaml	2018-01-27 00:15:37.839511917 -0800
+++ daemonset-arm.yaml	2018-01-26 23:50:31.484332549 -0800
@@ -1,19 +1,10 @@
 apiVersion: extensions/v1beta1
 kind: DaemonSet
 metadata:
-  creationTimestamp: 2018-01-27T07:27:28Z
-  generation: 2
   labels:
     k8s-app: kube-proxy
-  name: kube-proxy
+  name: kube-proxy-arm
   namespace: kube-system
-  resourceVersion: "1662"
-  selfLink: /apis/extensions/v1beta1/namespaces/kube-system/daemonsets/kube-proxy
-  uid: 8769e0b3-0333-11e8-8cb9-40a8f02df8cb
 spec:
   revisionHistoryLimit: 10
   selector:
@@ -29,7 +20,7 @@
       - command:
         - /usr/local/bin/kube-proxy
         - --config=/var/lib/kube-proxy/config.conf
-        image: gcr.io/google_containers/kube-proxy-amd64:v1.18.8
+        image: gcr.io/google_containers/kube-proxy-arm:v1.18.8
         imagePullPolicy: IfNotPresent
         name: kube-proxy
         resources: {}
@@ -48,7 +39,7 @@
       dnsPolicy: ClusterFirst
       hostNetwork: true
       nodeSelector:
-        kubernetes.io/arch: amd64
+        kubernetes.io/arch: arm
       restartPolicy: Always
       schedulerName: default-scheduler
       securityContext: {}
@@ -79,11 +70,3 @@
     rollingUpdate:
       maxUnavailable: 1
     type: RollingUpdate
-status:
-  currentNumberScheduled: 1
-  desiredNumberScheduled: 1
-  numberAvailable: 1
-  numberMisscheduled: 0
-  numberReady: 1
-  observedGeneration: 2
-  updatedNumberScheduled: 1
```
Now, you can create the new DaemonSet by running
```bash
kubectl create -f daemonset-arm.yaml
```
Finally, bring up the other nodes by running the `kubeadm join ...` command printed out during the initialization phase.

You should soon see everything up and running (I have an `amd64` master and 3 `arm` nodes in this example):
```
NAMESPACE     NAME                              READY     STATUS    RESTARTS   AGE
kube-system   etcd-master                       1/1       Running   0          54m
kube-system   kube-apiserver-master             1/1       Running   0          54m
kube-system   kube-controller-manager-master    1/1       Running   0          54m
kube-system   kube-dns-6f4fd4bdf-n7tgn          3/3       Running   0          55m
kube-system   kube-proxy-arm-8nggz              1/1       Running   0          31m
kube-system   kube-proxy-arm-9vxn8              1/1       Running   0          31m
kube-system   kube-proxy-arm-h48nx              1/1       Running   0          31m
kube-system   kube-proxy-arm-hvdxw              1/1       Running   0          31m
kube-system   kube-proxy-dw5nw                  1/1       Running   0          36m
kube-system   kube-scheduler-master             1/1       Running   0          54m
kube-system   weave-net-frjln                   2/2       Running   3          31m
kube-system   weave-net-qgw9s                   2/2       Running   0          53m
kube-system   weave-net-vmj5p                   2/2       Running   3          31m
kube-system   weave-net-xg766                   2/2       Running   3          31m
kube-system   weave-net-xh54m                   2/2       Running   3          31m
```
Success!

##
##

##
#
https://carlosedp.medium.com/building-a-hybrid-x86-64-and-arm-kubernetes-cluster-e7f94ff6e51d
#
##

Building a hybrid x86–64 and ARM Kubernetes Cluster
Since my last article where I built an ARM Kubernetes cluster composed of Rock64 boards, I got some new ARM SBCs with powerful RK3399 CPU's and also an Intel SBC called LattePanda Alpha that boosts a nice Intel CPU and 8GB memory.

With these boards in hand and my previous cluster in need of an update, I decided to build a new cluster with the latest Kubernetes version (1.13.1 at the time) also using latest metrics, monitoring and logging stacks.

This multi-architecture cluster demonstrates that it is possible to have a more powerful layer as the Master Nodes using AMD64 servers and smaller, cheaper and more power-saving SBCs as nodes. Some use-cases are Edge clusters or IOT applications. Also the cluster supports AMD64 nodes as well as any mix of architectures.

Overview
Hardware
For this cluster, I will use the LattePanda Alpha SBC as the Master Node and NFS Server. The LattePanda has a nice Intel Core m3–7y30 dual-core CPU (the same used on the 12-inch Macbook), 8GB of RAM and 32GB of internal eMMC storage. On this deployment, I’m using a 128GB NVMe SSD from Kingspec as the Master Node storage. It works perfectly and have an amazing performance. Also I have a 1TB SSD connected to the Master Node via USB3.0 where I provide the persistent storage using NFS.


The nodes will be two ARM64 SBCs, the FriendlyArm NanoPC-T4 and a Pine64 RockPro64. These boards have a Rockchip RK3399 hexa-core CPU, 4GB of memory,16GB internal eMMC storage and 1Gbps Ethernet. for the RockPro64 I have plans to use it as a NAS and Docker container host in the future.

All three are are fantastic SBCs with all features required to run as headless servers like this cluster or as a Linux Desktop environment with Wi-Fi connectivity. The NanoPC boards also support NVMe M.2 drives although support depends on Kernel and distribution used.


On the RockPro64, using it as a NAS would be a very good option since it has a PCI-E slot where and I got the two-port SATA card. I plan on adding a four or six port card once I build the NAS.


Pine64 RockPro64
All boards run Debian where in the LattePanda I’m using the default Debian distribution for AMD64 and on the ARM boards I’m using DietPi that is a lean Debian distribution for SBCs.


I might build a case to assemble the SBCs properly soon
Software
The building of a hybrid architecture cluster required some improvements from the main Kubernetes distribution provided since version 1.12. Kubernetes had AMD64 and ARM64 images for a while but to be able to transparently create the hybrid cluster, it required that Docker Manifests were pushed to the repositories where the main image tag pointed to the tagged architecture images. You can check if the image supports this using:

$ docker run --rm mplatform/mquery gcr.io/google-containers/kube-apiserver:v1.13.1
Image: gcr.io/google-containers/kube-apiserver:v1.13.1
* Manifest List: Yes
* Supported platforms:
- linux/amd64
- linux/arm
- linux/arm64
- linux/ppc64le
- linux/s390x
Kubernetes already have this in place for the main images (api-server, scheduler, controller, pause) but lacks for other images like the Dashboard, metrics-server and a few others. In some cases to overcome this I pulled the images from their main repositories, pushed into my DockerHub and created multi-arch the manifests to point to the correct architecture image. In some cases, I patched the Kubernetes deployment forcing that Pod to land on an ARM64 node (in case of the Dashboard for example).

Preparing the nodes
To be able to install Kubernetes, a few pre-requisites are needed for each node. To automate it, I made an Ansible playbook that does most of the job very quickly with no hassle. I also describe the tasks to be done manually below.

Ansible is a fantastic tool to automate configuration for any number of hosts. You create a file (or multiple files) called Playbooks. They are composed of Tasks that call Ansible Modules to provide the needed configuration. Ansible have tons of modules able to automate most tasks. Also it only needs ssh access to the hosts, no agents!

The Ansible playbook does additional tasks (in comparison to the manual instructions below) for installing utilities, adding a new user with Sudo, fix permission, disabling IPv6 and etc. Check the playbook for more info, it’s pretty straightforward.

To run, it’s just a matter of:

1. Install Ansible on the host you will use to fire the configuration playbook (could be the Master Node)

sudo apt update && sudo apt install ansible

2. Create an inventory file providing your hosts IPs and root password

[all:vars]
ansible_connection=ssh
ansible_ssh_user=root
ansible_ssh_pass=rootpassword
[nodes]
192.168.1.10
192.168.1.11
192.168.1.12
3. Grab the main.yaml playbook from GIST and save into the same dir of the inventory

4. Run the playbook

ansible-playbook -i inventory main.yml

Step-by-step manual setup
Install pre-reqs

sudo apt-get update
# Install SBC utility packages
sudo apt install -y nfs-common less vim ack git build-essential iptables ipset pciutils lshw file iperf3 net-tools lsb-release
# Fix ping permission
sudo chmod +s /bin/ping*
# Install Docker pre-requisites
sudo apt-get install \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg2 \
  software-properties-common
Install Docker

curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
echo “deb [arch=arm64] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable” | \
  sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install docker-ce=18.06.1~ce~3–0~debian
Verify the MAC address and product_uuid are unique for every node (this is important on SBCs)

# Check if the interface MAC addresses does not conflict between boards
ip link
# Check if the board UUID and Machine-Id does not conflict between boards
sudo cat /sys/class/dmi/id/product_uuid
sudo cat /etc/machine-id
Install Kubernetes packages

apt-get update && apt-get install -y apt-transport-https curl
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
deb https://apt.kubernetes.io/ kubernetes-xenial main
EOF
apt-get update
apt-get install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl
Creating the Cluster
Kubernetes is installed with the fantastic kubeadm tool. It configures the Master Node and provides the requirements for the other nodes to join the cluster.

Here is the steps to install (in the Master Node):

Pre-pull Kubernetes Images

sudo kubeadm config images pull

Create the cluster

sudo kubeadm init

After install, kubeadm will generate a command to be ran on the other nodes so they will join the cluster. The keys have 24h validity so in case you need to add nodes in the future, re-generate the keys with the command kubeadm token create --print-join-command in the Master Node and grab the command to be ran on the new nodes.

Run the kubeadm join command on additional nodes

Use the command generated in the Master Node and run on all nodes to be added:

kubeadm join --token secret.verysecrettokk8s 192.168.1.50:6443 --discovery-token-ca-cert-hash sha256:a57508843e3a356303d87972288571064cbf215f4fba5cb502f9d8370ef5c354
Copy the authentication files to the user dir

To be able to use the cluster via kubectl, copy the authentication files to the current user:

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
Install Weave Net overlay network

In this new cluster I will also use Weave Net. Weave provides lots of functionality, good performance and already have multi-arch images with correct tags and manifests.

kubectl apply -f “https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d ‘\n’)&env.NO_MASQ_LOCAL=1”
# Download the Weave Net tool to troubleshoot in case needed
sudo curl -L git.io/weave -o /usr/local/bin/weave
sudo chmod a+x /usr/local/bin/weave
The NO_MASQ_LOCAL environment variable allows the real client IP to be passed on to the services and pods that have the service.spec.externalTrafficPolicy=Local annotation.

Enable pod scheduling on Master

If you want to be able to run Pods also in the Master Node, taint the label so it can be schedulable.

kubectl taint nodes --all node-role.kubernetes.io/master-
Enable feature gate for TTL

To allow Jobs to use the TTL feature, edit all manifests using sudo in the Master Node from /etc/kubernetes/manifests and add the flag — --feature-gates=TTLAfterFinished=true below to the start end of the command section:

...
spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC
...
- --feature-gates=TTLAfterFinished=true
...
After this, wait 5 minutes for the Master pods to restart.

Cluster Status

To check the cluster status and if the nodes have joined successfully, use the command kubectl get nodes.

NAME STATUS ROLES AGE VERSION LABELS
k8s-armnode1 Ready <none> 4m18s v1.13.1 beta.kubernetes.io/arch=arm64,beta.kubernetes.io/os=linux,kubernetes.io/hostname=k8s-armnode1
k8s-armnode2 Ready <none> 4m8s v1.13.1 beta.kubernetes.io/arch=arm64,beta.kubernetes.io/os=linux,kubernetes.io/hostname=k8s-armnode2
k8s-master Ready master 10m v1.13.1 beta.kubernetes.io/arch=amd64,beta.kubernetes.io/os=linux,kubernetes.io/hostname=k8s-master,node-role.kubernetes.io/master=
Here you can see that the Master Node have the amd64 label and the two other nodes have the arm64 label. Multi-arch cluster success!

Additional Cluster Tools
The stack I used on the new cluster is similar to the first one. My repository on Github has been updated to provide all manifests and support files for this new version.

MetalLB

As MetalLB provides great Load Balancer functionality for the cluster, I will use it like in the previous cluster.

kubectl apply -f https://raw.githubusercontent.com/google/metallb/v0.7.3/manifests/metallb.yaml
kubectl apply -f ./1-MetalLB/metallb-conf.yaml
Traefik

Traefik will also be used as the Ingress Controller for the cluster. To deploy, use the manifests from the 2-Traefik dir. The domain names can be configured in the manifests.

cd 2-Traefik/
./deploy
There is also an external directory to deploy an external Ingress controller able to dynamically generate SSL certificates from LetsEncrypt. Check this article where I detail the architecture and deployment.

NFS Server

As the Master Node serves also as the NFS server for persistent storage, the process of configuring it is:

# Run all on the Master Node
sudo apt-get install nfs-kernel-server nfs-common
sudo systemctl enable nfs-kernel-server
sudo systemctl start nfs-kernel-server
sudo cat >> /etc/exports <<EOF
/data/kubernetes-storage/ 192.168.1.*(rw,sync,no_subtree_check,no_root_squash)
EOF
sudo exportfs -a
NFS Storageclass

In the 3-NFS_Storage dir are the manifests to deploy a NFS controller to provide dynamic Persistent Volumes. You may need to adjust the IP addresses and the mounts of your NFS config.

cd 3-NFS_Storage
kubectl apply -f *
Dashboard

The Kubernetes Dashboard is also deployed but it’s resource metrics and graphs still depend on Heapster that have been discontinued. There is an ongoing work to port it to metrics-server tracked on this issue and is scheduled for the next version. For now I use it without Heapster and InfluxDB.

cd 4-Dashboard
kubectl apply -f dashboard-admin-account.yaml
kubectl apply -f dashboard.yaml
kubectl apply -f dashboard-ingress.yaml
Dashboard have a problem where the Docker images don’t have a manifest for multi-architecture. In this case, I deployed the ARM64 image and added a tag via the patch command to force it to be scheduled on an ARM node.

You can use this technique to force determined pods to be ran only on certain nodes. It’s a matter of replacing the tag and the deployment. You can also add labels and tags to your taste.

kubectl patch deployment kubernetes-dashboard -n kube-system — patch ‘{“spec”: {“template”: {“spec”: {“nodeSelector”: {“beta.kubernetes.io/arch”: “arm64”}}}}}’
Metrics-server

Metrics-server is the replacement for Heapster on internal metrics. It provides the resource consumption for the nodes and pods to internal Kubernetes utilities like kubectl, Horizontal Pod Autoscaler and soon the Dashboard.

cd 5-Metrics-server
kubectl apply -f *
Installing metrics-server allows kubectl to display some metrics in the command line:

$ kubectl top nodes
NAME         CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
k8s-master   1152m        19%    1311Mi          35%
k8s-node1    292m         4%     689Mi           18%
$ kubectl top pods
NAME                                          CPU(cores)   MEMORY(bytes)
coredns-86c58d9df4-tk7g9                      14m          11Mi
coredns-86c58d9df4-vp942                      16m          11Mi
etcd-k8s-master                               130m         132Mi
kube-apiserver-k8s-master                     207m         423Mi
kube-controller-manager-k8s-master            170m         61Mi
kube-proxy-6xbsp                              23m          20Mi
kube-proxy-7zxth                              27m          15Mi

