

##
#
https://blog.stonegarden.dev/articles/2024/02/bootstrapping-k3s-with-cilium/
#
##


Bootstrapping K3s with Cilium


In this article we’ll explore how to bootstrap a more permanent, or production grade, Kubernetes cluster using k3s. Other tools like kubeadm, k0s, microk8s, or kubespray (which uses kubeadm under the hood) are also available.


#
This article is based on a fresh installation of Debian 12 Bookworm, specifically the network installation (netinst) image. 
The official generic cloud image might work better for you if you’re running a hypervisor.

Different Linux distro like Ubuntu, Rocky Linux, OpenSUSE, or Arch Linux should also work, but some steps might differ.

Enable sudo (optional)
#
Debian 12 netinst ships without sudo, so if you’re missing this you can install it by switching over to the root user
```
su -
and run

apt install sudo
usermod -aG sudo <user>
exit
```

This will install the sudo package and add your <user> to the sudo group, before exiting back to the regular user.

Enable ssh server (optional)
#
If you want to connect to the machine remotely you need a package like openssh-server. There’s an option to add this during the installation, but if you didn’t then run

sudo apt install openssh-server
Find the IP of the new machine by either running

hostname -I
or looking up the machine IP in your router. I recommend you set a static IP for the server in your router’s DHCP settings when you’re already there.

Back on our client machine we can copy the public key to the server by running

ssh-copy-id <user>@<ip>
We can now connect to the server without having to enter a password. Next we should harden the SSH-server. By editing the sshd_config on the remote machine
```
echo "PermitRootLogin no" | sudo tee /etc/ssh/sshd_config.d/01-disable-root-login.conf
echo "PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/02-disable-password-auth.conf
echo "ChallengeResponseAuthentication no" | sudo tee /etc/ssh/sshd_config.d/03-disable-challenge-response-auth.conf
echo "UsePAM no" | sudo tee /etc/ssh/sshd_config.d/04-disable-pam.conf
sudo systemctl reload ssh
```

we can disable root login and password authentication along with all types of “keyboard-interactive” authentication. In conjunction with disabling Pluggable Authentication Modules1 (PAM) this will only allow login using a private key.

For even tighter security you should check out fail2ban to block nefarious agents failing to access your machine.

Bootstrapping K3s
#
The only missing dependency for K3s is curl. Since Debian 12 ships without it, we need to first fetch that

sudo apt install curl
We’re now ready to install K3s on our machine. Following the quickstart guide it’s as easy as piping an unknown script directly to you shell!

curl -sfL https://get.k3s.io | sh -
… and a few seconds later you should have a working one-node Kubernetes “cluster.”

K3s comes equipped with everything you need to get started with Kubernetes, but it’s also very opinionated. In this article we’ll strip K3s down to more resemble upstream Kubernetes and replace the missing bits with Cilium.

Configuring K3s
#
If you already ran the above script you can start from scratch again by running

/usr/local/bin/k3s-uninstall.sh
To install a bare-bones K3s we disable some parts of the regular installation
```
curl -sfL https://get.k3s.io | sh -s - \
  --flannel-backend=none \
  --disable-kube-proxy \
  --disable servicelb \
  --disable-network-policy \
  --disable traefik \
  --cluster-init
  ```
  
This will disable the default Flannel Container Network Interface (CNI) as well as the kube-proxy. We’re also ditching the built-in Service Load Balancer and Network Policy Controller. The default Traefik Ingress Controller is also thrown out. Lastly we’re replacing the SQLite database with an embedded etcd instance for clustering.

If you prefer the above configuration can instead be supplied as a file

# /etc/rancher/k3s/config.yaml
flannel-backend: "none"
disable-kube-proxy: true
disable-network-policy: true
cluster-init: true
disable:
  - servicelb
  - traefik
The default location is /etc/rancher/k3s/config.yaml, but can be changed with the --config flag using an absolute path, e.g.

curl -sfL https://get.k3s.io | sh -s - --config=$HOME/config.yaml
This should make our k3s-cluster very similar to a vanilla Kubernetes installation through e.g. kubeadm, but without some extra drivers and extensions that ships with the upstream Kubernetes distribution that we probably don’t need.

Kube-config
#
K3s saves the kube-config file under /etc/rancher/k3s/k3s.yaml and installs a slightly modified version of kubectl that looks for the config-file at that location instead of the usual $HOME/.kube/config which other tools like Helm and Cilium CLI also use.

This discrepancy can easily be remedied by either changing the permissions of the k3s.yaml file2 and setting the KUBECONFIG environment variable to point at the K3s-location

sudo chmod 600 /etc/rancher/k3s/k3s.yaml
echo "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml" >> $HOME/.bashrc
source $HOME/.bashrc
As SquadraSec points out below, the k3s.yaml file should only be user readable, i.e. 600 and not 644 as I absentmindedly typed first.
or bby copying the k3s.yaml file to the default kube-config location, changing the owner of the copied file, and setting the KUBECONFIG env-variable to point at that file

mkdir -p $HOME/.kube
sudo cp -i /etc/rancher/k3s/k3s.yaml $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
echo "export KUBECONFIG=$HOME/.kube/config" >> $HOME/.bashrc
source $HOME/.bashrc
If you prefer, you can copy the kube-config-file to your local machine, just make sure to replace the IP in the server field with the node IP to avoid connection refused errors like

E0225 19:21:33.789450   62821 memcache.go:265] couldn't get current server API group list: Get "https://127.0.0.1:6443/api?timeout=32s": dial tcp 127.0.0.1:6443: connect: connection refused
The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?
Assuming everything went well you should be able to run

```
kubectl get pods --all-namespaces
to get the status of all pods in the cluster.

NAMESPACE     NAME                                      READY   STATUS              RESTARTS   AGE
kube-system   coredns-6799fbcd5-t5hrc                   0/1     ContainerCreating   0          4s
kube-system   local-path-provisioner-84db5d44d9-cgmds   0/1     ContainerCreating   0          4s
kube-system   metrics-server-67c658944b-58wbg           0/1     ContainerCreating   0          4s
```

The pods should be in either the ContainerCreating or Pending state since we haven’t installed a CNI yet, meaning the different components can’t properly communicate.

Helm (optional)
#
In the next part we’ll be installing Cilium using their own CLI which bundles parts of Helm. If you prefer you can instead use Helm directly. Follow the instructions on the Helm documentation for installation, or just pipe another script to bash (you always verify the contents of unknown scripts, right?)

curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
With helm in hand, add the Cilium Helm chart and update the Helm repo

helm repo add cilium https://helm.cilium.io/
helm repo update
Instead of cilium install you can run

helm install cilium cilium/cilium
and

helm upgrade cilium cilium/cilium
instead of cilium upgrade.

Installing Cilium
#
As the title suggest we’ll use Cilium to replace all the components we previously disabled. The easiest way to install Cilium is imho using the Cilium CLI. Another option is to use the Cilium Helm chart directly — as mentioned in the previous section, though I prefer the CLI-tool for the extra features like status and conectivity test.3

The latest version of Cilium CLI can be installed by running
```
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz

```
Next we need to find the Kubernetes API server address Cilium should use to talk to the control plane. 
When using only one control plane node this will be the same as the IP we found in the ssh-server section. If you plan on running multiple control plane nodes they should be load balanced using e.g. kube-vip or HAProxy.

Knowing the default API server port to be 6443 we install Cilium by running
```
API_SERVER_IP=<IP>
API_SERVER_PORT=<PORT>
cilium install \
  --set k8sServiceHost=${API_SERVER_IP} \
  --set k8sServicePort=${API_SERVER_PORT} \
  --set kubeProxyReplacement=true
```
Here we’re also explicitly setting Cilium in kube-proxy replacement mode for tighter integration.

As Marcel Schlegel mentions below, if you’re running with only one node you should also add --helm-set=operator.replicas=1 to the cilium install command, as the default value is 2 and the Cilium operator Deployment is set up with anti-affinity to spread to replicas across multiple nodes.
While the installation does its magic we can run

cilium status --wait
to wait for the dust to settle before displaying the Cilium status. Assuming everything went well you should be greeted with

    /¯¯\
 /¯¯\__/¯¯\    Cilium:             OK
 \__/¯¯\__/    Operator:           OK
 /¯¯\__/¯¯\    Envoy DaemonSet:    disabled (using embedded mode)
 \__/¯¯\__/    Hubble Relay:       disabled
    \__/       ClusterMesh:        disabled

Deployment             cilium-operator    Desired: 1, Ready: 1/1, Available: 1/1
DaemonSet              cilium             Desired: 1, Ready: 1/1, Available: 1/1
Containers:            cilium             Running: 1
                       cilium-operator    Running: 1
Cluster Pods:          0/3 managed by Cilium
Helm chart version:    1.15.0
Image versions         cilium             quay.io/cilium/cilium:v1.15.0@sha256:9cfd6a0a3a964780e73a11159f93cc363e616f7d9783608f62af6cfdf3759619: 1
                       cilium-operator    quay.io/cilium/operator-generic:v1.15.0@sha256:e26ecd316e742e4c8aa1e302ba8b577c2d37d114583d6c4cdd2b638493546a79: 1
Checking the status of all pods again

kubectl get po -A
should display them as Running 🏃 after a short while.

NAMESPACE     NAME                                      READY   STATUS    RESTARTS   AGE
kube-system   cilium-operator-6d4cdf7b55-sp9fx          1/1     Running   0          72s
kube-system   cilium-tskrg                              1/1     Running   0          72s
kube-system   coredns-6799fbcd5-t5hrc                   1/1     Running   0          2m54s
kube-system   local-path-provisioner-84db5d44d9-cgmds   1/1     Running   0          2m54s
kube-system   metrics-server-67c658944b-58wbg           1/1     Running   0          2m54s
Gratulerer! You’re now ready to start playing around with your Cilium powered K3s cluster.

Adding additional agents (optional)
#
With our one-node “cluster” up and running we can start adding worker nodes. The token to join a new node to the cluster can be found by running

sudo cat /var/lib/rancher/k3s/server/token
Take note of the token and recall the Kubernetes API server IP and port you previously used to configure Cilium. On the machine you want to serve as an agent run

K3S_TOKEN=<TOKEN>
API_SERVER_IP=<IP>
API_SERVER_PORT=<PORT>
curl -sfL https://get.k3s.io | sh -s - agent \
  --token "${K3S_TOKEN}" \
  --server "https://${API_SERVER_IP}:${API_SERVER_PORT}"
After a while the command should complete. Go back to either the control plane node or your client machine if you copied over the kube-config file and run

kubectl get nodes
If the new agent node connected successfully it should be shown as below

NAME       STATUS   ROLES                       AGE     VERSION
k3s-ag-0   Ready    <none>                      100s    v1.28.6+k3s2
k3s-cp-0   Ready    control-plane,etcd,master   6m32s   v1.28.6+k3s2
A new cilium-pod should also have started on the new agent node. To view all pods running on a given node you can run

NODE_NAME=<agentNodeName>
kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName="${NODE_NAME}"
which should show a single cilium pod running

NAMESPACE     NAME           READY   STATUS    RESTARTS   AGE     IP             NODE        NOMINATED NODE   READINESS GATES
kube-system   cilium-pntp9   1/1     Running   0          9m45s   192.168.1.66   k3s-agent   <none>           <none>
Now you have two nodes running K3s! Though if the control plane node goes down the agent nodes quickly stops working as well. For a more robust cluster you can add more control plane nodes.

Removing an agent node
#
Before removing an agent node you should drain it by running

kubectl drain <agentNodeName> --ignore-daemonsets --delete-local-data
This stops all running pods on the target node and schedule them to run on other nodes. Once all the pods have been rescheduled you can delete the node

kubectl delete node <agentNodeName>
Lastly you can run the k3s-agent-uninstall.sh-script to remove all traces of K3s.

/usr/local/bin/k3s-agent-uninstall.sh
Adding additional control plane nodes (optional)
#
If you’re aiming for a production environment cluster it’s recommended that you run at least three control plane nodes. That way you have redundancy in case one of the control plane nodes should fail. You should also have and external load balancer for the nodes, e.g. HAProxy as mentioned earlier. The K3s documentation is a great place to start on how to set up a Cluster Load Balancer.

The steps to adding additional control plane nodes is fairly similar to adding and agent, just make sure that the configuration matches on all control plane nodes.

Again fetch the join token from /var/lib/rancher/k3s/server/token and use either the IP and port of the first control plane node, or the load balancer IP if you’ve configured for high availability

K3S_TOKEN=<TOKEN>
API_SERVER_IP=<IP>
API_SERVER_PORT=<PORT>
curl -sfL https://get.k3s.io | sh -s - server \
  --token ${K3S_TOKEN} \
  --server "https://${API_SERVER_IP}:${API_SERVER_PORT}" \
  --flannel-backend=none \
  --disable-kube-proxy \
  --disable servicelb \
  --disable-network-policy \
  --disable traefik
Running

kubectl get nodes
should now display two nodes, both with the same roles

NAME        STATUS   ROLES                       AGE   VERSION
k3s-cp-0    Ready    control-plane,etcd,master   12m   v1.28.6+k3s2
k3s-cp-1    Ready    control-plane,etcd,master   11s   v1.28.6+k3s2
Note that it’s also possible to define dedicated etcd or control-plane nodes. For more details read the K3s documentation on Managing Server Roles.

Removing a control plane node
#
Removing a control plane node is similar to removing an agent node, simply drain it and delete it

kubectl drain <agentNodeName> --ignore-daemonsets --delete-local-data
kubectl delete node <agentNodeName>
The only difference is the uninstallation script k3s-uninstall.sh, instead of k3s-agent-uninstall.sh

/usr/local/bin/k3s-uninstall.sh
Configuring Cilium
#
Now that we’ve got our cluster up and running we can start configuring Cilium to properly replace all the parts we disabled earlier.

LB-IPAM
#
First we want to enable Load Balancer IP Address Management which will make Cilium able to allocate IPs to LoadBalancer Services.

To do this we first need to create a pool of IPs Cilium can hand out that works with our network. In my 192.168.1.1/24 network I want Cilium to only give out some of those IPs, I thus create the following CiliumLoadBalancerIPPool

1
2
3
4
5
6
7
8
9
# ip-pool.yaml
apiVersion: "cilium.io/v2alpha1"
kind: CiliumLoadBalancerIPPool
metadata:
  name: "first-pool"
spec:
  blocks:
    - start: "192.168.1.240"
      stop: "192.168.1.249"
Use your favourite text-editing tool to create a pool suitable for your needs. If the above pool also works for your network it can be applied by running

kubectl apply -f https://blog.stonegarden.dev/articles/2024/02/bootstrapping-k3s-with-cilium/resources/cilium/ip-pool.yaml
To check the status of all created IP-pools run

kubectl get ippools
This should display 10 available IPs and no conflicts if you created a similar IP pool as above

NAME         DISABLED   CONFLICTING   IPS AVAILABLE   AGE
first-pool   false      False         10              4s
Basic configuration
#
Next, recreate the same configuration we used to install Cilium in a values.yaml using your favourite text-editor

#values.yaml
k8sServiceHost: "<API_SERVER_IP>"
k8sServicePort: "<API_SERVER_PORT>"

kubeProxyReplacement: true
Running

cilium upgrade -f values.yaml
should result in no changes other than a revision update as we’ve already installed Cilium with the same configuration. You can double-check that everything works by running cilium status.

L2 announcements
#
Assuming the basic configuration still works we can enable L2 announcements to make Cilium respond to Address Resolution Protocol queries.

In the same values.yaml add

l2announcements:
  enabled: true

externalIPs:
  enabled: true
From experience we should also increase the client rate limit to avoid being request limited due to increased API usage with this feature enabled, to do this append

k8sClientRateLimit:
  qps: 50
  burst: 200
to the same values.yaml file.

To avoid having to manually restart the Cilium pods on config changes you can also append

operator:
  # replicas: 1  # Uncomment this if you only have one node
  rollOutPods: true

rollOutCiliumPods: true
If you’re running with only one node you also have to explicitly set operator.replicas: 1.
Next we create a CiliumL2AnnouncementPolicy to instruct Cilium how to do L2 announcements. A basic such policy is

1
2
3
4
5
6
7
8
9
# announce.yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumL2AnnouncementPolicy
metadata:
  name: default-l2-announcement-policy
  namespace: kube-system
spec:
  externalIPs: true
  loadBalancerIPs: true
This policy announces all IPs on all network interfaces. For more a more fine-grained announcement policy consult the Cilium documentation.

The above announcement policy can be applied by running.

kubectl apply -f https://blog.stonegarden.dev/articles/2024/02/bootstrapping-k3s-with-cilium/resources/cilium/announce.yaml
IngressController
#
We disabled the built-in Traefik IngressController earlier since Cilium can replace this functionality as well. Alternatively you can try out the new Gateway API which I’ve written about here.

Continue appending the values.yaml with the following to enable the Cilium IngressController

ingressController:
  enabled: true
  default: true
  loadbalancerMode: shared
  service:
    annotations:
      io.cilium/lb-ipam-ips: 192.168.1.240
Here we’ve enabled the IngressController-functionality of Cilium. To avoid having to explicitly set Spec.ingressClassName: cilium on each Ingress we also set it as the default IngressController. Next we chose to use a shared LoadBalancer Service for each Ingress.4 This means that you can route all requests to a single IP for reverse proxying. Lastly we annotate the shared IngressController LoadBalancer Service with an available IP from the pool we created earlier.

My full values.yaml-file now looks like

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
# values.yaml
k8sServiceHost: 192.168.1.74
k8sServicePort: 6443

kubeProxyReplacement: true

l2announcements:
  enabled: true

externalIPs:
  enabled: true

k8sClientRateLimit:
  qps: 50
  burst: 200

operator:
# replicas: 1  # Uncomment this if you only have one node
  rollOutPods: true

rollOutCiliumPods: true

ingressController:
  enabled: true
  default: true
  loadbalancerMode: shared
  service:
    annotations:
      io.cilium/lb-ipam-ips: 192.168.1.240
Make sure you have properly configured the highlighted lines and apply the configuration

cilium upgrade -f values.yaml
If everything went well you should now see a cilium-ingress LoadBalancer Service with an external-IP equal to the one you requested

kubectl get services --all-namespaces
NAMESPACE     NAME             TYPE           CLUSTER-IP      EXTERNAL-IP     PORT(S)                      AGE
...
kube-system   cilium-ingress   LoadBalancer   10.43.188.45    192.168.1.240   80:32469/TCP,443:30229/TCP   6s
...
Smoke test
#
Assuming you’ve followed this article correctly — and I haven’t made any mistakes writing it, you should now have a working K3s cluster with Cilium.

To make sure everything works we can deploy a smoke-test.

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
# smoke-test.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: whoami
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: whoami
  namespace: whoami
spec:
  replicas: 1
  selector:
    matchLabels:
      app: whoami
  template:
    metadata:
      labels:
        app: whoami
    spec:
      containers:
        - image: containous/whoami
          imagePullPolicy: Always
          name: whoami
---
apiVersion: v1
kind: Service
metadata:
  name: whoami
  namespace: whoami
spec:
  type: LoadBalancer
  ports:
    - name: http
      port: 80
  selector:
    app: whoami
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whoami
  namespace: whoami
spec:
  rules:
    - host: whoami.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: whoami
                port:
                  number: 80
Copy the above manifest or run

kubectl apply -f https://blog.stonegarden.dev/articles/2024/02/bootstrapping-k3s-with-cilium/resources/smoke-test.yaml
This will deploy whoami — a tiny Go webserver that print OS information and HTTP requests, together with a LoadBalancer Service and an Ingress.


whoami
Pod
Ingress
Service
First we check that the LoadBalancer Service has been assigned an external-IP

kubectl get service -n whoami
which should look like

NAME     TYPE           CLUSTER-IP      EXTERNAL-IP     PORT(S)        AGE
whoami   LoadBalancer   10.43.186.152   192.168.1.241   80:30109/TCP   8s
If the service has no external-IP then there’s probably something wrong with the LB-IPAM. Maybe the configured IP-pool is invalid?

Next try to curl the Service from the K3s machine, i.e.

curl 192.168.1.241
K3s node
whoami
IP
curl
Service
This should give a response similar to

Hostname: whoami-5f7946485b-r4j55
IP: 127.0.0.1
IP: ::1
IP: 10.0.1.197
IP: fe80::10d2:eff:fe4b:81a0
RemoteAddr: 10.0.0.29:47726
GET / HTTP/1.1
Host: 192.168.1.241
User-Agent: curl/7.88.1
Accept: */*
Next we can try the same curl from another client on the same network to see if L2 announcements work

K3s node
Client
whoami
IP
Service
curl
The last test is to check if the IngressController responds as expected. Find the external-IP of the shared IngressController service

kubectl get service -n kube-system cilium-ingress 
This should be a different IP than the whoami Service we tested earlier.

NAME             TYPE           CLUSTER-IP      EXTERNAL-IP     PORT(S)                      AGE
cilium-ingress   LoadBalancer   10.43.186.156   192.168.1.240   80:30674/TCP,443:32684/TCP   65m
By including a Host header in our curl the IngressController should be able to route the request to the correct Ingress

curl --header 'Host: whoami.local' 192.168.1.240
You could also try with the resolve option

curl --resolve whoami.local:80:192.168.1.240 whoami.local
which should also work when you go down the TLS-certificate rabbit-hole.

To make the hostname resolving also work in your browser of choice you can edit the /etc/hosts file to point to the Cilium IngressController LoadBalancer Service IP.

Append the following line to your /etc/hosts file

<cilim-ingess-IP>  whoami.local
or — if you have jq installed, you can run

echo "$(kubectl get svc -n kube-system cilium-ingress -o json | jq -r '.status.loadBalancer.ingress[0].ip') whoami.local" | sudo tee -a /etc/hosts
Navigating to http://whoami.local in you browser you should now see the same text as from the earlier curl-ing. 🥌

A simplified diagram of the whole request flow can be seen below

K3s node
Client
whoami
hostname
IP
IngressController
Service
Ingress
DNS lookup
curl
Once you’re done testing remember to remove the /etc/hosts entry to avoid a potential headache later.

Tips, Tricks, and Troubleshooting
#
Alot can go wrong when working with Kubernetes.

If the K3s bootstrapping fails you are prompted to run either

sudo systemctl status k3s.service
or

sudo journalctl -xeu k3s.service
for details. Though I’ve had more luck looking at the logs of the failing pods.

I find it cumbersome to write kubectl all the time, so I’m quick to add

alias k="kubectl"
in the ~/.bash_aliases file.

Many Kubernetes resources have shortnames. A list of all available shortnames can be found by running

kubectl api-resources
Using the alias combined with the above list — and information from kubectl get --help, we can boil

kubectl get pods --all-namespaces
down to

k get po -A
In this tutorial we’ve only worked in the kube-system namespace. To avoid specifying --namespace kube-system all the time we can instead modify the namespace of the current context

kubectl config set-context --current --namespace=kube-system
To debug pods we can now run to find the name of a misbehaving

k get po
to get the name of every pod in the current namespace.

With the name of the pod at hand we can either describe its state

k describe po <podName>
or show the logs

k logs <podName>
to quickly debug what’s going on.

If you prefer a more interactive experience I can’t recommend k9s enough!

The Cilium-CLI comes with a build-in connectivity tester if you experience any issues you think might be caused Cilium, to run the test suite simply run

cilium connectivity test
Summary
#
In this article we’ve initialised K3s using the following configuration

1
2
3
4
5
6
7
8
# k3s-config.yaml
flannel-backend: "none"
disable-kube-proxy: true
disable-network-policy: true
cluster-init: true
disable:
  - servicelb
  - traefik
by running

curl -sfL https://get.k3s.io | sh -s - --config=k3s-config.yaml
We’ve then replaced the disabled components with Cilium equivalents, which can be summarised using kustomize — which is built into kubectl, and its Helm chart inflation generator as

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - announce.yaml
  - ip-pool.yaml

helmCharts:
  - name: cilium
    repo: https://helm.cilium.io
    version: 1.15.1
    releaseName: "cilium"
    includeCRDs: true
    namespace: kube-system
    valuesFile: values.yaml
 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
# values.yaml
k8sServiceHost: 192.168.1.74
k8sServicePort: 6443

kubeProxyReplacement: true

l2announcements:
  enabled: true

externalIPs:
  enabled: true

k8sClientRateLimit:
  qps: 50
  burst: 200

operator:
# replicas: 1  # Uncomment this if you only have one node
  rollOutPods: true

rollOutCiliumPods: true

ingressController:
  enabled: true
  default: true
  loadbalancerMode: shared
  service:
    annotations:
      io.cilium/lb-ipam-ips: 192.168.1.240
1
2
3
4
5
6
7
8
9
# ip-pool.yaml
apiVersion: "cilium.io/v2alpha1"
kind: CiliumLoadBalancerIPPool
metadata:
  name: "first-pool"
spec:
  blocks:
    - start: "192.168.1.240"
      stop: "192.168.1.249"
1
2
3
4
5
6
7
8
9
# announce.yaml
apiVersion: cilium.io/v2alpha1
kind: CiliumL2AnnouncementPolicy
metadata:
  name: default-l2-announcement-policy
  namespace: kube-system
spec:
  externalIPs: true
  loadBalancerIPs: true
This configuration can then be applied by running

kubectl kustomize --enable-helm . | kubectl apply -f -
Next steps
#
Now that you hopefully have a working K3s-cluster with Cilium up and running it’s time to start using it. I highly recommend going the declarative route with GitOps, either using Flux CD or Argo CD. For inspiration, you can take a look at some of my other posts — e.g. Argo CD with Kustomize + Helm, or join the Home Operations Discord.

In an earlier version of this article I confused PAM with Privileged Access Management. Thanks to u/Klosterbruder on Reddit for pointing this out. ↩︎

The k3s.yaml permissions can also be explicitly set during initialisation using the --write-kubeconfig-mode flag. ↩︎

Since v0.15 cilium-cli defaults to Helm to install Cilium. ↩︎

This can be overridden on a per-Ingress basis using annotations. ↩︎
