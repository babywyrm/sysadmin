Adding a worker node to the Kubernetes cluster
You can add workers to an existing Kubernetes cluster.

Before you begin
Before you add a worker node, you must ensure that the version of the Kubernetes RPM files in the $HOME/fci-install-kit/helm/distrib/ directory match the version of Kubernetes installed. To do so, follow these steps:

On the Kubernetes master node, find the version of Kubernetes that is installed:
kubectl version --short

Results are similar to the following:
Client Version: v1.14.1
Server Version: v1.14.1

Check that your version matches the versions of the Kubernetes RPM files in the $HOME/fci-install-kit/helm/distrib/ directory. For example, the kubectl and kubeadm RPM files appear similar to the following:
`5c6cb3beb5142fa21020e2116824ba77a2d1389a3321601ea53af5ceefe70ad1-kubectl-1.14.1-0.x86_64.rpm`
`9e1af74c18311f2f6f8460dbd1aa3e02911105bfd455416381e995d8172a0a01-kubeadm-1.14.1-0.x86_64.rpm`

Attention: If the version returned by the kubectl command is equal to or higher than the packaged version, continue to follow steps in this procedure. If the version returned is lower than what is packaged, then you must first upgrade the installed Kubernetes by installing APAR PH09019 located on IBM Fix Central (Download | Readme).
Procedure
To add a worker node to the Kubernetes cluster:

Edit the $HOME/fci-install-kit/helm/install.hosts.properties file and add the new worker node. For example, if the next incremental worker node is worker.3, add a new entry similar to the following:
master.ip=172.18.160.90
master.fqdn=fci-master.ibm.com
master.root_password=passw0rd
master.external_ip=9.30.15.9

worker.1.ip=9.0.10.1 
worker.1.fqdn=fci-wkr1.ibm.com
worker.1.root_password=passw0rd

worker.2.ip=9.0.10.2
worker.2.fqdn=fci-wkr2.ibm.com
worker.2.root_password=passw0rd

worker.3.ip=9.0.10.3
worker.3.fqdn=fci-wkr3.ibm.com
worker.3.root_password=passw0rd

Run the following command:
./install.sh --add-workers

This command finds and initializes any new Kubernetes worker nodes and joins them to the cluster.
Notes:
The installer does not apply any taints or labels to the new nodes.
Pods do not automatically move to the new nodes until something causes a pod to end.
To verify that the worker node was added to the cluster:
kubectl get nodes

Results appear similar to the following. Verify that the new node is listed.
NAME                   STATUS   ROLES    AGE     VERSION
fci-master.ibm.com     Ready    master   3h44m   v1.14.1
fci-wkr1.ibm.com       Ready    <none>   81s     v1.14.1
fci-wkr2.ibm.com       Ready    <none>   81s     v1.14.1
fci-wkr3.ibm.com       Ready    <none>   81s     v1.14.1

