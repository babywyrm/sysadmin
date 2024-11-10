
##
#
https://docs.cilium.io/en/stable/installation/k8s-install-helm/
#
https://github.com/bryopsida/wireguard-chart
#
https://aws-ia.github.io/terraform-aws-eks-blueprints/patterns/network/wireguard-with-cilium/
#
##


Install Cilium
Setup Helm repository:

helm repo add cilium https://helm.cilium.io/
GenericGKEAKSEKSOpenShiftRKEk3sRancher DesktopTalos LinuxAlibaba ACK
To install Cilium on Amazon Elastic Kubernetes Service (EKS), perform the following steps:

Default Configuration:

Datapath

IPAM

Datastore

Direct Routing (ENI)

AWS ENI

Kubernetes CRD

For more information on AWS ENI mode, see AWS ENI.

Tip

To chain Cilium on top of the AWS CNI, see AWS VPC CNI plugin.

You can also bring up Cilium in a Single-Region, Multi-Region, or Multi-AZ environment for EKS.

Requirements:

The EKS Managed Nodegroups must be properly tainted to ensure applications pods are properly managed by Cilium:

managedNodeGroups should be tainted with node.cilium.io/agent-not-ready=true:NoExecute to ensure application pods will only be scheduled once Cilium is ready to manage them. However, there are other options. Please make sure to read and understand the documentation page on taint effects and unmanaged pods.

Below is an example on how to use ClusterConfig file to create the cluster:

apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
...
managedNodeGroups:
- name: ng-1
  ...
  # taint nodes so that application pods are
  # not scheduled/executed until Cilium is deployed.
  # Alternatively, see the note above regarding taint effects.
  taints:
   - key: "node.cilium.io/agent-not-ready"
     value: "true"
     effect: "NoExecute"
Limitations:

The AWS ENI integration of Cilium is currently only enabled for IPv4. If you want to use IPv6, use a datapath/IPAM mode other than ENI.

Patch VPC CNI (aws-node DaemonSet)

Cilium will manage ENIs instead of VPC CNI, so the aws-node DaemonSet has to be patched to prevent conflict behavior.

kubectl -n kube-system patch daemonset aws-node --type='strategic' -p='{"spec":{"template":{"spec":{"nodeSelector":{"io.cilium/aws-node-enabled":"true"}}}}}'
Install Cilium:

Deploy Cilium release via Helm:

helm install cilium cilium/cilium --version 1.16.3 \
  --namespace kube-system \
  --set eni.enabled=true \
  --set ipam.mode=eni \
  --set egressMasqueradeInterfaces=eth0 \
  --set routingMode=native
Note

This helm command sets eni.enabled=true and routingMode=native, meaning that Cilium will allocate a fully-routable AWS ENI IP address for each pod, similar to the behavior of the Amazon VPC CNI plugin.

This mode depends on a set of Required Privileges from the EC2 API.

Cilium can alternatively run in EKS using an overlay mode that gives pods non-VPC-routable IPs. This allows running more pods per Kubernetes worker node than the ENI limit but includes the following caveats:

Pod connectivity to resources outside the cluster (e.g., VMs in the VPC or AWS managed services) is masqueraded (i.e., SNAT) by Cilium to use the VPC IP address of the Kubernetes worker node.

The EKS API Server is unable to route packets to the overlay network. This implies that any webhook which needs to be accessed must be host networked or exposed through a service or ingress.

To set up Cilium overlay mode, follow the steps below:

Excluding the lines for eni.enabled=true, ipam.mode=eni and routingMode=native from the helm command will configure Cilium to use overlay routing mode (which is the helm default).

Flush iptables rules added by VPC CNI

iptables -t nat -F AWS-SNAT-CHAIN-0 \\
   && iptables -t nat -F AWS-SNAT-CHAIN-1 \\
   && iptables -t nat -F AWS-CONNMARK-CHAIN-0 \\
   && iptables -t nat -F AWS-CONNMARK-CHAIN-1
Some Linux distributions use a different interface naming convention. If you use masquerading with the option egressMasqueradeInterfaces=eth0, remember to replace eth0 with the proper interface name.

Video

If you’d like to learn more about Cilium Helm values, check out eCHO episode 117: A Tour of the Cilium Helm Values.

Restart unmanaged Pods
If you did not create a cluster with the nodes tainted with the taint node.cilium.io/agent-not-ready, then unmanaged pods need to be restarted manually. Restart all already running pods which are not running in host-networking mode to ensure that Cilium starts managing them. This is required to ensure that all pods which have been running before Cilium was deployed have network connectivity provided by Cilium and NetworkPolicy applies to them:

kubectl get pods --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{print "-n "$1" "$2}' | xargs -L 1 -r kubectl delete pod
pod "event-exporter-v0.2.3-f9c896d75-cbvcz" deleted
pod "fluentd-gcp-scaler-69d79984cb-nfwwk" deleted
pod "heapster-v1.6.0-beta.1-56d5d5d87f-qw8pv" deleted
pod "kube-dns-5f8689dbc9-2nzft" deleted
pod "kube-dns-5f8689dbc9-j7x5f" deleted
pod "kube-dns-autoscaler-76fcd5f658-22r72" deleted
pod "kube-state-metrics-7d9774bbd5-n6m5k" deleted
pod "l7-default-backend-6f8697844f-d2rq2" deleted
pod "metrics-server-v0.3.1-54699c9cc8-7l5w2" deleted
Note

This may error out on macOS due to -r being unsupported by xargs. In this case you can safely run this command without -r with the symptom that this will hang if there are no pods to restart. You can stop this with ctrl-c.

Validate the Installation
Cilium CLIManually
Warning

Make sure you install cilium-cli v0.15.0 or later. The rest of instructions do not work with older versions of cilium-cli. To confirm the cilium-cli version that’s installed in your system, run:

cilium version --client
See Cilium CLI upgrade notes for more details.

Install the latest version of the Cilium CLI. The Cilium CLI can be used to install Cilium, inspect the state of a Cilium installation, and enable/disable various features (e.g. clustermesh, Hubble).

LinuxmacOSOther
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
To validate that Cilium has been properly installed, you can run

cilium status --wait
   /¯¯\
/¯¯\__/¯¯\    Cilium:         OK
\__/¯¯\__/    Operator:       OK
/¯¯\__/¯¯\    Hubble:         disabled
\__/¯¯\__/    ClusterMesh:    disabled
   \__/

DaemonSet         cilium             Desired: 2, Ready: 2/2, Available: 2/2
Deployment        cilium-operator    Desired: 2, Ready: 2/2, Available: 2/2
Containers:       cilium-operator    Running: 2
                  cilium             Running: 2
Image versions    cilium             quay.io/cilium/cilium:v1.9.5: 2
                  cilium-operator    quay.io/cilium/operator-generic:v1.9.5: 2
Run the following command to validate that your cluster has proper network connectivity:

cilium connectivity test
ℹ️  Monitor aggregation detected, will skip some flow validation steps
✨ [k8s-cluster] Creating namespace for connectivity check...

---------------------------------------------------------------------------------------------------------------------
📋 Test Report
---------------------------------------------------------------------------------------------------------------------
✅ 69/69 tests successful (0 warnings)
Note

The connectivity test may fail to deploy due to too many open files in one or more of the pods. If you notice this error, you can increase the inotify resource limits on your host machine (see Pod errors due to “too many open files”).

Congratulations! You have a fully functional Kubernetes cluster with Cilium. 🎉

Next Steps
Setting up Hubble Observability

Inspecting Network Flows with the CLI

Service Map & Hubble UI

Identity-Aware and HTTP-Aware Policy Enforcement

Setting up Cluster Mesh

