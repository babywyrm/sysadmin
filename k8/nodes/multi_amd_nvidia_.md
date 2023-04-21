
# Kubernetes cluster setup based on amd64 && NVIDIA JETSON TX2
Thanks to @luxas create [the Kubernetes on ARM project](https://github.com/luxas/kubernetes-on-arm). But my project has some different, i have a VM on x86 as master node and two nvidia tx2 development kits as work node.
So my kubernetes cluster are multi-platform. I use [kubeadm](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/) as a deployment method.Some basic information of my platform is as follows.

## Versions
**kubeadm version** (use kubeadm version):1.10.0

**Environment**:
- **Kubernetes version** (use `kubectl version`):1.10.0
- **Cloud provider or hardware configuration**:an amd64 master and 1 arm nodes (nvidia tagra TX2)
- **OS** (e.g. from /etc/os-release): ubuntu 16.04
- **Kernel** (e.g. `uname -a`): Linux ubuntu 4.13.0-39-generic # 44~16.04.1-Ubuntu SMP Thu Apr 5 16:43:10 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux for amd64 && Linux tegra-ubuntu 4.4.38 # 1 SMP PREEMPT Sun Apr 22 02:51:59 UTC 2018 aarch64 aarch64 aarch64 GNU/Linux for arm
- **Others**:
iptables version: 1.6.0

## Steps
Follow the instructions at https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/ for setting up the master node. Before bring up the other nodes by running the `kubeadm join ...`, there are two important things we should do.
first, we should customize the `kube-proxy` on the arm node. Without this step, the kube-proxy pod on the arm node will be `crashloopback`.This is caused by image mismatch between master node and the worker node.Kube-proxy is run as a daemonset. This means,the daemonsets will be schedued to run on all nodes.If you inspect the kube-proxy, `kubectl describe kube-proxy -n kube-system` you will notice the image tag referencing to amd64.
Fortunately @squidpickles proposed a solution ,[Multiplatform (amd64 and arm) Kubernetes cluster setup](https://gist.github.com/squidpickles/dda268d9a444c600418da5e1641239af#multiplatform-amd64-and-arm-kubernetes-cluster-setup).
Add `nodeSelector` to kube-proxy manifest. You can get the node labes by running
```bash
kubectl describe node <node-name>
```
By running 
```bash
KUBE_EDITOR="nano" kubectl edit daemonset kube-proxy --namespace=kube-system
```
you can modify the manifest of `kube-proxy`.
```diff
       dnsPolicy: ClusterFirst
       hostNetwork: true
+      nodeSelector:
+        beta.kubernetes.io/arch: amd64
       restartPolicy: Always
       schedulerName: default-scheduler
       securityContext: {}
```
Make a new manifest for arm node, name `kube-proxy-arm`.
```diff
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
       - command:
         - /usr/local/bin/kube-proxy
         - --config=/var/lib/kube-proxy/config.conf
-        image: gcr.io/google_containers/kube-proxy-amd64:v1.10.1
+        image: gcr.io/google_containers/kube-proxy-arm:v1.10.1
         imagePullPolicy: IfNotPresent
         name: kube-proxy
         resources: {}
       dnsPolicy: ClusterFirst
       hostNetwork: true
       nodeSelector:
-        beta.kubernetes.io/arch: amd64
+        beta.kubernetes.io/arch: arm64
       restartPolicy: Always
       schedulerName: default-scheduler
       securityContext: {}
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
you can create the new DaemonSet by running
```bash
kubectl create -f daemonset-arm.yaml
```
When I completed this, I found that the status of the `kube-proxy pod` on the arm node is running. But when adding a network plug-in(weave), it was found that the arm node has been in a `not-ready` state, and the weave pod is `crashloopbackoff`.
The logs of weave:
```
Get https://10.96.0.1:443/api/v1/nodes: dial tcp 10.96.0.1:443: i/o timeout;
Failed to get peers
```
I think the problem is in `kube-proxy-arm`. So i check the logs:
```
kubectl logs kube-proxy-arm-bzrvg -n=kube-system
I0502 13:19:00.679884       1 feature_gate.go:226] feature gates: &{{} map[]}
W0502 13:19:00.699625       1 server_others.go:290] Can't use ipvs proxier, trying iptables proxier
I0502 13:19:00.702634       1 server_others.go:140] Using iptables Proxier.
I0502 13:19:00.740414       1 server_others.go:174] Tearing down inactive rules.
I0502 13:19:01.034561       1 server.go:444] Version: v1.10.1
I0502 13:19:01.099829       1 conntrack.go:98] Set sysctl 'net/netfilter/nf_conntrack_max' to 131072
I0502 13:19:01.100324       1 conntrack.go:52] Setting nf_conntrack_max to 131072
I0502 13:19:01.101273       1 conntrack.go:98] Set sysctl 'net/netfilter/nf_conntrack_tcp_timeout_established' to 86400
I0502 13:19:01.101430       1 conntrack.go:98] Set sysctl 'net/netfilter/nf_conntrack_tcp_timeout_close_wait' to 3600
I0502 13:19:01.102335       1 config.go:202] Starting service config controller
I0502 13:19:01.102946       1 controller_utils.go:1019] Waiting for caches to sync for service config controller
I0502 13:19:01.103395       1 config.go:102] Starting endpoints config controller
I0502 13:19:01.104678       1 controller_utils.go:1019] Waiting for caches to sync for endpoints config controller
I0502 13:19:01.206422       1 controller_utils.go:1026] Caches are synced for service config controller
I0502 13:19:01.206422       1 controller_utils.go:1026] Caches are synced for endpoints config controller
E0502 13:19:01.415172       1 proxier.go:1285] Failed to execute iptables-restore: exit status 1 (iptables-restore: line 27 failed
)
E0502 13:19:31.288315       1 proxier.go:1285] Failed to execute iptables-restore: exit status 1 (iptables-restore: line 27 failed
)
E0502 13:20:01.540382       1 proxier.go:1285] Failed to execute iptables-restore: exit status 1 (iptables-restore: line 27 failed
)
E0502 13:20:31.758797       1 proxier.go:1285] Failed to execute iptables-restore: exit status 1 (iptables-restore: line 27 failed
```
See more  details in [Failed to execute iptables-restore: exit status 1 in kube-proxy #784](https://github.com/kubernetes/kubeadm/issues/784).
It looks like `kube-proxy` encountered an error when generating iptables on the arm node.
After some inspection，I re-compiled the kernel of NVIDIA TX2 and loaded the kernel modules needed by netfliter and weave. Such as `nf_conntrak`，
`xt_set`,`vxlan`,`openvswitch`.
My workflow looks like:
```
$ git clone https://github.com/jetsonhacks/buildJetsonTX2Kernel.git
$ cd buildJetsonTX2Kernel
# For L4T 28.2, do the following:
$ git checkout vL4T28.2
```
There are three main scripts. The first script, getKernelSources.sh gets the kernel sources from the NVIDIA developer website, then unpacks the sources into /usr/src/kernel.
```
$ ./getKernelSources.sh
```
After the sources are installed, the script opens an editor on the kernel configuration file. PS: Need to install `QT4`. You can choose install the module you want.
The second script, makeKernel.sh, fixes up the makefiles so that the source can be compiled on the Jetson, and then builds the kernel and modules specified.
```
$ ./makeKernel.sh
```
The modules are then installed in /lib/modules/
The third script, copyImage.sh, copies over the newly built Image and zImage files into the /boot directory.
```
$ ./copyImage.sh
```
Once the images have been copied over to the /boot directory, the machine must be restarted for the new kernel to take effect.

When this is done, the error disappears. Everything is fine.

```
master@ubuntu:~$ kubectl describe node tegra-ubuntu
Name:               tegra-ubuntu
Roles:              <none>
Labels:             beta.kubernetes.io/arch=arm64
                    beta.kubernetes.io/os=linux
                    kubernetes.io/hostname=tegra-ubuntu
Annotations:        node.alpha.kubernetes.io/ttl=0
                    volumes.kubernetes.io/controller-managed-attach-detach=true
CreationTimestamp:  Sat, 05 May 2018 11:56:45 +0800
Taints:             <none>
Unschedulable:      false
Conditions:
  Type             Status  LastHeartbeatTime                 LastTransitionTime                Reason                       Message
  ----             ------  -----------------                 ------------------                ------                       -------
  OutOfDisk        False   Mon, 07 May 2018 20:51:32 +0800   Mon, 07 May 2018 20:40:48 +0800   KubeletHasSufficientDisk     kubelet has sufficient disk space available
  MemoryPressure   False   Mon, 07 May 2018 20:51:32 +0800   Mon, 07 May 2018 20:40:48 +0800   KubeletHasSufficientMemory   kubelet has sufficient memory available
  DiskPressure     False   Mon, 07 May 2018 20:51:32 +0800   Mon, 07 May 2018 20:40:48 +0800   KubeletHasNoDiskPressure     kubelet has no disk pressure
  PIDPressure      False   Mon, 07 May 2018 20:51:32 +0800   Sat, 05 May 2018 11:56:45 +0800   KubeletHasSufficientPID      kubelet has sufficient PID available
  Ready            True    Mon, 07 May 2018 20:51:32 +0800   Mon, 07 May 2018 20:40:48 +0800   KubeletReady                 kubelet is posting ready status
Addresses:
  InternalIP:  10.108.71.185
  Hostname:    tegra-ubuntu
Capacity:
 cpu:                4
 ephemeral-storage:  28768380Ki
 memory:             8034624Ki
 pods:               110
Allocatable:
 cpu:                4
 ephemeral-storage:  26512938965
 memory:             7932224Ki
 pods:               110
System Info:
 Machine ID:                 ae15719763c84b35196c20a95728b806
 System UUID:                ae15719763c84b35196c20a95728b806
 Boot ID:                    b4dfd2df-dd05-45b9-8251-51e871c474a3
 Kernel Version:             4.4.384.4.38-test
 OS Image:                   Ubuntu 16.04 LTS
 Operating System:           linux
 Architecture:               arm64
 Container Runtime Version:  docker://1.13.1
 Kubelet Version:            v1.10.0
 Kube-Proxy Version:         v1.10.0
PodCIDR:                     10.32.4.0/24
ExternalID:                  tegra-ubuntu
Non-terminated Pods:         (2 in total)
  Namespace                  Name                    CPU Requests  CPU Limits  Memory Requests  Memory Limits
  ---------                  ----                    ------------  ----------  ---------------  -------------
  kube-system                kube-proxy-arm-2fpgd    0 (0%)        0 (0%)      0 (0%)           0 (0%)
  kube-system                weave-net-jwrv5         20m (0%)      0 (0%)      0 (0%)           0 (0%)

```

```
master@ubuntu:~$ kubectl get pod --all-namespaces
NAMESPACE     NAME                             READY     STATUS    RESTARTS   AGE
kube-system   etcd-ubuntu                      1/1       Running   0          2d
kube-system   kube-apiserver-ubuntu            1/1       Running   0          2d
kube-system   kube-controller-manager-ubuntu   1/1       Running   0          2d
kube-system   kube-dns-86f4d74b45-pgwb8        3/3       Running   0          11d
kube-system   kube-proxy-arm-2fpgd             1/1       Running   5          2d
kube-system   kube-proxy-pjnwn                 1/1       Running   0          11d
kube-system   kube-proxy-wmd2p                 1/1       Running   0          10d
kube-system   kube-scheduler-ubuntu            1/1       Running   0          2d
kube-system   weave-net-jwrv5                  2/2       Running   3          1d
kube-system   weave-net-p282j                  2/2       Running   0          1d
kube-system   weave-net-vq8fz                  2/2       Running   0          1d

```

```
master@ubuntu:~$ kubectl get node
NAME           STATUS    ROLES     AGE       VERSION
nodex86        Ready     <none>    10d       v1.10.1
tegra-ubuntu   Ready     <none>    2d        v1.10.0
ubuntu         Ready     master    11d       v1.10.0
```
