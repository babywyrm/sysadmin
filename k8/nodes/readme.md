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
