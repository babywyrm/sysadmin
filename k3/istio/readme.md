

##
#
https://ranchermanager.docs.rancher.com/integrations-in-rancher/istio/configuration-options/install-istio-on-rke2-cluster
#
https://istio.io/latest/docs/setup/platform-setup/k3d/
#
https://qdnqn.com/using-istio-on-k3s/
#
##

```
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  components:
    cni:
      enabled: true
      k8s:
        overlays:
        - apiVersion: "apps/v1"
          kind: "DaemonSet"
          name: "istio-cni-node"
          patches:
          - path: spec.template.spec.containers.[name:install-cni].securityContext.privileged
            value: true
  values:
    cni:
      cniBinDir: /opt/cni/bin
      cniConfDir: /etc/cni/net.d
```

k3d is a lightweight wrapper to run k3s (Rancher Lab’s minimal Kubernetes distribution) in docker. k3d makes it very easy to create single- and multi-node k3s clusters in docker, e.g. for local development on Kubernetes.

Prerequisites
To use k3d, you will also need to install docker.
Install the latest version of k3d.
To interact with the Kubernetes cluster kubectl
(Optional) Helm is the package manager for Kubernetes
Installation
Create a cluster and disable Traefik with the following command:

```
$ k3d cluster create --api-port 6550 -p '9080:80@loadbalancer' -p '9443:443@loadbalancer' --agents 2 --k3s-arg '--disable=traefik@server:*'
```
To see the list of k3d clusters, use the following command:

$ k3d cluster list
k3s-default

To list the local Kubernetes contexts, use the following command.

$ kubectl config get-contexts
CURRENT   NAME                 CLUSTER              AUTHINFO             NAMESPACE
*         k3d-k3s-default      k3d-k3s-default      k3d-k3s-default

k3d- is prefixed to the context and cluster names, for example: k3d-k3s-default
If you run multiple clusters, you need to choose which cluster kubectl talks to. You can set a default cluster for kubectl by setting the current context in the Kubernetes kubeconfig file. Additionally you can run following command to set the current context for kubectl.

$ kubectl config use-context k3d-k3s-default
Switched to context "k3d-k3s-default".

Set up Istio for k3d
Once you are done setting up a k3d cluster, you can proceed to install Istio with Helm 3 on it.
```
$ kubectl create namespace istio-system
$ helm install istio-base istio/base -n istio-system --wait
$ helm install istiod istio/istiod -n istio-system --wait
```
(Optional) Install an ingress gateway:

$ helm install istio-ingressgateway istio/gateway -n istio-system --wait

Set up Dashboard UI for k3d
k3d does not have a built-in Dashboard UI like minikube. But you can still set up Dashboard, a web based Kubernetes UI, to view your cluster. Follow these instructions to set up Dashboard for k3d.

To deploy Dashboard, run the following command:

$ helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/
$ helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard

Verify that Dashboard is deployed and running.
```
$ kubectl get pod -n kubernetes-dashboard
NAME                                         READY   STATUS    RESTARTS   AGE
dashboard-metrics-scraper-8c47d4b5d-dd2ks    1/1     Running   0          25s
kubernetes-dashboard-67bd8fc546-4xfmm        1/1     Running   0          25s
```
Create a ServiceAccount and ClusterRoleBinding to provide admin access to the newly created cluster.
```
$ kubectl create serviceaccount -n kubernetes-dashboard admin-user
$ kubectl create clusterrolebinding -n kubernetes-dashboard admin-user --clusterrole cluster-admin --serviceaccount=kubernetes-dashboard:admin-user
```
To log in to your Dashboard, you need a Bearer Token. Use the following command to store the token in a variable.

$ token=$(kubectl -n kubernetes-dashboard create token admin-user)

Display the token using the echo command and copy it to use for logging in to your Dashboard.

$ echo $token

You can access your Dashboard using the kubectl command-line tool by running the following command:

$ kubectl proxy
Starting to serve on 127.0.0.1:8001

Click Kubernetes Dashboard to view your deployments and services.

You have to save your token somewhere, otherwise you have to run step number 4 everytime you need a token to log in to your Dashboard.


$ k3d cluster delete k3s-default
Deleting cluster "k3s-default" ...

IBM
