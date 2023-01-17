```
kubectl get services                # List all services 
kubectl get pods                    # List all pods
kubectl get nodes -w                # Watch nodes continuously
kubectl version                     # Get version information
kubectl cluster-info                # Get cluster information
kubectl config view                 # Get the configuration
kubectl describe node <node>        # Output information about a node
kubectl get pods                         # List the current pods
kubectl describe pod <name>              # Describe pod <name>
kubectl get rc                           # List the replication controllers
kubectl get rc --namespace="<namespace>" # List the replication controllers in <namespace>
kubectl describe rc <name>               # Describe replication controller <name>
kubectl get svc                          # List the services
kubectl describe svc <name>              # Describe service <name>

kubectl run <name> --image=<image-name>                             # Launch a pod called <name> 
                                                                    # using image <image-name> 
kubectl create -f <manifest.yaml>                                   # Create a service described 
                                                                    # in <manifest.yaml>
kubectl scale --replicas=<count> rc <name>                          # Scale replication controller 
                                                                    # <name> to <count> instances
kubectl expose rc <name> --port=<external> --target-port=<internal> # Map port <external> to 
                                                                    # port <internal> on replication 
                                                                    # controller <name>
kubectl delete pod <name>                                         # Delete pod <name>
kubectl delete rc <name>                                          # Delete replication controller <name>
kubectl delete svc <name>                                         # Delete service <name>
kubectl drain <n> --delete-local-data --force --ignore-daemonsets # Stop all pods on <n>
kubectl delete node <name>                                        # Remove <node> from the cluster
kubectl exec <service> <command> [-c <$container>] # execute <command> on <service>, optionally 
                                                   # selecting container <$container>
kubectl logs -f <name> [-c <$container>]           # Get logs from service <name>, optionally
                                                   # selecting container <$container>
watch -n 2 cat /var/log/kublet.log                 # Watch the Kublet logs
kubectl top node                                   # Show metrics for nodes
kubectl top pod                                    # Show metrics for pods
kubeadm init                                              # Initialize your master node
kubeadm join --token <token> <master-ip>:<master-port>    # Join a node to your Kubernetes cluster
kubectl create namespace <namespace>                      # Create namespace <name>
kubectl taint nodes --all node-role.kubernetes.io/master- # Allow Kubernetes master nodes to run pods
kubeadm reset                                             # Reset current state
kubectl get secrets                                       # List all secrets

```
##
##

## Add a kubectl context

```bash
# copy cluster's certificate to a file
vi cluster-certificate.txt

# Set cluster
kubectl config set-cluster <CLUSTER_NAME> --server=https://37.187.1.138:6443 --certificate-authority=cluster-certificate.txt --embed-certs=true

# Set credentials
kubectl config set-credentials <USER_NAME> --token=<TOKEN>

# Set context
kubectl config set-context <KUBECTL_CONTEXT_NAME> --cluster=<CLUSTER_NAME> --user=<USER_NAME> --namespace=<NAMESPACE>

# Use context
kubectl config use-context <KUBECTL_CONTEXT_NAME>
```

## Clean up a namespace

```bash
# Delete a config map
kubectl get configmaps | awk '{print $1}' | grep -v 'NAME' | xargs kubectl delete configmap

# Real "get all"
kubectl get -n <NAMESPACE> configmaps,daemonsets,deployments,endpoints,ingresses,jobs,persistentvolumeclaims,pods,podtemplates,replicasets,services,statefulsets

# Delete ALL
kubectl get -n <NAMESPACE> configmaps,daemonsets,deployments,endpoints,ingresses,jobs,persistentvolumeclaims,pods,podtemplates,replicasets,services,statefulsets,secrets | awk '{print $1}' | grep -v "NAME" | grep -v "secret/default-token" | xargs kubectl delete

```

## Stop/Start a deployment

```
kubectl get deployment

# Stop
kubectl scale deployment.apps/<DEPLOYMENT_NAME> --replicas 0

# Start
kubectl scale deployment.apps/<DEPLOYMENT_NAME> --replicas 1
```

Sometime you just want to restart a container into a pod.

This will send a `SIGTERM` signal to process 1, which is the main process running in the container. All other processes will be children of process 1, and will be terminated after process 1 exits.

Note: It will not solve your problem. This is only a quick fix.

```
kubectl exec -it <POD_NAME> -c <CONTAINER_NAME> -- /bin/sh -c "kill 1"
```

## Fix rewrite problems with PHPMyAdmin

I don't know why but sometimes, `helm upgrade` doesn't upgrade these annotations so I have to do it manualy. 

```
kubectl annotate --overwrite ingress <INGRESS_NAME> "nginx.ingress.kubernetes.io/rewrite-target"-
kubectl annotate --overwrite ingress <INGRESS_NAME> "ingress.kubernetes.io/rewrite-target"-
```

## Other cheat sheets

- [Official cheat sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [dennyzhang/cheatsheet-kubernetes-A4](https://github.com/dennyzhang/cheatsheet-kubernetes-A4)

## Tools

- [kubectx and kubens](https://github.com/ahmetb/kubectx) to "switch faster between clusters and namespaces in kubectl".
- [jonmosco/kube-ps1](https://github.com/jonmosco/kube-ps1)to add the current Kubernetes context and namespace to your prompt.
- [Kubernetes client kubectl container](https://github.com/lachie83/k8s-kubectl)
- [Kubectl-debug](https://github.com/aylei/kubectl-debug)
- [jordanwilson230/kubectl-plugins](https://github.com/jordanwilson230/kubectl-plugins)


##
##

kubectl get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].image}" |\

tr -s '[[:space:]]' '\n' |\

sort |\

uniq -c


##
##

# kubectl-tips
Tips on Kubernetes cluster management using kubectl command. A goal of this repository is to allow you reversely lookup kubectl commands from what you want to do around kubernetes cluster management.

<!-- TOC -->

- [kubectl-tips](#kubectl-tips)
	- [Kubectl Version Manager](#kubectl-version-manager)
	- [Print Cluster Info](#print-cluster-info)
	- [Print the supported API resources](#print-the-supported-api-resources)
	- [Print the available API versions](#print-the-available-api-versions)
	- [Display Resource (CPU/Memory) usage of nodes/pods](#display-resource-cpumemory-usage-of-nodespods)
	- [Updating Kubernetes Deployments on a ConfigMap/Secrets Change](#updating-kubernetes-deployments-on-a-configmapsecrets-change)
	- [Deploy and rollback app using kubectl](#deploy-and-rollback-app-using-kubectl)
	- [Get all endpoints in the cluster](#get-all-endpoints-in-the-cluster)
	- [Execute shell commands inside the cluster](#execute-shell-commands-inside-the-cluster)
	- [Access k8s API endpoint via local proxy](#access-k8s-api-endpoint-via-local-proxy)
	- [Port forward a local port to a port on k8s resources](#port-forward-a-local-port-to-a-port-on-k8s-resources)
	- [Change the service type to LoadBalancer by patching](#change-the-service-type-to-loadbalancer-by-patching)
	- [Delete Kubernetes Resources](#delete-kubernetes-resources)
	- [Using finalizers to control deletion](#using-finalizers-to-control-deletion)
	- [Delete a worker node in the cluster](#delete-a-worker-node-in-the-cluster)
	- [Evicted all pods in a node for investigation](#evicted-all-pods-in-a-node-for-investigation)
	- [Get Pods Logs](#get-pods-logs)
	- [Get Kubernetes events](#get-kubernetes-events)
	- [Get Kubernetes Raw Metrics - Prometheus metrics endpoint](#get-kubernetes-raw-metrics---prometheus-metrics-endpoint)
	- [Get Kubernetes Raw Metrics - metrics API](#get-kubernetes-raw-metrics---metrics-api)

<!-- /TOC -->


## Kubectl Version Manager

You can manager multiple kubectl version with [asdf](https://asdf-vm.com/) and [asdf-kubectl](https://github.com/asdf-community/asdf-kubectl)

Install asdf and asdf-kubectl

```bash
# Homebrew on macOS
# Install asdf
brew install asdf
# Add asdf.sh to your ~/.zshrc
echo -e "\n. $(brew --prefix asdf)/libexec/asdf.sh" >> ~/.zshrc
```

Install asdf-kubectl

```bash
# Install asdf-kubectl plugin
asdf plugin-add kubectl https://github.com/asdf-community/asdf-kubectl.git
# check installed plugin
asdf plugin list
# -> kubectl
```

Then, check available version

```bash
asdf list-all kubectl
```

Let's install 1.21.14

```bash
asdf install kubectl 1.21.14
# Check install kubectl version
asdf list kubectl
#-> *1.21.14
```

Finally configure asdf to use kubectl version 1.21.14

```bash
asdf global kubectl 1.21.14
```

Let's see how kubectl client version looks like

```bash
kubectl version --client

Client Version: version.Info{Major:"1", Minor:"21", GitVersion:"v1.21.14", GitCommit:"0f77da5bd4809927e15d1658fb4aa8f13ad890a5", GitTreeState:"clean", BuildDate:"2022-06-15T14:17:29Z", GoVersion:"go1.16.15", Compiler:"gc", Platform:"darwin/amd64"}
```


See also
- https://asdf-vm.com/
- https://asdf-vm.com/guide/getting-started.html
- https://github.com/asdf-community/asdf-kubectl

## Print Cluster Info

```bash
kubectl cluster-info

Kubernetes control plane is running at https://A8A4143BAA8FADD6BA355D6C2A12344.gr5.ap-northeast-1.eks.amazonaws.com
CoreDNS is running at https://A8A4143BAA8FADD6BA355D6C2A12345.gr7.ap-northeast-1.eks.amazonaws.com/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
Metrics-server is running at https://A8A4143BAA8FADD6BA355D6C2A12345.gr7.ap-northeast-1.eks.amazonaws.com/api/v1/namespaces/kube-system/services/https:metrics-server:/proxy
```

## Print the supported API resources

```bash
kubectl api-resources
kubectl api-resources -o wide
```

<details><summary>sample output</summary>
<p>

```
NAME                              SHORTNAMES         APIGROUP                       NAMESPACED   KIND
bindings                                                                            true         Binding
componentstatuses                 cs                                                false        ComponentStatus
configmaps                        cm                                                true         ConfigMap
endpoints                         ep                                                true         Endpoints
events                            ev                                                true         Event
limitranges                       limits                                            true         LimitRange
namespaces                        ns                                                false        Namespace
nodes                             no                                                false        Node
persistentvolumeclaims            pvc                                               true         PersistentVolumeClaim
persistentvolumes                 pv                                                false        PersistentVolume
pods                              po                                                true         Pod
podtemplates                                                                        true         PodTemplate
replicationcontrollers            rc                                                true         ReplicationController
resourcequotas                    quota                                             true         ResourceQuota
secrets                                                                             true         Secret
serviceaccounts                   sa                                                true         ServiceAccount
services                          svc                                               true         Service
mutatingwebhookconfigurations                        admissionregistration.k8s.io   false        MutatingWebhookConfiguration
validatingwebhookconfigurations                      admissionregistration.k8s.io   false        ValidatingWebhookConfiguration
customresourcedefinitions         crd,crds           apiextensions.k8s.io           false        CustomResourceDefinition
apiservices                                          apiregistration.k8s.io         false        APIService
controllerrevisions                                  apps                           true         ControllerRevision
daemonsets                        ds                 apps                           true         DaemonSet
deployments                       deploy             apps                           true         Deployment
replicasets                       rs                 apps                           true         ReplicaSet
statefulsets                      sts                apps                           true         StatefulSet
applications                      app,apps           argoproj.io                    true         Application
appprojects                       appproj,appprojs   argoproj.io                    true         AppProject
tokenreviews                                         authentication.k8s.io          false        TokenReview
localsubjectaccessreviews                            authorization.k8s.io           true         LocalSubjectAccessReview
selfsubjectaccessreviews                             authorization.k8s.io           false        SelfSubjectAccessReview
selfsubjectrulesreviews                              authorization.k8s.io           false        SelfSubjectRulesReview
subjectaccessreviews                                 authorization.k8s.io           false        SubjectAccessReview
horizontalpodautoscalers          hpa                autoscaling                    true         HorizontalPodAutoscaler
cronjobs                          cj                 batch                          true         CronJob
jobs                                                 batch                          true         Job
certificatesigningrequests        csr                certificates.k8s.io            false        CertificateSigningRequest
leases                                               coordination.k8s.io            true         Lease
eniconfigs                                           crd.k8s.amazonaws.com          false        ENIConfig
events                            ev                 events.k8s.io                  true         Event
daemonsets                        ds                 extensions                     true         DaemonSet
deployments                       deploy             extensions                     true         Deployment
ingresses                         ing                extensions                     true         Ingress
networkpolicies                   netpol             extensions                     true         NetworkPolicy
podsecuritypolicies               psp                extensions                     false        PodSecurityPolicy
replicasets                       rs                 extensions                     true         ReplicaSet
networkpolicies                   netpol             networking.k8s.io              true         NetworkPolicy
poddisruptionbudgets              pdb                policy                         true         PodDisruptionBudget
podsecuritypolicies               psp                policy                         false        PodSecurityPolicy
clusterrolebindings                                  rbac.authorization.k8s.io      false        ClusterRoleBinding
clusterroles                                         rbac.authorization.k8s.io      false        ClusterRole
rolebindings                                         rbac.authorization.k8s.io      true         RoleBinding
roles                                                rbac.authorization.k8s.io      true         Role
priorityclasses                   pc                 scheduling.k8s.io              false        PriorityClass
storageclasses                    sc                 storage.k8s.io                 false        StorageClass
volumeattachments                                    storage.k8s.io                 false        VolumeAttachment

```

</p>
</details>

## Print the available API versions
```bash
kubectl get apiservices
```

<details><summary>sample output</summary>
<p>

```
NAME                                   SERVICE   AVAILABLE   AGE
v1.                                    Local     True        97d
v1.apps                                Local     True        97d
v1.authentication.k8s.io               Local     True        97d
v1.authorization.k8s.io                Local     True        97d
v1.autoscaling                         Local     True        97d
v1.batch                               Local     True        97d
v1.networking.k8s.io                   Local     True        97d
v1.rbac.authorization.k8s.io           Local     True        97d
v1.storage.k8s.io                      Local     True        97d
v1alpha1.argoproj.io                   Local     True        4d
v1alpha1.crd.k8s.amazonaws.com         Local     True        6d
v1beta1.admissionregistration.k8s.io   Local     True        97d
v1beta1.apiextensions.k8s.io           Local     True        97d
v1beta1.apps                           Local     True        97d
v1beta1.authentication.k8s.io          Local     True        97d
v1beta1.authorization.k8s.io           Local     True        97d
v1beta1.batch                          Local     True        97d
v1beta1.certificates.k8s.io            Local     True        97d
v1beta1.coordination.k8s.io            Local     True        97d
v1beta1.events.k8s.io                  Local     True        97d
v1beta1.extensions                     Local     True        97d
v1beta1.policy                         Local     True        97d
v1beta1.rbac.authorization.k8s.io      Local     True        97d
v1beta1.scheduling.k8s.io              Local     True        97d
v1beta1.storage.k8s.io                 Local     True        97d
v1beta2.apps                           Local     True        97d
v2beta1.autoscaling                    Local     True        97d
v2beta2.autoscaling                    Local     True        97d
```

</p>
</details>


## Display Resource (CPU/Memory) usage of nodes/pods


Display Resource (CPU/Memory) usage of nodes
```bash
kubectl top node
```

<details><summary>sample output</summary>
<p>

```
NAME                          CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
aks-node-28537427-0           281m         1%     10989Mi         39%
aks-node-28537427-1           123m         0%     6795Mi          24%
aks-node-28537427-2           234m         1%     7963Mi          28%
```
</p>
</details>


Display Resource (CPU/Memory) usage of pods
```bash
kubectl top po -A
kubectl top po --all-namespaces
```

<details><summary>sample output</summary>
<p>

```
NAMESPACE                   NAME                                           CPU(cores)   MEMORY(bytes)
dd-agent                    dd-agent-2nffb                                 55m          235Mi
dd-agent                    dd-agent-kkxsq                                 26m          208Mi
dd-agent                    dd-agent-srnlt                                 29m          210Mi
kube-system                 azure-cni-networkmonitor-5k7ws                 1m           22Mi
kube-system                 azure-cni-networkmonitor-72sxx                 1m           20Mi
kube-system                 azure-cni-networkmonitor-wxqvm                 1m           22Mi
kube-system                 azure-ip-masq-agent-gft8h                      1m           11Mi
kube-system                 azure-ip-masq-agent-tc8jc                      1m           10Mi
kube-system                 azure-ip-masq-agent-v54pm                      1m           11Mi
kube-system                 coredns-6cb457974f-kth9q                       4m           25Mi
kube-system                 coredns-6cb457974f-m9lth                       4m           24Mi
kube-system                 coredns-autoscaler-66cdbfb8fc-9kklp            1m           11Mi
kube-system                 kube-proxy-b4x7q                               5m           47Mi
kube-system                 kube-proxy-gm8df                               6m           49Mi
kube-system                 kube-proxy-vsgbs                               5m           50Mi
kube-system                 kubernetes-dashboard-686c6f85dc-n5xgg          1m           19Mi
kube-system                 metrics-server-5b9794db67-5rs25                1m           18Mi
kube-system                 tunnelfront-f586b8b5c-lrfkm                    68m          52Mi
custom-app-00-dev1          custom-app-deployment-5db9d949dd-fnrqd         2m           1563Mi
custom-app-00-dev2          custom-app-deployment-c67497d95-rtggx          2m           1577Mi
custom-app-00-dev3          custom-app-deployment-958c59798-6vvwj          2m           1581Mi
custom-app-00-dev4          custom-app-deployment-5c7797bc85-mlppp         2m           1585Mi
custom-app-00-dev5          custom-app-deployment-bfd4596dd-d5q76          2m           1603Mi
custom-app-00-dev6          custom-app-deployment-6f9f56ffc6-tpngg         2m           1600Mi
custom-app-00-dev7          custom-app-deployment-7c6896ff98-4pmln         2m           1573Mi
```

</p>
</details>


## Updating Kubernetes Deployments on a ConfigMap/Secrets Change

`kubectl v1.15+` provides a rollout restart command that allows you to restart Pods in a Deployment and allow them pick up changes to a referenced ConfigMap, Secret or similar.

```bash
kubectl rollout restart deploy/<deployment-name>
kubectl rollout restart deploy <deployment-name>
```


## Deploy and rollback app using kubectl
```bash
kubectl run nginx --image nginx
kubectl run nginx --image=nginx --port=80 --restart=Never
kubectl expose deployment nginx --external-ip="10.0.47.10" --port=8000 --target-port=80
kubectl scale --replicas=3 deployment nginx
kubectl set image deployment nginx nginx=nginx:1.8
kubectl rollout status deploy nginx
kubectl set image deployment nginx nginx=nginx:1.9
kubectl rollout status deploy nginx
kubectl rollout history deploy nginkubectl get --raw /metricsx
```

Let's check rollout history
```bash
kubectl rollout history deploy nginx

deployment.extensions/nginx
REVISION  CHANGE-CAUSE
1         <none>
2         <none>
3         <none>
```

You can undo the rollout of nginx deploy like this:
```bash
kubectl rollout undo deploy nginx
kubectl describe deploy nginx |grep Image
    Image:        nginx:1.8
```

More specifically you can undo the rollout with `--to-revision` option
```bash
kubectl rollout undo deploy nginx --to-revision=1
kubectl describe deploy nginx |grep Image
    Image:        nginx
```

## Get all endpoints in the cluster
```bash
kubectl get endpoints [-A|-n <namespace>]
kubectl get ep [-A|-n <namespace>]
```

## Execute shell commands inside the cluster
You can exec shell commands in a new creating Pod
```bash
kubectl run --generator=run-pod/v1 -it busybox --image=busybox --rm --restart=Never -- sh
```
If you want to run `curl` from a pod (The busybox image above doesn't contain curl)
```bash
kubectl run --generator=run-pod/v1 -it --rm busybox --image=radial/busyboxplus:curl --restart=Never -- sh
```
If you want to debug databases connections from a pod
```bash
kubectl run mysql -it --rm --image=mysql -- mysql -h <host/ip> -P <port> -u <user> -p<password>
```

You can also exec shell commands in existing Pod
```bash
kubectl exec -n <namespace> -it <pod-name> -- /bin/sh
kubectl exec -n <namespace> -it <pod-name> -c <container-name> -- /bin/sh
```

You can change `kind` of the resource you're creating with option in `kubectl run`

| Kind      | Option |
| ----------- | ----------- |
| deployment  | node       |
| pod         | `--restart=Never` |
| job         | `--restart=OnFailure` |
| cronjob     | `--schedule='cron format(0/5 * * * ?'` |


> NOTE: kubernetes 1.18+
> kubectl run has removed previously deprecated flags not related to generator and pod creation. The kubectl run command now only creates pods. To create objects other than Pods, see the specific kubectl create subcommand.
>  So run `kubectl create deployment` in order to create deployment like this:
>```
> kubectl create deployment nginx --image=nginx
>kubectl create deployment nginx --image=nginx --dry-run -o yaml
>```
> see also [kubectl cheat sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)


## Access k8s API endpoint via local proxy

You can access k8s API via local proxy
```bash
# Making local proxy
kubectl proxy
Starting to serve on 127.0.0.1:8001
```

Access k8s API resources via local proxy

```bash
# Get pods list in namespace foo
curl http://localhost:8001/api/v1/namespaces/foo/pods
# Access pod's endpoint
curl http://localhost:8001/api/v1/namespaces/foo/pods/<pod-name>/proxy/<podendpoint>
curl http://localhost:8001/api/v1/namespaces/foo/pods/foo-86c498d84c-xbkn9/proxy/healthcheck
```

## Port forward a local port to a port on k8s resources

```bash
# kubectl port-forward -n <namespace> <resource> LocalPort:TargetPort
kubectl port-forward -n <namespace> redis-master-765d459796-258hz 7000:6379
kubectl port-forward -n <namespace> pods/redis-master-765d459796-258hz 7000:6379
kubectl port-forward -n <namespace> deployment/redis-master 7000:6379
kubectl port-forward -n <namespace> rs/redis-master 7000:6379
kubectl port-forward -n <namespace> svc/redis-master 7000:6379
```
See also [this](https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/) for more detail

## Change the service type to LoadBalancer by patching 

```bash
# kubectl patch svc SERVICE_NAME -p '{"spec": {"type": "LoadBalancer"}}'
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "LoadBalancer"}}'
```

## Delete Kubernetes Resources

```bash
# Delete resources that has name=<label> label
kubectl delete svc,cm,secrets,deploy -l name=<label> -n <namespace>
# Delete all certain resources from a certain namespace
# --all is used to delete every object of that resource type instead of specifying it using its name or label.
kubectl delete svc,cm,secrets,deploy --all -n <namespace>
# Delete all resources (except crd) from a certain namespace
kubectl delete all --all -n <namespace>

# Delete pods in namespace <namespace>
for pod in $(kubectl get po -n <namespace> --no-headers=true | cut -d ' ' -f 1); do
  kubectl delete pod $pod -n <namespace>
done

# Delete pods with --grace-period=0 and --force option
#    Add --grace-period=0 in order to delete pod as quickly as possible
#    Add --force in case that pod stay terminating state and cannnot be deleted
kubectl delete pod <pod> -n <namespace> --grace-period=0 --force
```


## Using finalizers to control deletion

You can delete the k8s object by patching command to remove finalizers. Simply patch it on the command line to remove the finalizers, so the object will be deleted

For example, you want to delete `configmap/mymap`
```bash
kubectl patch configmap/mymap \
    --type json \
    --patch='[ { "op": "remove", "path": "/metadata/finalizers" } ]'
```

![](https://d33wubrfki0l68.cloudfront.net/2921aff96caba07229c862903fea89cbab9ad5a6/8e8fd/images/blog/2021-05-14-using-finalizers-to-control-deletion/state-diagram-finalize.png)
ref: https://kubernetes.io/blog/2021/05/14/using-finalizers-to-control-deletion/

Read [Using Finalizers to Control Deletion](https://kubernetes.io/blog/2021/05/14/using-finalizers-to-control-deletion/) to understand how the object will be deleted by using finalizers
## Delete a worker node in the cluster

A point is to `cordon` a node at first, then to evict pods in the node with `drain`.
```bash
kubectl get nodes  # to get nodename to delete
kubectl cordon <node-name>
kubectl drain --ignore-daemonsets <node-name>
kubectl delete node <node-name>
```
> [NOTE] Add `--ignore-daemonsets` if you want to ignore DaemonSet for eviction

## Evicted all pods in a node for investigation

A point is to `cordon` a node at first, then to evict pods in the node with `drain`, to `uncordon` after the investigation
```bash
kubectl get nodes  # to get nodename to delete
kubectl cordon <node-name>
kubectl drain --ignore-daemonsets <node-name>
```
Now that you evicted all pods in the node, you can do investigation in the node. After the investigation, you can `uncordon` the node with the following command.
```
kubectl uncordon <node-name>
```
> [NOTE] Add `--ignore-daemonsets` if you want to ignore DaemonSet for eviction

## Get Pods Logs
You can get Kubernetes pods logs by running the following commands
```bash
kubectl logs <pod-name> -n <namespace>

# Add -f option if the logs should be streamed
kubectl logs <pod-name> -n <namespace> -f 
kubectl logs <pod-name> -n <namespace> -f --tail 0
```

Or you can use 3rd party OSS tools. For example, you can get `stern` that allows you to aggregate logs of all pods and to filter them by using regular expression like `stern <expression>`
```bash
stern <keyword> -n <namespace>
```

## Get Kubernetes events 

You can Pods' events with the following commands which will show events at the end of the output for the pod (Relatively recent events will appear).

```bash
kubectl describe pod <podname> -n <namespace>
```

```bash
# Get recent events in a specific namespace
kubectl get events -n <namespaces>
kubectl get events -n kube-system

# Get recent events for all resources in the system
# Get events from all namespaces with either --all-namespaces or -A 
kubectl get event --all-namespaces
kubectl get event -A
kubectl get event -A -o wide

# No Pod events
kubectl get events --field-selector involvedObject.kind!=Pod
# Events from a specific Pod
kubectl get events --field-selector involvedObject.kind=Pod,involvedObject.name=<podname>
# Events from a specific Node
kubectl get events --field-selector involvedObject.kind=Node,involvedObject.name=<nodename>

# Warning events (from all namespaces)
kubectl get events --field-selector type=Warning -A
# NOT normal events (from all namespaces)
kubectl get events --field-selector type!=Normal -A
```

## Get Kubernetes Raw Metrics - Prometheus metrics endpoint

Many Kubernetes components exposes their metrics via the `/metrics` endpoint, including API server, etcd and many other add-ons. These metrics are in [Prometheus format](https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md), and can be defined and exposed using [Prometheus client libs](https://prometheus.io/docs/instrumenting/clientlibs/)

```
kubectl get --raw /metrics
```

<details><summary>sample output</summary>
<p>

```
APIServiceOpenAPIAggregationControllerQueue1_adds 282663
APIServiceOpenAPIAggregationControllerQueue1_depth 0
APIServiceOpenAPIAggregationControllerQueue1_longest_running_processor_microseconds 0
APIServiceOpenAPIAggregationControllerQueue1_queue_latency{quantile="0.5"} 63
APIServiceOpenAPIAggregationControllerQueue1_queue_latency{quantile="0.9"} 105
APIServiceOpenAPIAggregationControllerQueue1_queue_latency{quantile="0.99"} 126
APIServiceOpenAPIAggregationControllerQueue1_queue_latency_sum 1.4331448e+07
APIServiceOpenAPIAggregationControllerQueue1_queue_latency_count 282663
APIServiceOpenAPIAggregationControllerQueue1_retries 282861
APIServiceOpenAPIAggregationControllerQueue1_unfinished_work_seconds 0
APIServiceOpenAPIAggregationControllerQueue1_work_duration{quantile="0.5"} 59
APIServiceOpenAPIAggregationControllerQueue1_work_duration{quantile="0.9"} 98
APIServiceOpenAPIAggregationControllerQueue1_work_duration{quantile="0.99"} 2003
APIServiceOpenAPIAggregationControllerQueue1_work_duration_sum 2.1373689e+07
APIServiceOpenAPIAggregationControllerQueue1_work_duration_count 282663
...
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="1e-08"} 0
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="1e-07"} 0
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="1e-06"} 0
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="9.999999999999999e-06"} 459
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="9.999999999999999e-05"} 473
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="0.001"} 924
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="0.01"} 927
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="0.1"} 928
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="1"} 928
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="10"} 928
workqueue_work_duration_seconds_bucket{name="non_structural_schema_condition_controller",le="+Inf"} 928
workqueue_work_duration_seconds_sum{name="non_structural_schema_condition_controller"} 0.09712353499999991
...
```
</p>
</details>


## Get Kubernetes Raw Metrics - metrics API

You can access [Metrics API](https://github.com/kubernetes/metrics) via kubectl proxy like this:

```
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes
kubectl get --raw /apis/metrics.k8s.io/v1beta1/pods
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes/<node-name>
kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/<namespace-name>/pods/<pod-name>
```
(ref: [feiskyer/kubernetes-handbook](https://github.com/feiskyer/kubernetes-handbook/blob/master/en/addons/metrics.md#metrics-api))

Outputs are unformated JSON. It's good to use `jq` to parse it.

<details><summary>sample output -  /apis/metrics.k8s.io/v1beta1/nodes</summary>
<p>

```json
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes | jq

{
  "kind": "NodeMetricsList",
  "apiVersion": "metrics.k8s.io/v1beta1",
  "metadata": {
    "selfLink": "/apis/metrics.k8s.io/v1beta1/nodes"
  },
  "items": [
    {
      "metadata": {
        "name": "ip-xxxxxxxxxx.ap-northeast-1.compute.internal",
        "selfLink": "/apis/metrics.k8s.io/v1beta1/nodes/ip-xxxxxxxxxx.ap-northeast-1.compute.internal",
        "creationTimestamp": "2020-05-24T01:29:05Z"
      },
      "timestamp": "2020-05-24T01:28:58Z",
      "window": "30s",
      "usage": {
        "cpu": "105698348n",
        "memory": "819184Ki"
      }
    },
    {
      "metadata": {
        "name": "ip-yyyyyyyyyy.ap-northeast-1.compute.internal",
        "selfLink": "/apis/metrics.k8s.io/v1beta1/nodes/ip-yyyyyyyyyy.ap-northeast-1.compute.internal",
        "creationTimestamp": "2020-05-24T01:29:05Z"
      },
      "timestamp": "2020-05-24T01:29:01Z",
      "window": "30s",
      "usage": {
        "cpu": "71606060n",
        "memory": "678944Ki"
      }
    }
  ]
}

```

</p>
</details>


<details><summary>sample output - /apis/metrics.k8s.io/v1beta1/namespaces/NAMESPACE/pods/PODNAME </summary>
<p>

```json
kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/kube-system/pods/cluster-autoscaler-7d8d69668c-5rcmt | jq

{
  "kind": "PodMetrics",
  "apiVersion": "metrics.k8s.io/v1beta1",
  "metadata": {
    "name": "cluster-autoscaler-7d8d69668c-5rcmt",
    "namespace": "kube-system",
    "selfLink": "/apis/metrics.k8s.io/v1beta1/namespaces/kube-system/pods/cluster-autoscaler-7d8d69668c-5rcmt",
    "creationTimestamp": "2020-05-24T01:33:17Z"
  },
  "timestamp": "2020-05-24T01:32:58Z",
  "window": "30s",
  "containers": [
    {
      "name": "cluster-autoscaler",
      "usage": {
        "cpu": "1030416n",
        "memory": "27784Ki"
      }
    }
  ]
}

```
</p>
</details>


