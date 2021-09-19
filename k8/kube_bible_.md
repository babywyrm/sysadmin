https://github.com/dennyzhang/cheatsheet-kubernetes-A4

###############################################
#############
#############

* Kubectl Kubernetes CheatSheet                                   :Cloud:
:PROPERTIES:
:type:     kubernetes
:export_file_name: cheatsheet-kubernetes-A4.pdf
:END:

#+BEGIN_HTML
<a href="https://github.com/dennyzhang/cheatsheet-kubernetes-A4"><img align="right" width="200" height="183" src="https://www.dennyzhang.com/wp-content/uploads/denny/watermark/github.png" /></a>
<div id="the whole thing" style="overflow: hidden;">
<div style="float: left; padding: 5px"> <a href="https://www.linkedin.com/in/dennyzhang001"><img src="https://www.dennyzhang.com/wp-content/uploads/sns/linkedin.png" alt="linkedin" /></a></div>
<div style="float: left; padding: 5px"><a href="https://github.com/dennyzhang"><img src="https://www.dennyzhang.com/wp-content/uploads/sns/github.png" alt="github" /></a></div>
<div style="float: left; padding: 5px"><a href="https://www.dennyzhang.com/slack" target="_blank" rel="nofollow"><img src="https://www.dennyzhang.com/wp-content/uploads/sns/slack.png" alt="slack"/></a></div>
</div>

<br/><br/>
<a href="http://makeapullrequest.com" target="_blank" rel="nofollow"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"/></a>
#+END_HTML

- PDF Link: [[https://github.com/dennyzhang/cheatsheet-kubernetes-A4/blob/master/cheatsheet-kubernetes-A4.pdf][cheatsheet-kubernetes-A4.pdf]], Category: [[https://cheatsheet.dennyzhang.com/category/cloud/][Cloud]]
- Blog URL: https://cheatsheet.dennyzhang.com/cheatsheet-kubernetes-A4
- Related posts: [[https://cheatsheet.dennyzhang.com/cheatsheet-kubernetes-A4][Kubectl CheatSheet]], [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Kubernetes Yaml]], [[https://github.com/topics/denny-cheatsheets][#denny-cheatsheets]]

File me [[https://github.com/dennyzhang/cheatsheet.dennyzhang.com/issues][Issues]] or star [[https://github.com/dennyzhang/cheatsheet.dennyzhang.com][this repo]].
** Common Commands
| Name                                 | Command                                                                                   |
|--------------------------------------+-------------------------------------------------------------------------------------------|
| Run curl test temporarily            | =kubectl run --generator=run-pod/v1 --rm mytest --image=yauritux/busybox-curl -it=        |
| Run wget test temporarily            | =kubectl run --generator=run-pod/v1 --rm mytest --image=busybox -it wget=                 |
| Run nginx deployment with 2 replicas | =kubectl run my-nginx --image=nginx --replicas=2 --port=80=                               |
| Run nginx pod and expose it          | =kubectl run my-nginx --restart=Never --image=nginx --port=80 --expose=                   |
| Run nginx deployment and expose it   | =kubectl run my-nginx --image=nginx --port=80 --expose=                                   |
| List authenticated contexts          | =kubectl config get-contexts=, =~/.kube/config=                                           |
| Set namespace preference             | =kubectl config set-context <context_name> --namespace=<ns_name>=                         |
| List pods with nodes info            | =kubectl get pod -o wide=                                                                 |
| List everything                      | =kubectl get all --all-namespaces=                                                        |
| Get all services                     | =kubectl get service --all-namespaces=                                                    |
| Get all deployments                  | =kubectl get deployments --all-namespaces=                                                |
| Show nodes with labels               | =kubectl get nodes --show-labels=                                                         |
| Get resources with json output       | =kubectl get pods --all-namespaces -o json=                                               |
| Validate yaml file with dry run      | =kubectl create --dry-run --validate -f pod-dummy.yaml=                                   |
| Start a temporary pod for testing    | =kubectl run --rm -i -t --image=alpine test-$RANDOM -- sh=                                |
| kubectl run shell command            | =kubectl exec -it mytest -- ls -l /etc/hosts=                                             |
| Get system conf via configmap        | =kubectl -n kube-system get cm kubeadm-config -o yaml=                                    |
| Get deployment yaml                  | =kubectl -n denny-websites get deployment mysql -o yaml=                                  |
| Explain resource                     | =kubectl explain pods=, =kubectl explain svc=                                             |
| Watch pods                           | =kubectl get pods  -n wordpress --watch=                                                  |
| Query healthcheck endpoint           | =curl -L http://127.0.0.1:10250/healthz=                                                  |
| Open a bash terminal in a pod        | =kubectl exec -it storage sh=                                                             |
| Check pod environment variables      | =kubectl exec redis-master-ft9ex env=                                                     |
| Enable kubectl shell autocompletion  | =echo "source <(kubectl completion bash)" >>~/.bashrc=, and reload                        |
| Use minikube dockerd in your laptop  | =eval $(minikube docker-env)=, No need to push docker hub any more                        |
| Kubectl apply a folder of yaml files | =kubectl apply -R -f .=                                                                   |
| Get services sorted by name          | kubectl get services --sort-by=.metadata.name                                             |
| Get pods sorted by restart count     | kubectl get pods --sort-by='.status.containerStatuses[0].restartCount'                    |
| List pods and images                 | kubectl get pods -o='custom-columns=PODS:.metadata.name,Images:.spec.containers[*].image' |
| List all container images            | [[https://github.com/dennyzhang/cheatsheet-kubernetes-A4/blob/master/list-all-images.sh#L14-L17][list-all-images.sh]]                                                                        |
| kubeconfig skip tls verification     | [[https://github.com/dennyzhang/cheatsheet-kubernetes-A4/blob/master/skip-tls-verify.md][skip-tls-verify.md]]                                                                        |
| [[https://kubernetes.io/docs/tasks/tools/install-kubectl/][Ubuntu install kubectl]]               | ="deb https://apt.kubernetes.io/ kubernetes-xenial main"=                                 |
| Reference                            | [[https://github.com/kubernetes/kubernetes/tags][GitHub: kubernetes releases]]                                                               |
| Reference                            | [[https://cheatsheet.dennyzhang.com/cheatsheet-minikube-A4][minikube cheatsheet]], [[https://cheatsheet.dennyzhang.com/cheatsheet-docker-A4][docker cheatsheet]], [[https://cheatsheet.dennyzhang.com/cheatsheet-openshift-A4][OpenShift CheatSheet]]                              |
** Check Performance
| Name                                         | Command                                              |
|----------------------------------------------+------------------------------------------------------|
| Get node resource usage                      | =kubectl top node=                                   |
| Get pod resource usage                       | =kubectl top pod=                                    |
| Get resource usage for a given pod           | =kubectl top <podname> --containers=                 |
| List resource utilization for all containers | =kubectl top pod --all-namespaces --containers=true= |
** Resources Deletion
| Name                                    | Command                                                  |
|-----------------------------------------+----------------------------------------------------------|
| Delete pod                              | =kubectl delete pod/<pod-name> -n <my-namespace>=        |
| Delete pod by force                     | =kubectl delete pod/<pod-name> --grace-period=0 --force= |
| Delete pods by labels                   | =kubectl delete pod -l env=test=                         |
| Delete deployments by labels            | =kubectl delete deployment -l app=wordpress=             |
| Delete all resources filtered by labels | =kubectl delete pods,services -l name=myLabel=           |
| Delete resources under a namespace      | =kubectl -n my-ns delete po,svc --all=                   |
| Delete persist volumes by labels        | =kubectl delete pvc -l app=wordpress=                    |
| Delete state fulset only (not pods)     | =kubectl delete sts/<stateful_set_name> --cascade=false= |
#+BEGIN_HTML
<a href="https://cheatsheet.dennyzhang.com"><img align="right" width="185" height="37" src="https://raw.githubusercontent.com/dennyzhang/cheatsheet.dennyzhang.com/master/images/cheatsheet_dns.png"></a>
#+END_HTML
** Log & Conf Files
| Name                      | Comment                                                                   |
|---------------------------+---------------------------------------------------------------------------|
| Config folder             | =/etc/kubernetes/=                                                        |
| Certificate files         | =/etc/kubernetes/pki/=                                                    |
| Credentials to API server | =/etc/kubernetes/kubelet.conf=                                            |
| Superuser credentials     | =/etc/kubernetes/admin.conf=                                              |
| kubectl config file       | =~/.kube/config=                                                          |
| Kubernetes working dir    | =/var/lib/kubelet/=                                                       |
| Docker working dir        | =/var/lib/docker/=, =/var/log/containers/=                                |
| Etcd working dir          | =/var/lib/etcd/=                                                          |
| Network cni               | =/etc/cni/net.d/=                                                         |
| Log files                 | =/var/log/pods/=                                                          |
| log in worker node        | =/var/log/kubelet.log=, =/var/log/kube-proxy.log=                         |
| log in master node        | =kube-apiserver.log=, =kube-scheduler.log=, =kube-controller-manager.log= |
| Env                       | =/etc/systemd/system/kubelet.service.d/10-kubeadm.conf=                   |
| Env                       | export KUBECONFIG=/etc/kubernetes/admin.conf                              |
** Pod
| Name                         | Command                                                                                   |
|------------------------------+-------------------------------------------------------------------------------------------|
| List all pods                | =kubectl get pods=                                                                        |
| List pods for all namespace  | =kubectl get pods -all-namespaces=                                                        |
| List all critical pods       | =kubectl get -n kube-system pods -a=                                                      |
| List pods with more info     | =kubectl get pod -o wide=, =kubectl get pod/<pod-name> -o yaml=                           |
| Get pod info                 | =kubectl describe pod/srv-mysql-server=                                                   |
| List all pods with labels    | =kubectl get pods --show-labels=                                                          |
| [[https://github.com/kubernetes/kubernetes/issues/49387][List all unhealthy pods]]      | kubectl get pods --field-selector=status.phase!=Running --all-namespaces                  |
| List running pods            | kubectl get pods --field-selector=status.phase=Running                                    |
| Get Pod initContainer status | =kubectl get pod --template '{{.status.initContainerStatuses}}' <pod-name>=               |
| kubectl run command          | kubectl exec -it -n "$ns" "$podname" -- sh -c "echo $msg >>/dev/err.log"                  |
| Watch pods                   | =kubectl get pods  -n wordpress --watch=                                                  |
| Get pod by selector          | kubectl get pods --selector="app=syslog" -o jsonpath='{.items[*].metadata.name}'          |
| List pods and images         | kubectl get pods -o='custom-columns=PODS:.metadata.name,Images:.spec.containers[*].image' |
| List pods and containers     | -o='custom-columns=PODS:.metadata.name,CONTAINERS:.spec.containers[*].name'               |
| Reference                    | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]]                                                           |
** Label & Annotation
| Name                             | Command                                                           |
|----------------------------------+-------------------------------------------------------------------|
| Filter pods by label             | =kubectl get pods -l owner=denny=                                 |
| Manually add label to a pod      | =kubectl label pods dummy-input owner=denny=                      |
| Remove label                     | =kubectl label pods dummy-input owner-=                           |
| Manually add annotation to a pod | =kubectl annotate pods dummy-input my-url=https://dennyzhang.com= |
** Deployment & Scale
| Name                         | Command                                                                  |
|------------------------------+--------------------------------------------------------------------------|
| Scale out                    | =kubectl scale --replicas=3 deployment/nginx-app=                        |
| online rolling upgrade       | =kubectl rollout app-v1 app-v2 --image=img:v2=                           |
| Roll backup                  | =kubectl rollout app-v1 app-v2 --rollback=                               |
| List rollout                 | =kubectl get rs=                                                         |
| Check update status          | =kubectl rollout status deployment/nginx-app=                            |
| Check update history         | =kubectl rollout history deployment/nginx-app=                           |
| Pause/Resume                 | =kubectl rollout pause deployment/nginx-deployment=, =resume=            |
| Rollback to previous version | =kubectl rollout undo deployment/nginx-deployment=                       |
| Reference     | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]], [[https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#pausing-and-resuming-a-deployment][Link: Pausing and Resuming a Deployment]] |
#+BEGIN_HTML
<a href="https://cheatsheet.dennyzhang.com"><img align="right" width="185" height="37" src="https://raw.githubusercontent.com/dennyzhang/cheatsheet.dennyzhang.com/master/images/cheatsheet_dns.png"></a>
#+END_HTML
** Quota & Limits & Resource
| Name                          | Command                                                                 |
|-------------------------------+-------------------------------------------------------------------------|
| List Resource Quota           | =kubectl get resourcequota=                                             |
| List Limit Range              | =kubectl get limitrange=                                                |
| Customize resource definition | =kubectl set resources deployment nginx -c=nginx --limits=cpu=200m=     |
| Customize resource definition | =kubectl set resources deployment nginx -c=nginx --limits=memory=512Mi= |
| Reference                     | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]]                                         |
** Service
| Name                            | Command                                                                           |
|---------------------------------+-----------------------------------------------------------------------------------|
| List all services               | =kubectl get services=                                                            |
| List service endpoints          | =kubectl get endpoints=                                                           |
| Get service detail              | =kubectl get service nginx-service -o yaml=                                       |
| Get service cluster ip          | kubectl get service nginx-service -o go-template='{{.spec.clusterIP}}'            |
| Get service cluster port        | kubectl get service nginx-service -o go-template='{{(index .spec.ports 0).port}}' |
| Expose deployment as lb service | =kubectl expose deployment/my-app --type=LoadBalancer --name=my-service=          |
| Expose service as lb service    | =kubectl expose service/wordpress-1-svc --type=LoadBalancer --name=ns1=           |
| Reference                       | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]]                                                   |
** Secrets
| Name                             | Command                                                                 |
|----------------------------------+-------------------------------------------------------------------------|
| List secrets                     | =kubectl get secrets --all-namespaces=                                  |
| Generate secret                  | =echo -n 'mypasswd', then redirect to base64 --decode=                  |
| Get secret                       | =kubectl get secret denny-cluster-kubeconfig=                           |
| Get a specific field of a secret | kubectl get secret denny-cluster-kubeconfig -o jsonpath="{.data.value}" |
| Create secret from cfg file      | kubectl create secret generic db-user-pass --from-file=./username.txt   |
| Reference                        | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]], [[https://kubernetes.io/docs/concepts/configuration/secret/][Link: Secrets]]                          |
** StatefulSet
| Name                               | Command                                                  |
|------------------------------------+----------------------------------------------------------|
| List statefulset                   | =kubectl get sts=                                        |
| Delete statefulset only (not pods) | =kubectl delete sts/<stateful_set_name> --cascade=false= |
| Scale statefulset                  | =kubectl scale sts/<stateful_set_name> --replicas=5=     |
| Reference                          | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]]                          |
** Volumes & Volume Claims
| Name                      | Command                                                      |
|---------------------------+--------------------------------------------------------------|
| List storage class        | =kubectl get storageclass=                                   |
| Check the mounted volumes | =kubectl exec storage ls /data=                              |
| Check persist volume      | =kubectl describe pv/pv0001=                                 |
| Copy local file to pod    | =kubectl cp /tmp/my <some-namespace>/<some-pod>:/tmp/server= |
| Copy pod file to local    | =kubectl cp <some-namespace>/<some-pod>:/tmp/server /tmp/my= |
| Reference  | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]]                              |
** Events & Metrics
| Name                            | Command                                                    |
|---------------------------------+------------------------------------------------------------|
| View all events                 | =kubectl get events --all-namespaces=                      |
| List Events sorted by timestamp | kubectl get events --sort-by=.metadata.creationTimestamp   |
** Node Maintenance
| Name                                      | Command                       |
|-------------------------------------------+-------------------------------|
| Mark node as unschedulable                | =kubectl cordon $NODE_NAME=   |
| Mark node as schedulable                  | =kubectl uncordon $NODE_NAME= |
| Drain node in preparation for maintenance | =kubectl drain $NODE_NAME=    |
** Namespace & Security
| Name                          | Command                                                                                             |
|-------------------------------+-----------------------------------------------------------------------------------------------------|
| List authenticated contexts   | =kubectl config get-contexts=, =~/.kube/config=                                                     |
| Set namespace preference      | =kubectl config set-context <context_name> --namespace=<ns_name>=                                   |
| Switch context                | =kubectl config use-context <context_name>=                                                         |
| Load context from config file | =kubectl get cs --kubeconfig kube_config.yml=                                                       |
| Delete the specified context  | =kubectl config delete-context <context_name>=                                                      |
| List all namespaces defined   | =kubectl get namespaces=                                                                            |
| List certificates             | =kubectl get csr=                                                                                   |
| [[https://kubernetes.io/docs/concepts/policy/pod-security-policy/][Check user privilege]]          | kubectl --as=system:serviceaccount:ns-denny:test-privileged-sa -n ns-denny auth can-i use pods/list |
| [[https://kubernetes.io/docs/concepts/policy/pod-security-policy/][Check user privilege]]          | =kubectl auth can-i use pods/list=                                                                  |
| Reference                     | [[https://cheatsheet.dennyzhang.com/kubernetes-yaml-templates][Link: kubernetes yaml templates]]                                                                     |
** Network
| Name                              | Command                                                  |
|-----------------------------------+----------------------------------------------------------|
| Temporarily add a port-forwarding  | =kubectl port-forward redis-134 6379:6379=               |
| Add port-forwarding for deployment | =kubectl port-forward deployment/redis-master 6379:6379= |
| Add port-forwarding for replicaset | =kubectl port-forward rs/redis-master 6379:6379=         |
| Add port-forwarding for service    | =kubectl port-forward svc/redis-master 6379:6379=        |
| Get network policy                | =kubectl get NetworkPolicy=                              |
** Patch
| Name                          | Summary                                                             |
|-------------------------------+---------------------------------------------------------------------|
| Patch service to loadbalancer | kubectl patch svc $svc_name -p '{"spec": {"type": "LoadBalancer"}}' |
** Extenstions
| Name                                    | Summary                    |
|-----------------------------------------+----------------------------|
| Enumerates the resource types available | =kubectl api-resources=    |
| List api group                          | =kubectl api-versions=     |
| List all CRD                            | =kubectl get crd=          |
| List storageclass                       | =kubectl get storageclass= |
#+BEGIN_HTML
<a href="https://cheatsheet.dennyzhang.com"><img align="right" width="185" height="37" src="https://raw.githubusercontent.com/dennyzhang/cheatsheet.dennyzhang.com/master/images/cheatsheet_dns.png"></a>
#+END_HTML
** Components & Services
*** Services on Master Nodes
| Name                     | Summary                                                                                    |
|--------------------------+--------------------------------------------------------------------------------------------|
| [[https://github.com/kubernetes/kubernetes/tree/master/cmd/kube-apiserver][kube-apiserver]]           | API gateway. Exposes the Kubernetes API from master nodes                                  |
| [[https://coreos.com/etcd/][etcd]]                     | reliable data store for all k8s cluster data                                               |
| [[https://github.com/kubernetes/kubernetes/tree/master/cmd/kube-scheduler][kube-scheduler]]           | schedule pods to run on selected nodes                                                     |
| [[https://github.com/kubernetes/kubernetes/tree/master/cmd/kube-controller-manager][kube-controller-manager]]  | Reconcile the states. node/replication/endpoints/token controller and service account, etc |
| cloud-controller-manager |                                                                                            |
*** Services on Worker Nodes
| Name              | Summary                                                                                      |
|-------------------+----------------------------------------------------------------------------------------------|
| [[https://github.com/kubernetes/kubernetes/tree/master/cmd/kubelet][kubelet]]           | A node agent makes sure that containers are running in a pod                                 |
| [[https://github.com/kubernetes/kubernetes/tree/master/cmd/kube-proxy][kube-proxy]]        | Manage network connectivity to the containers. e.g, iptable, ipvs                            |
| [[https://github.com/docker/engine][Container Runtime]] | Kubernetes supported runtimes: dockerd, cri-o, runc and any [[https://github.com/opencontainers/runtime-spec][OCI runtime-spec]] implementation. |

*** Addons: pods and services that implement cluster features
| Name                          | Summary                                                                   |
|-------------------------------+---------------------------------------------------------------------------|
| DNS                           | serves DNS records for Kubernetes services                                |
| Web UI                        | a general purpose, web-based UI for Kubernetes clusters                   |
| Container Resource Monitoring | collect, store and serve container metrics                                |
| Cluster-level Logging         | save container logs to a central log store with search/browsing interface |

*** Tools
| Name                  | Summary                                                     |
|-----------------------+-------------------------------------------------------------|
| [[https://github.com/kubernetes/kubernetes/tree/master/cmd/kubectl][kubectl]]               | the command line util to talk to k8s cluster                |
| [[https://github.com/kubernetes/kubernetes/tree/master/cmd/kubeadm][kubeadm]]               | the command to bootstrap the cluster                        |
| [[https://kubernetes.io/docs/reference/setup-tools/kubefed/kubefed/][kubefed]]               | the command line to control a Kubernetes Cluster Federation |
| Kubernetes Components | [[https://kubernetes.io/docs/concepts/overview/components/][Link: Kubernetes Components]]                                 |
** More Resources
License: Code is licensed under [[https://www.dennyzhang.com/wp-content/mit_license.txt][MIT License]].

https://kubernetes.io/docs/reference/kubectl/cheatsheet/

https://codefresh.io/kubernetes-guides/kubernetes-cheat-sheet/

#+BEGIN_HTML
<a href="https://cheatsheet.dennyzhang.com"><img align="right" width="201" height="268" src="https://raw.githubusercontent.com/USDevOps/mywechat-slack-group/master/images/denny_201706.png"></a>
<a href="https://cheatsheet.dennyzhang.com"><img align="right" src="https://raw.githubusercontent.com/dennyzhang/cheatsheet.dennyzhang.com/master/images/cheatsheet_dns.png"></a>

<a href="https://www.linkedin.com/in/dennyzhang001"><img align="bottom" src="https://www.dennyzhang.com/wp-content/uploads/sns/linkedin.png" alt="linkedin" /></a>
<a href="https://github.com/dennyzhang"><img align="bottom"src="https://www.dennyzhang.com/wp-content/uploads/sns/github.png" alt="github" /></a>
<a href="https://www.dennyzhang.com/slack" target="_blank" rel="nofollow"><img align="bottom" src="https://www.dennyzhang.com/wp-content/uploads/sns/slack.png" alt="slack"/></a>
#+END_HTML
* org-mode configuration                                           :noexport:
#+STARTUP: overview customtime noalign logdone showall
#+DESCRIPTION:
#+KEYWORDS:
#+LATEX_HEADER: \usepackage[margin=0.6in]{geometry}
#+LaTeX_CLASS_OPTIONS: [8pt]
#+LATEX_HEADER: \usepackage[english]{babel}
#+LATEX_HEADER: \usepackage{lastpage}
#+LATEX_HEADER: \usepackage{fancyhdr}
#+LATEX_HEADER: \pagestyle{fancy}
#+LATEX_HEADER: \fancyhf{}
#+LATEX_HEADER: \rhead{Updated: \today}
#+LATEX_HEADER: \rfoot{\thepage\ of \pageref{LastPage}}
#+LATEX_HEADER: \lfoot{\href{https://github.com/dennyzhang/cheatsheet-kubernetes-A4}{GitHub: https://github.com/dennyzhang/cheatsheet-kubernetes-A4}}
#+LATEX_HEADER: \lhead{\href{https://cheatsheet.dennyzhang.com/cheatsheet-kubernetes-A4}{Blog URL: https://cheatsheet.dennyzhang.com/cheatsheet-kubernetes-A4}}
#+AUTHOR: Denny Zhang
#+EMAIL:  denny@dennyzhang.com
#+TAGS: noexport(n)
#+PRIORITIES: A D C
#+OPTIONS:   H:3 num:t toc:nil \n:nil @:t ::t |:t ^:t -:t f:t *:t <:t
#+OPTIONS:   TeX:t LaTeX:nil skip:nil d:nil todo:t pri:nil tags:not-in-toc
#+EXPORT_EXCLUDE_TAGS: exclude noexport
#+SEQ_TODO: TODO HALF ASSIGN | DONE BYPASS DELEGATE CANCELED DEFERRED
#+LINK_UP:
#+LINK_HOME:
* #  --8<-------------------------- separator ------------------------>8-- :noexport:
* DONE Misc scripts                                                :noexport:
  CLOSED: [2018-11-17 Sat 12:23]
- Tail pod log by label
#+BEGIN_SRC sh
namespace="mynamespace"
mylabel="app=mylabel"
kubectl get pod -l "$mylabel" -n "$namespace" | tail -n1 \
    | awk -F' ' '{print $1}' | xargs -I{} \
      kubectl logs -n "$namespace" -f {}
#+END_SRC

- Get node hardware resource utilization
#+BEGIN_SRC sh
kubectl get nodes --no-headers \
     | awk '{print $1}' | xargs -I {} \
     sh -c 'echo {}; kubectl describe node {} | grep Allocated -A 5'

kubectl get nodes --no-headers | awk '{print $1}' | xargs -I {} \
    sh -c 'echo {}; kubectl describe node {} | grep Allocated -A 5 \
     | grep -ve Event -ve Allocated -ve percent -ve -- ; echo'
#+END_SRC

- Apply the configuration in manifest.yaml and delete all the other configmaps that are not in the file.

#+BEGIN_EXAMPLE
kubectl apply --prune -f manifest.yaml --all --prune-whitelist=core/v1/ConfigMap
#+END_EXAMPLE
* [#A] Kubernetes                                         :noexport:IMPORTANT:
https://github.com/dennyzhang/cheatsheet-kubernetes-A4

k8s provides declarative primitives for the "desired state"
- Self-healing
- Horizontal scaling
- Automatic binpacking
- Service discovery and load balancing
** Names of certificates files
https://github.com/kubernetes/kubeadm/blob/master/docs/design/design_v1.9.md
Names of certificates files:
ca.crt, ca.key (CA certificate)
apiserver.crt, apiserver.key (API server certificate)
apiserver-kubelet-client.crt, apiserver-kubelet-client.key (client certificate for the apiservers to connect to the kubelets securely)
sa.pub, sa.key (a private key for signing ServiceAccount )
front-proxy-ca.crt, front-proxy-ca.key (CA for the front proxy)
front-proxy-client.crt, front-proxy-client.key (client cert for the front proxy client)
** TODO update k8s cheatsheet github: https://github.com/alex1x/kubernetes-cheatsheet
** TODO Setting up MySQL Replication Clusters in Kubernetes: https://blog.kublr.com/setting-up-mysql-replication-clusters-in-kubernetes-ab7cbac113a5
** TODO MySQL on Docker: Running Galera Cluster on Kubernetes
https://severalnines.com/blog/mysql-docker-running-galera-cluster-kubernetes
** TODO Try Functions as a Service - a serverless framework for Docker & Kubernetes http://docs.get-faas.com/
https://blog.alexellis.io/first-faas-python-function/
** TODO [#A] k8s clustering elasticsearch
https://blog.alexellis.io/kubernetes-kubeadm-video/
** TODO k8s scale with redis
** TODO k8s scale with mysqld
** TODO [#A] k8s: https://5pi.de/2016/11/20/15-producation-grade-kubernetes-cluster/
** TODO Try kops with k8s
** TODO k8s free course: https://classroom.udacity.com/courses/ud615
** TODO feedbackup for k8s study project
Aaron Mulholland [1:18 AM]
So it looks pretty good. Got some good concepts in early on. Couple of suggestions for further work;

Potentially the following scenarios;
    * Setting up ingresses and TLS
              * Fully configure something like Nginx Ingress Controller or Traefik.
              * Create TLS Secrets within Kubernetes, and use them in your ingress controller.
    * Managing RBAC  (Don't know enough about this one, but sounds like a good concept to include)
              * Creating new roles, etc

I'll have a think and if anymore come to me, I'll let you know.
  
#########################
#########################
