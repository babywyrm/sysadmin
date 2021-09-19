## reference
* https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands

## cheatsheet
* https://cloud.google.com/anthos/gke/docs/on-prem/reference/cheatsheet
* https://medium.com/flant-com/kubectl-commands-and-tips-7b33de0c5476
* https://prefetch.net/blog/2019/10/16/the-beginners-guide-to-creating-kubernetes-manifests/
* https://kubernetes.io/docs/user-guide/kubectl-cheatsheet/
* https://learnk8s.io/blog/kubectl-productivity/
* https://medium.com/faun/kubectl-commands-cheatsheet-43ce8f13adfb
* https://gist.github.com/so0k/42313dbb3b547a0f51a547bb968696ba
* https://github.com/dennyzhang/cheatsheet-kubernetes-A4
* https://medium.com/bitnami-perspectives/imperative-declarative-and-a-few-kubectl-tricks-9d6deabdde
* http://blog.kubernetes.io/2015/10/some-things-you-didnt-know-about-kubectl_28.html

## cool gear to have
* https://medium.com/@KarlKFI/a-select-list-of-kubernetes-tools-38249fc27155
* https://medium.com/free-code-camp/how-to-set-up-a-serious-kubernetes-terminal-dd07cab51cd4
* https://github.com/kubernetes-sigs/krew-index/blob/master/plugins.md

## imperative
* https://kubernetes.io/docs/tasks/manage-kubernetes-objects/imperative-command/
* https://medium.com/better-programming/kubernetes-tips-create-pods-with-imperative-commands-in-1-18-62ea6e1ceb32
* https://medium.com/bitnami-perspectives/imperative-declarative-and-a-few-kubectl-tricks-9d6deabdde
* https://blog.heptio.com/using-kubectl-to-jumpstart-a-yaml-file-heptioprotip-6f5b8a63a3ea

## debug
* https://ahmet.im/blog/kubectl-man-in-the-middle/

## context, namespace
```
 get current context: kubectl config view -o=jsonpath='{.current-context}'
 get all contexts:  kubectl config get-contexts -o=name | sort -n
 get namesapce:  kubectl get namespaces -o=jsonpath='{range .items[*].metadata.name}{@}{"\n"}{end}'
 
kubectl config use-context <cluster_name_in_kubeconfig>
kubectl --context <context>

## set the namespace for the current context
kubectl config set-context gke_sandbox-co_us-west1-a_cka --namespace=kube-system
kubectl config set-context --current --namespace=kube-system
```
 
## API 
* https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/
* api group https://kubernetes.io/docs/reference/using-api/api-overview/#api-groups

```
# Print the supported API group and its versions on the server, in the form of "group/version"
k api-versions | sort 

# list api-resources with sorting
kubectl api-resources --sort-by=name 
kubectl api-resources --sort-by=kind

# find out what is under the api group

k api-resources --api-group apps
NAME                  SHORTNAMES   APIGROUP   NAMESPACED   KIND
controllerrevisions                apps       true         ControllerRevision
daemonsets            ds           apps       true         DaemonSet
deployments           deploy       apps       true         Deployment
replicasets           rs           apps       true         ReplicaSet
statefulsets          sts          apps       true         StatefulSet

k api-resources --api-group extensions
NAME        SHORTNAMES   APIGROUP     NAMESPACED   KIND
ingresses   ing          extensions   true         Ingress

k api-resources --api-group=batch
NAME       SHORTNAMES   APIGROUP   NAMESPACED   KIND
cronjobs   cj           batch      true         CronJob
jobs                    batch      true         Job

k api-resources --api-group=networking.k8s.io
NAME              SHORTNAMES   APIGROUP            NAMESPACED   KIND
ingressclasses                 networking.k8s.io   false        IngressClass
ingresses         ing          networking.k8s.io   true         Ingress
networkpolicies   netpol       networking.k8s.io   true         NetworkPolicy

# so we have group networking.k8s.io from api-resource, version (v1) from api-version, now we can explain
k explain ingress --api-version=networking.k8s.io/v1 --recursive

k explain --api-version=apps/v1 deployment --recursive

# for each "group/version" in the output above except for "api/v1"
kubectl get --raw /apis/group/version |  jq -r '.resources[].kind'

kubectl get --raw /apis/apps/v1 | jq . -C | less -R

```

### list resources under a specific api version.
This is due to API deprecations
* https://github.com/kubernetes/kubernetes/issues/58131#issuecomment-356823588

```
kubectl get deployments.v1.apps
```

## secret
```
echo $(kubectl get secret/terraform -o jsonpath="{.data['terraform\.json']}" | base64 --decode)
```

## Play with jid and jq
* https://gist.github.com/so0k/42313dbb3b547a0f51a547bb968696ba
* https://kubernetes.io/docs/tasks/access-application-cluster/list-all-running-container-images/

```

grace=$(kubectl get po cassandra-0 -o=jsonpath=‘{.spec.terminationGracePeriodSeconds}’) 
grace=$(kubectl get sts -l component=elasticsearch,role=data -o jsonpath='{..terminationGracePeriodSeconds}'

kubectl get svc -l component=elasticsearch,role=client -o jsonpath='{..ip}'
kubectl get pods -o jsonpath="{..image}"
kubectl get pods -o jsonpath="{.items[*].spec.containers[*].image}"
kubectl get pods -o jsonpath='{.items[*].status.podIP}'
kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}' | tr " " "\n"
kubectl get nodes -o json | jq '.items[] | .spec'
kubectl get no -o go-template='{{range .items}}{{.spec.podCIDR}}{{"\n"}}{{end}}'
kubectl get pods -o jsonpath='{range .items[*]}{"\n"}{.metadata.name}{":\t"}{range .spec.containers[*]}{.image}{", "}{end}{end}'
kubectl get pods -o go-template --template="{{range .items}}{{range .spec.containers}}{{.image}} {{end}}{{end}}"

kubectl get pods --all-namespaces -o jsonpath="{..image}" |\
tr -s '[[:space:]]' '\n' |\
sort |\
uniq -c
```
## custom-columns 
```
k get po -A -o=custom-columns='DATA:spec.containers[*].image'
kubectl get pv --sort-by=.spec.capacity.storage -o=custom-columns="NAME:.metadata.name,CAPACITY:.spec.capacity.storage"
k get deployment -o custom-columns='IMAGE:.spec.template.spec.containers[*].image,LABEL:.spec.template.metadata.labels.k8s-app' -n kube-system
```
## sort-by

```
kubectl get po --sort-by=.spec.nodeName -o wide
kubectl get po --sort-by=".metadata.creationTimestamp"
```

## Get the TCP LB port and IP
```
  EXT_IP="$(kubectl get svc hello-server -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')"
  EXT_PORT=$(kubectl --namespace default get service hello-server -o=jsonpath='{.spec.ports[0].port}')
  echo "$EXT_IP:$EXT_PORT"
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$EXT_IP:$EXT_PORT"/)" -eq 200 ] || exit 1
```


## deployment

### rollout 
```
kubectl rollout pause deployment/hello
kubectl rollout status deployment/hello
# check the versions on pods
kubectl get pods -o jsonpath --template='{range .items[*]}{.metadata.name}{"\t"}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
kubectl rollout resume deployment/hello
# roll back
kubectl rollout undo deployment/hello
```
## find top resource hungry pod
```
# cpu
k top pods --sort-by=cpu
kubectl top pods -A | sort -rn -k 3
# memory
kubectl top pods -A | sort -rn -k 4
# top 1
kubectl top pod | grep -v NAME | sort -k 3 -nr | awk -F ' ' 'NR==1{print $1}'
```
## rbac
```
k auth can-i get crd
k auth can-i '*' '*' --all-namespaces
k auth can-i get crd --as system:serviceaccount:velero:velero
k auth can-i '*' '*' --as system:serviceaccount:default:remote-admin-sa --all-namespaces

# with krew plugins

## check out rbac roles for a given user/group,sa

## first find out what we have 
k rbac-lookup -k user
k rbac-lookup -k group
k rbac-lookup -k serviceaccount
# then find out what velero can do
k rbac-lookup velero -o wide

# from resource perspective
k who-can list '*'
k who-can create customresourcedefinition

## access matrix for user/group,sa
k access-matrix --sa default:deployer
k access-matrix --sa kube-system:kube-state-metrics

##########################
##
##

Kubernetes
==========

## Install

### Prerequisites
1. Bash v5+ checkout [Upgrading Bash on macOS](https://itnext.io/upgrading-bash-on-macos-7138bd1066ba)
2. bash-completion@2

### Install Docker and Kubernetes(k8s)
> Installing *Docker* and *Kubernetes* on **MacOS** is eazy. 

Download and install `Docker for Mac` **Edge** Version. [Download Link](https://hub.docker.com/editions/community/docker-ce-desktop-mac)

After installation, you get `Docker` engine with option to enable `Kubernetes` and `kubectl` cli tool on your `MacOS`.

### Install bash-completion for MacOS (Bash v5+)
```bash
brew install bash-completion@2
```
Paste this into your ~/.extra or ~/.bash_profile  file:
```bash
# bash-completion used with Bash v5+
export BASH_COMPLETION_COMPAT_DIR="/usr/local/etc/bash_completion.d"
[[ -r "/usr/local/etc/profile.d/bash_completion.sh" ]] && . "/usr/local/etc/profile.d/bash_completion.sh"
```

### Enable kubectl auto-completion for MacOS (Bash v5+)
```bash
kubectl completion bash > $(brew --prefix)/etc/bash_completion.d/kubectl
alias k=kubectl
complete -F __start_kubectl k
```

### Creating a Kubernetes cluster
1. After Docker for Mac is installed, configure it with sufficient resources. You can do that via the [Advanced menu](https://docs.docker.com/docker-for-mac/#advanced) in Docker for Mac's preferences. Set **CPUs** to at least **4** and Memory to at least **8.0 GiB**.
2. Now enable Docker for Mac's [Kubernetes capabilities](https://docs.docker.com/docker-for-mac/#kubernetes) and wait for the cluster to start up.
3. Install [kubernetic](https://kubernetic.com/) app. This works as replacement for `kubernetes-dashboard`
4. Follow instructions [here](https://github.com/knative/docs/blob/master/install/Knative-with-Docker-for-Mac.md) and [here](https://polarsquad.github.io/istio-workshop/) to setup **Istio** and **Knative**. 

---

## Install Tools (Optional)


### Skaffold
  [Skaffold](https://skaffold.dev/docs/) is a command line tool (from Google) that facilitates continuous development for Kubernetes applications.
  It also provides building blocks and describe customizations for a CI/CD pipeline.
```bash
brew install skaffold
skaffold version
```

### Helm
  [helm][1] has client-side cli and server-side `tiller` components
  
  Install Helm via `brew`. More info [Here](https://collabnix.com/kubernetes-application-deployment-made-easy-using-helm-on-docker-for-mac-18-05/)
  
```bash
# install helm cli on mac with brew
brew install kubernetes-helm
```
#### To begin working with Helm 
  install tiller into the kube-system
  This will install Tiller to your running Kubernetes cluster.
  It will also set up any necessary local configuration.
```bash
helm init
```

#### Check if it is working 
```
# check version
helm version
# show if tiller is installed
kubectl get pods --namespace kube-system
# upgrade helm version
helm init --upgrade
```

#### Using Helm
```
# update charts repo
helm repo update

# install postgre chart
# helm install --name nginx stable/nginx-ingress
helm install --name pg --namespace default --set postgresPassword=postgres,persistence.size=1Gi stable/postgresql
kubectl get pods -n default

# list installed charts
helm ls

# delete postgre
$ helm delete my-postgre

# delete postgre and purge
$ helm delete --purge my-postgre
```

#### You can also create your own Chart by using the scaffolding command 
```bash
helm create mychart
```
  This will create a folder which includes all the files necessary to create your own package :
```
├── Chart.yaml
├── templates
│   ├── NOTES.txt
│   ├── _helpers.tpl
│   ├── deployment.yaml
│   ├── ingress.yaml
│   └── service.yaml
└── values.yaml
```

#### optionally add `helm-secrets` [plugin](https://developer.epages.com/blog/tech-stories/kubernetes-deployments-with-helm-secrets/)

```bash
helm plugin install https://github.com/futuresimple/helm-secrets 
```

### Ingress Controller with Traefik
> based on [Docker for Mac with Kubernetes — Ingress Controller with Traefik](https://medium.com/@thms.hmm/docker-for-mac-with-kubernetes-ingress-controller-with-traefik-e194919591bb)

`cd .deploy/traefik`
    
1. Create a file called `traefik-values.yaml`.
    ```yaml
    dashboard:
      enabled: true
      domain: traefik.k8s
    ssl:
      enabled: true
      insecureSkipVerify: true
    kubernetes:
      namespaces:
        - default
        - kube-system
    ```

2. Install the Traefik Chart and check if the pod is up and running.
    ```bash
    helm install stable/traefik --name=traefik --namespace=kube-system -f traefik-values.yaml
    kubectl get pods --namespace=kube-system
    kubectl get ingress traefik-dashboard --namespace=kube-system -o yaml
    # to see traefik logs
    kubectl logs $(kubectl get pods --namespace=kube-system -lapp=traefik -o jsonpath='{.items[0].metadata.name}') -f --namespace=kube-system
    # To update, if you change `traefik-values.yaml` later
    helm upgrade --namespace=kube-system  -f traefik-values.yaml traefik stable/traefik
    ```

3. Add your domains to MacOS `/etc/hosts` as needed. Other options:  `wildcard DNS in localhost development` [1](https://gist.github.com/eloypnd/5efc3b590e7c738630fdcf0c10b68072), [2](https://medium.com/localz-engineering/kubernetes-traefik-locally-with-a-wildcard-certificate-e15219e5255d)

    ```
    127.0.0.1       localhost traefik.k8s web.traefik.k8s keycloak.traefik.k8s 
    ```

4. Deploying the K8s dashboard and check if the pod is up and running.
    ```
    cd .deploy/traefik
    git clone https://github.com/thmshmm/chart-k8s-dashboard.git k8s-dshbrd/
    helm install k8s-dshbrd --name kubernetes-dashboard --namespace=kube-system
    kubectl get ingress kubernetes-dashboard --namespace=kube-system -o yaml
    ```


### kompose
> cli tool to conver Docker Compose files to Kubernetes
```bash
# install
brew install kompose
# to use
kompose convert -f docker-compose.yaml
```

### kube-ps1
optionally add Kubernetes prompt info for bash
```bash
brew install kube-ps1
```

### Kubefwd
> [kubefwd](https://github.com/txn2/kubefwd) is a command line utility built to port forward some or all pods within a Kubernetes namespace
#### Install
```bash
# If you are running MacOS and use homebrew you can install kubefwd directly from the txn2 tap:
brew install txn2/tap/kubefwd
# To upgrade
brew upgrade kubefwd
```
#### Usage
```bash
# Forward all services for the namespace the-project:
sudo kubefwd services -n the-project
# Forward all services for the namespace the-project where labeled system: wx:
sudo kubefwd services -l system=wx -n the-project
```

---

## Usage 

### kubectl Cheat Sheets
> To read more on kubectl, check out the [Kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/).


### Kubectl commands
> commonly used Kubectl commands

> you can pratice kubectl commands at [katacoda](https://www.katacoda.com/courses/kubernetes/playground) playground

```
kubectl version
kubectl cluster-info
kubectl get storageclass
kubectl get nodes
kubectl get ep kube-dns --namespace=kube-system
kubectl get persistentvolume
kubectl get  PersistentVolumeClaim --namespace default
kubectl get pods --namespace kube-system
kubectl get ep
kubectl get sa
kubectl get serviceaccount
kubectl get clusterroles
kubectl get roles
kubectl get ClusterRoleBinding
# Show Merged kubeconfig settings.
kubectl config view
kubectl config get-contexts
# Display the current-context
kubectl config current-context           
kubectl config use-context docker-desktop
kubectl port-forward service/ok 8080:8080 8081:80 -n the-project
# Delete evicted pods
kubectl get po --all-namespaces | awk '{if ($4 ~ /Evicted/) system ("kubectl -n " $1 " delete pods " $2)}'
```

### Namespaces and Context

> Execute the kubectl Command for Creating Namespaces
```bash
# Namespace for Developers
kubectl create -f namespace-dev.json
# Namespace for Testers
kubectl create -f namespace-qa.json
# Namespace for Production
kubectl create -f namespace-prod.json
```

> Assign a Context to Each Namespace
```
# Assign dev context to development namespace
kubectl config set-context dev --namespace=dev --cluster=minikube --user=minikube
# Assign qa context to QA namespace
kubectl config set-context qa --namespace=qa --cluster=minikube --user=minikube
# Assign prod context to production namespace
kubectl config set-context prod --namespace=prod --cluster=minikube --user=minikube
```

> Switch to the Appropriate Context
```
# List contexts
kubectl config get-contexts
# Switch to Dev context
kubectl config use-context dev
# Switch to QA context
kubectl config use-context qa
# Switch to Prod context
kubectl config use-context prod

kubectl config current-context
```

> see cluster-info
```bash
kubectl cluster-info
```
> nested kubectl commands

```bash
kubectl -n istio-system port-forward $(kubectl -n istio-system get pod -l app=servicegraph -o jsonpath='{.items[0].metadata.name}') 8082:8088
```

> kubectl proxy creates proxy server between your machine and Kubernetes API server.
By default it is only accessible locally (from the machine that started it).

```
kubectl proxy --port=8080
curl http://localhost:8080/api/
curl http://localhost:8080/api/v1/namespaces/default/pods
```

### Accessing logs
```bash
# get all the logs for a given pod:
kubectl logs my-pod-name
# keep monitoring the logs
kubectl -f logs my-pod-name
# Or if you have multiple containers in the same pod, you can do:
kubectl -f logs my-pod-name internal-container-name
# This allows users to view the diff between a locally declared object configuration and the current state of a live object.
kubectl alpha diff -f mything.yml
```

### Execute commands in running Pods
```bash
kubectl exec -it my-pod-name -- /bin/sh
```

### CI/CD
> Redeploy newly build image to existing k8s deployment
```
BUILD_NUMBER = 1.5.0-SNAPSHOT // GIT_SHORT_SHA
kubectl diff -f sample-app-deployment.yaml
kubectl -n=staging set image -f sample-app-deployment.yaml sample-app=xmlking/ngxapp:$BUILD_NUMBER
```

### Rolling back deployments
> Once you run `kubectl apply -f manifest.yml`
```bash
# To get all the deploys of a deployment, you can do:
kubectl rollout history deployment/DEPLOYMENT-NAME
# Once you know which deploy you’d like to roll back to, you can run the following command (given you’d like to roll back to the 100th deploy):
kubectl rollout undo deployment/DEPLOYMENT_NAME --to-revision=100
# If you’d like to roll back the last deploy, you can simply do:
kubectl rollout undo deployment/DEPLOYMENT_NAME
```

### Tips and Tricks
```bash
# Show resource utilization per node:
kubectl top node
# Show resource utilization per pod:
kubectl top pod
# if you want to have a terminal show the output of these commands every 2 seconds without having to run the command over and over you can use the watch command such as
watch kubectl top node
# --v=8 for debuging 
kubectl get po --v=8
```

####  troubleshoot headless services  
```bash
k get ep
# ssh to one of the container and run dns check:
host <httpd-discovery>
```

#### Alias

```bash
alias k="kubectl"
alias watch="watch "
alias kg="kubectl get"
alias kgdep="kubectl get deployment"
alias ksys="kubectl --namespace=kube-system"
alias kd="kubectl describe"
alias bb="kubectl run busybox --image=busybox:1.30.1 --rm -it --restart=Never --command --"
```

> you can use `busybox` for debuging inside cluster

```bash
bb nslookup demo
bb wget -qO- http://demo:8888
bb sh
```
 
#### Container Security
> for better security add following securityContext settings to manifest
```yaml
securityContext:
  # Blocking Root Containers
  runAsNonRoot: true
  # Setting a Read-Only Filesystem
  readOnlyRootFilesystem: true
  # Disabling Privilege Escalation
  allowPrivilegeEscalation: false
  # For maximum security, you should drop all capabilities, and only add specific capabilities if they’re needed:
    capabilities:
      drop: ["all"]
      add: ["NET_BIND_SERVICE"]
```


#### Debug k8s

For many steps here you will want to see what a `Pod` running in the k8s cluster sees. The simplest way to do this is to run an interactive busybox `Pod`:
```bash
kubectl run -it --rm --restart=Never busybox --image=busybox sh
```

#### Debugging with an ephemeral debug container

Ephemeral containers are useful for interactive troubleshooting when `kubectl exec` is insufficient because a container has crashed or a container image doesn't include debugging utilities, such as with `distroless` images. 

This allows a user to inspect a running pod without restarting it and without having to enter the container itself to, for example, check the filesystem, execute additional debugging utilities, or initial network requests from the pod network namespace. Part of the motivation for this enhancement is to also eliminate most uses of SSH for node debugging and maintenance

```bash
# First, create a pod for the example: 
kubectl run ephemeral-demo --image=k8s.gcr.io/pause:3.1 --restart=Never
# add a debugging container 
kubectl alpha debug -it ephemeral-demo --image=busybox --target=ephemeral-demo
```

#### Generateing k8s YAML from local files using `--dry-run`
```bash
# generate a kubernetes tls file
kubectl create secret tls keycloak-secrets-tls \
--key tls.key --cert tls.crt \
-o yaml --dry-run > 02-keycloak-secrets-tls.yml
```

#### iTerm2 tips
> in iTerm2
1. split screen horizontally
2. go to the bottom screen and split it vertically

I was using top screen for the work with yaml files and kubectl.

Left bottom screen was running:

    watch kubectl get pods

Right bottom screen was running:

    watch "kubectl get events --sort-by='{.lastTimestamp}' | tail -6"

With such setup it was easy to observe in real time how my pods are being created.



---

## Reference 

[1]: https://docs.helm.sh/using_helm/#installing-helm
1. [Debug Services](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-service/)
1. [debug-running-pod](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-running-pod/)
1. [Docker for Mac with Kubernetes — Enable Ingress and K8S Dashboard](https://medium.com/@thms.hmm/docker-for-mac-with-kubernetes-ingress-controller-with-traefik-e194919591bb)
1. [Example recipes for Kubernetes Network Policies](https://github.com/ahmetb/kubernetes-network-policy-recipes)
1. [How To Use GPG on the Command Line](http://blog.ghostinthemachines.com/2015/03/01/how-to-use-gpg-command-line/)
5. [Using Your YubiKey with OpenPGP](https://support.yubico.com/support/solutions/articles/15000006420-using-your-yubikey-with-openpgp)
1. [Kubernetes Deployments with Helm - Secrets](https://developer.epages.com/blog/tech-stories/kubernetes-deployments-with-helm-secrets/)

##################
##
##
##
