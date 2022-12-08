# Kubectl output options

Let's look at some basic kubectl output options. 

Our intention is to list nodes (with their AWS InstanceId) and Pods (sorted by node).

We can start with:

```
kubectl get no
```

and 

```
kubectl get po -o wide
```

## Json and Jq

I've found the internal data structures easier to explore using the `-o json` output with [jid](https://github.com/simeji/jid) 
and [jq](https://stedolan.github.io/jq).

Once both `jq` and `jid` are installed (assuming OSX), we can quickly discover the data with the following command:

```
kubectl get no -o json | jid -q | pbcopy
```

This allows us to explore the json data interactively and keep our final `jq` query on the clipboard:

[![asciicast](https://asciinema.org/a/cpazej888znujgm04ewzsv0mk.png)](https://asciinema.org/a/cpazej888znujgm04ewzsv0mk)

**note**: `jid` currently implements it's own query parser to allow powerfull autocompletion, the drawback is
a lack of support for all the `jq` constructs (i.e.: we have to specify an index for array elements during discovery).

As can be seen in the recording: 
once done with `jid`, getting rid of the index on the `items` array in `jq`, did gave us the full listing.

`jq` gives us a lot more power for example:

Boxing the result into it's own array and constructing a new object combining
several nested attributes gives us the following query:

```
kubectl get no -o json | jq -r '[.items[] | {name:.metadata.name, id:.spec.externalID, unschedulable:.spec.unschedulable}]'
```

Here is how the above query was built up using `jid` and `jq`:
[![asciicast](https://asciinema.org/a/egmrydi963o31232sry4bfscf.png)](https://asciinema.org/a/egmrydi963o31232sry4bfscf)

Converting the json array into a tabular output with `jq` can be done using `@tsv` as follows:

```
kubectl get no -o json | jq -r '.items[] | select(.spec.unschedulable!=true) | [.metadata.name,.spec.externalID] | @tsv'
```

Jq also allows us to sort:

```
kubectl get po -o json | jq -r '.items | sort_by(.spec.nodeName)[] | [.spec.nodeName,.metadata.name] | @tsv'
```
The input for the `sort_by` command must be an array, we iterate the elements after the sorting.

## Custom Columns and Sorting

If all we need is a nicely formatted, sorted tabular report, `kubectl` has built-in support for powerfull sorting:

```
kubectl get po -o wide --sort-by=.spec.nodeName
```

Using `jid` to list pods sorted by node:
[![asciicast](https://asciinema.org/a/36q5fxao2l8lta6ztf9akqciq.png)](https://asciinema.org/a/36q5fxao2l8lta6ztf9akqciq)

The usage of Custom Columns with the knowledge of the data structure gained from `jid`, is also much easier:

```
kubectl get no -o=custom-columns=NAME:.metadata.name,AWS-INSTANCE:.spec.externalID,UNSCHEDULABLE:.spec.unschedulable
```

**Note**: apart from using `grep`, there is no easy way to filter.

## Golang Templates

If we do not wish to use `jq` (or have no access to `jq`) need filtering and powerfull output control, 
we may use Kubectl's built-in support for golang templates (inline or from a template file on disk):

```
kubectl get no -o go-template='{{range .items}}{{if .spec.unschedulable}}{{.metadata.name}} {{.spec.externalID}}{{"\n"}}{{end}}{{end}}'
or
kubectl get no -o go-template="{{range .items}}{{if .spec.unschedulable}}{{.metadata.name}} {{.spec.externalID}}:{{end}}{{end}}" | tr ":" "\n"
```

I could not find an easy way to print newline characters with inline golang template, so used a trick 
printing colons and using `tr` to convert colons to newlines.

## JSONPath 

Golang templates can be complicated and verbose - an alternative, if you are more familiar with `jq`-style queries, or `awscli`,
is to use JSONPath.

```
kubectl get no -o jsonpath="{.items[?(@.spec.unschedulable)].metadata.name}"
```

Internally, this seems tightly coupled to the golang templates.

Kubectl supports a superset of JSONPath, with a special `range` keyword to iterate over ranges, 
using the same trick to add newlines:

```
kubectl get no -o jsonpath="{range.items[?(@.spec.unschedulable)]}{.metadata.name}:{end}" | tr ":" "\n"
```

More examples of using jsonpath can be found in 
[the Kubernetes tests for the JSONPath utility](https://github.com/kubernetes/kubernetes/blob/v1.5.0-beta.2/pkg/util/jsonpath/jsonpath_test.go#L149)

##
##

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

## retrieve the default kubernetes service account token
 kubectl get secret $(kubectl get serviceaccounts default -o jsonpath='{.secrets[0].name}') -o json|jq -r .data.token |base64 -D 
 
## Decode it using Python (pip install PyJWT)

import jwt
var="encoded.jwt.token"
jwt.decode(var, options={"verify_signature":False})

##
##
### Overview
- Automatically deploying and managing container is called container orchestration
- K8s is an container orchestration tool/technology
- Other alternatives of K8s are *docker swarm* and *mesos*

### Cluster architecture
- K8s cluster is a set of machines (or nodes) running in sync
- One of the node is master node, responsible for actual orchestration
- `kube-scheduler` schedules pods on nodes based on node capacity, load on node and other policies. This runs in `kube-system` namespace
- `kubelet` runs on worker node which listens for instructions from kube-apiserver and manages containers
- `kube-proxy` enables communication within **services** within the cluster
- `kubectl` tool is used to deploy an manage applications on k8s clusters
- As k8s is container orchestration tool so we also need one container runtime engine like docker

#### ETCD
- ETCD is a distributed reliable key-value store that is simple, secure and fast
- K8s uses **etcd** cluster in *master* node to store information like which node is master, nodes, pods, configs, secrets, accounts, roles, bindings and other information
- `etdctl` is a command line too which comes with ETCD server
```bash
./etcdctl set key1 value1
./etcdctl get key1
```
- All the `kubectl get` command output comes from etcd server

#### Kube-API server
- `kube-apiserver` is used for all management related communication in a cluster. It runs on *master* node
- When we run a from `kubectl`, it reaches kube-api server which authenticates and validates the request and then interacts with *etcd* server and returns back the response
- We don't necessarily need to use kubectl, we can directly make requests like POST request using curl to create a pod

#### Kube controller manager
- Controller consistently monitors the state of the system and takes necessary action to bring back the system to normal state in case of problems
- Kube controller interacts with `kube-apiserver` to get cluster info. This also runs on *master* node and this is the brain of the cluster
- There are many controller in k8s, listed below are 2 of those
  - **Node controller**: Monitors which pod is down/unhealthy then takes necessary action to launch a new one if down
  - **Replication controller**: Ensures desired number of pods are running at all times within a set

#### Kube scheduler
- Decides which pod goes to which node so that right container ends up on right node. It decides on basis of node CPU/mem available and required by container and finds best fit
- This also runs on *master* node

#### Kubelet
- This runs on *worker* nodes and responsible to getting gathering commands from kube apiserver and sending back the all reports for that worker node
- `kubelet` needs to installed manually on worker nodes, this not installed automatically with `kubeadm` like other components

#### kube proxy
- This runs as daemonset on *each* node
- Manages networking in k8s cluster so that each pod in a cluster is able to communicate every other pod

#### Pods
- **POD** is a single instance of an application
- We add single container in a pod - this is recommendation but pod can have multiple containers in some cases like a container may have some helper containers which may go in same pod. Containers running in same pod can communicate using `localhost` itself

### Setup
- Install `kubectl` utility first to interact with k8s cluster

#### Minikube
- `minikube` is the easiest way to install k8s cluster, it installs all components (etcd, container runtime, ...) on a single machine/node
```bash
minikube start                          # Start minikube
minikube stop                           # Stop minikube
minikube service appname-service --url  # Get external URL of appname
```
#### Kubeadm
- `kubeadm` is more advanced tool to create multi-node k8s cluster
- We can use tool like `vgrant` to create VMs on machine to have multiple nodes in k8s - master and worker(s)

### YAML file
- K8s works on yaml files, it expects 4 top level attributes
  - apiVersion
  - Kind
  - metadata
  - spec
- Below is sample yaml file to deploy a pod with `nginx` container
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    app: nginx
    tier: frontend
spec:
  containers:
  - name: nginx
    image: nginx
```

### Replication controllers
- Controllers are the brain behind k8s cluster, they are the process which monitors k8s objects and takes desired action
- **Replication** controller ensures, specified number of pods are running at all times. Also helps for load balancing across pods - scaling
- `kind = ReplicationController`, *pod* and *replicas* info is present in `spec` section of yaml file
```yaml
apiVersion: v1
kind: ReplicationController
metadata:
  name: ...
  labels:
    ...
spec:
  template:
      <pod-definition>
  replicas: ...
```

### Replica sets
- This serves the same purpose as replication controller but it's an older technology. Replica sets is the recommended way
- `apiVersion = apps/v1` and `kind = ReplicaSet` and `spec` section remains same as above and one more params called `selector` used to select pods for replication. Selector is used to match which pods to monitor and it can be possible that pods with given labels already exists (or some exists) then replica set won't create those pods but just monitor those to have desired number of pods
```yaml
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: ...
  labels:
    ...
spec:
  template:
      <pod-definition>
  replicas: ...
  selectors:
      matchLabels:
        ...
```

### Deployments
- Provides capability for rolling updates, rollback, pausing and resume changes
- *Deployments* come higher in the heirarchy than replica sets (pod > replica sets > deployments)
- yaml file is almost same as of replicasets but `kind = Deployment` for deployment object
- On deploying, it creates a new replica set which in turn creates pods
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ...
  labels:
    ...
spec:
  template:
      <pod-definition>
  replicas: ...
  selectors:
      matchLabels:
        ...
```

### Namespaces(ns)
- Default ns is automatically created when a cluster is setup
- `kube-system` (for networking like DNS and security) and `kube-public` (for keeping public resources) are other ns created at cluster startup
- Each ns has
  - Isolation: Each ns is isolated from other, we can have a cluster with 2 ns `dev` and `prod`. These 2 will be isolated from each other. We can access resources/services deployed in other ns using ns with service name like web-app.dev.svc...
  - Policies: Each ns has different policies
  - Resource limits: We can define different quota of resources in each ns

### Services
- It is a k8s virtual object which enables communication between various internal and external components like access from browser, b/w frontend and backend services
- Enables loose coupling in our microservices in application

We have 3 types of services in k8s
#### NodePort
- This service is used to make internal service(like webserver) accessible to the users(outside world) on a port. It exposes application on a port on all hosts
- Has range of ports from 30000 to 30767
```yaml
apiVersion: v1
kind: Service
metadata:
    ...
spec:
  type: NodePort
  ports:
    - targetPort: 80
      port: 80
      nodePort: 30008
  selectors:
    ...
```
- This file has 3 ports - ports are wrt to service
  - targetPort: Pod port, this is actual port to access inside port
  - port: Service port
  - nodePort: Port exposed to external world
- For multiple pods are running with given `selector`, it acts as load balancer and distributes traffic to various pods randomly
- For multiple nodes in cluster, we can access application using any of the node port IP and port, nodePort service created spans **across nodes** in the cluster

#### ClusterIP
- Creates an IP (and name) to communicate b/w services like from set of frontend and backend services. This is for **internal** access only(within cluster, not bound to specific node), different microservices communicate using ClusterIP service
- This is the **default** service type
- K8s creates one ClusterIP service by default named `kubernetes`
```yaml
apiVersion: v1
kind: Service
metadata:
    name: backend
...
spec:
  type: ClusterIP
  ports:
    - targetPort: 80
      port: 80
  selectors:
    ...
```
- Imperative way to create service
```bash
# Expose pod `messaging` on running on 6379 to 6379
# We can use deployment, rc or rs instead of pod
# We can also specify `targetPort` if want some other external port
k expose pod messaging --name messaging-service --port=6379
```

#### LoadBalancer
- Used to create single endpoint like *http://some-domain.com* to access the application. The application may have multiple nodes running, the will help us create a common name to access it. Without this we will have to access the apps using specific `nodeIP:port` which is very hard to remember and will change when node restarts (may get new IP)
```yaml
apiVersion: v1
kind: Service
...
spec:
  type: LoadBalancer
  ports:
    - targetPort: 80
      port: 80
      nodePort: 30008
  selectors:
    ...
```
- Using `LoadBalancer` in cloud providers like `AWS`, `GCP`, k8s sends the request to cloud provider to provision a load balancer which can be used to access the application

### Imperative vs declarative approach
#### Imperative
- Providing instructions writing in english to do something
- In k8s, anything done using `kubectl` command except `apply` is imperative approach like `kubectl run, edit, expose, create, scale, replace, delete, ...`
- This is faster, we just have to run the right command - `yaml` file not always required. Use this in certification exam to save time

#### Declarative
- Using tools like terraform, chef, puppet, ansible. This does lot of error handling and maintains state of steps done so far
- In k8s, done using `kubectl apply` command, checks for what is the state of the system and performs relevant action only

- It is recommended not to mix imperative and declarative approaches

### Networking
- Each Pod is assigned with an IP
- K8s does not handle networking to communicate b/w pods so in multi node cluster, we has to setup the networking on our own using other networking softwares like vmware nsx, etc.

### Scheduling
- Scheduler assigns node for a pod, when we deploy a pod, property called `nodeName` (in spec section) is assigned to pod which has node name where this pod has to run
- If pod doesn't get a `nodeName` assigned to it, pod remains in `Pending` state
- We can also assign `nodeName` manually - by using this `nodeName` property set with our deployment yaml file
- Note that we can't change the `nodeName` of a running instance of pod, to mimic this behaviour we use `Binding` object and send a POST request for this pod
#### Taint and tolerations
- We can taint certain nodes so that only specific pods can be scheduled on those nodes. This is useful when we want to use some nodes for specific use case
- For those specific pods which should be scheduled on tainted nodes we add tolerations for those pods which makes pods tolerant to the taint and gets scheduled on tainted nodes
- Below command can be used to taint a node
```bash
k taint nodes node-name key=value:taint-effect  # Sample

k taint nodes node1 app=blue:NoSchedule  # Example
```
- `<taint-effect>` specifies what happens to pod which do not tolerate this taint, it can have 3 values
  - `NoSchedule` Don't schedule those pods on this node
  - `PreferNoSchedule` System will try to avoid scheduling on this node but that's not guaranteed
  - `NoExecute` Don't schedule pods and existing pods which don't tolerate the taint will be evicted. This is possible if some pods got scheduled on nodes before they were tainted

- We can add tolerations to pods in yaml definition file in spec section
```yaml
...
spec:
  ...
  tolerations:
  - key: app
    operator: Equal
    value: blue
    effect: NoSchedule
```
- When we create a cluster, taint is applied on *master node* so that no pod(workload) is scheduled on master nodes. Can be checked using below command
```bash
k describe node <master-node-name> | grep Taint
```
- Untaint node
```bash
kubectl taint nodes <nodeName> node-role.kubernetes.io/master:NoSchedule-
```
- Tainting nodes only restricts nodes from allowing certain pods to be scheduled on those nodes but it doesn't guarantee that a specific pod gets scheduled on specific node. A tolerant pod can be scheduled on any node in the system. If we have requirement to schedule some pods on specific nodes, this can be achieved using `node affinity`

#### Node selector
- To schedule a pod on specific node we can use `nodeSelector` in spec section of pod definition yaml file
```yaml
...
spec:
  ...
  nodeSelector:
    size: Large
```
- Size given in above command is the label that we has to add on nodes using below command
```bash
k label nodes node-1 size=Large
```
- Node selector have limitation like it doesn't support complex selection filters like schedule pod on medium or large nodes or don't schedule on small nodes, for these use cases we can use *Node Affinity*

#### Node affinity
- We can add `affinity` in spec section of pod yaml definition file, to select specific nodes for scheduling pods
```yaml
...
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: size
            operator: In
            values:
            - Large
            - Medium
```
- Other operators we can use are `Exists` (doesn't need a value), `NotIn`, etc
- Other node affinity `preferredDuringSchedulingIgnoredDuringExecution` and  `preferredDuringSchedulingRequiredDuringExecution`
  - Scheduling: Starting pod - assigning a node to pod
  - Execution: Pod is already scheduled and in running state. Considered when pod is already running on a node and someone changes the node labels

#### Resource requirements and limits
- When scheduler tries to schedule a pod, k8s checks for pod's resource requirements and places on node which has sufficient resources
- By default container requests for 0.5 CPU and 256 Mi of RAM for getting scheduled, this can be modified by adding `resources` section under spec of pod yaml definition
```yaml
...
spec
  ...
  resources:
    requests:
      memory: "1Gi"
      cpu: 1
```
- 1 CPU = 1000m = 1 vCPU = 1 AWS vCPU = 1 GCP core = 1 Azure core = 1 Hyperthread. m is millicore
- It can as low as 0.1 which is 100m
- For memory
  - 1 K (kilobyte) = 1,000 bytes
  - 1 M = 1,000,000 bytes
  - 1 G = 1,000,000,000 bytes
  - 1 Ki (kibibyte) = 1,024 bytes
  - 1 Mi = 1,048,576 bytes
  - ...
- While container is running it's resource requirements can go high so by default k8s sets a limit of 1 vCPU and 512 Mi to containers, this can also be changed by adding `limits` section under `resources` section
```yaml
...
spec:
  resources:
    ...
    limits:
      memory: "2Gi"
      cpu: 2
```
- If container tries to use more CPU then limits, then it is throttled and in case if memory exceeds container is terminated

#### Daemon sets
- Daemon sets ensures that one copy of a Pod is always running in all nodes in the cluster, when a new node is added to cluster daemon set pod starts running on that node
- Some application of using daemon set
  - Monitoring solution
  - Logs viewer
- `kube-proxy` runs as daemon set
- YAML definition of daemon set is similar to replica sets, change is in the kind only, other params are same
```yaml
apiVersion: apps/v1
kind: DaemonSet
...
spec:
  ...
  template:
    ...
```
- K8s (v1.12 onwards) uses `nodeAffinity` and default scheduler to deploy daemon sets in each node

#### Static pods
- Suppose we don't have master node in cluster (which `kube-api` server, etcd server and other things), we only have worker nodes which has `kubelet` now we can't create resources as we don't have kube-api server which can give instructions to kubelet to create anything
- In this scenario we place `pod` definition yaml files at `pod-manifests-path` which is by default `/etc/kubernetes/manifets`, and `kubelet` checks this path and creates any pod if it finds at this path, if later pod definition file is deleted pod also gets deleted. This way of creating pods is called `static pods`
- `kubelet` only understands `pod` so we are only able to create only pods and not deployments or replica sets
- `pod-manifests-path` or `staticPodPath` can be updated while running `kubelet service`. To know current path check `-config` option used in `kubelet` binary running (`ps -eaf | grep kubelet`), `-config` contains kubeconfig file having other details
- Now static pod is created but we can't use `kubectl get pods` to check pods because it `kubectl` interacts with kube-api server which is not running so in this case we can use docker commands `docker ps`
- This is used to deploy control plane components while creating k8s server - etcd, api-server, controller-manager, scheduler (these pods have `nodeName - master or controlplane` appended to there name)

#### Multiple schedulers
- Apart from default k8s cluster scheduler running on master node, we can also deploy our own scheduler
- Custom scheduler can be deployed just like any other pod with some name - image should be `k8s.gcr.io/kube-scheduler:v1.20.0`, has a command section which contains various options like `leader-elect`, `port`, ...
- While deploying other service pod we can specify our custom scheduler using `schedulerName` option in spec section

### Monitoring and logging
- K8s has monitoring server called *Metrics server* which keeps all cluster metrics, this is an in memory solution so we won't get historical data
- `Kubelet` running on each node has another component called `cAdvisor` or container advisor which retrieves performance metrics from pods and exposes them to metrics server through kubelet APIs
- We can install metric server using
```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```
- To view metrics, we can use below `top` commands
```bash
k top node  # See CPU and memory usage of all nodes
k top pod   # See CPU and memory usage of pods in current namespace
```
- To view pod logs
```bash
k logs <podName>     # Get all logs from begining to now
k logs -f <podName>  # Stream logs

# If a pod has multiple containers in it, specfify container name also
k logs -f <podName> <containerName>

# Check logs from all containers in a pod
k logs -f <podName> --all-containers

# Previous pod logs
k logs -f <podName> --previous

# If core components are down then kubectl commands won't work, we can get use journalctl to see logs of components like kubelet
journalctl -u kubelet  # Get kubelet logs

# We also use docker commands to get logs if kubectl is not working
docker logs <docker-id>
```

### Application lifecycle management
#### Rolling updates and rollback
- When a deployment is created, a rollout is triggered and creates a revision of deployment. On every subsequent deployment this revision if updated, this helps us to rollback to a previous version if necessary
- To see rollouts, use below commands
```bash
k rollout status deployment/myapp-deployment   # Get status of rollout
k rollout history deployment/myapp-deployment  # Get rollout history
```
- K8s support 2 deployment strategies
   - **Recreate**: Delete all exiting deployments and then create new ones. This will cause some downtime and all new may have some issues. This is NOT the *default* deployment strategy
   - **Rolling update**: This deletes one object (or pod) at a time and deploy newer version one by one. This way application never goes down and upgrade is seamless. This is the *default* deployment strategy in k8s
- These 2 strategies can also be seen by describing a deployment, we will get the strategy name and how pods got updated - rolling or recreate
- Under the hood, deployment creates a replica set and creates required number of pods, when deployment is updated - new replica set is created and all new pods are started in it and stopping pods from existing replica sets. To see use `k get replicasets`
- If we a notice problem after upgrading our application/deployment, we can undo the deployment and rollback to previous revision, it will destroy the pods in new replica set and bring older ones up in old replica set
```bash
k rollout undo deployment/myapp-deployment  # Rollback last deployment
```

#### Commands and arguments
- In `Dockerfile` we have 2 fields
  - `ENTRYPOINT`: Specifies which command to run
  - `CMD`: Takes arguments which goes with above command given in entrypoint
- In pod definition file, we can overwrite both the above options using `command` and `args` option respectively
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ubuntu-sleeper
spec:
  containers:
  - name: ubuntu-sleeper
    image: ubuntu-sleeper
    command: ["my-sleep"]  # Run this command (overwritten `ENTRYPOINT`)
    args: ["10"]  # Pass argument 10 with above command (overwritten `CMD`)
```

#### Configure environment variables
We can specify environment variables for a pod in it's definition file using `env` or `envFrom` parameter. There are 3 ways get value for env vars
##### Directly env name and value
```yaml
env:
  - name: APP_COLOR
    value: pink
```
##### ConfigMap
ConfigMaps are used to save all configurations required by application at central place, this can be referred in pod definition file and all name/value will be available
- ConfigMaps can be created using imperative way or declarative way
```bash
# Imperative approach
k create configmap <cm-name> --from-literal=<key1>=<value1> --from-literal=<key2>=<value2>
k create configmap <cm-name> --from-file=<path-to-file>  # Can use file with all key/val also

k get configmaps
k describe configmaps
```
- Declarative approach
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  APP_COLOR: blue
  APP_MODE: prod
```
- To use above configMap in pod definition file use `envFrom`
```yaml
envFrom:
  - configMapRef:
      name: app-config  # ConfigMap name
```
- Above config injects all env vars from configMap to pod, we can also take selective
```yaml
env:
  - name: APP_COLOR
    valueFrom:
      configMapKeyRef:
        name: app-config
        key: APP_COLOR
```
- ConfigMaps can also be mounted to volumes
```yaml
volumes:
  - name: app-config-volume
    configMap:
      name: app-config
```
##### Secrets
Can be used to store any sensitive information. Same as configMaps but data is stored in encoded format. Secrets data is kept in encoded format `base64`
- Imperative way to create secret
```bash
k create secret generic <secret-name> --from-literal=<key1>=<value1> --from-literal=<key2>=<value2>
k create secret generic <secret-name> --from-file=<path-to-file>  # Can use file with all key/val also

k get secrets
k describe secrets
```
- Declarative way: To use declarative way values should be `base64` encoded, if we don't want to encode to `base64` we can use `stringData` field instead of `data`
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
data:
  DB_Host: bXlzcWwK
  DB_User: cm9vdAo=
  DB_Passowrd: YWJjMTIzCg==
```
- To use above secret in pod definition file use `envFrom`
```yaml
envFrom:
  - secretRef:
      name: app-secret  # secret name
```
- Above config injects all env vars from secret to pod, we can also take selective
```yaml
env:
  - name: APP_COLOR
    valueFrom:
      secretKeyRef:
        name: app-secret
        key: DB_Passowrd
```
- Secrets can also be mounted to volumes. This mounting creates files in container for each parameter one file is created.
```yaml
volumes:
  - name: app-secret-volume
    secret:
      name: app-secret
```
```bash
# 3 files are created corresponding to 3 vars in secret
ls /opt/app-secret-volumes
DB_Host  DB_Passowrd  DB_User
```

#### Multi container pods
- There can be cases when we need 2 services to work together - scale up/down, share same network (can be accessed using localhost), share same volume. Example would be web server and a logging service
- Use 2 containers defined in `containers` section of spec
```yaml
...
spec:
  containers:
  - name: sample-app
    image: sample-app:1.1
  - name: logger
    image: log-agent:1.5
```
- 3 multi container pods design patterns [discussed in CKAD course]
  - sidecar: For example using logging service with app container
  - adapter
  - ambassador

#### Init containers
- Init containers are used for doing some task before actual container starts like some other task is done or checkout some source code from repository. This executes only once at the beginning
- Similar to containers but defined under `initContainers` section in spec section - it is a list so can have multiple init containers and it executes in sequence as defined
- If init container fails whole pod is restarted
```yaml
spec:
  containers:
  - name: myapp-container
    image: busybox:1.28
    command: ['sh', '-c', 'echo The app is running! && sleep 3600']
  initContainers:
  - name: init-myservice
    image: busybox:1.28
    command: ['sh', '-c', 'until nslookup myservice; do echo waiting for myservice; sleep 2; done;']
  - name: init-mydb
    image: busybox:1.28
    command: ['sh', '-c', 'until nslookup mydb; do echo waiting for mydb; sleep 2; done;']
```

### Cluster maintenance
#### OS upgrades
- If a node is down, then k8s waits for `node eviction timeout` (default=5 mins) before scheduling pods on that node to other nodes. In cases when node is down and comes up immediately, pods are scheduled on the same node
- For maintenance purpose we can drain all pods on a node to get scheduled on other nodes. Pods which are not managed by `deployment` or `replicaSets` are lost and not scheduled on other nodes (this is warned and can deleted using `--force` option)
```bash
k drain <node-name>
k drain <node-name> --ignore-daemonsets
```
- When node back again, we can `uncordan` to make this node available for scheduling new pods
```bash
k uncordon <node-name>
```
- There is another command `cordon` which makes a node un-schedulable for new pods however existing pods remain running on that node
```bash
k cordon <node-name>
```

#### Kubernetes versions
```bash
# This gives client and server versions
# client = kubectl version
# server = kubernetes version
k version
k version --short

k get nodes  # Also gives kubelet version running
```
- Version = x.y.x
  x = Major version
  y = Minor version
  z = Patch version

#### Cluster upgrade process
- `kube-apiserver` is the main component in k8s cluster, if this is at version X (minor version) then
  - `controller-manager` and `kube-scheduler` can at max one version lower than X
  - And `kubelet` and `kube-proxy` can be at max 2 versions lower than X
  - None of them can have higher version than X
  - However `kubectl` can have version between X - 1 to X + 1
- At a given point in time, k8s community supports latest 3 versions (minor)
- 2 steps in upgrading cluster
  - First upgrade `master nodes`: While master node upgrade is in process, workloads on worker nodes will continue to work but management functions won't like we can't create or delete a pod or if pod crashes it won't be rescheduled
  - Then `worker nodes`: We have 3 strategies for this
    - Upgrade all worker nodes at the same time - requires downtime
    - Upgrade one node at a time - kind of rolling upgrade
    - Add new nodes with upgraded version then remove existing nodes
- Recommended approach is to upgrade one minor version at a time - not to skip the versions
```bash
kubeadm upgrade plan

# This command does not upgrade kubelet, we has to upgrade kubelet by going(ssh) on each nodes and upgrading
kubeadm upgrade apply <version>
```
- Follow this for complete steps: https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/
- **Note**: While upgrading, all `kubectl` commands should be run on control plane nodes and NOT in worker nodes even when we are upgrading worker nodes

#### Backups and restore methods
We need to backup below componets in a cluster
- Resource configs: Take backup of all resources deployed (either using imperative or declarative way).
  - We can use below command to get all resources deployed
  ```bash
  k get all --all-namespaces -o yaml > all-resources.yaml
  ```
  - There are other solutions already build for this to take backup of all resources like `velero` by heptIO
- ETCD cluster: Stores state of the cluster, this also runs as a **static pod** on master nodes
  - Taking backup of ETCD also gives all resource information
  - We can take backup of ETCD using `etcdctl` command
  ```bash
  # trusted-ca-file, cert-file and key-file can be obtained from the description of the etcd Pod
  ETCDCTL_API=3 etcdctl --endpoints=https://<IP>:2379 \
    --cacert=<trusted-ca-file> --cert=<cert-file> --key=<key-file> \
    snapshot save <backup-file-location>

  # To restore this snapshot
  # 1 - we can first stop kube api server
  service kube-apiserver stop

  # 2 -  then restore from backup
  ETCDCTL_API=3 etcdctl restore <snapshot-name>.db --data-dir=/var/lib/etcd-from-backup

  # 3 - update etcd with new path, etcd is static pod so update manifests file (by default here - /etc/kubernetes/manifests/etcd.yaml)

  # 4 - reload service daemon and restart etcd service
  systemctl daemon-reload
  service etcd restart

  # 5 - start kube apiserver
  service kube-apiserver start
  ```
- Volumes

### Security
All communication between various k8s components are TLS based
#### Authentication
- `kube-apiserver` serves all requests to the cluster so this is responsible to authenticating the requests. User can send request using `kubectl` command or `curl`
- Authentication can be done below methods, it is configured while starting kube-apiserver
- Basic authentication
  - Static password file: Using username and password from csv file. While requesting using `curl` we can use `-u` option to specify username/password
  - Static token file: Instead of using password, keeping token in file. This token can be sent in `header of HTTP request`
  - **Note**: Both above method are not recommended as they are not secure, so we use *certificate* based authentication

#### TLS
- Symmetric encryption: Same key is used for encryption and decryption. Problem is sharing that key b/w client and server securely
- Asymmetric encryption: Uses 2 keys
  - Public key: For encryption
  - Private key: For decryption
- `ssh` also uses asymmetric encryption - `ssh-keygen` generates public and private keys. Private key is used to login to the server and public key is used to lock the access to severs
##### HTTPS flow
- Key exchange - PKI (Public key infrastructure)
  - Server shares public key (certificate) to client
  - Client generates *encryption key* and sends back to server - this key is encrypted using public key which can only be decrypted using server using private key
  - Now both client and server has exchanged *encryption key* securely which can be used to encrypt further messages
- Domain authorization
  - With public key (from server to client), a digital certificate is also sent which is signed/approved/authorized by a certificate authority (CA) to confirm that domain is actually what is says - like xyz.com is actually xyz.com and not someone else with fraud identity. Some popular CA are symantec, digicert, globalsign, ...
  - Domain owner has to generate a certificate signing request (CSR) and sent to CA, then CA verifies all details and sends back signed certificate
  - How CAs are validated? Each CA also have a pair of public and private key (this is called **root certificates**) and they sign the certificates using private key and there public keys are stored in each clinet like browsers so from there client verifies certificate is signed by authorized by CA
  - For interval usage, we can host our own CA also and sign certificates
- Naming conventions
  - Public key(certificate): *.crt, *.pem
  - Private key: *.key, *-key.pem
- **Note**: Private key can also be used to encrypt data and can be decrypted using public key, this is never done because anyone having public key will be able to decrypt it
- Everything mentioned above is to verify if we are communicating to right server or not using it's certificate, there can be cases when server also needs to verify if it is communicating to correct client and can ask for *client certificate* from client

#### TLS in k8s
Bases on interaction, we can have server and client components in k8s. Each component will have it's own certificate
- Server
  - kube-apiserver: apiserver.crt, apiserver.key
  - etcd: etcdserver.crt, etcdserver.key
  - kubelet: kubelet.crt, kubelet.key
- Client: All below clients talks to `kube-apiserver`
  - User(admin): admin.crt, admin.key
  - kube-scheduler: scheduler.crt, scheduler.key
  - kube-controller-manager: controller-manager.crt, controller-manager.key
  - kube-proxy: kube-proxy.crt, kube-proxy.key
- We also need at least one CA to generate certificates for all above components which also has certificates - ca.crt, ca.key

#### TLS in k8s - certificate creation
- Generate CA self signed certificates - root certificates
```bash
# 1. Generate keys
openssl genrsa -out ca.key 2048

# 2. Certificate signing request
openssl req -new -key ca.key -subj "/CN=KUBERNETES-CA" -out ca.csr

# 3. Sign certificates
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt

# Now for all other certificates, we will use this key pair to sign them
```
- Generate certificates for other components and sign using above CA - like admin user certificate
```bash
# 1. Generate keys
openssl genrsa -out admin.key 2048

# 2. Certificate signing request
openssl req -new -key admin.key -subj "/CN=kube-admin" -out admin.csr
openssl req -new -key admin.key -subj "/CN=kube-admin/O=system:masters" -out admin.csr  # Admin user

# 3. Sign certificates - using CA key pair
openssl x509 -req -in ca.csr -CA ca.crt -CAkey ca.key -out admin.crt
```
- Now we have admin user certificate, we can use this in 3 ways
  - curl command
  ```bash
  curl https://kube-apiserver:6443/api/v1/pods \
    --key admin.key --cert admin.crt
    --cacert ca.crt
  ```
  - kubectl command
  ```bash
  kubectl get pods \
    --server kube-apiserver:6443 \
    --client-key admin.key
    --client-certificate admin.crt
    --certificate-authority ca.crt
  ```
  - Specifying certificates in each command is not very handy so add these information to `kubeconfig` file, then specify this file with command
  ```bash
  kubectl get pods --kubeconfig ~/.kube/<config-name>

  # By default kubeconfig file used is ~/.kube/config
  ```
- **Note**: Each component should have root certificate file (ca.crt) present with them

#### View certificate details
- We should know how cluster is setup, like if cluster is setup using `kubeadm` then all certificates are placed at `/etc/kubernetes/pki/`
- If we want to know the details from a components certificate, we can use below command - will print details like `expiry`, `issuer`, `alternate names`, ...
```bash
openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout

# Decode CSR file
openssl req -in filename.csr -noout -text
```

#### Certificates API
- `kubeadm` tool creates a pair of CA keys (public and private keys) and places them on master node so master is becomes our CA server. All new CSR will go to master to getting signed
- When a new user wants to access the cluster he can create a CSR and send to admin, admin will then creates a CSR object using yaml manifests file - `kind: CertificateSigningRequest`
```yaml
...
kind: CertificateSigningRequest
...
spec:
  ...
  request:
    <base64 encoded CSR>
```
- Now admin can use kubectl commands to view/approve CSRs
```bash
k get csr                     # Get list of all CSRs
k certificate approve <name>  # Approve CSR
k get csr <name> -o yaml      # Gives user certificate in base64 format
```
- On master node all certificate related operations is taken care by `controller-manager` - has `csr-approving` and `csr-signing` controllers.
- To sign the CSR, controller manager should have root certificates (CA key pairs) - while starting controller manager is accepts root certificates in `--cluster-signing-cert-file` and `--cluster-sigining-key-file`

#### Kubeconfig
- kubeconfig file has 3 sections
  - Clusters: List of cluster (dev, prod) with CA root certificates - `ca.crt`
  - Users: List of users (admin, readonly) with certificate key pairs (crt and key)
  - Contexts: Combination of above 2 - List of cluster and users like which cluster to user with which user - readonly@prod, admin@dev, ... At the top level of config file, we also have a default context to use if we don't explicitly chose one
```bash
k config view                       # See current kubeconfig file
k config use-context prod@readonly  # Change current context. This command updates the `current-context` field in kubeconfig file

# Use some other kubeconfig (default is ~/.kube/config)
export KUBECONFIG=/path/my-kube-config

# Set default context of given kubeconfig to context-1
k config --kubeconfig=/path/my-custom-config use-context context-1
```
- We can also set the `namespace` in `context` section of kubeconfig file to point a specific namespace, by default it is pointed to `default` ns
```bash
# Set context to dev, from next commands we don't have specify ns name in commands
k config set-context --current --namespace=dev
```
- To debug problems with `kubeconfig` file, we can use `cluster-info` command
```bash
# Use current kubeconfig
k cluster-info

# Use custom kubeconfig
k cluster-info --kubeconfig=/path/to/kubeconfig
```

#### API groups
- Objects in k8s are categorised in different API groups
  - /metrics: Getting metrics
  - /healthz: Get health information
  - /version: Get cluster version
  - /api: Interact with various core resources like pods, configMaps, namespace, etc.
  - /apis: Named APIs, further categorized into below API groups
    - /apps: /v1/deployments, /v1/replicasets, /v1/statefulsets
    - /extensions
    - /networking.k8s.io: /v1/networkpolicies
    - /storage.k8s.io
    - /authentication.k8s.io
    - /certificates.k8s.io: /v1/certificatesigningrequests
  - /logs: For fetching logs
- Verbs are operation of API groups like `get`, `list`, `update`, ...
- To list all API groups we can do a curl on cluster domain name
```bash
curl http://<api-server>:6443

# Above command will fail we haven't specified the certificates so we can use `kubectl` to start a proxy client which will take certs from `kubeconfig` and run on localhost
kubectl proxy
Starting to serve on 127.0.0.1:8001

# Now we can access cluster using curl command via this proxy - will use credentials from kubeconfig and forward request to api server
curl http://localhost:8001  # List all API groups
curl http://localhost:8001/version
curl http://localhost:8001/api/v1/pods
```

#### Authorization
- Once user/machine gains access to cluster what all things it can do is defined by **authorization**
- Authorization mechanisms
  - Node: Used by agents inside cluster like `kubelet`, these requests are authorized by *Node authorizer*. In certificates if name has `system` like `system:node` then these are system components and authorized using node authorizer
  - ABAC: Attribute based access control, for external access
    - This associates user(s) to a set of permissions
    - We can create these policy using `kind: Policy`
    - Managment is harder because we has to update policy for each user when required to update permissions
  - RBAC: Role based
    - Instead of user(s) <> permission mapping, we create a role like `developer`, `security-team` and role has set of permissions then associate user to role
  - Webhook: Outsource authorization to other tools like `open policy agent`
- We can provide `authorization-mode` in kube-apiserver (by default it is `always-allow`), it can have multiple values like Node,RBAC,Webhook - For access, check is made against all values specified till access if granted to chain ends

#### RBAC
- To create a role, we create `Role` object. In `rule` section, we can add various access permissions. This has scope of namespace
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: testing
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list", "get", "create", "update", "delete"]
- apiGroups: [""]
  resources: ["ConfigMaps"]
  verbs: ["create"]
```
- Link user(s) to role - using `RoleBinding` object
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: devuser-developer-binding
subjects:
- kind: User
  name: dev-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
```
- We can also check, we user(self, other) has access to perform some operation
```bash
k auth can-i create deployments
k auth can-i delete nodes
k auth can-i create pods --as dev-user

# Can dev-user has permission to create pod in test namespace
k auth can-i create pods --as dev-user --namespace test
```
- We can also give access to specific resources, using `resourceName` field in rules
```yaml
...
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "create", "delete"]
  resourceName: ["blue", "green"]
```
- Imperative ways
```bash
k create role pod-reader --verb=get --verb=list --verb=watch --resource=pods
k create rolebinding pod-reader-binding --clusterrole=pod-reader --user=bob --namespace=acme
```

#### Cluster role and role bindings
- Resources in k8s can be namespaced(pods, rs, cm, roles) or cluster scoped(nodes, clusterroles) - can get whole list using
```bash
k api-resources --namespaced=true   # Get all namespaced resources
k api-resources --namespaced=false
```
- `clusterrole` and `clusterrolebindings` has cluster scope (remember role had ns scope) - this role created has cluster level access
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-administrator
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["list", "get", "create", "delete"]
```
- Link user(s) to cluster role - using `ClusterRoleBinding` object
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-role-binding
subjects:
- kind: User
  name: cluster-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-administrator
  apiGroup: rbac.authorization.k8s.io
```
- Imperative ways
```bash
k create clusterrole pod-reader --verb=get,list,watch --resource=pods
k create clusterrolebinding pod-reader-binding --clusterrole=pod-reader --user=root
```
- Although clusterRole is cluster scoped but we can create it for namespaced resources also - will access on all namespace for that object. For example if we create `clusterRole` for `pods`, then this role will have to pods across all namespaces

#### Service accounts
- 2 types of accounts
  - User: used by humans like Admin, developer
  - Service: used by machined like build tools, prometheus
  ```bash
  k create serviceaccounts dashboard-sa
  k get serviceaccounts
  k describe serviceaccounts dashboard-sa
  ```
- Imperative way
```bash
# Grant read-only permission within "my-namespace" to the "my-sa" service account
k create rolebinding my-sa-view \
  --clusterrole=view \
  --serviceaccount=my-namespace:my-sa \
  --namespace=my-namespace
```
- Service account has a token which is used by any third party service to access cluster(kube-apiserver using `curl` command), this token is kept as secret. This sa can now be associated with a role using RBAC for specific access
- If third party service is running in cluster itself like as a pod then we can mount this secret as volume and then pod can access it directly - use `serviceAccountName` field in `spec` section
- A default service account is also created in each ns and moounted with each pod if don't specify any other
- `automountServiceAccountToken: false` - don't mount service account token with pod

#### Image security
- When we specify image in pod definition file, it follows docker naming convention - `image: nginx` actually becomes `image: docker.io/library/nginx` where
  - `docker.io` is the default registry to look for image
  - `library` is default user/account
  - `nginx` is the repository name for image
- `gcr.io` is another public registry where all k8s related images stored, for end to end testing `gcr.io/kubernetes-e2e-test-image/dnsutils`
- Public cloud providers also has container registry service like `ECR` is by AWS
- Private repository: Store images which are not public, requires some credentials to access - using `docker login`
```bash
docker login private-registry.io
docker run private-registry.io/apps/internal-app
```
- For using private registry in pod definition file, we has to create secret of type `docker-registry` and specify name in pod definition
```bash
k create secret docker-registry regcred \
    --docker-server=private-registry.io \
    --docker-username=registry-user \
    --docker-password=registry-password \
    --docker-email=registry-user@org.com
```
```yaml
...
kind: Pod
spec:
  containers:
      image: private-registry.io/apps/internal-app
  imagePullSecrets:
  - name: regcred
...
```

#### Security context
- Security context can be set at the pod and/or container level
  - Pod level: Applies to all containers defined in this pod definition
  ```yaml
  ...
  spec:
    securityContext:
      runAsUser: 1000  # Default is root, skip this if want to run as root
    containers:
      ...
  ```
  - Container level: Applies to specfic container. Note if applied at both pod and container level, container level is applicable
  ```yaml
  ...
  spec:
    containers:
      securityContext:
        runAsUser: 1000
        capabilities:
          add: ["MAC_ADMIN"]
      ...
  ```
- We can also set container `capabilities` which can only be at container level (as in above example)

#### Network policy
- 2 types of traffic - Ingress and Egress
- Ingress: Traffic coming into the server/network
- Egress: Going out of server/network
- Replying back to client does not matter - doesn't require egress configuration, this is enabled by default
- Ingress or egress is always looked from that specific server perspective - like for DB we only require ingress traffic
- K8s is by default configured with "All allow" means, any pod can communicate with any other pod/service within the cluster - using pod IP, name, etc.
- To restrict traffic we apply network policies to pod, this is done using selectors using labels and using it in `NetworkPolicy` object. Below example shows to apply network policy on `db` so that only `api-pods` can connect to `db` on port 3306 - this will restrict others like web server pods from accessing db
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-policy
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          name: api-pod
    ports:
    - protocol: TCP
      port: 3306
```
- Network policies are enforced by networking solutions implemented on k8s cluster and not all networking solutions support network policies. Solutions that support are - `kube-router`, `calico`, `romana`, `weave-net`
- We can further filter down on whom to allow with namespace filter
```yaml
...
  ingress:
  - from:
    - podSelector:
        matchLabels:
          name: api-pod
      namespaceSelector:
        matchLabels:
          name: prod
...
```
- For situations like allowing backup server which is not deployed as cluster in pod we can allow specific IP address also
```yaml
...
  ingress:
  - from:
    - podSelector:
        matchLabels:
          name: api-pod
    - ipBlock:
        cidr: 192.168.5.10/32
...
```
- For configuring `egress` - `from` in ingress becomes `to` and rest remains same

### Storage
#### Storage in docker
- Volumes in docker: https://gist.github.com/hansrajdas/d950ffd99c3ae817b08fd11592dc82eb#file-system

#### Container storage interface
- Intially k8s only used to work with docker runtime and it's code was also embedded into k8s but with other container runtimes coming in (like rkt, crio), docker was moved out of k8s and `container runtime interface` which developed
- CRI governs the interface that when a new runtime is developed, how it will communicate with k8s so that k8s don't have to change to support it
- Similar to CRI, container networking interface(CNI) and container storage interface(CSI) is developed. CSI is a standard followed by storage drivers to work with any orchestration tool, some of storage drivers are `portworx`, `Amazon EBS`, etc.
- CSI defines set of RPCs (like `createVolume`, `deleteVolume`) which will be called orchestrator and must be implemented by these storage drivers

#### Volumes
- Like in containers, pod data is also gets deleted when a pod is deleted so to persist the data, we use volumes and mounts
- We can attach volume to pod using `volumeMounts` to refer one of `volumes` created
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: random-num
spec:
  containers:
  - image: alpine
    name: alpine
    command: ["/bin/sh", "-c"]
    args: ["shuf -i 0-100 -n 1 >> /opt/number.out;]
    volumeMounts:
    - mountPath: /opt
      name: data-volume
  volumes:
  - name: data-volume
    hostpath:
      path: /data
      type: Directory
```
- Now pod `/opt` maps to host `/data` directory whatever pod writes on path `/opt` will be present on host `/data` directory even if pod dies
- This approach is not recommended if we have multi node cluster because directory will be specific to node so we use external storage solutions like `NFS`, `AWS EBS`, etc and specific option instead of `hostpath`, for example for `AWS EBS`, we use `awsElasticBlockStore`
```yaml
...
volumes:
- name: data-volume
  awsElasticBlockStore:
    volumeID: <volume-id>
    fsType: ext4
```

#### Persistent volumes(PV)
- In above section, we saw how volumes can be created the problem is it created with each pod definition. If we have lot of pods, it is hard to add/manage `volumes` with each pod so we create a `PersistentVolume` and use it with pods using `PersistentVolumeClaim` to claim the volumes persistent
```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-vol1
spec:
  accessModes:
    - ReadWriteOnce
  capacity:
    storage: 1Gi
  awsElasticBlockStore:
    volumeID: <volume-id>
    fsType: ext4
```

#### Persistent volume claims(PVC)
- Admin creates PV and user creates PVC to use the storage
- When PVC is created is gets maps to one of the PV which matches the PVC claim criteria. If user want to bind to specific PV - can provide additional filters also
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: myclaim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Mi
```
- We can now use `PVC` with pod (or replicasets, deployments) definition
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
spec:
  containers:
    - name: myfrontend
      image: nginx
      volumeMounts:
      - mountPath: "/var/www/html"
        name: mypd
  volumes:
    - name: mypd
      persistentVolumeClaim:
        claimName: myclaim
```
- We cannot delete PVC if it used by any pod - if we try it will be in `terminating` state until pod is deleted

#### Storage classes
- Before creating PV, we must create volume in provider we are using like with AWS, we must provision EBS first before PV - this is called static provisioning
- To solve above dependency we use `storageClasses` which takes the provider name and creates `PV` automatically for us like on AWS or GCP - this is dynamic provisioning
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: google-storage
provisioner: kubernetes.io/gce-pd
parameters:
  type: pd-ssd
  replication-type: regional-pd
```
- Then in PVC, we can refer this storage using `storageClassName: google-storage` in `spec` section and rest PVC definition remains same

### Networking
#### Switching routing
- To connect 2 hosts, we need to connect boths hosts using **swtich** using host's interface. Using `ip link` command we can check interface(s) on host
- **Router** connects 2 switches(networks) and creates. Router IP is the first one in the network
- We can have several routers, so hosts should know to send a packet to a host in other network which router to use - for this we use gateways (if host is a room then gateway is the door). To configure a gateway on a host, we can use below command
```bash
# To reach any IP in network 192.168.2.0/24 use gateway(router) address 192.168.1.1
# Route should be added on all hosts to send packets to hosts on other n/w
ip route add 192.168.2.0/24 via 192.168.1.1

# We can add default route for all other IPs/NW which we don't know
# Any IP for which explicit route is not added, use 192.168.1.1
ip route add default via 192.168.1.1

# See routes added on host
ip route show
route
```
- Using host as router: Linux by default doesn't forward packets received on one interface to other, this is disabled for security reasons. We can enable it using
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```
- Above setting is not retained across reboots, we can set `net.ipv4.ip_forward=1` in `/etc/sysctl.conf` file

#### DNS
- We can add custom IP to hostname mapping `/etc/hosts` file. This translation of hostname to IP is known as Name resolution
- Managing host/IP mapping like above is hard when number of hosts increases (and IPs of host can also change) so we use `DNS` server for this and configure host to point to this DNS server for host to IP lookup
- IP of DNS server can be added in `/etc/resolv.conf` file with field `nameserver` so when host doesn't know IP of a host it goes to this DNS server to get IP of a host
- If entry for same hostname is present in `/etc/hosts` and nameserver(DNS sever) both then host first checks local `/etc/hosts` file if not found then goes to DNS server configured. This ordering can also be changed using `/etc/nsswitch` file
- For public internet hosts like (google.com, fb.com, ...) we can configure global DNS servers like `8.8.8.8` (by google) to check for host IPs this can be added to `/etc/hosts` file or configure our local DNS server to check at `8.8.8.8` if not found
- We can add another entry called `search` in `/etc/hosts` file which appends domain name with host we want to search like
```bash
...
search mycompany.com
...

# If we ping `gitlab`, it will change the domain name to `gitlab.mycompany.com` automatically if it exists
# We can have list in search to have multiple items
```
- Record types
  - A: Maps IP to hostnames
  - AAAA: Maps IPv6 to hostnames
  - CNAME: Maps one name to another name (like fb.com is same as facebook.com)
- Tools
  - ping: Simple, gives IP in ping traces
  - nslookup: Resolves using DNS server, it doesn't take into account local /etc/hosts mappings
  - dig: More detailed
- Using hosts as DNS: We have various tools for this `coreDNS` is one of those. This runs on port `53`, which is the default port of DNS server

#### Docker networking
Refer this section: https://gist.github.com/hansrajdas/d950ffd99c3ae817b08fd11592dc82eb#docker-networking

#### Cluster networking
- In a k8s cluster we can have multiple nodes - master and workers with unique IPs and mac addresses, below are some ports required to be open for each component in a cluster
- ETCD(on master node): Port 2379, all control plane components connect to
- ETCD(on master node): Port 2380, is only for etcd peer-to-peer connectivity
- kube-api(on master node): Port 6443
- kubelet(on master and worker node): Port 10250
- kube-scheduler(on master and worker node): Port 10250
- kube-controller-manager(on master node): Port 10252
- services(on master node): Port 30000-32767
- **NOTE**: If things are not working, all ports are one the first things to verify

#### Pod networking and CNI
- K8s don't have any networking solution but it requires that each IP gets an unique IP address and every pod is reachable from every other pod in a cluster (with multi node also) without having to configure any NAT rules. In smaller nodes with couple of nodes, we can configure networking/routing using scripts but for large cluster it becomes hard to manage so in for those we use networking solutions(plugins) available that does this like weaveworks, flannel, cilium, vmware nsx
- We can specify the CNI/network-plugin options in `kubelet` component using below args
```bash
...
    --network-plugin=cni \
    --cni-bin-dir=/opt/cni/bin \
    --cni-conf-dir=/etc/cni/net.d \
...
```

#### CNI weaveworks
- weavework agent runs on each node and communicate with each other regarding the nodes, networks and pod. Each agent stores the topology of the entire setup and know pods and there IPs on other nodes
- weave creates its own bridge on each node and names it `weave` and assigns IP address to each n/w
- Deployed as daemon set to run on each node

#### IP address management - weave
- CNI plugin (like weave) assigns IPs to pods. In CNI config file `/etc/cni/net.d/net-script.conf` we specify `IPAM` configuration, subnets, routes, etc.
- Weave creates interface on each host with name `weave`, use `ifconfig` command to check
- Weave default subnet is `10.32.0.0/12` which is 10.32.0.1 to 10.47.255.254, around 1,048,574 IPs for pods

#### Service networking
- For services refer [this](#Services) section. This section discusses about service networking
- `kube-proxy` runs on each node which listens for changes from kubeapi server and everytime a new service is to created kube-proxy gets into action and assigns IP to the service. Unlike pod service spans across cluster
- kube-proxy creates routing rules corresponding to each service created, in this routing rule port is also present like if packet comes on IP:PORT forward it to POD-IP. This routing can be set using 3 ways - `userspace`, `iptables(default)`, `ipvs`, this can be configured by setting `--proxy-mode` in kube-proxy config
- Service IP range is configured in `kube-api-server`
```bash
kube-api-server --service-cluster-ip-range ipNet  # Default 10.0.0.0/24

# We can see the rules from NAT tables using iptables
iptables -L -t nat | grep <service-name>

# Check kube-proxy logs for routing created and mode/proxier used
cat /var/log/kube-proxy.log
```

#### DNS in kubernetes
- k8s deploys a built in DNS server by default when we setup is a cluster
- All pods and services are reachable using IP address within the cluster
- For each service k8s creates a DNS record by default which maps service name to service IP. Within same namespace, we can access the service using service names. From other namespace, we has to specify namespace also
- All service names are sub domain under domain namespace name
- All namespaces are sub domain under service `svc`
- All `svc` are sub domain under root domain called `cluster.local` by default
```bash
service name: web-service
namespace: apps

# Within same namespace
curl http://web-service

# From other namespaces, we can use any
curl http://web-service.apps
curl http://web-service.apps.svc
curl http://web-service.apps.svc.cluster.local  # FQDN
```
- DNS records for pods are not created by defualt but we can enable that, once enabled it's entry is made with dots replaced in IP with `-` to IP and not pod name to IP. If pod IP is `1.2.3.4` then entry would be `1-2-3-4` maps to `1.2.3.4`
```bash
curl http://1-2-3-4.apps.pod.cluster.local
```

#### CoreDNS in kubernetes
- Initial k8s DNS component was `kube-dns` but after `v1.12` k8s recommended to use `coreDNS`
- `coreDNS` is deployed as a replicaSet in cluster and takes a config using configMap, coreDNS config on host is placed at `/etc/coredns/Corefile`. coreDNS watches for any new service or pod (if enabled in coreDNS config file) created and adds an entry in its database
- To access coreDNS, a service is also created with name `kube-dns`. Pods are configured (by kubelet) to have kube-dns IP in `nameserver` field in file `/etc/resolv.conf`. This file also has `search` fields to make FQDN from only service-name or service.namespace

#### Ingress
- K8s object which acts as application load balancer(Layer 7) - directs request to different services based on URL path
- This becomes single where SSL can be implemented - independent of all services
- Ingress deployment - we need two things
  - **Ingress controller**: This is one of the third party solution like `nginx`, `HA proxy`, etc. K8s doesn't come with any default ingress controller so has to install one. We will use `nginx` as an example and see what all objects are required to deploy `nginx` igress controller
    - Deployment: Image used will modified version of `nginx`: `quay.io/kubernetes-ingress-controller/nginx_ingress_controller`
    - Service: Of type `NodePort` with selector of above ingress controller
    - ConfigMap: To store nginx config data
    - ServiceAccount: To access all objects - role, clusterBinding, roleBinding
  - **Ingress resources**: Configuration rules on ingress controller to route traffic to specific service based on URL like `p1.domain.com` should go to `p1` service, `p2...` to p2 or `domain.com/p1` to p1,  and so on. This rsource is created using below definition file
  ```yaml
  apiVersion: extensions/v1beta1
  kind: Ingress
  metadata:
    name: ingress-wear
  spec:
    backend:
      serviceName: wear-service  # Route all traffic to wear service
      servicePort: 80
  ```
    - We can define `rules` (with paths) in ingress resources to map traffic from different URLs to specific service
    ```yaml
    ...
    spec:
      rules:
      - http:
          paths:
          - path: /wear
            backend:
              serviceName: wear-service
              servicePort: 80
          - path: /watch
            backend:
              serviceName: watch-service
              servicePort: 80
    ```
    - We can define `rules` (with host) in ingress resources to map traffic from different subdomains to specific service
    ```yaml
    ...
    spec:
      rules:
      - host: wear.my-online-store.com
        http:
          paths:
          - backend:
              serviceName: wear-service
              servicePort: 80
      - host: watch.my-online-store.com
        http:
          paths:
          - backend:
              serviceName: watch-service
              servicePort: 80
    ```
    - Imperative way of creating ingress resources
    ```bash
    kubectl create ingress <ingress-name> --rule="host/path=service:port"

    # Example
    kubectl create ingress ingress-test --rule="wear.my-online-store.com/wear*=wear-service:80"
    ```

### Designing a cluster
- Designing a cluster would depend on what is the purpose of it, based on the purpose we can have design in different ways
  - **minikube**: Used to deploy *single node cluster* very easily. This provisions a VM and then runs k8s
  - **kubeadm**: Used to deploy *multi node cluster*. This expects VMs are already provisioned
- There no solution available on *windows* to use k8s, we has to provision a linux based VM on windows to use k8s
- For HA cluster, we use multiple *master* nodes, which is backed by a *load balancer* which directs the requests to one of the master nodes. Master nodes has below components running
  - API server: All API servers are active on all master nodes
  - Controller manager(replication & node): Only one is active others are on standby, active is elected using leader election
  - Scheduler: Only one is active others are on standby, active is elected using leader election
  - ETCD: It is distributed system so API server can reach to any of the ETCD instance running for read or write
- ETCD runs with master node and generally on master node but for complex(and HA) clusters we can run ETCD on separate nodes and connect to master nodes
- We can run cluster on-prem or cloud. In cloud, we have option to self manage cluster or use managed solutions like EKS(AWS), GKE(GCP), ...

#### ETCD in HA
- ETCD is a distributed, reliable key value store that is simple, secure and fast
- Client can connect to any instance of ETCD in cluster and perform read/write operation. If 2 writes come at the same time on 2 different ETCD instances then one is selected on the basis of leaders consent, write is complete when leader gets sconsent from other instanes in the instances
- Leader is elected using `raft` algorithm - voting election kind of mechanism
- Write is considered successful if `quorum = N/2 + 1` has that write propogated, if cluster has instances less than quorum(majority nodes) then cluster will be down
- It is recommended to have `odd` number of instances for better fault tolerance
- For installation, we can download the latest binary from github. `ETCDCTL` utility can be used to access ETCD cluster

### Install kubernetes the "kubeadm" way
Steps to setup cluster using `kubeadm` tool
- Have multiple hosts to designate one or more as master nodes - we can also use `vagrant` for provision virtual machines, [this](https://github.com/kodekloudhub/certified-kubernetes-administrator-course/blob/master/Vagrantfile) vagrantfile provisions one master and 2 worker nodes
- [Install](https://kubernetes.io/docs/setup/production-environment/container-runtimes/) container runtime like `docker` on each host(master & worker)
- [Install](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/) `kubeadm, kubelet and kubectl` on all hosts(master & worker)
- [Initialze](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#preparing-the-required-container-images) master nodes - setting up all master node components
- Setup [POD networking](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#pod-network) solution like `calico, weave net, etc.` on all nodes so all that all pods can communicate with each other
- Join worker nodes to master nodes, command is printed on running `kubeadm init` to join master - run this command on each worker nodes
- Launch applications - create pods

### Debugging failures
- Master nodes
  - Check `kube-system` pods are up and running if we unable to perform managment operations like scaling pods up/down
- Worker nodes
  - Check node status
  - Describe nodes, if it's in *Ready* state
  - Check kubelet certificates, if they are not expired
  - Check kubelet status, if it is running `service kubelet status`
  - kubelet logs `sudo journalctl -u kubelet`
- Network troubleshooting: https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/learn/lecture/24452872#content

### JSON PATH
- When dealing with cluster with large number of nodes and objects, it becomes hard to query each node/objests and check for relevant information. So we can get print only relevant result, filter and sort on specific field using `jsonpath`  option in `kubectl` command
```bash
k get nodes -ojsonpath='{.items[*].metadata.name}'        # Prints only node name
k get nodes -ojsonpath='{.items[*].status.capacity.cpu}'  # Prints cpu
...

# Print node name and cpu info
k get nodes -ojsonpath='{.items[*].metadata.name}{"\n"}{.items[*].status.capacity.cpu}'

# We can format output using loops
k get nodes -ojsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.capacity.cpu}{"\n"}{end}'

# Using custom columns is another way to printing required information - as above
k get nodes -ocustom-columns=<COLUMN NAME>:<JSON PATH>

# Print node name and CPU
k get nodes -ocustom-columns=NODE:.metadata.name,CPU:.status.capacity.cpu

# We can also use sort-by option to sort according to some value (using json path)
k get nodes --sort-by=.metadata.name

# Filter based on specfic condition - get context name for user `aws-user`
kubectl config view --kubeconfig=/root/my-kube-config -ojsonpath='{.contexts[?(@.context.user=="aws-user")].name}'
```

### Other stuff
#### Last applied configuration
- Last applied configuration is also kept with live yaml configuration. This helps k8s figure out if something is deleted then delete it from deployed version. Like a label is deleted from in new file applied, it will be checked if it was present in last applied config then will be deleted from deployed version.
- Last applied configuration is only stored when we use `kubectl apply` command, with `kubectl create/replace` command this info is not stored.
- So 3 things are compared when using `kubectl apply` command
  - New yaml file
  - Deployed yaml version
  - Last applied configuration

#### Labels, selectors and annotations
- Labels can be applied in k8s objects which can be used as selector for filtering required objects
- Like labels we can also have annotations which holds metadata info like buildversion, etc

#### Deployments vs stateful sets
- Deployment - You specify a PersistentVolumeClaim that is shared by all pod replicas. In other words, shared volume. The backing storage obviously must have ReadWriteMany or ReadOnlyMany accessMode if you have more than one replica pod.
- StatefulSet - You specify a volumeClaimTemplates so that each replica pod gets a unique PersistentVolumeClaim associated with it. In other words, no shared volume. Here, the backing storage can have ReadWriteOnce accessMode. StatefulSet is useful for running things in cluster e.g Hadoop cluster, MySQL cluster, where each node has its own storage.
- Read more here: https://stackoverflow.com/questions/41583672/kubernetes-deployments-vs-statefulsets

### Commands
**Note**: We have used pod name as `nginx` in all commands, this should be replaced with specific pod name. We have aliased *kubectl* command to *k*
```bash
alias k=kubectl
```

#### Create/run
```bash
# Create a pod
k run nginx --image=nginx

# Create pod with label
k run nginx --image=nginx -l tier=msg

# Create pod and expose port
kubectl run httpd --image=httpd:alpine --port=80 --expose

k create deployment httpd-frontend --image=https:2.4-alpine
k create namespace dev  # Create 'dev' namespace

# Doesn't create the object, only gives the yaml file
k run nginx --image=nginx --dry-run=client -o yaml > pod-definition.yaml
k create deployment nginx --image=nginx nginx --dry-run=client -o yaml > nginx-deployment.yaml
k create service clusterip redis --tcp=6379:6379 --dry-run=client -o yaml > service-definition.yaml

# Run a pod to debug or run some command like checking nslook from a pod for a service - we can use busybox image
# --rm will delete pod once command is completed or we exit from shell prompt
kubectl run --rm -it debug1 --image=<image>  --restart=Never -- <command>
kubectl run --rm -it debug1 --image=busybox:1.28  --restart=Never -- sh  # Attach with shell
```

#### Deploy yaml file
```bash
k apply -f filename.yaml
k create -f filename.yaml

# Deploy this in given namespace. This ns info can also be added in yaml definition itself
# to avoid giving in command always, like when creating a pod, it can be added in metadata section
k create -f filename.yaml -n my-namespace
```

#### Get
```bash
k get all                       # Get all k8s objects deployed
k get pods                      # Get list of all pods in current namespace like default
k get pods -n kube-system       # Get list of all pods in 'kube-system' namespace
k get pods --all-namespaces     # Get pods in all ns
k get pods -o wide              # Gives more info like IP, node, etc.
k get pods nginx                # Get specific pod info
k get pods --show-labels        # Get labels column also
k get pods --no-headers         # Don't print header
k get pods -selector app=App1   # Get pods having "app=App1" label
k get pods -l app=App1          # -l is same as -selector

# Pods running on a node
k get pods -A --field-selector spec.nodeName=<nodeName>

# Using jq - this general command can be used to filter any other parameter
k get pods -A --field-selector spec.nodeName=<nodeName> -o json | jq -r '.items[] | [.metadata.namespace, .metadata.name] | @tsv'

k get replicationcontrollers  # Get list of replica controllers

k get replicaset
k get deployments

k get services

k get daemonsets

k get events
```

#### Describe
```bash
k describe pod
k describe pod nginx

k describe replicaset myapp-replicaset

k describe deployments
k describe services

k describe daemonsets <name>
```

#### Edit
```bash
k edit pod nginx  # Opens this pods yaml file in editor and we can make the changes

k edit replicaset myapp-replicaset
```

#### Delete
```bash
k delete pod nginx

k delete replicaset myapp-replicaseet
```

#### Scale replicaSets
```bash
k replace -f replicaseet-definition.yml  # Update num of replicas and deploy yaml file

k scale --replicas=6 -f replicaseet-definition.yml
k scale --replicas=6 replicaset myapp-replicaset

k scale deployment -replicas=3 httpd-frontend
```

#### Others
- Update image in a deployment (but take care, deployment file will have different image version - originally specified)
```bash
k set image deployment/myapp-deployment nginx=nginx:1.9.1
```
- See all options available for a resource
```bash
k explain <kind>           # Format
k explain pod              # See top level options
k explain pod --recursive  # See all options

# See all tolerations options
k explain pod --recursive  | grep -A5 tolerations

# Get node summary like free persistent volume(pv) space, which we can't find with other commands
kubectl get --raw /api/v1/nodes/ip-10-3-9-207.us-west-2.compute.internal/proxy/stats/summary
```

### Certification tip
- Use dry-run option: https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/learn/lecture/14937836#content
- Imperative Commands with Kubectl: https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/learn/lecture/15018998#content
- CKA practice tests
  - Lightning Lab - 1: https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/learn/lecture/18341304#content
  - 3 Mock exams: https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/learn/lecture/15328838#content
- https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/learn/lecture/16103293#overview

### References
- K8s for absolute beginners: https://www.udemy.com/course/learn-kubernetes/
- kubeclt cheat sheet: https://kubernetes.io/docs/reference/kubectl/cheatsheet/
- HTTPS: https://robertheaton.com/2014/03/27/how-does-https-actually-work/
- Installing k8s, the hard way: https://www.youtube.com/watch?v=uUupRagM7m0&list=PL2We04F3Y_41jYdadX55fdJplDvgNGENo
- Kodecloudhub CKA course: https://github.com/kodekloudhub/certified-kubernetes-administrator-course
- End to End tests(removed from CKA exam): https://www.youtube.com/watch?v=-ovJrIIED88&list=PL2We04F3Y_41jYdadX55fdJplDvgNGENo&index=19
- CKA with Practice Tests:
  - https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/
  - https://killer.sh/
- CKA FAQs: https://www.udemy.com/course/certified-kubernetes-administrator-with-practice-tests/learn/lecture/15717196#overview
  - Use the code - `DEVOPS15` - while registering for the CKA or CKAD exams at Linux Foundation to get a 15% discount

##################
##
##
##
