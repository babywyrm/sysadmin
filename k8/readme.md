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
