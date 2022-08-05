## reference
* https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands
* [how it works](https://github.com/jamiehannaford/what-happens-when-k8s)

## cheatsheet
* https://itnext.io/tips-tricks-for-cka-ckad-and-cks-exams-cc9dade1f76d
* https://cloud.google.com/anthos/gke/docs/on-prem/reference/cheatsheet
* https://medium.com/flant-com/kubectl-commands-and-tips-7b33de0c5476
* https://prefetch.net/blog/2019/10/16/the-beginners-guide-to-creating-kubernetes-manifests/
* https://kubernetes.io/docs/user-guide/kubectl-cheatsheet/
* https://learnk8s.io/blog/kubectl-productivity/
* https://medium.com/faun/kubectl-commands-cheatsheet-43ce8f13adfb
* https://gist.github.com/so0k/42313dbb3b547a0f51a547bb968696ba
* https://www.atomiccommits.io/everything-useful-i-know-about-kubectl

## cool gear to have
* https://karlkfi.medium.com/a-select-list-of-kubernetes-tools-38249fc27155
* https://karlkfi.medium.com/compendium-of-kubernetes-application-deployment-tools-80a828c91e8f
* https://medium.com/free-code-camp/how-to-set-up-a-serious-kubernetes-terminal-dd07cab51cd4
* https://krew.sigs.k8s.io/plugins/

## imperative
* https://kubernetes.io/docs/tasks/manage-kubernetes-objects/imperative-command/
* https://medium.com/better-programming/kubernetes-tips-create-pods-with-imperative-commands-in-1-18-62ea6e1ceb32
* https://medium.com/bitnami-perspectives/imperative-declarative-and-a-few-kubectl-tricks-9d6deabdde
* https://blog.heptio.com/using-kubectl-to-jumpstart-a-yaml-file-heptioprotip-6f5b8a63a3ea

## clean up pods 
Did this for cleaning up pods with not in Running state such as Terminated

```
k get po --field-selector=status.phase!=Running -o custom-columns=":metadata.name" --no-headers | xargs kubectl delete po
```

## waitfor

* https://vadosware.io/post/so-you-need-to-wait-for-some-kubernetes-resources/

## debug 
```
kubectl run -it --rm debug --image=busybox -- sh
```
* busybox https://busybox.net/downloads/BusyBox.html

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
* API group https://kubernetes.io/docs/reference/using-api/api-overview/#api-groups
* API convention https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#api-conventions

```
# Print the supported API group and its versions on the server, in the form of "group/version"
k api-versions | sort 

# list api-resources with sorting
kubectl api-resources --sort-by=name 
kubectl api-resources --sort-by=kind

# find out what is under the api group

k api-resources --api-group=networking.k8s.io
NAME              SHORTNAMES   APIVERSION             NAMESPACED   KIND
ingressclasses                 networking.k8s.io/v1   false        IngressClass
ingresses         ing          networking.k8s.io/v1   true         Ingress
networkpolicies   netpol       networking.k8s.io/v1   true         NetworkPolicy

# then we can explain with $APIVERSION
k explain --api-version=$APIVERSION ingress --recursive
k explain --api-version=apps/v1 deployment --recursive

# for each "group/version" in the output above except for "api/v1"
kubectl get --raw /apis/${group/version} |  jq -r '.resources[].kind'

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
k get pv --sort-by=.spec.capacity.storage -o=custom-columns="NAME:.metadata.name,CAPACITY:.spec.capacity.storage"
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

```
## find top resource hungry pod
```
# cpu
k top pods --sort-by=cpu --no-headers 
kubectl top pods -A --no-headers | sort -rn -k 3
# memory
kubectl top pods -A --no-headers | sort -rn -k 4
# top 1
kubectl top pod  --no-headers | grep -v NAME | sort -k 3 -nr | awk -F ' ' 'NR==1{print $1}'
```

## metrics
* https://talkcloudlytome.com/raw-kubernetes-metrics-with-kubectl/
* https://www.datadoghq.com/blog/how-to-collect-and-graph-kubernetes-metrics/

```
# all nodes
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes | jq -C . | less -R
# individual node 
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes/$NODE_NAME

# all pods
kubectl get --raw /apis/metrics.k8s.io/v1beta1/pods | jq . -C | less -R
# individual pod
kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/$NS/pods/$POD

# jq
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes \
| jq '[.items [] | {nodeName: .metadata.name, nodeCpu: .usage.cpu, nodeMemory: .usage.memory}]'

kubectl get --raw /apis/metrics.k8s.io/v1beta1/pods | jq . -C | less -R
```
