k8s kubectl cheat sheet

```
10966  argocd app delete wordpress-beta\n
10967  argocd app create wordpress-beta --repo https://github.com/zzzz/argocd-example-apps.git --path wordpress-beta --dest-namespace wordpress --dest-server https://kubernetes.default.svc\n
10970  argocd app list
10971  argocd app delete wordpress-beta\n
10974  argocd app list
10984  argocd app create wordpress-beta \\n  --repo https://github.com/zzzz/argocd-example-apps.git \\n  --path wordpress-beta \\n  --dest-server https://kubernetes.default.svc \\n  --dest-namespace wordpress \\n  --sync-policy automated\n

11071  argocd app delete wordpress-beta --cascade
11072  argocd app delete wordpress-beta --cascade \n
11080  argocd app list
11083  argocd app create wordpress-beta \\n    --repo https://github.com/zzzz/argocd-example-apps.git \\n    --path wordpress-beta \\n    --dest-server https://kubernetes.default.svc \\n    --dest-namespace wordpress\n
11084  argocd app list
11085  argocd app sync wordpress-beta
```

kubectl.md
references
https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands
how it works
https://medium.com/@bingolbalihasan/how-does-kubectl-work-writing-custom-kubectl-commands-da86e5d49c74
cheatsheet & tips
https://kubernetes.io/docs/user-guide/kubectl-cheatsheet/
https://github.com/devoriales/kubectl-cheatsheet
https://learncloudnative.com/blog/2022-05-10-kubectl-tips
https://itnext.io/tips-tricks-for-cka-ckad-and-cks-exams-cc9dade1f76d
https://cloud.google.com/anthos/gke/docs/on-prem/reference/cheatsheet
https://medium.com/flant-com/kubectl-commands-and-tips-7b33de0c5476
https://prefetch.net/blog/2019/10/16/the-beginners-guide-to-creating-kubernetes-manifests/
https://medium.com/faun/kubectl-commands-cheatsheet-43ce8f13adfb
https://gist.github.com/so0k/42313dbb3b547a0f51a547bb968696ba
https://www.atomiccommits.io/everything-useful-i-know-about-kubectl
cool gear to have
https://karlkfi.medium.com/a-select-list-of-kubernetes-tools-38249fc27155
https://karlkfi.medium.com/compendium-of-kubernetes-application-deployment-tools-80a828c91e8f
https://krew.sigs.k8s.io/plugins/
JSONAPTH
# loop with range
# list pod's name
k get po -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
k get po -o jsonpath={.items..metadata.name}
# list node names and cpu capacity
k get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.capacity.cpu}{"\n"}{end}'

# list image
kubectl get pods -o jsonpath="{..image}" | tr -s '[[:space:]]' '\n'  | sort | uniq
kubectl get pods -o jsonpath="{.items[*].spec.containers[*].image}"
kubectl get pods -o jsonpath='{.items[*].status.podIP}' 
kubectl get pods -o jsonpath='{range .items[*]}{"\n"}{.metadata.name}{":\t"}{range .spec.containers[*]}{.image}{", "}{end}{end}'

kubectl get svc -l component=elasticsearch,role=client -o jsonpath='{..ip}'
grace=$(kubectl get po cassandra-0 -o=jsonpath=‘{.spec.terminationGracePeriodSeconds}’) 
grace=$(kubectl get sts -l component=elasticsearch,role=data -o jsonpath='{..terminationGracePeriodSeconds}'

# list node instance type, zone, ami
echo "***list karpenter nodes ami"
kubectl get nodes -L karpenter.k8s.aws/instance-ami-id -l karpenter.sh/provisioner-name=default -o custom-columns="Name:.metadata.name,InstanceType:.metadata.labels.node\.kubernetes\.io/instance-type,\
Zone:.metadata.labels.topology\.kubernetes\.io/zone,Ami:.metadata.labels.karpenter\.k8s\.aws/instance-ami-id"
custom-columns
# same query  in jsonpath
k get po -o custom-columns='POD_NAME:metadata.name'
# same query as in jsonpath for node and cpu counts
k get nodes -o custom-columns="NODE:.metadata.name,CPU:.status.capacity.cpu"

# node name
k get nodes -o custom-columns=NAME:.metadata.name
# pod name
k get po -o custom-columns=NAME:.metadata.name
# image name
k get po -o custom-columns='IMAGE:spec.containers[*].image'

# list container image and k8s-app lable value in kube-system
k get deployment -o custom-columns='IMAGE:.spec.template.spec.containers[*].image,LABEL:.spec.template.metadata.labels.k8s-app' -n kube-system
sort-by
# implict range or items[*]

k get nodes --sort-by=".metadata.name"
k get nodes --sort-by=".status.capacity.cpu"

k get po --sort-by=.spec.nodeName -o wide
k get po --sort-by=".metadata.creationTimestamp"
k get pv --sort-by=.spec.capacity.storage -o custom-columns="NAME:.metadata.name,CAPACITY:.spec.capacity.storage"

clean up pods
Did this for cleaning up pods with not in Running state such as Terminated

k get po --field-selector=status.phase!=Running -o custom-columns=":metadata.name" --no-headers | xargs kubectl delete po
mysql and psql
kubectl run -n default mysql-client-${USER} --image=mysql:5.7 -it --restart=Never -- /bin/bash
kubectl run -n default psql-cli-${USER} --image=postgres -it  --restart=Never -- bash
wait for
https://vadosware.io/post/so-you-need-to-wait-for-some-kubernetes-resources/
kubectl -n istio-system wait --for=jsonpath='{.data.ca\.crt}' secrets/cacerts
debug
kubectl run -it --rm debug --image=busybox -- sh
busybox https://busybox.net/downloads/BusyBox.html
cert compare
kubectl get validatingwebhookconfigurations.admissionregistration.k8s.io aws-load-balancer-webhook -ojsonpath={.webhooks[0].clientConfig.caBundle}  | base64 -d  | openssl x509 -noout -text
kubectl get secret -n kube-system  aws-load-balancer-tls -ojsonpath="{.data.ca\.crt}" |base64 -d   |openssl x509 -noout -text
context, namespace
 get current context: kubectl config view -o=jsonpath='{.current-context}'
 get all contexts:  kubectl config get-contexts -o=name | sort -n
 get namesapce:  kubectl get namespaces -o=jsonpath='{range .items[*].metadata.name}{@}{"\n"}{end}'
 
kubectl config use-context <cluster_name_in_kubeconfig>
kubectl --context <context>

## set the namespace for the current context
```
kubectl config set-context gke_sandbox-co_us-west1-a_cka --namespace=kube-system
kubectl config set-context --current --namespace=kube-system
API
https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/
API group https://kubernetes.io/docs/reference/using-api/api-overview/#api-groups
API convention https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#api-conventions
# Print the supported API group and its versions on the server, in the form of "group/version"
k api-versions | sort 

# list api-resources with sorting
kubectl api-resources --sort-by=name 
kubectl api-resources --sort-by=kind
```

# find out what is under the api group
```
k api-resources --api-group=networking.k8s.io
NAME              SHORTNAMES   APIVERSION             NAMESPACED   KIND
ingressclasses                 networking.k8s.io/v1   false        IngressClass
ingresses         ing          networking.k8s.io/v1   true         Ingress
networkpolicies   netpol       networking.k8s.io/v1   true         NetworkPolicy
```
# then we can explain with $APIVERSION
k explain --api-version=$APIVERSION ingress --recursive
k explain --api-version=apps/v1 deployment --recursive

# for each "group/version" in the output above except for "api/v1"
kubectl get --raw /apis/${group/version} |  jq -r '.resources[].kind'

kubectl get --raw /apis/apps/v1 | jq . -C | less -R

API_SERVER_ENDPOINT="$(kubectl config view --raw -o json | jq -r '.clusters[0].cluster.server')

list resources under a specific api version.
This is due to API deprecations

kubernetes/kubernetes#58131 (comment)
kubectl get deployments.v1.apps
secret
echo $(kubectl get secret/terraform -o jsonpath="{.data['terraform\.json']}" | base64 --decode)
Play with jid and jq
https://gist.github.com/so0k/42313dbb3b547a0f51a547bb968696ba
https://kubernetes.io/docs/tasks/access-application-cluster/list-all-running-container-images/
Get the TCP LB port and IP
  EXT_IP="$(kubectl get svc hello-server -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')"
  EXT_PORT=$(kubectl --namespace default get service hello-server -o=jsonpath='{.spec.ports[0].port}')
  echo "$EXT_IP:$EXT_PORT"
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$EXT_IP:$EXT_PORT"/)" -eq 200 ] || exit 1
deployment
rollout
kubectl rollout pause deployment/hello
kubectl rollout status deployment/hello
# check the versions on pods
kubectl get pods -o jsonpath --template='{range .items[*]}{.metadata.name}{"\t"}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
kubectl rollout resume deployment/hello
# roll back
kubectl rollout undo deployment/hello
rbac
# list what a sa 's rbac
k auth can-i --list  --as system:serviceaccount:datadog:datadog 
k auth can-i get crd --as system:serviceaccount:velero:velero
k auth can-i '*' '*' --as system:serviceaccount:default:remote-admin-sa --all-namespaces
# list what I can do
k auth can-i get crd
k auth can-i '*' '*' --all-namespaces

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

find top resource hungry pod
# pod sort by cpu
k top pods --sort-by=cpu --no-headers 
# container sort by memory
k top pods --containers --sort-by=memory
kubectl top pods -A --no-headers | sort -rn -k 3
# memory
kubectl top pods -A --no-headers | sort -rn -k 4
# top 1
kubectl top pod  --no-headers | grep -v NAME | sort -k 3 -nr | awk -F ' ' 'NR==1{print $1}'
metrics
https://talkcloudlytome.com/raw-kubernetes-metrics-with-kubectl/
https://www.datadoghq.com/blog/how-to-collect-and-graph-kubernetes-metrics/
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
labels
kubectl get nodes -L karpenter.sh/nodepool -L node.kubernetes.io/instance-type -L topology.kubernetes.io/zone -L karpenter.sh/capacity-type



@pydevops
Author
pydevops commented on Jul 18

```
```
# Remove argocd apps finalizer script
```
#!/usr/bin/env bash
APPS=$(kubectl -n argocd get app -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
for app in $APPS
do
 echo "patch $app 's finalizer"
 kubectl patch app/$app \
    --type json \
    --patch='[ { "op": "remove", "path": "/metadata/finalizers" } ]'
done
