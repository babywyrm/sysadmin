

01.minikube.md
```
create a new minikube profile
minikube profile lab
minikube set config for cpu/memory/disk
minikube config set cpus 4
minikube config set memory 8192
minikube config set disk-size 10240MB
view the set configs
minikube config view
Redeploy minikube
minikube delete && minikube start
Access a deployed application
minikube service hello-minikube --url
minikube service list
minikube enable addons
minikube addons list
minkube addons enable heapster
# once the heapster pod is up, connect to grafana interface(admin/admin)
minikube addons open heapster
kubectl switch current namespace
ksns(){
  #kubectl config set-context $(kubectl config current-context) --namespace=${1-default}
  kubectl config set-context --current --namespace=${1-default}

}
ksns kube-system
kubectl get current namespace
kgns(){
  echo "Current Namespace: $(kubectl get sa default -o jsonpath='{.metadata.namespace}')"
}
kgns
Debug minikube start
minikube start -v=7
02.kubernetes.md
Loading Dashboard
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/master/aio/deploy/recommended/kubernetes-dashboard.yaml

kubectl expose deployment kubernetes-dashboard --type=NodePort --name kubernetes-dashboard-svc

Setup Sevice Account & Associate ClusterRole for Dashboard login
# Create service account
kubectl create serviceaccount cluster-admin-dashboard-sa

# Bind ClusterAdmin role to the service account
kubectl create clusterrolebinding cluster-admin-dashboard-sa \
    --clusterrole=cluster-admin \
    --serviceaccount=kube-system:cluster-admin-dashboard-sa

# Parse the token
kubectl describe secret $(kubectl -n kube-system get secret | awk '/^cluster-admin-dashboard-sa-token-/{print $1}') | awk '$1=="token:"{print $2}'
03.kubernetes-tricks.md
Run a random pod
kubectl run hello-minikube --image=gcr.io/google_containers/echoserver:1.4 --port=8080
Expose the deployment using Nodeport
kubectl expose deployment hello-minikube --type=NodePort
Aliases
alias k="kubectl"
alias kgpow="kubectl get pods -o wide"
alias kgnow="kubectl get nodes -o wide"
alias knodes="kubectl get nodes -L nodetype -L failure-domain.beta.kubernetes.io/zone --sort-by='.metadata.labels.nodetpe'"
alias kevents="kubectl get events --sort-by='lastTimestamp'"
alias tf='terraform'
alias ekslist='aws eks list-clusters'
alias eksset='aws eks udpate-kubeconfig --name '
alias sshsh='aws ssm start-session --target'
create Context
k config set-credentials demouser@internal.users --client-key=user.key --client-certificate=user.crt
k config set-context demouser@internal.users --cluster=kubernetes --user=demouser@internal.users
k config get-contexts
k config use-context demouser@internal.users
