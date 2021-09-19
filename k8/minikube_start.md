Install kubektl
curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl && chmod +x ./kubectl && sudo mv ./kubectl /usr/local/bin/kubectl
kubectl version --client
kubernetes mangement
alias kubectl='sudo kubectl'
alias k='sudo kubectl'
k cluster-info
#Create a deployment
k create deployment hello-minikube --image=k8s.gcr.io/echoserver:1.10
# Expose it as a service
k expose deployment hello-minikube --type=NodePort --port=8080
k get pods
k get svc
k logs hello-minikube
sudo minikube service hello-minikube --url
k delete svc hello-minikube
k delete deployment hello-minikube
Pods
k get pod --all-namespaces
``


# Minikube management
``` shell
minikube start --vm-driver=none
minikube status
## Addons
minikube addons list
minikube addons enable ingress
Containers
k exec mypod -- echo 'hello world'
k exec -it mypod bash
Describe
k describe <object> <name>
Create/update based on YAML file
k create -f mypod.yml
k apply -f mypod.yml
Dashboard
sudo minikube dashboard
Labels
k get pod --show-labels
k get pod -L env -L app
k get pod -l env=dev
k get pod -l env!=dev
k get pod -l env in (prod,dev)
k get pod -l env notin (prod,dev)

k get node --show-labels
k get node -L env
k label node kub-node1 env=dev

k delete pod -l env=dev
Annotations
k describe pod mypod
k annotate pod mypod notes='asdsdgsdgsgd'
Name Spaces
k get ns
k create -f custom-namespace.yaml
k create -f mypod.yml -n custom-namespace
k get pod -n custom-namespace
k get pods --namespace kube-system
Replica Controllers
Old version of Replicasets.

k create -f mypod-rc.yaml
## Delete pod then watch it get recreated
k delete mypod-b65bg
k get pods
k get rc
k scale rc mypod --replicas=10
ReplicaSet
Like replication controllers, but allows better selectors via labels

k create -f mypod-replicaset.yaml
k get pods
k get rs
k delete rs mypod
DameonSet
These run pods on all nodes

k create -f daemon-set.yml
k get ds
k get node --show-labels
k label node kub-node2 disk=ssd
k get node -L disk
k label node kub-node2 disk=hdd --overwrite
Jobs
One off jobs. don't restart after they are complete unlike contaienrs maintained by replicasets

k create -f job.yml
k get jobs
Cron Jobs
minute, hour, dom, mont, dow

k create -f cronjob.yml
k get cronjobs
Services
k create -f mypod-svc.yml
k get svc
k describe service podsvc
k get endpoints
k exec mypod -- curl http://podsvc.default.svc.cluster.local
#You can see how DNS servers are injected into containers
k exec mypod -- cat /etc/resolv.conf
Volumes
k create -f mongodb.yml
k exec -it mongodb -- mongo
use mydb
db.test.insert({name:'test'})
db.test.find()
exit

# delete/recreate pod
k delete pod mongodb
k create -f mongodb.yml
k exec -it mongodb -- mongo
use mydb
db.test.find()
