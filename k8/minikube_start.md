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

#################################################
#################################################

ga-setup-minikube
Sets up Minikube for your Github Actions.

Motivation
The KinD (Kubernetes in Docker) is amazing, and has a Github Action, but if you want to test deeper level integrations, e.g. you are writing a CNI or Service Operator, you might need Minikube.

Minikube is a mature project (at Kubernetes timescale), comes with multiple VM driver, supports Persistent Volumes, GPUs, etc.

Also, many online Kubernetes tutorial guides you through Minikube, so this action can be handy if you want to write tests against your homework.

This action assumes a Linux environment, but might work with MacOS and Windows Minikube. Anyway, it is not tested atm. PRs are welcome!

Because Minicube is flexible, there is no need to pass a lot of variable in one command line, but it is possible to set your config gradually with minikube config set and at the end start Minikube with minikube start. Therefore this action just does the basics to download and set the minimum requirement for Minikube. The rest is up to you.

Example usage
name: "Create cluster using Minikube"
on: [pull_request, push]

jobs:
  minikube-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@master
    - uses: opsgang/ga-setup-minikube@v0.1.1
      with:
        minikube-version: 1.4.0
        k8s-version: 1.15.1
    - name: Testing
      run: |
        minikube config set vm-driver docker
        minikube config set kubernetes-version v1.15.1
        minikube start
        minikube update-context
        kubectl cluster-info
        kubectl get pods -n kube-system
Note: GitHub Actions workers come pre-configured with kubectl version 1.15.1.

Optional inputs
minikube-version: Version of the Minikube. The default is 1.4.0 .
k8s-version: The Kubernetes version to use. The default is 1.15.1.
Build from source
Ref

$ npm install
$ npm i -g @vercel/ncc
$ ncc build src/setup-minikube.ts --license LICENSE
