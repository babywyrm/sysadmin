Defensive
Smarter Kubernetes Access Control: A Simpler Approach to Auth - Rob Scott, ReactiveOps

Others
Install Docker on Ubuntu
Reference from here.

# remove old versions
apt-get remove docker docker-engine docker.io containerd runc
# install
apt-get update
apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install docker-ce docker-ce-cli containerd.io

Install minikube
The documentation can be found here. In AWS you need to run:

curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
install minikube-linux-amd64 /usr/local/bin/minikube
swapoff -a
apt install conntrack
minikube start --driver=none
Install kubectl
# https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
Create containers
Privileged container
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
  - name: sec-ctx-8
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      allowPrivilegeEscalation: true
      privileged: true
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        add: ["NET_ADMIN", "SYS_TIME"]
EOF
Container with environment variables passwords
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: envvars-db
  namespace: default
spec:
  containers:
  - name: envvars-multiple-secrets
    image: nginx
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          key: db-username-key
          name: db-username
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          key: db-password-key
          name: db-password
EOF

kubectl apply -f - <<EOF

apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: null
  name: mars
---

apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: mars
  name: user1
  
---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: kube-system
  name: list-secrets
rules:
- apiGroups: ["*"]
  resources: ["secrets"]
  verbs: ["get", "list"]
  
---

apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  namespace: kube-system
  name: list-secrets-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: list-secrets
subjects:
  - kind: ServiceAccount
    name: user1
    namespace: mars
    
---

apiVersion: v1
kind: Pod
metadata:
  name: alpine-secret
  namespace: mars
spec:
  containers:
  - name: alpine-secret
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 100000"]
  serviceAccountName: user1
  automountServiceAccountToken: true
  hostNetwork: true
---

apiVersion: v1
kind: Secret
metadata:
  name: db-username
data:
  db-username-key: YWRtaW4=

---

apiVersion: v1
kind: Secret
metadata:
  name: db-password
data:
  db-password-key: MTIzNDU=

EOF

Get ServiceAccount token by name
kubectl get secrets $(kubectl get sa <SERVICE_ACCOUNT_NAME> -o json | jq -r '.secrets[].name') -o json | jq -r '.data.token' | base64 -d
Function:

alias k=kubectl
function getSecretByName {
k get secrets $(k get sa $1 -o json | jq -r '.secrets[].name') -o json | jq -r '.data.token' | base64 -d
}

getSecretByName <serviceAccountName>
*Replace <SERVICE_ACCOUNT_NAME> with the name

Delete multiple containers
// delete by match with grep
kubectl delete po $(kubectl get pods -o go-template -n <NAMESPACE> --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' | grep <SEARCH_STRING) -n <NAMESPACE>

// delete specific pods
kubectl delete pods -n <NAMESPACE> $(echo -e 'alpine1\nalpine2\nalpine3')
Get docker container IPs
docker inspect --format='{{.Name}}' $(docker ps -aq -f label=kubelabel)
docker inspect --format='{{ .NetworkSettings.IPAddress }}' $(docker ps -aq -f label=kubelabel)
