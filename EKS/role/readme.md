# eksctl version
eksctl version
0.20.0

# kubectl/Kubernetes version
Client Version: version.Info{Major:"1", Minor:"18", GitVersion:"v1.18.3", GitCommit:"2e7996e3e2712684bc73f0dec0200d64eec7fe40", GitTreeState:"clean", BuildDate:"2020-05-21T14:51:23Z", GoVersion:"go1.14.3", Compiler:"gc", Platform:"darwin/amd64"}
Server Version: version.Info{Major:"1", Minor:"16+", GitVersion:"v1.16.8-eks-e16311", GitCommit:"e163110a04dcb2f39c3325af96d019b4925419eb", GitTreeState:"clean", BuildDate:"2020-03-27T22:37:12Z", GoVersion:"go1.13.8", Compiler:"gc", Platform:"linux/amd64"}

CLUSTER_NAME=lukaszbudniktest1
AWS_REGION=us-east-2

# eksctl will use the current identity to provision EKS cluster
aws sts get-caller-identity
eksctl create cluster --version 1.16 --name $CLUSTER_NAME --region $AWS_REGION

# user who created the cluster has full permissions
kubectl config current-context
kubectl apply -f https://k8s.io/examples/application/deployment.yaml
kubectl get pods

# open another session and use different IAM user/role
# aws cli can generate a new entry in kubeconfig for a different IAM user/role
aws sts get-caller-identity
aws eks update-kubeconfig --name $CLUSTER_NAME --region $AWS_REGION
kubectl config current-context

# test it - Kubernetes doesn't know anything about the new user
kubectl get pods
error: You must be logged in to the server (Unauthorized)

# back to first session
# add a new entry to either mapUsers or mapRoles in "configmap/aws-auth"
# see https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html for more information
# this section maps either IAM user or IAM role to Kubernetes user and groups
# below I'm mapping IAM lbudnik-test2 user to Kubernetes user "lukasz" and group "readonly"
# you can get ARN from aws sts get-caller-identity
# mapUsers: |
#  - groups:
#    - readonly
#    userarn: arn:aws:iam::XXXX:user/lbudnik-test2
#    username: lukasz
kubectl edit -n kube-system configmap/aws-auth

# create role binding for "readonly" group to "view" ClusterRole
cat <<EOF > role-binding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: default
  name: view
subjects:
- kind: Group
  name: readonly
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
EOF
kubectl apply -f role-binding.yaml

# switch back to the another session and now test a couple of kubectl commands
kubectl get deployments
kubectl get pods
# as expected create and delete fail
kubectl delete -f https://k8s.io/examples/application/deployment.yaml
Error from server (Forbidden): error when deleting "https://k8s.io/examples/application/deployment.yaml": deployments.apps "nginx-deployment" is forbidden: User "lukasz" cannot delete resource "deployments" in API group "apps" in the namespace "default"

# switch back to first session
# delete the deployment
kubectl delete -f https://k8s.io/examples/application/deployment.yaml
# delete the cluster
eksctl delete cluster --name $CLUSTER_NAME --region $AWS_REGION
  
 
#################
  
  #!/bin/bash
CLUSTERNAME=cluster-name
CLUSTER_API=cluster-api
NAMESPACE=namespace
USERNAME=username
ORGANIZATION=organization

KEY_FILE=$USERNAME.key
CSR_FILE=$USERNAME.csr
CRT_FILE=$USERNAME.crt
CERTIFICATE_NAME=$USERNAME.$NAMESPACE

openssl genrsa -out $KEY_FILE 2048
openssl req -new -key $KEY_FILE -out $CSR_FILE -subj "/CN=$USERNAME/O=$ORGANIZATION"

# To make it repeatable
kubectl get csr $CERTIFICATE_NAME && kubectl delete csr $CERTIFICATE_NAME

cat <<EOF | kubectl create -f -
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: $CERTIFICATE_NAME
spec:
  groups:
  - system:authenticated
  request: $(cat $CSR_FILE | base64 | tr -d '\n')
  usages:
  - digital signature
  - key encipherment
  - client auth
  - server auth
EOF

kubectl certificate approve $CERTIFICATE_NAME
# Retrieve the cert issued by k8s
echo "Exporting the certificate..."
kubectl get csr $CERTIFICATE_NAME -o jsonpath='{.status.certificate}'  | base64 -D > $CRT_FILE

echo "Setting permissions for the user..."
cat <<EOF | kubectl apply -f -
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: $USERNAME-binding
  namespace: $NAMESPACE
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: User
  name: $USERNAME
  apiGroup: rbac.authorization.k8s.io
EOF

echo "Creating the user kube-config file..."
kubectl config set-cluster $CLUSTERNAME \
    --server=$CLUSTER_API \
    --insecure-skip-tls-verify=true \
    --kubeconfig="config";

kubectl config set-credentials $USERNAME \
  --client-certificate=$(pwd)/$CRT_FILE \
  --client-key=$(pwd)/$KEY_FILE \
  --embed-certs \
  --kubeconfig="config";

kubectl config set-context default \
    --cluster=$CLUSTERNAME \
    --namespace=$NAMESPACE \
    --user=$USERNAME \
    --kubeconfig="config";

kubectl config use-context default \
    --kubeconfig="config";

echo "Verifying the config is working..."
kubectl get all --kubeconfig=config

  
#################  
  
  
  
