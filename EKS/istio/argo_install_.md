# Source: https://gist.github.com/a63a6970c46a2b08beb283a5b1f03b7c

####################
# Create a Cluster #
####################

# Install AWS IAM Authenticator: https://github.com/awsdocs/amazon-eks-user-guide/blob/master/doc_source/install-aws-iam-authenticator.md

# Only if you did not yet clone that repository
git clone \
    https://github.com/vfarcic/devops-catalog-code.git

cd devops-catalog-code

git pull

cd terraform-eks/simple

# Replace `[...]` with your access key ID`
export AWS_ACCESS_KEY_ID=[...]

# Replace `[...]` with your secret access key
export AWS_SECRET_ACCESS_KEY=[...]

terraform init

terraform apply

export KUBECONFIG=$PWD/kubeconfig

kubectl get nodes

cd ../../../

#################
# Install Istio #
#################

istioctl install --skip-confirmation

export ISTIO_HOSTNAME=$(kubectl \
    --namespace istio-system \
    get svc istio-ingressgateway \
    --output jsonpath="{.status.loadBalancer.ingress[0].hostname}")

export ISTIO_HOST=$(\
    dig +short $ISTIO_HOSTNAME)

echo $ISTIO_HOST

# Repeat the `export` commands if the output is empty

# If the output contains more than one IP, wait for a while longer, and repeat the `export` commands.

# If the output continues having more than one IP, choose one of them and execute `export INGRESS_HOST=[...]` with `[...]` being the selected IP.

######################
# Ingress Controller #
######################

kubectl apply \
    --filename https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v0.35.0/deploy/static/provider/aws/deploy.yaml

export INGRESS_HOSTNAME=$(kubectl \
    --namespace ingress-nginx \
    get svc ingress-nginx-controller \
    --output jsonpath="{.status.loadBalancer.ingress[0].hostname}")

export INGRESS_HOST=$(\
    dig +short $INGRESS_HOSTNAME)

echo $INGRESS_HOST

# Repeat the `export` commands if the output is empty

# If the output contains more than one IP, wait for a while longer, and repeat the `export` commands.

# If the output continues having more than one IP, choose one of them and execute `export INGRESS_HOST=[...]` with `[...]` being the selected IP.

###########
# Argo CD #
###########

helm repo add argo \
    https://argoproj.github.io/argo-helm

helm repo update

helm upgrade --install \
    argocd argo/argo-cd \
    --namespace argocd \
    --create-namespace \
    --version 2.10.0 \
    --set server.ingress.hosts="{argocd.$INGRESS_HOST.nip.io}" \
    --set server.ingress.enabled=true \
    --set server.extraArgs="{--insecure}" \
    --set installCRDs=false \
    --set controller.args.appResyncPeriod=30 \
    --wait

export PASS=$(kubectl \
    --namespace argocd \
    get pods \
    --selector app.kubernetes.io/name=argocd-server \
    --output name \
    | cut -d'/' -f 2)

argocd login \
    --insecure \
    --username admin \
    --password $PASS \
    --grpc-web \
    argocd.$INGRESS_HOST.nip.io

argocd account update-password \
    --current-password $PASS \
    --new-password admin123

export ARGOCD_ADDR=$(kubectl \
    --namespace argocd \
    get ingress argocd-server \
    --output jsonpath="{.spec.rules[0].host}")

#######################
# Destroy The Cluster #
#######################

cd devops-catalog-code/terraform-eks/simple

kubectl --namespace ingress-nginx \
    delete service ingress-nginx-controller

kubectl --namespace istio-system \
    delete service istio-ingressgateway

terraform destroy

cd ../../../
