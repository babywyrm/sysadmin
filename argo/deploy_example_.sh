##
##
# Source: https://gist.github.com/ae00efa6892fcb0b295bbdba73bef3ad

############################################
# Applying GitOps Principles Using Argo CD #
############################################

######################################
# Installing And Configuring Argo CD #
######################################

# Docker Desktop (docker-3gb-2cpu.sh): https://gist.github.com/0fff4fe977b194f4e9208cde54c1aa3c
# Minikube (minikube.sh): https://gist.github.com/2a6e5ad588509f43baa94cbdf40d0d16
# GKE (gke-simple-ingress.sh): https://gist.github.com/925653c9fbf8cce23c35eedcd57de86e
# EKS (eks-simple-ingress.sh): https://gist.github.com/2fc8fa1b7c6ca6b3fefafe78078b6006
# AKS (aks-simple-ingress.sh): https://gist.github.com/e24b00a29c66d5478b4054065d9ea156

git clone \
    https://github.com/vfarcic/devops-catalog-code.git

cd devops-catalog-code

git pull

# Only if macOS
brew tap argoproj/tap

# Only if macOS
brew install argoproj/tap/argocd

# Only if Linux or WSL
VERSION=$(curl --silent \
    "https://api.github.com/repos/argoproj/argo-cd/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"([^"]+)".*/\1/')

# Only if Linux or WSL
sudo curl -sSL -o /usr/local/bin/argocd \
    https://github.com/argoproj/argo-cd/releases/download/$VERSION/argocd-linux-amd64

# Only if Linux or WSL
sudo chmod +x /usr/local/bin/argocd

kubectl create namespace argocd

helm repo add argo \
    https://argoproj.github.io/argo-helm

cat argo/argocd-values.yaml

helm upgrade --install \
    argocd argo/argo-cd \
    --namespace argocd \
    --set server.ingress.hosts="{argocd.$INGRESS_HOST.nip.io}" \
    --values argo/argocd-values.yaml \
    --wait

export PASS=$(kubectl --namespace argocd \
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

echo $PASS

argocd account update-password

open http://argocd.$INGRESS_HOST.nip.io

kubectl --namespace argocd get pods

cd ../

#########################################
# Deploying An Application With Argo CD #
#########################################

git clone \
    https://github.com/vfarcic/devops-toolkit.git

cd devops-toolkit

ls -1 k8s

kubectl create namespace devops-toolkit

argocd app create devops-toolkit \
    --repo https://github.com/vfarcic/devops-toolkit.git \
    --path k8s \
    --dest-server https://kubernetes.default.svc \
    --dest-namespace devops-toolkit

open http://argocd.$INGRESS_HOST.nip.io

kubectl --namespace devops-toolkit \
    get all

argocd app delete devops-toolkit

open http://argocd.$INGRESS_HOST.nip.io

kubectl --namespace devops-toolkit \
    get all

kubectl delete namespace devops-toolkit

ls -1 helm

cd ..

###############################
# Defining Whole Environments #
###############################

open https://github.com/vfarcic/argocd-production

# Replace `[...]` with the GitHub organization
export GH_ORG=[...]

git clone \
    https://github.com/$GH_ORG/argocd-production.git

cd argocd-production

cat project.yaml

kubectl apply \
    --filename project.yaml

kubectl --namespace argocd \
    get appprojects

open http://argocd.$INGRESS_HOST.nip.io/settings/projects

kubectl create namespace production

ls -1 helm

ls -1 helm/templates

cat helm/templates/devops-toolkit.yaml

cat helm/templates/devops-paradox.yaml

cat apps.yaml

cat apps.yaml \
    | sed -e "s@vfarcic@$GH_ORG@g" \
    | tee apps.yaml

git add .

git commit -m "Changed the org"

git push

kubectl --namespace argocd apply \
    --filename apps.yaml

open http://argocd.$INGRESS_HOST.nip.io

kubectl --namespace production get all

kubectl --namespace production get ingresses

###################################################
# Updating Applications Through GitOps Principles #
###################################################

cat helm/templates/devops-toolkit.yaml \
    | sed -e "s@latest@2.9.17@g" \
    | sed -e "s@devopstoolkitseries.com@devops-toolkit.$INGRESS_HOST.nip.io@g" \
    | tee helm/templates/devops-toolkit.yaml

git add .

git commit -m "New release"

git push

kubectl --namespace production get \
    deployment devops-toolkit-devops-toolkit \
    --output jsonpath="{.spec.template.spec.containers[0].image}"

kubectl --namespace production get \
    deployment devops-toolkit-devops-toolkit \
    --output jsonpath="{.spec.template.spec.containers[0].image}"

kubectl --namespace production get ingresses

open http://devops-toolkit.$INGRESS_HOST.nip.io

rm helm/templates/devops-paradox.yaml

git add .

git commit -m "Removed DOP"

git push

open http://argocd.$INGRESS_HOST.nip.io

kubectl --namespace production get pods

############################
# Destroying The Resources #
############################

kubectl delete namespace argocd

kubectl delete namespace production

cd ..
