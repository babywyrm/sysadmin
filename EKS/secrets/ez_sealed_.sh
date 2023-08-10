sh# Source: https://gist.github.com/820aecf0799d679d9082eef00d07b515

#############################################################################
# Bitnami Sealed Secrets                                                    #
# How To Store Kubernetes Secrets In Git Repositories Without Getting Fired #
# https://youtu.be/xd2QoV6GJlc                                              #
#############################################################################

# Referenced videos:
# - What Is GitOps And Why Do We Want It?: https://youtu.be/qwyRJlmG5ew
# - Argo CD: Applying GitOps Principles To Manage Production Environment In Kubernetes: https://youtu.be/vpWQeoaiRM4
# - Flux CD v2 With GitOps Toolkit - Kubernetes Deployment And Sync Mechanism (Second Review): https://youtu.be/R6OeIgb7lUI

#########
# Setup #
#########

# Create a k8s cluster
# Install `kubeseal` CLI from https://github.com/bitnami-labs/sealed-secrets

kubectl apply \
    --filename https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.13.1/controller.yaml

###################
# Sealing secrets #
###################

kubectl --namespace default \
    create secret \
    generic mysecret \
    --dry-run=client \
    --from-literal foo=bar \
    --output json

kubectl --namespace default \
    create secret \
    generic mysecret \
    --dry-run=client \
    --from-literal foo=bar \
    --output json \
    | kubeseal \
    | tee mysecret.yaml

kubectl create \
    --filename mysecret.yaml

kubectl get secret mysecret \
    --output yaml

kubectl get secret mysecret \
    --output jsonpath="{.data.foo}" \
    | base64 --decode && echo

kubeseal --fetch-cert
