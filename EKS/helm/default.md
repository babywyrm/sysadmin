Using Helm with Amazon EKS

##
#
https://docs.aws.amazon.com/eks/latest/userguide/helm.html
#
##


PDF
RSS

The Helm package manager for Kubernetes helps you install and manage applications on your Kubernetes cluster. For more information, see the Helm documentation

. This topic helps you install and run the Helm binaries so that you can install and manage charts using the Helm CLI on your local system.
Important

Before you can install Helm charts on your Amazon EKS cluster, you must configure kubectl to work for Amazon EKS. If you have not already done this, see Create a kubeconfig for Amazon EKS before proceeding. If the following command succeeds for your cluster, you're properly configured.

kubectl get svc

To install the Helm binaries on your local system

    Run the appropriate command for your client operating system.

        If you're using macOS with Homebrew

, install the binaries with the following command.

brew install helm

If you're using Windows with Chocolatey

, install the binaries with the following command.

choco install kubernetes-helm

If you're using Linux, install the binaries with the following commands.

curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 > get_helm.sh
chmod 700 get_helm.sh
./get_helm.sh

Note

If you get a message that openssl must first be installed, you can install it with the following command.

    sudo yum install openssl

To pick up the new binary in your PATH, Close your current terminal window and open a new one.

See the version of Helm that you installed.

helm version --short | cut -d + -f 1

The example output is as follows.

v3.9.0

At this point, you can run any Helm commands (such as helm install chart-name) to install, modify, delete, or query Helm charts in your cluster. If you're new to Helm and don't have a specific chart to install, you can:

    Experiment by installing an example chart. See Install an example chart

in the Helm Quickstart guide

.

Create an example chart and push it to Amazon ECR. For more information, see Pushing a Helm chart in the Amazon Elastic Container Registry User Guide.

Install an Amazon EKS chart from the eks-charts
GitHub repo or from ArtifactHub.
