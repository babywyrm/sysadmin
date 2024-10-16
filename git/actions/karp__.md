GitHub Action Runners on AWS EKS

##
#
https://medium.com/@mahmood1/github-action-runners-on-aws-eks-e6339c2b9d4b
#
##

·
May 25, 2024

Today, I will show you how to use GitHub Action Runners on AWS EKS (Elastic Kubernetes Service). 
To make this work, we will need a few other components installed in the cluster, such as:

    GitHub Actions Controller
    Karpenter: Just-in-time Nodes for EKS

I’m assuming you already have an existing EKS cluster, but if you don’t, clone the simple-eks Terraform, I put together here: https://github.com/mahmoodr786/simple-eks. Do not use this terraform for production, as it creates the EKS as public and private. Although it only allows your Public IP, the recommendation is to keep your cluster private and access it using a VPN or Bastion. It also allows more IAM permissions than you need to get everything operational.

git clone https://github.com/mahmoodr786/simple-eks
cd simple-eks
terraform apply

This might take 10 to 15 minutes to complete. Once completed, you should see your cluster and the node group.

To access your cluster, you must get the Kube Config by running the following command.

aws eks update-kubeconfig --name simple-eks-cluster --region us-east-1

To confirm you can reach the cluster, run the following command:

kubectl get pods -A

Now that we have the cluster ready let's deploy the two controllers we need using Helm. We will start with Karpenter

helm registry logout public.ecr.aws
```
helm upgrade --install karpenter oci://public.ecr.aws/karpenter/karpenter --version "0.36.2" --namespace kube-system --create-namespace \
  --set "settings.clusterName=simple-eks-cluster" \
  --set controller.resources.requests.cpu=0.5 \
  --set controller.resources.requests.memory=1Gi \
  --set controller.resources.limits.cpu=0.5  \
  --set controller.resources.limits.memory=1Gi \
  --set controller.ttlSecondsAfterEmpty=300
```

```
cat <<EOF | kubectl apply -f -

apiVersion: karpenter.sh/v1beta1
kind: NodePool
metadata:
  name: default
spec:
  template:
    spec:
      requirements:
        - key: kubernetes.io/arch
          operator: In
          values: ["amd64"]
        - key: kubernetes.io/os
          operator: In
          values: ["linux"]
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["on-demand"]
        - key: karpenter.k8s.aws/instance-category
          operator: In
          values: ["c", "m", "r"]
        - key: karpenter.k8s.aws/instance-generation
          operator: Gt
          values: ["0"]
      nodeClassRef:
        name: default
  limits:
    cpu: 10000
  disruption:
    consolidationPolicy: WhenUnderutilized
    expireAfter: 720h # 30 * 24h = 720h
---
apiVersion: karpenter.k8s.aws/v1beta1
kind: EC2NodeClass
metadata:
  name: default
spec:
  amiFamily: AL2 # Amazon Linux 2
  role: "eks_node_group_role" 
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: "simple-eks-cluster"
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: "simple-eks-cluster"
EOF
```

We will first need to create a PAT token for the GitHub Actions Controller.
You can follow the instructions here: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners-with-actions-runner-controller/quickstart-for-actions-runner-controller.

Below, you can see that I have set the resource limits for runners to 7 CPUs and 14 Gi of RAM. An instance with those specs does not exist in our node groups, so Karpenter will see that and create the instance for the Actions to run on. This saves you on costs, and it only takes about two minutes for the instance to come up and run your job.

Set your GitHub URL and the PAT token, then run the Helm commands.
```
helm install arc \
    --namespace "arc-systems" \
    --create-namespace \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller

helm install "arc-runner-set" \
    --namespace "arc-runners" \
    --create-namespace \
    --set githubConfigUrl="https://github.com/yourusername/yourreponame" \
    --set githubConfigSecret.github_token="ghp_somepattokenhere342342234" \
    --set "template.spec.containers[0].resources.requests.cpu=7" \
    --set "template.spec.containers[0].resources.requests.memory=14Gi" \
    --set "template.spec.containers[0].resources.limits.cpu=7" \
    --set "template.spec.containers[0].resources.limits.memory=14Gi" \
    --set "template.spec.containers[0].name=runner" \
    --set "template.spec.containers[0].image=ghcr.io/actions/actions-runner:latest" \
    --set "template.spec.containers[0].command[0]=/home/runner/run.sh \
    oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```
We can now create our GitHub Actions Workflow. 
If you have an existing workflow, then go ahead. If not, use the simple one below and commit to the main branch of your repo you put in the githubConfigUrl.
```
name: CI
on:
  workflow_dispatch:
jobs:
  build:
    runs-on: arc-runner-set
    steps:
      - uses: actions/checkout@v4
      - name: Run a one-line script
        run: echo Hello, world!

      - name: Run a multi-line script
        run: |
          cat README.md
```


Let’s run the workflow by going to actions.

The build is waiting to be picked up by a runner.

We can see that our Pod has come up, and it is in a pending state.

We can now see that Karpenter has created our instance.

The build is now successfully completed.

Karpenter has now terminated the instance after the job was completed.

That is it. Don’t forget to terraform destroy.

