## Notes

Capturing some notes on how I setup my EKS cluster, as it took several attempts 😂 😳 

### AWS Account

I created a **brand new AWS account**, since I kept bumping up against limits when using the existing GitHub / Professional Services AWS. I made a careful note of:

1. My AWS account id
1. My Access Key ID
1. My Secret Access Key

Despite what the AWS docs say, I used my root credentials throughout this demo, just to save time.

### Installation
I followed the steps from [this guide](https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html) to setup `aws`, `eksctl`, `kubectl`, and `aws-iam-authenticator` _locally_:

```bash

pip install awscli --upgrade --user

# Install eksctl
brew tap weaveworks/tap

brew install weaveworks/tap/eksctl

eksctl version
# [ℹ]  version.Info{BuiltAt:"", GitCommit:"", GitTag:"0.3.1"}
```

### Install and Configure kubectl for Amazon EKS

It's already done for us on macOS (thanks homebrew :bow:):

```bash
which kubectl
# /usr/local/bin/kubectl

which aws-iam-authenticator
# /Users/swinton/go/bin/aws-iam-authenticator
```
### Create Your Amazon EKS Cluster and Worker Nodes

Despite what [this page](https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html#eksctl-create-cluster) says, I just did:

```bash
eksctl create cluster
```

I had to wait for my AWS account to be approved before this would work. It seems the account has to be approved for each region separately, when it comes to EKS.

_Eventually_ I was able to get an EKS cluster running in the `us-east-2` region.

### Access the cluster

```bash
# When your cluster is ready, test that your kubectl configuration is correct
kubectl get svc
```

### Generate a kube config

```bash
CLUSTER_NAME=fabulous-monster-1565378541  # this was generated from the above eksctl create cluster command 
AWS_DEFAULT_REGION=us-east-2
aws eks update-kubeconfig --name $CLUSTER_NAME --region $AWS_DEFAULT_REGION
```

This generates a `~/.kube/config` file, I then base64-encoded the contents of this file and saved it as a secret, `KUBE_CONFIG_DATA`, in my @bbq-beets repo.

```bash
cat ~/.kube/config | base64 | pbcopy
```

### ECR

For the demo to work, it's also necessary to create an ECR registry, in the same AWS region as the EKS cluster (`us-east-2` in my case). I did this directly via the AWS console:

![Screen Shot 2019-08-13 at 2 57 08 PM](https://user-images.githubusercontent.com/27806/62972884-a7f6cb80-bdda-11e9-91ae-15c71e37b2ac.png)

I then updated [the kube `config.yml`](https://github.com/bbq-beets/example-eks/blob/146f5ac5efbfa7b39da2af8dfb47b5d8149ec9ae/config.yml#L19) to match this ECR registry URI.

### Secrets

The following secrets are also required:

![Screen Shot 2019-08-13 at 2 49 11 PM](https://user-images.githubusercontent.com/27806/62972422-9a8d1180-bdd9-11e9-9fd5-8edc0e9565e1.png)

1. `AWS_ACCOUNT_ID`: My AWS account id
1. `AWS_ACCESS_KEY_ID`: My Access Key ID for my **root** account, which isn't the ideal, but it works
1. `AWS_SECRET_ACCESS_KEY`: My Secret Access Key for my **root** account, which isn't the ideal, but it works
1. `AWS_ECR_PASSWORD`: The password for ECR, obtained via `aws ecr get-login --region $AWS_REGION --no-include-email`
1. `KUBE_CONFIG_DATA`: From the above, `cat ~/.kube/config | base64 | pbcopy`
