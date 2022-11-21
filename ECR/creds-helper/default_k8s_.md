# Archived
##
#
https://github.com/aws-containers/amazon-ecr-public-creds-helper-script-for-k8s
#
##


serviceaccount.lyaml

```
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-secrets-editor
  namespace: ecr-public-creds-helper
---
# As you may realized, this is not the minimum permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-editor
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: edit-secrets
subjects:
- kind: ServiceAccount
  name: sa-secrets-editor
  namespace: ecr-public-creds-helper
roleRef:
  kind: ClusterRole
  name: secrets-editor
  apiGroup: rbac.authorization.k8s.io
  
```  
### This repository was archived as Amazon ECR Public today handles all image pull requests sent from workloads on AWS compute as `authenticated` requests.

# Amazon ECR "Public" credentials helper script for Kubernetes

Amazon ECR "Public" credentials helper script for Kubernetes (`ecr-public-creds-helper-for-k8s` for short) allows your Kubernetes clusters pull public container images from [Amazon ECR Public](https://aws.amazon.com/blogs/aws/amazon-ecr-public-a-new-public-container-registry/) registries **as authenticated users** to get the limit upgraded to `10` pulls per second which is `1` for unauthenticated users as described [here](https://docs.aws.amazon.com/AmazonECR/latest/public/public-service-quotas.html), and unlimited data bandwidth as described [here](https://aws.amazon.com/ecr/pricing/).

`ecr-public-creds-helper-for-k8s` is one of the workarounds to access ECR Public as authenticated users from your Kubernetes clusters until 1) Amazon ECR Public get supported by the upstream Kubernetes project and/or 2) Official Amazon ECR Public support for AWS Fargate by Amazon EKS.

`ecr-public-creds-helper-for-k8s` runs in your cluster as a Kubernetes CronJob every 8 hours by default. It authenticates against ECR Public and stores the auth token as Kubernetes Secrets within namespaces you specified.

Each pod (even on AWS Fargate) will reference that Kubernetes Secret in its namespace by specifying the `imagePullSecrets` field in the PodSpec. You may also want to patch the `default` service account in each namespace to avoid writing `imagePullSecrets` in all PodSpecs, see the comments at the [entrypoint.sh#L21](entrypoint.sh#L21) for further details.

See the "[Create a Secret by providing credentials on the command line](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/#create-a-secret-by-providing-credentials-on-the-command-line)" section and the "[Create a Pod that uses your Secret](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/#create-a-pod-that-uses-your-secret)" in the Kubernetes documentation to understand how it works.

## Motivations

This project aims to fill the gap between Amazon EKS (Kubernetes, both EC2 and Fargate) and Amazon ECR Public. There are two pain points for users at the time of release of this repository as follows:

1. Kubernetes supports Amazon ECR (the private one) to pull private ECR images with automatic auth via IAM roles, but still the latest version (1.20, at this moment) of Kubernetes doesn't support ECR Public yet. Thus there is no straightforward way to pull ECR Public container images from EKS/Kubernetes clusters as authenticated users. This means users are forced to access ECR Public as unauthenticated users from their Kubernetes clusters, resulting that pulls from ECR Public could be throttled easily and frequently.
1. [A PR in the "awslabs/amazon-ecr-credential-helper" GitHub repository](https://github.com/awslabs/amazon-ecr-credential-helper/pull/253) could solve the pain point #1 someday, but the "awslabs/amazon-ecr-credential-helper" itself cannot be used for EKS/Fargate workloads by its design. EKS/Fargate users, not only EKS/EC2 users, obviously need a way to use ECR Public as authenticated users, so this is also the pain point that this project addresses.

## Installation

### Step 0 - Clone repo

```shell
$ git clone https://github.com/aws-containers/amazon-ecr-public-creds-helper-for-k8s.git
$ cd amazon-ecr-public-creds-helper-for-k8s
```

### Step 1 - Build and Push creds-helper container image

```shell
$ export CREDS_HELPER_CONTAINER_IMAGE=<your-creds-helper-container-image-name-here>

$ docker build -t ${CREDS_HELPER_CONTAINER_IMAGE} .

$ docker push ${CREDS_HELPER_CONTAINER_IMAGE}
```

### Step 2 - Create namespace

Create a namespace for `ecr-public-creds-helper-for-k8s` to run as a CronJob in your Kubernetes cluster.

```shell
$ kubectl apply -f namespace.yaml
namespace/ecr-public-creds-helper created
```

### Step 3 - Create service account

Create a service account to allow `ecr-public-creds-helper-for-k8s` to edit Kubernetes secrets.

```shell
$ kubectl apply -f serviceaccount.yaml
serviceaccount/sa-secrets-editor created
clusterrole.rbac.authorization.k8s.io/secrets-editor created
clusterrolebinding.rbac.authorization.k8s.io/edit-secrets created
```

### Step 4 - Create IAM role

Create an AWS IAM role to allow `ecr-public-creds-helper-for-k8s` to authenticate against Amazon ECR Public. We use the mechanism called [IAM Roles for Service Accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) to map it to the service account which you created in the previous step.

If you have not enabled IRSA in your Kubernetes cluster yet, please follow the [IRSA documentation](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) and/or the [blog post](https://aws.amazon.com/blogs/opensource/introducing-fine-grained-iam-roles-service-accounts/) for enabling IRSA for your Kubernetes cluster.

#### Steps with eksctl

We're going to use `eksctl` here to show the steps to create and map the IAM role in an EKS cluster, but you can also use the AWS CLI, the AWS management console, CloudFormation, Terraform or whatever you want to use.

```shell
$ export POLICY_ARN=$(aws iam create-policy --policy-name AmazonECRPublicAuthOnlyPolicy --policy-document file://iam-permission.json --query Policy.Arn --output text)
## Check you've created the policy successfully
$ echo ${POLICY_ARN}
arn:aws:iam::YOUR_AWS_ACCOUNT_ID:policy/AmazonECRPublicAuthOnlyPolicy

$ export EKS_CLUSTER_NAME=<your-eks-cluster-name-here>

$ eksctl create iamserviceaccount --cluster=${EKS_CLUSTER_NAME} \
    --name=sa-secrets-editor \
    --namespace=ecr-public-creds-helper \
    --attach-policy-arn=${POLICY_ARN} \
    --override-existing-serviceaccounts \
    --approve
```

### Step 5 - Configure and Apply

#### Configure cronjob.yaml

Edit the [cronjob.yaml](cronjob.yaml) before running `ecr-public-creds-helper-for-k8s` in your Kubernetes cluster.

```shell
$ vim cronjob.yaml
```

There are two **required** fields to change.

##### 1. `image` field

Replace `${CREDS_HELPER_CONTAINER_IMAGE}` in [line.22 in the cronjob.yaml](cronjob.yaml#L22) with your creds helper container image name which you built and pushed in the Step 1.

##### 2. `env.value` field

Replace the value (`default foo bar`) of `TARGET_NAMESPACES` environment variable in [line.26 in the cronjob.yaml](cronjob.yaml#L26) with a space-delimited list which includes one or multiple Kuberentes namespaces where your pods need the auth token for ECR Public.

Let's say you want to pull ECR Public container images in three namespaces (`default`, `prometheus`, `my-app`) with auth token, then the `env.value` field will look like: `value: "default prometheus my-app"`.

`ecr-public-creds-helper-for-k8s` will store the auth token as Kubernetes Secrets in these namespaces.

#### Apply cronjob.yaml

Run `ecr-public-creds-helper-for-k8s` in your Kubernetes cluster.

```shell
$ kubectl apply -f cronjob.yaml
cronjob.batch/ecr-public-creds-helper created
```

### Step 6 - (Optional but recommended) Run Job manually

Create an initial auth token manually to let your pods use it without waiting the initial cronjob to be started. Note that `ecs-public-creds-helper-for-k8s` [refreshes the auth token in every 8 hours by default](cronjob.yaml#L8).

```shell
$ kubectl create job initial-creds-job \
    -n ecr-public-creds-helper \
    --from=cronjob/ecr-public-creds-helper
job.batch/initial-creds-job created

## Check the pod log to make sure it works as expected
$ export POD_NAME=$(kubectl get pods --selector=job-name=initial-creds-job -n ecr-public-creds-helper -o jsonpath='{.items[0].metadata.name}')

$ echo ${POD_NAME}
initial-creds-job-r4fbp # you'll see something like this

$ kubectl logs ${POD_NAME} -n ecr-public-creds-helper
### You'll see the same number of lines as the namespaces you specified in the "TARGET_NAMESPACES" in the cronjob.yaml
secret/ecr-public-token created
secret/ecr-public-token created
secret/ecr-public-token created

$ kubectl delete job initial-creds-job -n ecr-public-creds-helper
job.batch "initial-creds-job" deleted
```

## Use auth tokens in Pods

Now your pod can use the auth token (Kubernetes secret) created by `ecr-public-creds-helper-for-k8s` to pull public container images as an authenticated user from Amazon ECR Public registries.

You can reference the auth token from your pods like:

```yaml
apiVersion: v1
kind: Pod
# ~ snip ~
spec:
# ~ snip ~
  imagePullSecrets:
  - name: ecr-public-token
# ~ snip ~
```

See also [examples/pod.yaml](examples/pod.yaml) for full example.

If you don't want to add `imagePullSecrets` in each PodSpec, you may want to see the comments in the [entrypoint.sh](entrypoint.sh#L18).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

Licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
