##
#
https://aws.amazon.com/blogs/containers/enabling-cross-account-access-to-amazon-eks-cluster-resources/
#
##

Enabling cross-account access to Amazon EKS cluster resources
by Satya Vajrapu and Jason Smith | on 17 MAR 2020 | in Amazon Elastic Kubernetes Service, AWS Fargate, Containers | Permalink |  Comments |  Share
Amazon Elastic Kubernetes Service (Amazon EKS) is a managed service that makes it easy for you to run Kubernetes on AWS without needing to stand up or maintain your own Kubernetes control plane. The recent launches of managed node groups and Amazon EKS on AWS Fargate removes the need to provision and manage infrastructure for pods. Kubernetes is an open-source system for automating the deployment, scaling, and management of containerized applications

Often customers manage their AWS environments separated using multiple AWS accounts. They do not want production resources to interact or coexist with development or staging resources. While this provides the benefits of better resource isolation, it increases the access management overhead.

User access to multiple accounts can be managed by leveraging temporary AWS security credentials using AWS Security Token Service (STS) and IAM roles. But what if the resources, say, containerized workloads or pods in an Amazon EKS cluster hosted in one account wants to interact with the Amazon EKS cluster resources hosted in another account? In this previous blog, we discussed how to use fine-grained roles at the pod level using IAM Roles for Service Accounts (IRSA). In this blog, we extend this solution and demonstrate how a pod in an Amazon EKS cluster hosted in one account can interact and manage the AWS resources and Amazon EKS cluster resources in a different account.

Scenario
Let’s assume that we have a customer with multiple accounts – dev, stg, and prod who wants to manage the resources from a continuous integration (CI) account. An Amazon EKS cluster in this CI account needs to access AWS resources to these target accounts. One simple way to grant access to the pods in the CI account to target cross-account resources is:

Create roles in these target accounts
Grant assume role permissions to the CI account Amazon EKS cluster node instance profile on the target account roles
And finally, trust this cluster node instance profile in the target account’s role(s)


Though this will allow the Amazon EKS cluster in the CI account to communicate with the AWS resources in the target accounts, it grants any pod running on this node access to this role. At AWS, we always insist to follow the standard security advice of granting least privilege, or granting only the permissions required to perform a task. Start with a minimum set of permissions and grant additional permissions as necessary.

Solution
AWS Identity and Access Management (IAM) supports federated users using OpenID Connect (OIDC). Amazon EKS hosts a public OIDC discovery endpoint per cluster containing the signing keys for the ProjectedServiceAccountToken JSON web tokens so external systems, like IAM, can validate and accept the OIDC tokens issued by Kubernetes. The steps below outline the process to grant access to the Amazon EKS cluster in the CI account to AWS resources and an Amazon EKS cluster in the target account while being restricted to the service account assigned to the pod.



Prerequisites
To follow the steps outlined in this post, you need an AWS account.

Configure your AWS Command Line Interface (AWS CLI) settings to use multiple configurations that you can refer to with a name by specifying the --profile option and assigning a name. The steps outlined below uses two named profiles, ci-env and target-env. For more information on setting the profiles, please check here.

1.    Fetch the CI account cluster’s OIDC issuer URL
If your Amazon EKS cluster version is 1.14 or updated to 1.13 on or after September 3, 2019, it will have an OpenID Connect issuer URL. You can get this URL from the Amazon EKS console directly, or you can use the following AWS CLI command to retrieve it.

aws eks describe-cluster --name <CI_EKS_CLUSTER_NAME> --query "cluster.identity.oidc.issuer" --output text --profile ci-env

2.    Create an OIDC provider for the cluster in the CI account
Navigate to the IAM console in the CI account, choose Identity Providers, and then select Create provider. Select OpenID Connect for provider type and paste the OIDC issuer URL for your cluster for provider URL. Enter sts.amazonaws.com for audience as shown below.



Once the information is entered, choose Next Step. Review if all the provided information is correct in the page and finally choose Create in the next page to create your identity provider. Save the OIDC provider URL for the next step.



3.    Configuring the CI account – IAM role and policy permissions
Create an IAM role in the CI account, ci-account-iam-role, with a trust relationship to the cluster’s OIDC provider and specify the service-account, namespace to restrict the access. In this case, I am specifying ci-namespace and ci-serviceaccount for namespace and serviceaccount respectively. Replace the OIDC_PROVIDER with the provider URL saved in the previous step.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::CI_ACCOUNT_ID:oidc-provider/OIDC_PROVIDER"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "<OIDC_PROVIDER>:sub": "system:serviceaccount:ci-namespace:ci-serviceaccount"
        }
      }
    }
  ]
}
```
Once the role is created, attach the IAM policy that you want to associate with the serviceaccount. In our case, the serviceaccount must be able to assume role to the target account, so grant the following assume role permissions.

Note that if you haven’t created the target account IAM role, please proceed to step 4 and complete configuring the target AWS account and then finish associating this policy.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::TARGET_ACCOUNT_ID:role/target-account-iam-role"
        }
    ]
}
```
In Kubernetes, you define the IAM role to associate with a service account in your cluster by adding the eks.amazonaws.com/role-arn annotation to the service account. In other words, annotate your service account associated with the cluster in the CI account with the role ARN as shown below.

apiVersion: v1
kind: ServiceAccount
metadata:
  name: ci-serviceaccount

  namespace: ci-namespace
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::CI_ACCOUNT_ID:role/ci-account-iam-role

The equivalent kubectl command is:

kubectl annotate serviceaccount -n ci-namespace ci-serviceaccount eks.amazonaws.com/role-arn=arn:aws:iam::CI_ACCOUNT_ID:role/ci-account-iam-role

4.    Configuring the target account – IAM role and policy permissions
In your target account, create an IAM role named target-account-iam-role with a trust relationship that allows AssumeRole permissions to CI account’s IAM role created in the previous step as shown below.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::CI_ACCOUNT_ID:role/ci-account-iam-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```
Create an IAM policy with the necessary permissions the service account’s pods in CI account cluster would need to manage. The policy shown below grants basic list permissions on some AWS resources in the target account.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "eks:DescribeCluster",
                "eks:ListClusters"
            ],
            "Resource": "*"
        }
    ]
}
```

Note that if you haven’t created associated the target policy to the CI account outlined in step 3, please do the association before proceeding with the next step.

5.    Verifying the cross-account access to AWS resources
Now that the IAM access roles and policies are configured at both the ends- CI and target accounts, we create a sample Kubernetes pod in the CI cluster and test the cross-account access to AWS resources of the target account.

Open your favorite editor and save the below contents to a file named awsconfig-configmap.yaml. This configmap is to set the AWS CLI profiles used in the deployment pod.

[profile ci-env]
role_arn = arn:aws:iam::CI_ACCOUNT_ID:role/ci-account-iam-role
web_identity_token_file = /var/run/secrets/eks.amazonaws.com/serviceaccount/token.

[profile target-env]
role_arn = arn:aws:iam::TARGET_ACCOUNT_ID:role/target-account-iam-role
source_profile = ci-env
role_session_name = xactarget

Create a Kubernetes configMap resource with the below Kubectl command.

kubectl create configmap awsconfig-configmap --from-file=config=awsconfig-configmap.yaml -n ci-namespace

Let us create another configMap resource to store the installation scripts. Name a file named script-configmap.yaml and save the below contents into the file.

#!/bin/bash
apt-get update -y && apt-get install -y python curl wget unzip jq nano -y
curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
unzip awscli-bundle.zip
./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
cp -r aws_config/ ~/.aws/
curl -o kubectl https://amazon-eks.s3-us-west-2.amazonaws.com/1.14.6/2019-08-22/bin/linux/amd64/kubectl
chmod +x ./kubectl
mv ./kubectl /usr/local/bin/kubectl
kubectl version

Create the second Kubernetes configMap resource with the below kubectl command.

kubectl create configmap script-configmap --from-file=script.sh=script-configmap.yaml -n ci-namespace

Now it’s time to create a deployment and test the cross-account access. Create another file named test-deployment.yaml.

Note to replace the values for namespace and serviceaccount if you specified different values in step 3 while creating the OIDC trust relationship.
```
apiVersion: apps/v1
kind: Deployment
metadata:
  creationTimestamp: null
  labels:
    app: test-deployment
  name: test-deployment
  namespace: ci-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-pod
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: test-pod
    spec:
      containers:
      - image: ubuntu
        name: ubuntu
        command: ["sleep","10000"]
        volumeMounts:
        - name: test-volume
          mountPath: /aws_config
        - name: script-volume
          mountPath: /scripts
      volumes:
      - name: test-volume
        configMap:
          name: awsconfig-configmap
      - name: script-volume
        configMap:
          name: script-configmap
      serviceAccountName: ci-serviceaccount
```
Apply the pod manifest file to create a test container pod with the following command.

kubectl apply -f test-deployment.yaml

Log in to the pod’s bash terminal.

POD_NAME=$(kubectl get pod -l app=test-pod -n ci-namespace -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD_NAME -it -n ci-namespace -- bash

Execute the script mounted to the pod to install the required binaries and libraries.

sh /scripts/script.sh

Verify if the pod is able to assume both the ci-env and target-env roles by issuing the below calls.

aws sts get-caller-identity --profile ci-env

aws sts get-caller-identity --profile target-env

The pod now has basic list permissions on the AWS resources as defined in the previous step. Below command should output the list of Amazon EKS clusters in the target account.

aws eks list-clusters --region <AWS_REGION> --profile target-env

You can also run a DescribeCluster command to describe the contents of any cluster.

aws eks describe-cluster --region <AWS_REGION> --profile target-env --name <TARGET_EKS_CLUSTER_NAME>

6.    Configuring target account’s Amazon EKS cluster – Modify the aws-auth configmap
For the CI account cluster pod to access and manage the target cluster’s resources, you must edit the aws-auth configmap of the cluster in the target account by adding the role to the system:masters group. Below is how the configmap should look after the changes.

  mapRoles: |
. . .
    - groups:
      - system:masters
      rolearn: arn:aws:iam::TARGET_ACCOUNT_ID:role/target-account-iam-role
      username: test-user

7.    Test the access to Amazon EKS clusters in the target accounts
In the pod created from step 5, update the kubeconfig to test the access to the target account’s EKS cluster.

aws --region <AWS_REGION> eks update-kubeconfig --name <TARGET_EKS_CLUSTER_NAME> --profile target-env

The pod should now be able to access the target cluster’s kube resources. Verify by issuing some sample kubectl get calls to access the target account’s EKS resources.

kubectl get namespaces     

kubectl get pods -n kube-system
