# 1. Understanding AWS IRSA and EKS Roles

##
#
https://platformwale.blog/2023/08/02/iam-roles-for-service-accounts-irsa-in-aws-eks-within-and-cross-aws-accounts/
#
https://medium.com/@samuelbagattin/aws-iam-authentication-for-pods-in-eks-irsa-with-examples-5d8fa16aafba
#
##


IAM Roles for Service Accounts (IRSA) is a feature in Amazon EKS that allows you to assign AWS IAM roles to Kubernetes service accounts. 

# This integration enhances security by:

Fine-Grained Permissions: Assigning specific IAM roles to different Kubernetes service accounts instead of using a single IAM role for all pods.
Least Privilege: Ensuring pods have only the permissions they need to perform their tasks.


Improved Security: Avoiding the need to manage static AWS credentials within pods.
Key Concepts
EKS (Elastic Kubernetes Service): A managed Kubernetes service by AWS.
Service Account: A Kubernetes object that provides an identity for processes running in a pod.
IAM Role: An AWS identity with specific permissions.
IRSA: The integration that allows associating IAM roles with Kubernetes service accounts.
2. Setting Up IRSA for EKS
Before diving into scripting, ensure that your EKS cluster is configured to support IRSA. Here's how:

Prerequisites
EKS Cluster: An existing EKS cluster.
kubectl Configured: kubectl should be configured to communicate with your EKS cluster.
AWS CLI: Installed and configured with necessary permissions.

# Steps
Create an OIDC Provider for Your EKS Cluster:

IRSA relies on OpenID Connect (OIDC) to authenticate pods. 
If you haven't set up an OIDC provider for your EKS cluster, do so:

```
aws eks describe-cluster --name your-cluster-name --query "cluster.identity.oidc.issuer" --output text
```


If an OIDC provider isn't associated, create one using the AWS Management Console or AWS CLI.

Verify OIDC Provider:

Ensure the OIDC provider is associated with your EKS cluster:

```
eksctl utils associate-iam-oidc-provider --cluster your-cluster-name --approve
```

Note: This command uses eksctl. 
If you prefer using AWS CLI or the console, adjust accordingly.


3. Creating IAM Roles and Policies
To allow pods to access specific AWS services (like Vault), you need to create IAM roles with appropriate policies.

Example: Creating an IAM Policy
Suppose your pod needs to read secrets from AWS Secrets Manager.

Define the Policy (secrets-manager-policy.json):

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:region:account-id:secret:your-secret-name"
    }
  ]
}
```


Create the Policy:

```
aws iam create-policy \
  --policy-name SecretsManagerAccess \
  --policy-document file://secrets-manager-policy.json
```


Note the Policy ARN returned after creation.

Example: Creating an IAM Role for the Service Account
Trust Relationship:

The IAM role needs a trust relationship that allows the EKS service account to assume the role. Create a trust-policy.json:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::account-id:oidc-provider/oidc.eks.region.amazonaws.com/id/eks-cluster-id"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.region.amazonaws.com/id/eks-cluster-id:sub": "system:serviceaccount:namespace:service-account-name"
        }
      }
    }
  ]
}
```

# Replace:

account-id with your AWS account ID.
region with your AWS region.
eks-cluster-id with your cluster's OIDC ID.
namespace and service-account-name with your Kubernetes namespace and service account name.
Create the IAM Role:

```
aws iam create-role \
  --role-name EKSServiceAccountRole \
  --assume-role-policy-document file://trust-policy.json
```



Attach the Policy to the Role:

```
aws iam attach-role-policy \
  --role-name EKSServiceAccountRole \
  --policy-arn arn:aws:iam::account-id:policy/SecretsManagerAccess
```



4. Associating IAM Roles with Kubernetes Service Accounts
Now, link the IAM role to a Kubernetes service account.

Steps
Create a Kubernetes Namespace (if not existing):

```
kubectl create namespace your-namespace
```



Create the Service Account with IAM Role Annotation:

```
# service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: your-service-account
  namespace: your-namespace
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::account-id:role/EKSServiceAccountRole
```

    
Apply the service account:

```
kubectl apply -f service-account.yaml
```


5. Deploying Pods with the Service Account
Deploy a Kubernetes pod (e.g., a Deployment) that uses the service account with the IAM role.

# Example Deployment

```
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: python-app
  namespace: your-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: python-app
  template:
    metadata:
      labels:
        app: python-app
    spec:
      serviceAccountName: your-service-account
      containers:
        - name: python-container
          image: python:3.9-slim
          command: [ "python", "/app/app.py" ]
          volumeMounts:
            - name: app-volume
              mountPath: /app
      volumes:
        - name: app-volume
          configMap:
            name: python-app-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: python-app-config
  namespace: your-namespace
data:
  app.py: |
    import boto3
    import os

    def get_secret():
        client = boto3.client('secretsmanager', region_name='your-region')
        secret_name = "your-secret-name"
        response = client.get_secret_value(SecretId=secret_name)
        secret = response['SecretString']
        print(f"Secret: {secret}")

    if __name__ == "__main__":
        get_secret()

``` 
Apply the deployment:

```
kubectl apply -f deployment.yaml
```

Ensure you have a ConfigMap named python-app-config with your Python script.

6. Accessing AWS Services Using Boto3 in Python
Within the pod, the Python script uses Boto3 to access AWS Secrets Manager. Thanks to IRSA, the pod assumes the IAM role EKSServiceAccountRole, which has permissions to access the specified secret.

Python Script Explanation
Boto3 Client Initialization: Boto3 automatically retrieves temporary credentials provided by the IRSA-assigned IAM role via the web identity token.

Fetching Secret: The script fetches a secret from AWS Secrets Manager and prints it.

```
import boto3
import os

def get_secret():
    # Initialize a Secrets Manager client
    client = boto3.client('secretsmanager', region_name='your-region')
    
    secret_name = "your-secret-name"
    
    try:
        # Retrieve the secret value
        response = client.get_secret_value(SecretId=secret_name)
        
        # Extract the secret
        secret = response['SecretString']
        print(f"Secret: {secret}")
    except Exception as e:
        print(f"Error retrieving secret: {e}")

if __name__ == "__main__":
    get_secret()
```

    
Notes:

Replace your-region with your AWS region (e.g., us-west-2).
Replace your-secret-name with the name of your secret in Secrets Manager.
Testing the Setup
Check Pod Logs:

After deploying, check the logs to see if the secret was fetched successfully.

```
kubectl logs deployment/python-app -n your-namespace
```



Expected Output:

```
Secret: {"username":"admin","password":"s3cr3t"}
```

(The actual secret content will vary based on what you stored in Secrets Manager.)

Troubleshooting:

Permission Errors: If the pod cannot access the secret, ensure that the IAM role has the necessary permissions and that the service account is correctly annotated.

Network Issues: Ensure that the pod has network access to AWS Secrets Manager endpoints.

Accessing External Services Like Vault
If you want your pods to access external services like HashiCorp Vault, you can integrate Vault with AWS IAM for authentication. Here's a high-level overview:

Configure Vault to Use AWS IAM Auth Method:

Set up Vault's AWS auth method to allow authentication using IAM roles.

Update IAM Role and Policy:

Ensure the IAM role associated with your service account has permissions to authenticate with Vault.

Modify Python Script to Authenticate with Vault:

Use Vault's API to authenticate and retrieve secrets.

# Example: 

Authenticating with Vault Using AWS IAM
Here's a simplified example of how you might authenticate with Vault using AWS IAM credentials obtained via IRSA.

```
import boto3
import requests
import json

def get_vault_token():
    # Get AWS credentials from the environment
    session = boto3.Session()
    credentials = session.get_credentials().get_frozen_credentials()
    
    # Prepare AWS SigV4 signed request to Vault's AWS auth endpoint
    # This is a simplified example. In practice, you'd need to handle signing correctly.
    
    # Replace with your Vault's address and role
    vault_addr = "https://your-vault-address:8200"
    role = "your-vault-role"
    
    # Assume Vault is set up to accept AWS IAM authentication
    auth_endpoint = f"{vault_addr}/v1/auth/aws/login"
    
    # Construct the payload as per Vault's AWS auth method requirements
    payload = {
        "role": role,
        # Include necessary AWS credentials info
        # This typically includes the IAM role's ARN and possibly other details
    }
    
    response = requests.post(auth_endpoint, json=payload)
    
    if response.status_code == 200:
        token = response.json()['auth']['client_token']
        return token
    else:
        raise Exception(f"Failed to authenticate with Vault: {response.text}")

def get_vault_secret(token):
    vault_addr = "https://your-vault-address:8200"
    secret_path = "secret/data/your-secret"
    
    headers = {
        "X-Vault-Token": token
    }
    
    response = requests.get(f"{vault_addr}/v1/{secret_path}", headers=headers)
    
    if response.status_code == 200:
        secret = response.json()['data']['data']
        print(f"Vault Secret: {secret}")
    else:
        raise Exception(f"Failed to retrieve secret from Vault: {response.text}")

if __name__ == "__main__":
    vault_token = get_vault_token()
    get_vault_secret(vault_token)

```



I have been working with Kubernetes on AWS using EKS for some time, so I wanted to share a better way than using EC2 instance profile to authenticate pods to AWS APIs.

In this article I will show how to setup IAM Roles for Service Accounts (IRSA) using Terraform and Kubernetes manifests, and how to use this authentication mechanism with a microservice running in the cluster.

Unlike kube2iam or kiam, IRSA is the official AWS way to authenticate pods to AWS API.

The full source code used to create an test all the components — the EKS cluster, the Kubernetes resources, the application and its associated Dockerfile — are publicly available in this GitHub repository.

GitHub - SamuelBagattin/eks-irsa-example
Source code associated to my article on IRSA in EKS
github.com

Architecture
Diagram showing how a pod is authenticating to STS using IRSA
Architecture — Pod authenticating the AWS API using IRSA
The schema below shows the necessary setup to get security credentials to access the AWS API, using an IAM Role dedicated to its service account.

There are several components to take into account :

An up and running EKS cluster
An IAM Identity Provider configured to authenticate resources from the EKS cluster throught the OpenID Connect protocol (OIDC), to the AWS Account
A running pod and its associated service account
An IAM role with a trust policy allowing the previous service account to perform AssumeRoleWithWebIdentity
The process during which the pod obtains temporary STS security credentials, to authenticate to AWS API through the role’s identity
AWS IAM Setup
This section assumes that you already have an EKS Cluster up and running.

The full Terraform source code (including the EKS cluster and node group) is available in here :

eks-irsa-example/infrastructure at master · SamuelBagattin/eks-irsa-example
github.com

First, we need to create an IAM OIDC provider in the AWS account referencing the cluster’s OIDC issuer url.


IAM OIDC provider creation
Then, to authenticate our app to the AWS API, we need to create an IAM role

This role will be assumable only by pods that will mount a specific Kubernetes service-account.


IAM role creation
As you can see below, the trust policy of the role has the following specifications :

Allows assuming the role only through AssumeRoleWithWebIdentity API call
Only if the requester has the identity of the serviceaccount my-serviceaccount located in the default namespace
Only if the request has been made through the previously create OIDC provider
Finally, we create the IAM role and its associated permissions.
This sample code has been inspired from the Terraform documentation

Kubernetes resources setup
We will now create the Kubernetes service-account and associate it to the IAM role.


The manifest below creates the service-account my-serviceaccount in the namespace default

Note the eks.amazonaws.com/role-arn annotation : this is the one attribute that will help the app know which IAM role to assume (full documentation can be found in the AWS website)

Now we can create a pod (or any Kubernetes resource that manages pods).


This pod manifest creates a pod mounting the service-account previously created, and starts our app.

The container image used has been built from the app we will create at the end of this article

Kubernetes pod-identity mutating webhook configuration
To help with authenticating pod to the AWS API, a brand new EKS cluster will come with a mutating webhook configuration named pod-identity-webhook.

GitHub - aws/amazon-eks-pod-identity-webhook: Amazon EKS Pod Identity Webhook
This webhook is for mutating pods that will require AWS IAM access. After version v0.3.0, --in-cluster=true no longer…
github.com

Here is a sample manifest of this resource (no need to apply it):


When a pod is created in any namespace, for each container located in the namespace, the webhook creates the following environment variables in the manifest :

AWS_STS_REGIONAL_ENDPOINTS set to regional by default, tells the SDK to use the current region endpoint to issue STS API calls
AWS_DEFAULT_REGION and AWS_REGION set to the region in which the cluster is running
AWS_ROLE_ARN set to the ARN of the IAM role you specified in the eks.amazonaws.com/role-arn service-account annotation
AWS_WEB_IDENTITY_TOKEN_FILE contains the path where is stored the Kubernetes service account token. This token will be used to get temporary STS credentials (usually set to /var/run/secrets/eks.amazonaws.com/serviceaccount/token)
Authenticating a microservice
Now that all infrastructure and Kubernetes resources are setup, we can develop and deploy an app running in the cluster, that will use the previously described authentication mechanism

I will use a simple Golang app to perform the authentication and issue API calls using the AWS SDK, but the steps should be fairly similar in any other language.

As usual the full source code can be found here :

```
eks-irsa-example/app at master · SamuelBagattin/eks-irsa-example
```

github.com


We assume that you already have a Golang app with the AWS SDK installed and an empty main function present.

The previous code sample :

Creates a new session using the default credentials chain
Creates an STS client to receive the temporary credentials
Gets the service account token associated to the pod
Gets the ARN of the role that will be assumed
Now we can get temporary credentials and issue API calls using the IAM role.


This code performs the following operations :

Requests temporary STS credentials using AssumeRoleWithWebIdentity by specifying the previously obtained role ARN and SA token, as well as the session duration and the session name.
Creates a new session using the temporary credentials
Creates a new STS client using the new identity and prints authentication information about the current session
Creates an S3 client using the same identity to test the permissions we gave previously to the role
Once built into a container image and deployed using the previous pod manifest, the application will output similar logs :


Here we go ! Your application now has its own role and its own set of permissions thanks to IRSA 🚀
