# 1. Understanding AWS IRSA and EKS Roles


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
Important Notes:
