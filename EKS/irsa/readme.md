
# 1. What is IRSA?
IRSA (IAM Roles for Service Accounts) is a mechanism in EKS that lets you associate an AWS IAM role with a Kubernetes Service Account. 
The net result is that your pods get temporary, least-privileged AWS credentials for that role, automatically rotated by AWS behind the scenes.

Once your pod runs under this service account/role mapping, it can call AWS STS AssumeRole under the hood without requiring long-lived AWS access/secret keys in the environment or on disk.

# 2. How Does This Help With HashiCorp Vault?
HashiCorp Vault supports an AWS authentication method (often referred to as the “IAM auth method”) which can verify your AWS identity. The flow typically goes like this:

Your Pod obtains short-lived AWS credentials automatically via IRSA.
Your Python App (running inside the pod) uses those AWS credentials to sign a request to Vault’s AWS Auth method (for example, vault auth enable aws with type=iam).
Vault checks (via AWS STS) that those credentials are valid and map to the Vault role you configured.
Vault issues your application a Vault token (or lease) with the policies you’ve attached.
Your Python App uses that Vault token to retrieve ephemeral secrets from Vault.
When done, your application discards them (i.e., don’t write to disk; keep them in memory only).
Because the IAM creds provided by IRSA are ephemeral, you never have to bake them into your container image or store them as Kubernetes secrets on disk.

# 3. High-Level Steps to Set This Up
3.1 Configure OIDC Provider in EKS
Enable OIDC for your EKS cluster (this is typically done in eksctl or via the AWS Console).
An IAM OIDC identity provider gets linked to your cluster (the usual “oidc.eks.amazonaws.com/id/xxxxx”).
3.2 Create an IAM Role with Trust Policy
Create an IAM Role with a trust relationship that allows the OIDC identity provider from your EKS cluster to assume this role.
Restrict the trust to a specific service account namespace/name if you want a narrower scope.
For example, the trust policy JSON might look like:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub": "system:serviceaccount:my-namespace:my-service-account"
        }
      }
    }
  ]
}
```

(Adjust ARNs, OIDC provider IDs, namespace, etc. as needed.)

3.3 Attach IAM Policies to the Role
You will attach policies that allow your pod to perform the AWS calls needed to do Vault’s AWS IAM auth. Typically, that means permissions to call sts:GetCallerIdentity (at a minimum) or to do a quick STS-based sign to Vault’s endpoint. Usually, sts:AssumeRole is not needed unless your Vault config does something more advanced. Vault’s iam auth method mostly needs your application to sign the request with your ephemeral AWS credentials.

3.4 Create a K8s Service Account with IRSA
In your Kubernetes cluster, define a service account that references the IAM role’s ARN you created above.
For example:


```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  namespace: my-namespace
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/MyIRSARoleForVault"
```

3.5 Configure Vault
Vault needs to have the AWS IAM Auth method enabled and configured to trust your role. A minimal example:


# Enable the AWS auth method
```
vault auth enable aws
```

# Configure the AWS auth method
```
vault write auth/aws/config/client_secret_access_key=EXAMPLE client_access_key=EXAMPLE
```

# (Usually you'd do something more secure, or rely on Vault's internal compute role.)

# Create a Vault role that maps IAM principals to Vault policies
```
vault write auth/aws/role/my-vault-aws-role \
  auth_type=iam \
  bound_iam_principal_arn=arn:aws:iam::123456789012:role/MyIRSARoleForVault \
  policies="my-vault-policy" \
  max_ttl=1h
```

(In production, you’d configure the AWS auth backend in a more secure manner, but this is the basic idea. You only want to allow the specific IAM role(s) from EKS to be mapped into your Vault role.)


4. Pythonic Workflow Example
Below is a minimal Python script using hvac to:

Automatically discover the ephemeral credentials from IRSA via boto3.Session().
Use those creds to authenticate to Vault with the AWS IAM method.
Retrieve some secret from Vault.
Avoid writing secrets to disk; keep them in memory.


```
import os
import hvac
import boto3
from botocore.exceptions import BotoCoreError, NoCredentialsError

def get_vault_secret():
    # 1. Get AWS credentials from IRSA (via boto3)
    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        # Make sure they're not None
        if not credentials or not credentials.access_key:
            raise Exception("No valid AWS credentials found via IRSA.")
        
        access_key = credentials.access_key
        secret_key = credentials.secret_key
        session_token = credentials.token  # If using assumed roles (temporary session)
    except (BotoCoreError, NoCredentialsError) as e:
        raise Exception(f"Unable to get AWS creds via IRSA: {e}")

    # 2. Initialize an hvac Client
    vault_addr = os.getenv('VAULT_ADDR', 'https://vault.example.com')
    client = hvac.Client(url=vault_addr, verify=True)  # verify=False if skipping SSL checks (not recommended!)

    # 3. Perform IAM Auth to Vault
    #    The `role` here should match the Vault role name you created in the 'auth/aws/role' step
    role_name = "my-vault-aws-role"
    
    try:
        # hvac has an 'aws' method; specifically 'iam_login' for IAM-based auth
        login_response = client.auth.aws.iam_login(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            role=role_name
        )
    except hvac.exceptions.Forbidden as e:
        raise Exception(f"Vault login failed (Forbidden). Check role config: {e}")
    except Exception as e:
        raise Exception(f"Vault login failed: {e}")

    if not client.is_authenticated():
        raise Exception("Vault client is not authenticated after IAM login.")

    # 4. If needed, read secrets from Vault
    # For example, if you store credentials at `secret/data/my-app`
    secret_path = "secret/data/my-app"
    read_response = client.secrets.kv.v2.read_secret_version(path=secret_path)
    
    # The secret data is ephemeral here— do with it what you need, then discard
    secret_data = read_response['data']['data']
    print("Retrieved secrets from Vault:", secret_data)

    # 5. Return or use the secrets in memory only; do not write to disk
    return secret_data

if __name__ == "__main__":
    secret_data = get_vault_secret()
    # Use these ephemeral creds...
    # ...
    # Then discard them from memory once done
```

Key points:

boto3 automatically picks up the AWS credentials from the container’s IRSA-provided metadata.
hvac.Client(url=...): You can set VAULT_ADDR environment variable for the Vault address so you don’t hardcode it.
aws.iam_login(...): This is how we do the Vault AWS IAM Auth within hvac. We pass in the ephemeral credentials from IRSA.
We never store them on disk— your code just uses them in memory.
Once your process ends or the container stops, everything is gone.
5. Additional Tips and Thoughts
Rotate or Re-Login
The Vault token you get from client.auth.aws.iam_login(...) is typically short-lived (depending on your Vault role’s TTL). If you need to run long jobs, you may want a re-authentication mechanism or use Vault’s token renewal.

Avoid Hardcoding

Don’t hardcode the Vault address or AWS region— pass them via environment variables (or a config map in Kubernetes).
Let IRSA handle the AWS credentials behind the scenes, so you never embed AWS secrets in your images.
TLS/SSL

Always secure Vault traffic with TLS/SSL. If you are using self-signed certs, ensure your container trusts the CA, or set verify=False only if absolutely necessary (and for dev/test usage).
Vault Policies

The Vault role/policies you assign to the EKS IAM role should be as narrow as possible, giving only the minimal read access your pods need.
PodSecurity and Secrets

If you want an additional layer of security, consider ephemeral volumes or even an in-memory approach (like RamFS or tmpfs) if you need to temporarily store secrets. But ideally, read them from Vault and keep them in memory only.



And KMS


# 1. Overview of IRSA on EKS
What is IRSA?
IAM Roles for Service Accounts (IRSA) allows you to assign a dedicated IAM role to a Kubernetes service account. When pods run with that service account, they receive short-lived AWS credentials automatically via the cluster’s OIDC provider. This avoids using broad node-level IAM permissions and helps enforce the principle of least privilege.

How It Works:

Service Account Annotation: You annotate a Kubernetes service account with an IAM role ARN.
OIDC Provider: EKS clusters are configured with an OIDC identity provider. AWS uses this provider to validate tokens presented by pods.
Credential Injection: When a pod starts, it automatically receives a projected service account token. AWS SDKs (or custom code) running in the pod exchange that token for temporary credentials that correspond to the IAM role.


# 2. AWS KMS Integration
AWS Key Management Service (KMS):
KMS provides secure creation, storage, and management of cryptographic keys. It is commonly used to encrypt data, manage secrets, and enforce encryption policies for data at rest or in transit.

Why Use KMS with IRSA?

Granular Permissions: You can craft IAM policies that only allow certain operations (e.g., encrypt, decrypt, re-encrypt) on specific KMS keys.
Secure Key Access: IRSA ensures that only pods with the proper service account (and therefore the proper IAM role) can call KMS APIs.
Auditing and Rotation: KMS integrates with CloudTrail for logging and supports key rotation, which further enhances security.


# 3. Workflow Architecture
Below is a high-level workflow combining IRSA and KMS on EKS:

A. Setup Phase
Configure the OIDC Provider on EKS:

Ensure your EKS cluster is configured with an OIDC provider.
Follow AWS’s documentation to set up the provider.
Create IAM Roles with Minimal KMS Permissions:

Define IAM roles that grant only the necessary KMS actions (e.g., kms:Encrypt, kms:Decrypt).
Include conditions in the IAM policy to further restrict access (e.g., by source IP, specific resource ARNs, or tags).
Annotate Kubernetes Service Accounts:

Create service accounts in your Kubernetes cluster and annotate them with the corresponding IAM role ARN.
Example annotation:

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: key-manager
  namespace: myapp
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<account-id>:role/MyKMSAccessRole
```


# Define KMS Key Policies:

Configure the key policy to allow access from the IAM roles associated with your service accounts.
Ensure that the key policy is as restrictive as possible, aligning with your security requirements.
B. Runtime Phase
Pod Launch and Credential Acquisition:

When a pod starts using the annotated service account, the AWS SDK (or a custom client) automatically retrieves temporary credentials via IRSA.
The pod now has credentials scoped to only the permissions defined in the IAM role (including KMS permissions).
KMS API Operations:

The pod performs cryptographic operations by calling AWS KMS APIs (e.g., encrypting/decrypting data, generating data keys).
Example workflow for data encryption:
The pod calls GenerateDataKey to get a plaintext key and an encrypted version.
The plaintext key is used to encrypt data locally, while the encrypted key is stored alongside the data.
For decryption, the pod calls Decrypt with the encrypted key to retrieve the plaintext key, then decrypts the data.
Auditing and Logging:

AWS CloudTrail records all KMS operations, allowing you to audit usage.
Integrate with monitoring tools to alert on any unusual or unauthorized API calls.
Key Rotation and Secret Management:

Automate key rotation using AWS KMS’s built-in rotation (if supported) or custom workflows.
If you have a customer-specific workflow (e.g., each customer has a unique IRSA role and possibly a dedicated KMS key), use your backend (Aurora, for example) to manage and lookup these configurations before performing key operations.


# 4. Security and Best Practices

Least Privilege:

Always limit IAM policies attached to the service accounts to only the necessary KMS actions.
Use conditions and key policies to further restrict usage to specific pods or applications.
Short-Lived Credentials:

Leverage IRSA’s short-lived tokens to reduce the risk if credentials are ever exposed.
Audit Logging:

Enable CloudTrail and monitor logs for KMS API usage.
Set up alerts for any anomalous activity or policy violations.
Separation of Duties:

If your environment supports multiple customers or applications, isolate roles and keys so that compromise in one area does not lead to broader exposure.
Consider using separate KMS keys per customer or application as needed.
Regular Reviews and Penetration Testing:

Periodically review IAM policies, service account annotations, and KMS key policies.
Conduct penetration testing to ensure that misconfigurations or vulnerabilities are identified and remediated.



# 5. Example Use Case Scenario

Imagine a multi-tenant application running on EKS, where each tenant (customer) has unique encryption keys and separate access permissions:

Configuration:

Each tenant’s service account is annotated with an IAM role that permits only specific KMS actions on that tenant’s KMS key.
The backend database (e.g., Aurora) stores mappings of customer IDs to IAM roles and KMS key ARNs.
Workflow:

When a tenant’s workload starts, it uses IRSA to retrieve temporary credentials.
The application looks up the customer’s configuration from Aurora.
The application calls AWS KMS to encrypt/decrypt sensitive data specific to that tenant using the assigned key.
All operations are logged and monitored via CloudTrail.

