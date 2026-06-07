

Each environment (dev, prod, staging) contains subdirectories for different applications (app1, app2, etc.), 
and secrets for each app are stored in AWS Secrets Manager with names following a consistent pattern, such as app1-dev, app2-prod, etc.


```

import os,sys,re
import boto3

def list_directories(base_dir):
    """Recursively list all directories under the base directory."""
    directories = []
    for root, dirs, files in os.walk(base_dir):
        for dir_name in dirs:
            directories.append(os.path.join(root, dir_name))
    return directories

def get_secret_name(env, app):
    """Construct the secret name based on environment and app name."""
    return f"{app}-{env}"

def decrypt_secret(secret_name):
    """Retrieve and decrypt a secret from AWS Secrets Manager."""
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except Exception as e:
        print(f"Error retrieving secret {secret_name}: {e}")
        return None

def process_secrets(base_dir):
    """Process and decrypt all secrets for each environment and app."""
    environments = next(os.walk(base_dir))[1]  # Top-level directories
    all_secrets = {}
    
    for env in environments:
        env_path = os.path.join(base_dir, env)
        apps = [d for d in os.listdir(env_path) if os.path.isdir(os.path.join(env_path, d))]
        
        env_secrets = {}
        for app in apps:
            secret_name = get_secret_name(env, app)
            secret_value = decrypt_secret(secret_name)
            if secret_value:
                env_secrets[app] = secret_value
        
        if env_secrets:
            all_secrets[env] = env_secrets
    
    return all_secrets

def save_secrets_to_file(secrets, output_file):
    """Save decrypted secrets to a file."""
    with open(output_file, 'w') as f:
        for env, apps in secrets.items():
            f.write(f"Environment: {env}\n")
            for app, secret in apps.items():
                f.write(f"  App: {app}\n")
                f.write(f"    Secret: {secret}\n")
            f.write("\n")

if __name__ == "__main__":
    base_dir = "/path/to/project-root"  # Update this path
    output_file = "decrypted_secrets.txt"
    
    print(f"Processing secrets in {base_dir}...")
    all_secrets = process_secrets(base_dir)
    
    print(f"Saving decrypted secrets to {output_file}...")
    save_secrets_to_file(all_secrets, output_file)
    
    print("Done!")



/project-root/
  ├── dev/
  │   ├── app1/
  │   ├── app2/
  │   └── ...
  ├── prod/
  │   ├── app1/
  │   ├── app2/
  │   └── ...
  ├── staging/
  │   ├── app1/
  │   ├── app2/
  │   └── ...
  ```

Key Concepts
AWS Secrets Manager: A service for securely storing, managing, and retrieving secrets.
AWS Systems Manager (SSM) Parameter Store: Another service for storing configuration data and secrets, with support for both plain text and encrypted values.
AWS Key Management Service (KMS): A service for creating and controlling encryption keys used to encrypt secrets.
Managing Secrets with Terraform

1. Storing Secrets with AWS Secrets Manager
Here’s how you can create a secret in AWS Secrets Manager using Terraform:
```
resource "aws_secretsmanager_secret" "example_secret" {
  name = "example-secret"
  description = "An example secret for our environment"

  tags = {
    environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "example_secret_version" {
  secret_id     = aws_secretsmanager_secret.example_secret.id
  secret_string = jsonencode({
    username = "admin"
    password = "supersecret"
  })
}
```

Explanation:
aws_secretsmanager_secret: This resource creates a new secret in AWS Secrets Manager.
aws_secretsmanager_secret_version: This resource manages the value (version) of the secret. You can update the secret by creating a new version.
var.environment: A variable representing the environment (e.g., dev, prod). This allows you to manage different secrets for different environments.
2. Retrieving and Using Secrets
To use a secret in your Terraform configuration, you need to retrieve it:

```
data "aws_secretsmanager_secret" "example_secret" {
  name = aws_secretsmanager_secret.example_secret.name
}

data "aws_secretsmanager_secret_version" "example_secret_version" {
  secret_id = data.aws_secretsmanager_secret.example_secret.id
}

output "example_secret_value" {
  value = data.aws_secretsmanager_secret_version.example_secret_version.secret_string
}
```
Explanation:
data "aws_secretsmanager_secret": This data source retrieves metadata about the secret.
data "aws_secretsmanager_secret_version": This data source retrieves the current version of the secret.
The output shows how you can access the secret value in your Terraform configuration.
3. Managing Secrets Across Multiple Environments (Stacks)
When managing multiple environments, you can use Terraform workspaces or separate state files to manage different environments (stacks). Here’s how you can manage secrets across environments:

```
variable "environment" {
  type    = string
  default = "dev"
}

resource "aws_secretsmanager_secret" "example_secret" {
  name = "example-secret-${var.environment}"
  description = "An example secret for the ${var.environment} environment"

  tags = {
    environment = var.environment
  }
}
```
Explanation:
The secret name is dynamically generated based on the environment. This ensures that each environment (stack) has its own secret.
When you switch environments (e.g., from dev to prod), Terraform will create or manage a different set of secrets.
4. Decrypting All Secrets Across Stacks
If you want to decrypt all secrets across different stacks, you can use the AWS CLI or SDKs to retrieve and decrypt secrets programmatically. Here’s an example using AWS CLI:

```
aws secretsmanager get-secret-value --secret-id example-secret-dev
aws secretsmanager get-secret-value --secret-id example-secret-prod
```

Explanation:
Replace example-secret-dev and example-secret-prod with the actual secret names.
This command retrieves the secret value and automatically decrypts it using AWS KMS.
If you want to automate this process across all environments, you can write a script (e.g., in Python using Boto3) that iterates over all environments and retrieves the secrets.

Example Python Script to Decrypt All Secrets:

```

environments = ["dev", "prod", "staging"]
secret_name_template = "example-secret-{}"

client = boto3.client('secretsmanager')

for env in environments:
    secret_name = secret_name_template.format(env)
    response = client.get_secret_value(SecretId=secret_name)
    secret = response['SecretString']
    print(f"Secret for {env}: {secret}")

```


Explanation:
This script uses the Boto3 library to interact with AWS Secrets Manager.
It iterates over a list of environments, retrieves, and decrypts the secrets for each environment.
Best Practices
Use Separate Secrets for Each Environment: Ensure that secrets are isolated by environment to prevent accidental access or leakage.
Rotate Secrets Regularly: AWS Secrets Manager supports automatic rotation of secrets, which can be configured through Terraform.
Restrict Access: Use IAM policies to restrict access to secrets based on roles and least privilege principles.
Monitor and Audit: Enable logging and monitoring on Secrets Manager and KMS to track access and changes to your secrets.
