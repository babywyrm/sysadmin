# Cloud

Cloud provider, infrastructure-as-code, registry, and cloud-local emulation
research lives here.

## Layout

- `aws/`: AWS operations, detection, IAM, Lambda, S3, Splunk, and security notes.
- `aws/ecr/`: Amazon ECR scripts, GitHub Actions notes, image tagging, and cleanup.
- `azure/`: Azure operations, PowerShell, ARM templates, and security notes.
- `gcp/`: Google Cloud notes.
- `digitalocean/`: DigitalOcean hardening and recovery notes.
- `localstack/`: LocalStack service mocks and client examples.
- `terraform/`: Terraform examples and infrastructure-as-code notes.

## Boundaries

- EKS cluster operations stay under the future `kubernetes/eks/` area.
- Container runtime details stay under `containers/`.
- Old scratch Terraform under `devops/terraform/` needs separate review before
  being merged here.
