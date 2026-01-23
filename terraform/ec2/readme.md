
# EC2 Access to Secrets Manager Using IAM Roles (IMDSv2)

## Overview

This document describes the **standard, secure AWS pattern** for allowing an EC2 instance to access **AWS Secrets Manager** without embedding static credentials.

The approach uses:

- **IAM Role for EC2**
- **Instance Profile**
- **EC2 Instance Metadata Service (IMDSv2)**
- **Temporary STS credentials**

This eliminates hard‑coded AWS access keys and supports automatic credential rotation.

---

## Architecture

```text
┌────────────────────────────────────────────
│                AWS Account
│
│  ┌──────────────────────────────────────
│  │            IAM Role
│  │  - secretsmanager:GetSecretValue
│  │  - kms:Decrypt
│  └───────────────▲──────────────────────
│                  │
│            Instance Profile
│                  │
│  ┌───────────────┴──────────────────────
│  │              EC2 Instance
│  │
│  │  Application / AWS SDK
│  │
│  │  1. Request credentials
│  │     http://169.254.169.254
│  │     /latest/meta-data/iam/
│  │     security-credentials/
│  │
│  │  2. Receive temporary credentials
│  │     (STS AccessKey, Secret, Token)
│  │
│  │  3. Call Secrets Manager API
│  │     secretsmanager:GetSecretValue
│  │
│  └──────────────────────────────────────
│
│        AWS Secrets Manager
│        - Encrypted secrets (KMS)
│        - IAM authorization enforced
│
└────────────────────────────────────────────
```

---

## Security Properties

- ✅ No static credentials stored on disk
- ✅ Temporary STS credentials only
- ✅ Automatic rotation
- ✅ IMDSv2 enforced (mitigates SSRF)
- ✅ Least‑privilege IAM policies

---

## Terraform: IAM Role and Instance Profile

```hcl
resource "aws_iam_role" "ec2_role" {
  name = "ec2-secrets-manager-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "secrets_manager_policy" {
  name = "ec2-secrets-manager-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.secrets_manager_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-secrets-manager-profile"
  role = aws_iam_role.ec2_role.name
}
```

---

## Terraform: New EC2 Instance (IMDSv2 Enforced)

```hcl
resource "aws_instance" "example" {
  ami           = "ami-xxxxxxxxxxxxxxxxx" # Replace
  instance_type = "t3.micro"
  subnet_id     = var.subnet_id

  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "ec2-with-imds-and-secrets"
  }
}
```

---

## Applying This to an Existing EC2 Instance

### What Can Be Updated Live

| Setting | Requires Restart |
|------|------------------|
| IAM instance profile | No |
| IMDSv2 enforcement | No |
| IAM policy permissions | No |

---

## Option A: Manage Existing EC2 with Terraform (Recommended)

### Import the Instance

```bash
terraform import aws_instance.existing i-0123456789abcdef0
```

### Attach IAM Role and Enforce IMDSv2

```hcl
resource "aws_instance" "existing" {
  instance_id = "i-0123456789abcdef0"

  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  lifecycle {
    ignore_changes = [
      ami,
      instance_type,
      subnet_id,
      user_data,
      tags
    ]
  }
}
```

---

## Option B: Apply Without Importing the EC2

Use Terraform only for IMDSv2 and IAM resources, then attach once:

```bash
aws ec2 associate-iam-instance-profile \
  --instance-id i-0123456789abcdef0 \
  --iam-instance-profile Name=ec2-secrets-manager-profile
```

Terraform can still manage IMDSv2:

```hcl
resource "aws_ec2_instance_metadata_options" "imds" {
  instance_id = "i-0123456789abcdef0"

  http_endpoint               = "enabled"
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
}
```

---

## Application Usage (No Code Changes)

AWS SDKs automatically retrieve credentials from IMDS.

Example:

```bash
aws secretsmanager get-secret-value \
  --secret-id my-secret
```

---

## Validation

```bash
# Request IMDSv2 token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Verify IAM role
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/info
```

---

## Relevant AWS Documentation

- IAM Roles for EC2  
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html

- Instance Profiles  
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html

- EC2 Instance Metadata Service  
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html

- IMDSv2 Configuration  
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

- Secrets Manager Authorization  
  https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html

- SSRF and Metadata Credential Theft  
  https://aws.amazon.com/blogs/security/defense-in-depth-open-source-ssrf-protection/

---

## Summary

This pattern is the **AWS‑recommended and security‑approved** method for EC2 workloads to access Secrets Manager:

- IAM role + instance profile
- Temporary credentials via IMDSv2
- No static secrets
- Safe for production and compliance

##
##
