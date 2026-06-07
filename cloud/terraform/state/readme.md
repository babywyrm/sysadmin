S3 backend for Terraform
##
#
Copied verbatim from https://github.com/ozbillwang/terraform-best-practices
#
##

Createe a s3 bucket and dynamodb table to use as terraform backend.

dynamodb_table_name = terraform-lock
s3_bucket_name = <account_id>-terraform-states
usage
# make sure you are on the right aws account
pip install awscli
aws s3 ls

# If you don't set default region in your aws configuration, and you want to create the resources in region "us-east-1"
export AWS_DEFAULT_REGION=us-east-1
export AWS_REGION=us-east-1

# Dry-run
terraform init
terraform plan

# apply the change
# make sure you are on the right aws account
pip install awscli
aws s3 ls

# If you don't set default region in your aws configuration, and you want to create the resources in region "us-east-1"
export AWS_DEFAULT_REGION=us-east-1
export AWS_REGION=us-east-1

# Dry-run
terraform init
terraform plan

```
# apply the change
terraform apply
main.tf
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# CREATE AN S3 BUCKET AND DYNAMODB TABLE TO USE AS A TERRAFORM BACKEND
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ----------------------------------------------------------------------------------------------------------------------
# REQUIRE A SPECIFIC TERRAFORM VERSION OR HIGHER
# This module has been updated with 0.12 syntax, which means it is no longer compatible with any versions below 0.12.
# This module is forked from https://github.com/gruntwork-io/intro-to-terraform/tree/master/s3-backend
# ----------------------------------------------------------------------------------------------------------------------

terraform {
  required_version = ">= 0.12"
}

# ------------------------------------------------------------------------------
# CONFIGURE OUR AWS CONNECTION
# ------------------------------------------------------------------------------

provider "aws" {}

# ------------------------------------------------------------------------------
# CREATE THE S3 BUCKET
# ------------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
}

resource "aws_s3_bucket" "terraform_state" {
  # With account id, this S3 bucket names can be *globally* unique.
  bucket = "${local.account_id}-terraform-states"

  # Enable versioning so we can see the full revision history of our
  # state files
  versioning {
    enabled = true
  }

  # Enable server-side encryption by default
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# ------------------------------------------------------------------------------
# CREATE THE DYNAMODB TABLE
# ------------------------------------------------------------------------------

resource "aws_dynamodb_table" "terraform_lock" {
  name         = "terraform-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
outputs.tf
output "s3_bucket_name" {
  value       = aws_s3_bucket.terraform_state.id
  description = "The NAME of the S3 bucket"
}

output "s3_bucket_arn" {
  value       = aws_s3_bucket.terraform_state.arn
  description = "The ARN of the S3 bucket"
}

output "s3_bucket_region" {
  value       = aws_s3_bucket.terraform_state.region
  description = "The REGION of the S3 bucket"
}

output "dynamodb_table_name" {
  value       = aws_dynamodb_table.terraform_lock.name
  description = "The ARN of the DynamoDB table"
}

output "dynamodb_table_arn" {
  value       = aws_dynamodb_table.terraform_lock.arn
  description = "The ARN of the DynamoDB table"
}
s3.md
# main.tf
terraform {
  backend "s3" {
    encrypt = true
  }
}

# example of 'partial configuration':
# https://www.terraform.io/docs/backends/config.html#partial-configuration
#
# cat config/backend-dev.conf
bucket  = "<account_id>-terraform-states"
key     = "development/service-name.tfstate"
encrypt = true
region  = "ap-southeast-2"
dynamodb_table = "terraform-lock"
NOTE: you'll need a config/dev.tfvars too to set your other environment values.

env=dev
terraform get -update=true
terraform init -backend-config=config/backend-${env}.conf
terraform plan -var-file=config/${env}.tfvars
terraform apply -var-file=config/${env}.tfvars
@serhiiromaniuk
serhiiromaniuk commented on Jan 28, 2022
output "dynamodb_table_name" {
  value       = aws_dynamodb_table.terraform_lock.name

  # ARN here?
  description = "The ARN of the DynamoDB table"
}

##
##
```



```
provider "aws" {
  region = "us-east-2"
  default_tags {
    tags = {
      tag1 = "value1"
      tag2 = "value2"
    }
  }
}


resource "aws_s3_bucket" "terraform_state" {
  bucket = "dest-bucket-name"

  # Prevent accidental deletion of this S3 bucket
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "enabled" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "default" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "dest-state-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
```
