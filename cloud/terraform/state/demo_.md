
##
#
https://gist.github.com/rowleyaj/13737308799838ff989dc15a278e1cf7
#
##

Testing the S3 backend + DynamoDB locking
Clone this gist and change directory to it
Rename run-2nd.tf to an alternative file ending to prevent it being run.

```
terraform init
Normally you would plan and save to a file but for this example we're going to just apply directly terraform apply
Rename run-2nd.tf back to it's original name

The backend has changed so requires a new terraform init
terraform apply
run-1st.tf
# This uses Terraform to configure the resources required for remote state
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "state" {
  bucket = "rowleyaj-tf-state-demo"
  
  tags {
    Name        = "rowleyaj-tf-state-demo"
    Environment = "testing"
  }
}

resource "aws_dynamodb_table" "state" {
  name           = "rowleyaj-terraform-state-lock"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags {
    Name        = "rowleyaj-terraform-state-lock"
    Environment = "testing"
  }
}

resource "null_resource" "sleep" {
  provisioner "local-exec" {
    command = "sleep 10"
  }
}
run-2nd.tf
# This doesn't need to be it's own file but I've seperated it out to show the 
#   process used during this test. Either add this as separate file or append
#   to the file above and re-run
terraform {
  required_version = "~> 0.10"

  backend "s3" {
    bucket  = "rowleyaj-tf-state-demo"
    key     = "v1/terraform-remote-state-example"
    region  = "us-east-1"
    encrypt = true

    dynamodb_table = "rowleyaj-terraform-state-lock"
  }
}


###
###


locals {
  define_lifecycle_rule = var.noncurrent_version_expiration != null || length(var.noncurrent_version_transitions) > 0
}

data "aws_region" "state" {
}

#---------------------------------------------------------------------------------------------------
# KMS Key to Encrypt S3 Bucket
#---------------------------------------------------------------------------------------------------

resource "aws_kms_key" "this" {
  description             = var.kms_key_description
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = var.kms_key_enable_key_rotation

  tags = var.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.kms_key_alias}"
  target_key_id = aws_kms_key.this.key_id
}

#---------------------------------------------------------------------------------------------------
# Bucket Policies
#---------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "state_force_ssl" {
  statement {
    sid     = "AllowSSLRequestsOnly"
    actions = ["s3:*"]
    effect  = "Deny"
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

#---------------------------------------------------------------------------------------------------
# Bucket
#---------------------------------------------------------------------------------------------------

resource "aws_s3_bucket_policy" "state_force_ssl" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_force_ssl.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

resource "aws_s3_bucket" "state" {
  bucket_prefix = var.override_s3_bucket_name ? null : var.state_bucket_prefix
  bucket        = var.override_s3_bucket_name ? var.s3_bucket_name : null
  force_destroy = var.s3_bucket_force_destroy

  tags = var.tags
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "state" {
  depends_on = [aws_s3_bucket_ownership_controls.state]
  bucket     = aws_s3_bucket.state.id
  acl        = "private"
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "state" {
  count = var.s3_logging_target_bucket != null ? 1 : 0

  bucket        = aws_s3_bucket.state.id
  target_bucket = var.s3_logging_target_bucket
  target_prefix = var.s3_logging_target_prefix
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  count  = local.define_lifecycle_rule ? 1 : 0
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "auto-archive"
    status = "Enabled"

    dynamic "noncurrent_version_transition" {
      for_each = var.noncurrent_version_transitions

      content {
        noncurrent_days = noncurrent_version_transition.value.days
        storage_class   = noncurrent_version_transition.value.storage_class
      }
    }

    dynamic "noncurrent_version_expiration" {
      for_each = var.noncurrent_version_expiration != null ? [var.noncurrent_version_expiration] : []

      content {
        noncurrent_days = noncurrent_version_expiration.value.days
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###
###
