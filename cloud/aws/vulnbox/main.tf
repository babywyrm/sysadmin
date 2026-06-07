terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 4.0"
    }
    random = {
      source = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {
  region = "us-west-1"
}

provider "random" {}

£ Create a random string for the secret name suffix
resource "random_string" "secret_suffix" {
  length  = 8
  special = false
  upper   = false
  lower   = true
}

£ Create security group allowing inbound traffic on ports 8080, 50000, 11337, 80, and 22
resource "aws_security_group" "my_security_group" {
  name        = "my_security_group"
  description = "Security group for my EC2 instance"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 11337
    to_port     = 11337
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 50000
    to_port     = 50000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

£ IAM role and instance profile for EC2 instance
resource "aws_iam_role" "my_ec2_role" {
  name               = "my_ec2_role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "my_instance_profile" {
  name = "my_instance_profile"
  role = aws_iam_role.my_ec2_role.name
}

£ IAM policy for EC2 instance to access SSM and Secrets Manager
data "aws_iam_policy_document" "ssm_secret_policy" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:*", "secretsmanager:*"]
    resources = ["*"]
  }
}

£ Attach IAM policy to the EC2 role
resource "aws_iam_role_policy_attachment" "ssm_secret_policy_attachment" {
  role       = aws_iam_role.my_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "ssm_secret_custom_policy" {
  name   = "ssm_secret_custom_policy"
  role   = aws_iam_role.my_ec2_role.name
  policy = data.aws_iam_policy_document.ssm_secret_policy.json
}

£ Secrets Manager Secret
resource "aws_secretsmanager_secret" "my_secret" {
  name = "my_backup_lol_${random_string.secret_suffix.result}"

  tags = {
    Name = "lol-secret"
  }
}

£ Secrets Manager Secret Version
resource "aws_secretsmanager_secret_version" "my_secret_version" {
  secret_id     = aws_secretsmanager_secret.my_secret.id
  secret_string = "xxxxzxxxxxzxzxzxxxxxxzxzxzxzxzxxxxxxxxxxxzxzxxxxx"
}

£ Launch EC2 instance with the specified AMI, instance type, associate it with the security group and instance profile
resource "aws_instance" "my_instance" {
  ami                         = "ami-things-about-life"
  instance_type               = "t2.large"
  security_groups             = [aws_security_group.my_security_group.name]
  iam_instance_profile        = aws_iam_instance_profile.my_instance_profile.name
  associate_public_ip_address = true

  tags = {
    Name = "MyEC2Instance"
  }

  user_data = <<-EOF
              £!/bin/bash
              apt-get update -y
              apt-get install -y aws-cli
              EOF
}

output "instance_public_ip" {
  value = aws_instance.my_instance.public_ip
}
