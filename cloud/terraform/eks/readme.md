
```
# create some variables
variable "eks_managed_node_groups" {
  type        = map(any)
  description = "Map of EKS managed node group definitions to create"
}
variable "autoscaling_average_cpu" {
  type        = number
  description = "Average CPU threshold to autoscale EKS EC2 instances."
}

# create EKS cluster
module "cluster" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.13.1"

  cluster_name                    = var.cluster_name
  cluster_version                 = "1.26"
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true
  subnet_ids                      = module.vpc.private_subnets
  vpc_id                          = module.vpc.vpc_id
  eks_managed_node_groups         = var.eks_managed_node_groups

  node_security_group_additional_rules = {
    # allow connections from ALB security group
    ingress_allow_access_from_alb_sg = {
      type                     = "ingress"
      protocol                 = "-1"
      from_port                = 0
      to_port                  = 0
      source_security_group_id = aws_security_group.alb.id
    }
    # allow connections from EKS to the internet
    egress_all = {
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
    # allow connections from EKS to EKS (internal calls)
    ingress_self_all = {
      protocol  = "-1"
      from_port = 0
      to_port   = 0
      type      = "ingress"
      self      = true
    }
  }
}
output "cluster_endpoint" {
  value = module.cluster.cluster_endpoint
}
output "cluster_certificate_authority_data" {
  value = module.cluster.cluster_certificate_authority_data
}

# create IAM role for AWS Load Balancer Controller, and attach to EKS OIDC
module "eks_ingress_iam" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.17.1"

  role_name                              = "load-balancer-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.cluster.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

# create IAM role for External DNS, and attach to EKS OIDC
module "eks_external_dns_iam" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.17.1"

  role_name                     = "external-dns"
  attach_external_dns_policy    = true
  external_dns_hosted_zone_arns = ["arn:aws:route53:::hostedzone/*"]

  oidc_providers = {
    ex = {
      provider_arn               = module.cluster.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

# set spot fleet Autoscaling policy
resource "aws_autoscaling_policy" "eks_autoscaling_policy" {
  count = length(var.eks_managed_node_groups)

  name                   = "${module.cluster.eks_managed_node_groups_autoscaling_group_names[count.index]}-autoscaling-policy"
  autoscaling_group_name = module.cluster.eks_managed_node_groups_autoscaling_group_names[count.index]
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = var.autoscaling_average_cpu
  }
}
```
data.tf
```

data "aws_vpc" "this" {
  id = "vpc-09f6a265a28ff8c52"
}

data "aws_subnet_ids" "public" {
  vpc_id = data.aws_vpc.this.id

  filter {
    name   = "tag:Name"
    values = ["*public*"]
  }
}

data "aws_subnet_ids" "private" {
  vpc_id = data.aws_vpc.this.id

  filter {
    name   = "tag:Name"
    values = ["*private*"]
  }
}

data "aws_eks_cluster" "cluster" {
  name = module.test-cluster.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.test-cluster.cluster_id
}

data "aws_iam_policy_document" "fargate_profile" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole"
    ]
    principals {
      type = "Service"
      identifiers = [
        "eks.amazonaws.com",
        "eks-fargate-pods.amazonaws.com"
      ]
    }
  }
}
```
main.tf
```
locals {
  cluster_features = {
    reloader       = false
    alb_ingress    = false
    velero         = false
    sealed_secrets = false
  }
  roles = [
    {
      username = "maws-admin"
      rolearn  = "arn:aws:iam::517826968395:role/maws-admin"
      groups   = ["system:masters"]
    }
  ]

  node_groups = {
    default_ng = {
      desired_capacity = "3"
      min_capacity     = "3"
      max_capacity     = "10"
      instance_type    = "t3.small"
      subnets          = data.aws_subnet_ids.private.ids

      additional_tags = {
        "kubernetes.io/cluster/${var.cluster_name}" = "shared"
        "k8s.io/cluster-autoscaler/enabled"         = "true"
      }
    }
  }
}

resource "aws_iam_role" "fargate" {
  name               = "${module.test-cluster.cluster_id}-fargate-profile"
  assume_role_policy = data.aws_iam_policy_document.fargate_profile.json
}

module "test-cluster" {
  source           = "github.com/mozilla-it/terraform-modules//aws/eks?ref=master"
  cluster_name     = var.cluster_name
  cluster_version  = "1.16"
  vpc_id           = data.aws_vpc.this.id
  cluster_subnets  = data.aws_subnet_ids.public.ids
  map_roles        = local.roles
  node_groups      = local.node_groups
  cluster_features = local.cluster_features
}
providers.tf
provider "aws" {
  region = "us-west-2"
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
  version                = "~> 1"
}

provider "helm" {
  version = "~> 1"

  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
    token                  = data.aws_eks_cluster_auth.cluster.token
    load_config_file       = false
  }
}
```
