module "vpc" {
  source               = "terraform-aws-modules/vpc/aws"
  version              = "3.19.0"
  name                 = "mycluster-vpc"
  cidr                 = var.vpc_cidr
  azs                  = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets      = var.private_subnets_cidr
  public_subnets       = var.public_subnets_cidr
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/mycluster" = "shared"
    "kubernetes.io/role/elb"          = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/mycluster  = "shared"
    "kubernetes.io/role/internal-elb" = "1"
    "karpenter.sh/discovery"          = "mycluster"
  }
  tags = {
    "kubernetes.io/cluster/mycluster" = "shared"
  }
}
module "vpc-security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.17.1"
  create  = true
  name        = "mycluster-security-group"
  description = "Security group for VPC"
  vpc_id      = module.vpc.vpc_id
  ingress_with_cidr_blocks = var.ingress_rules
  ingress_with_self = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = -1
      description = "Ingress with Self"
    }
  ]
  egress_with_cidr_blocks = [{
    cidr_blocks = "0.0.0.0/0"
    from_port   = 0
    to_port     = 0
    protocol    = -1
  }]
  tags = {
    Name                      = "mycluster-security-group"
    "karpenter.sh/discovery"  = "mycluster"
  }
}
