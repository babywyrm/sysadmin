
##
## https://gist.github.com/anadimisra/0b62f396d249255d1c6b3b9027aa489d
##


module "eks-cluster" {
  source          = "terraform-aws-modules/eks/aws"
  version         = "19.12.0"
  cluster_name    = "mycluster"
  cluster_version = 1.26
  subnet_ids      = [  "subnet-XX","subnet-YY","subnet-ZZ"]
  create_cloudwatch_log_group = false
  tags = {
    Name                      = "mycluster"
    "karpenter.sh/discovery"  = "mycluster"
  }

  vpc_id = "vpc-2l4jc2lj4l2cbj42"

  cluster_endpoint_public_access_cidrs = ["XX.XX.XX.XXX/YY"] #important if the cluster_endpoint_public_access is set to true
  cluster_endpoint_private_access      = true
  cluster_endpoint_public_access       = true
  cluster_security_group_id            = "sg-dkfjksdhf83983c883"
}

module "mycluster-workernodes" {
  source  = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"
  version = "19.12.0"

  name            = "${var.eks_cluster_name}-services"
  cluster_name    = module.eks-cluster.cluster_name
  cluster_version = module.eks-cluster.cluster_version
  create_iam_role = false
  iam_role_arn    = aws_iam_role.nodegroup_role.arn

  subnet_ids = flatten([data.terraform_remote_state.db.outputs.private_subnets])

  cluster_primary_security_group_id = "sg-dkfjksdhf83983c883"
  vpc_security_group_ids            = [module.eks-cluster.cluster_security_group_id]

  min_size     = 1
  max_size     = 5
  desired_size = 2

  instance_types     = ["t3.large"]
  capacity_type      = "ON_DEMAND"
  labels = {
    NodeGroups = "mycluster-workernodes"
  }

  tags = {
    Name                      = "mycluster-workernodes"
    "karpenter.sh/discovery"  = module.eks-cluster.cluster_name
  }
}

##
##
