#!/usr/bin/python3

##
##

# CDK
from constructs import Construct
from cdktf import App, TerraformOutput, TerraformStack, Token

# terraform provider
from imports.aws import AwsProvider, DataAwsCallerIdentity

# terraform module
from imports.vpc import Vpc
from imports.eks import Eks


AWS_REGION = 'us-east-1'
AVAILABILITY_ZONES = [AWS_REGION + suf for suf in ('a', 'b', 'c')]
TAGS = {"Environment": "test", "Delete me": "true"}
VPC_CIDR = '10.0.0.0/16'
PRIVATE_SUBNETS = ['10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24']
PUBLIC_SUBNETS = ['10.0.101.0/24', '10.0.102.0/24', '10.0.103.0/24']
CLUSTER_VERSION = '1.17'
NODE_GROUP_INSTANCE_TYPE = "m5.large"


class BasicStack(TerraformStack):
    def __repr__(self):
        return f"{super().__repr__()}: {self.__dict__}"

    def _eks_cluster(self):
        return Eks(
            self, 'TestEksCluster',
            cluster_name='test-eks-cluster',
            subnets=Token().as_list(self.eks_cluster_vpc.private_subnets_output),
            vpc_id=Token().as_string(self.eks_cluster_vpc.vpc_id_output),
            manage_aws_auth=False,
            cluster_version=CLUSTER_VERSION,
            node_groups=self._node_groups(),
            tags=TAGS
        )

    def _node_groups(self):
        return [
            {
                "instance_types": [NODE_GROUP_INSTANCE_TYPE],
                "capacity_type": "SPOT",
                "desired_capacity": 1,
                "max_capacity": 2,
                "min_capacity": 1,
            }
        ]

    def _eks_cluster_vpc(self):
        return Vpc(
            self, 'TestEksClusterVpc',
            name='test-eks-cluster-vpc',
            cidr=VPC_CIDR,
            azs=AVAILABILITY_ZONES,
            private_subnets=PRIVATE_SUBNETS,
            public_subnets=PUBLIC_SUBNETS,
            enable_nat_gateway=True,
            tags=TAGS
        )

    def _tf_outputs(self):
        TerraformOutput(self, 'cluster_endpoint', value=self.eks_cluster.cluster_endpoint_output)
        TerraformOutput(self, 'create_user_arn', value=DataAwsCallerIdentity(self, 'current').arn)
        TerraformOutput(self, 'kubeconfig', value=self.eks_cluster.kubeconfig_output)

    def __init__(self, scope: Construct, ns: str):
        super().__init__(scope, ns)

        AwsProvider(self, 'Aws', region=AWS_REGION)

        self.eks_cluster_vpc = self._eks_cluster_vpc()
        self.eks_cluster = self._eks_cluster()
        self.tf_outputs = self._tf_outputs()


if __name__ == '__main__':
    app = App()
    try:
        stack = BasicStack(scope=app, ns="test-eks-stack")
        app.synth()
    except BaseException as err:
        print(f">> Error occurred: {err}")
        
##
##
