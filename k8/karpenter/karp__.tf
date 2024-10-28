# Install Karpenter in a specific namespace with required resources and configurations
resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true
  name             = "karpenter"
  repository       = "oci://public.ecr.aws/karpenter"
  chart            = "karpenter"
  version          = "v0.27.3"

  # Set Karpenter controller resources
  values = [
    <<-EOF
    controller:
      resources:
        requests:
          cpu: 500m
          memory: 512Mi
        limits:
          cpu: 800m
          memory: 1Gi
    EOF
  ]

  # Associate the required IAM Role to the Karpenter service account
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = var.karpenter_irsa_iam_role_arn
  }

  # Cluster-specific settings for Karpenter
  set {
    name  = "settings.aws.clusterName"
    value = var.eks_cluster_name
  }

  set {
    name  = "settings.aws.clusterEndpoint"
    value = data.aws_eks_cluster.cluster.endpoint
  }

  # Specify default IAM instance profile for nodes
  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = var.karpenter_instance_role_name
  }

  # Set log level for debugging
  set {
    name  = "logLevel"
    value = "debug"
    type  = "string"
  }
}

# Define the Provisioner for Karpenter with spot instance specifications and scaling limits
resource "helm_release" "karpenter_provisioner" {
  depends_on = [helm_release.karpenter]
  name       = "karpenter-provisioner"
  repository = "https://nishantn3.github.io/helm-charts"
  chart      = "raw"
  version    = "0.2.5"

  values = [
    <<-EOF
    resources:
      - apiVersion: karpenter.sh/v1alpha5
        kind: Provisioner
        metadata:
          name: default
        spec:
          requirements:
            # Use spot instances
            - key: karpenter.sh/capacity-type
              operator: In
              values: ["spot"]
            # Specify instance families for cost optimization
            - key: karpenter.k8s.aws/instance-family
              operator: In
              values: ${var.karpenter_instance_types}
          # Define resource limits for scaling nodes
          limits:
            resources:
              cpu: 100
          providerRef:
            name: default
          labels:
            node-type: spot
          # TTL (time-to-live) for empty nodes and nodes reaching expiration
          ttlSecondsAfterEmpty: 100
          ttlSecondsUntilExpired: 86400
    EOF
  ]
}

# Configure AWSNodeTemplate to link nodes to specified subnets, security groups, and tags
resource "helm_release" "karpenter_nodetemplate" {
  depends_on = [helm_release.karpenter]
  name       = "karpenter-nodetemplate"
  repository = "https://nishantn3.github.io/helm-charts"
  chart      = "raw"
  version    = "0.2.5"

  values = [
    <<-EOF
    resources:
      - apiVersion: karpenter.k8s.aws/v1alpha1
        kind: AWSNodeTemplate
        metadata:
          name: default
        spec:
          # Subnet selector for Karpenter nodes
          subnetSelector:
            "karpenter.sh/discovery/${var.eks_cluster_name}": "*"
          # Security group selector for Karpenter nodes
          securityGroupSelector:
            karpenter.sh/discovery/${var.eks_cluster_name}: ${var.eks_cluster_name}
          # Tags to organize and manage nodes
          tags:
            karpenter.sh/discovery/${var.eks_cluster_name}: ${var.eks_cluster_name}
    EOF
  ]
}

##
##

helm_release.karpenter:

Installs Karpenter with specific CPU and memory requests/limits.
Associates an IAM role (var.karpenter_irsa_iam_role_arn) for permissions on AWS resources.
Sets up the Karpenter controller to connect to the EKS cluster by specifying the cluster name, endpoint, and an IAM instance profile for node roles.
The logLevel is set to debug for easier troubleshooting.
helm_release.karpenter_provisioner:

Defines the Provisioner to manage and scale spot instances based on demand.
Limits CPU resources to 100 cores and uses instance types specified by var.karpenter_instance_types.
Applies ttlSecondsAfterEmpty and ttlSecondsUntilExpired to terminate empty or expired nodes, enhancing cost efficiency.
helm_release.karpenter_nodetemplate:

Specifies AWSNodeTemplate to link nodes with selected subnets and security groups, configured with subnetSelector and securityGroupSelector using the karpenter.sh/discovery label.
Applies cluster-specific tags to manage Karpenter resources and organize them within AWS.

##
##

resource "kubectl_manifest" "karpenter_node_template" {
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1alpha1
    kind: AWSNodeTemplate
    metadata:
      name: platform
    spec:
      subnetSelector:
        karpenter.sh/discovery: ${module.eks_vpc_us_east_1.cluster_name}
      securityGroupSelector:
        karpenter.sh/discovery: ${module.eks_vpc_us_east_1.cluster_name}
      instanceProfile: ${module.eks_blueprints_addons_east_1.karpenter.node_instance_profile_name}
      tags:
        karpenter.sh/discovery: ${module.eks_vpc_us_east_1.cluster_name}
  YAML
}

##
##

import { aws_eks as eks } from "aws-cdk-lib";
import { aws_iam as iam } from "aws-cdk-lib";
import { aws_ec2 as ec2 } from "aws-cdk-lib";
import { aws_ssm as ssm } from "aws-cdk-lib";
import { Construct } from "constructs";
import { Duration, CfnJson } from "aws-cdk-lib";

interface KarpenterProps {
  /**
   * The FargateCluster on which karpenter needs to be added
   */
  cluster: eks.FargateCluster;
  /**
   * The kubernetes version for the Bottlerocket AMI's Karpenter is going to run
   */
  version: eks.KubernetesVersion;
  /**
   * The VPC in which karpenter is going to operate
   */
  vpc: ec2.IVpc;
}

/**
 * This construct adds Karpenter on a clusterrole level to an eks.FargateCluster
 * following the guide: https://karpenter.sh/docs/getting-started/
 * It creates 2 IAM roles, one for the Nodes and one for the Controller.
 * It then adds and configures Karpenter on the cluster
 */
export class Karpenter extends Construct {
  public readonly KarpenterNodeRole: iam.Role;
  public readonly karpenterControllerRole: iam.Role;
  public readonly karpenterHelmChart: eks.HelmChart;
  constructor(scope: Construct, id: string, props: KarpenterProps) {
    super(scope, id);

    const karpenterControllerPolicy = new iam.Policy(
      this,
      "karpenterControllerPolicy",
      {
        statements: [
          new iam.PolicyStatement({
            actions: [
              "ec2:CreateLaunchTemplate",
              "ec2:CreateFleet",
              "ec2:RunInstances",
              "ec2:CreateTags",
              "iam:PassRole",
              "ec2:TerminateInstances",
              "ec2:DescribeLaunchTemplates",
              "ec2:DescribeInstances",
              "ec2:DescribeSecurityGroups",
              "ec2:DescribeSubnets",
              "ec2:DescribeInstanceTypes",
              "ec2:DescribeInstanceTypeOfferings",
              "ec2:DescribeAvailabilityZones",
              "ssm:GetParameter",
            ],
            resources: ["*"],
          }),
        ],
      }
    );

    const conditions = new CfnJson(this, "ConditionPlainJson", {
      value: {
        [`${props.cluster.openIdConnectProvider.openIdConnectProviderIssuer}:aud`]:
          "sts.amazonaws.com",
        [`${props.cluster.openIdConnectProvider.openIdConnectProviderIssuer}:sub`]: `system:serviceaccount:karpenter:karpenter`,
      },
    });
    const principal = new iam.OpenIdConnectPrincipal(
      props.cluster.openIdConnectProvider
    ).withConditions({
      StringEquals: conditions,
    });
    this.karpenterControllerRole = new iam.Role(
      this,
      "karpenterControllerRole",
      {
        assumedBy: principal,
        description: `This is the karpenterControllerRole role Karpenter uses to allocate compute for ${props.cluster.clusterName}`,
        roleName: `KarpenterControllerRole-${props.cluster.clusterName}`,
      }
    );
    this.karpenterControllerRole.attachInlinePolicy(karpenterControllerPolicy);

    this.KarpenterNodeRole = new iam.Role(this, "KarpenterNodeRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      description: `This is the KarpenterNodeRole role Karpenter uses to give compute permissions for ${props.cluster.clusterName}`,
      roleName: `KarpenterNodeRole-${props.cluster.clusterName}`,
    });

    [
      "AmazonEKSWorkerNodePolicy",
      "AmazonEKS_CNI_Policy",
      "AmazonEC2ContainerRegistryReadOnly",
      "AmazonSSMManagedInstanceCore",
    ].forEach((element) => {
      this.KarpenterNodeRole.addManagedPolicy(
        iam.ManagedPolicy.fromAwsManagedPolicyName(element)
      );
    });

    new iam.CfnInstanceProfile(this, "cfnKarpenterInstanceProfile", {
      roles: [this.KarpenterNodeRole.roleName],
      instanceProfileName: `KarpenterNodeInstanceProfile-${props.cluster.clusterName}`,
      path: "/",
    });

    props.cluster.awsAuth.addRoleMapping(this.KarpenterNodeRole, {
      groups: ["system:bootstrappers", "system:nodes"],
      username: "system:node:{{EC2PrivateDNSName}}",
    });

    this.karpenterHelmChart = new eks.HelmChart(this, "karpenterHelmChart", {
      chart: "karpenter",
      createNamespace: true,
      version: "0.5.3",
      cluster: props.cluster,
      namespace: "karpenter",
      release: "karpenter",
      repository: "https://charts.karpenter.sh",
      timeout: Duration.minutes(15),
      wait: true,
      values: {
        controller: {
          clusterName: props.cluster.clusterName,
          clusterEndpoint: props.cluster.clusterEndpoint,
        },
        serviceAccount: {
          annotations: {
            "eks.amazonaws.com/role-arn": this.karpenterControllerRole.roleArn,
          },
        },
      },
    });

    // Karpenter does not default encrypt the disk with aws/ebs key or kms
    // Karpenter at 0.5.3 does currently not support a flag that enables boottime disk encryption
    // So in CDK we generate a launch template that follows the Kubernetes version we use.
    const blockDeviceOS: ec2.BlockDevice = {
      deviceName: "/dev/xvda",
      volume: ec2.BlockDeviceVolume.ebs(2, {
        encrypted: true,
      }),
    };
    const blockDeviceImages: ec2.BlockDevice = {
      deviceName: "/dev/xvdb",
      volume: ec2.BlockDeviceVolume.ebs(20, {
        encrypted: true,
      }),
    };

    // We set the userdata to begin with a custom empty string, since Bottlerocket just takes in configuration
    const userData = ec2.UserData.custom("");
    userData.addCommands(...renderBottlerocketUserData(props.cluster));
    const template = new ec2.LaunchTemplate(this, "defaultKarpenterLT", {
      launchTemplateName: `defaultKarpenterLT-${props.cluster.clusterName}`,
      machineImage: new BottleRocketImage({
        kubernetesVersion: props.version.version,
      }),
      userData,
      blockDevices: [blockDeviceOS, blockDeviceImages],
      securityGroup: props.cluster.clusterSecurityGroup,
      role: this.KarpenterNodeRole
    });

    const karpenterGlobalProvider = props.cluster.addManifest(
      "karpenterGlobalProvider",
      {
        apiVersion: "karpenter.sh/v1alpha5",
        kind: "Provisioner",
        metadata: {
          name: "default",
        },
        spec: {
          ttlSecondsUntilExpired: 2592000,
          ttlSecondsAfterEmpty: 30,
          requirements: [
            {
              key: "karpenter.sh/capacity-type",
              operator: "In",
              values: ["on-demand"],
            },
            {
              key: "kubernetes.io/arch",
              operator: "In",
              values: ["arm64", "amd64"],
            },
            {
              key: "topology.kubernetes.io/zone",
              operator: "In",
              values: ["eu-west-1a", "eu-west-1b", "eu-west-1c"],
            },
          ],
          labels: {
            "cluster-name": `${props.cluster.clusterName}`,
          },
          provider: {
            instanceProfile: `KarpenterNodeInstanceProfile-${props.cluster.clusterName}`,
            launchTemplate: `defaultKarpenterLT-${props.cluster.clusterName}`,
          },
        },
      }
    );
    karpenterGlobalProvider.node.addDependency(this.karpenterHelmChart);
  }
}

export function renderBottlerocketUserData(cluster: eks.ICluster): string[] {
  return [
    "[settings.kubernetes]",
    `api-server="${cluster.clusterEndpoint}"`,
    `cluster-certificate="${cluster.clusterCertificateAuthorityData}"`,
    `cluster-name="${cluster.clusterName}"`,
  ];
}

/**
 * Properties for BottleRocketImage
 */
export interface BottleRocketImageProps {
  /**
   * The Kubernetes version to use
   */
  readonly kubernetesVersion: string;
}

/**
 * Construct an Bottlerocket image from the latest AMI published in SSM
 */
export class BottleRocketImage implements ec2.IMachineImage {
  private readonly kubernetesVersion: string;

  private readonly amiParameterName: string;

  /**
   * Constructs a new instance of the BottleRocketImage class.
   */
  public constructor(props: BottleRocketImageProps) {
    this.kubernetesVersion = props.kubernetesVersion;

    // set the SSM parameter name
    this.amiParameterName = `/aws/service/bottlerocket/aws-k8s-${this.kubernetesVersion}/x86_64/latest/image_id`;
  }

  /**
   * Return the correct image
   */
  public getImage(scope: Construct): ec2.MachineImageConfig {
    const ami = ssm.StringParameter.valueForStringParameter(
      scope,
      this.amiParameterName
    );
    return {
      imageId: ami,
      osType: ec2.OperatingSystemType.LINUX,
      userData: ec2.UserData.custom(""),
    };
  }
}



