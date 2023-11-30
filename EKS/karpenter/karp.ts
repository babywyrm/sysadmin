// https://gist.github.com/gbvanrenswoude/b5363d78d39ff32ace9899942110184d
//
//

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
