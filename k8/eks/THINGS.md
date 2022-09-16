Swatmobile - AWS EKS gists
amazon-eks-nodegroup-with-mixed-instances-custom.yml
---
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Amazon EKS Node Group'
Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      -
        Label:
          default: "EKS Configuration"
        Parameters:
          - ClusterName
          - ClusterControlPlaneSecurityGroup
          - NodeInstanceProfile
          - UseExistingNodeSecurityGroups
          - ExistingNodeSecurityGroups
          - NodeImageId
          - VpcId
          - KeyName
          - NodeGroupName
          - Subnets
          - BootstrapArgumentsForOnDemand
          - BootstrapArgumentsForSpotFleet
      -
        Label:
          default: "Auto Scaling Configuration"
        Parameters:
          - NodeAutoScalingGroupMinSize
          - NodeAutoScalingGroupDesiredSize
          - NodeAutoScalingGroupMaxSize
          - ClusterAutoscalerStatus
          - NodeInstanceType
          - ASGAutoAssignPublicIp
          - OnDemandBaseCapacity
          - OnDemandPercentageAboveBaseCapacity
          - SpotInstancePools
          - InstanceTypesOverride

Parameters:
  VpcId:
    Description: The VPC of the worker instances
    Type: AWS::EC2::VPC::Id

  Subnets:
    Description: Select 3 subnets where workers can be created.
    Type: List<AWS::EC2::Subnet::Id>

  NodeInstanceProfile:
    Type: String
    Description: Use the existing Instance Profile ARN for your nodegroup
    Default: ""

  KeyName:
    Description: The EC2 Key Pair to allow SSH access to the instances
    Type: AWS::EC2::KeyPair::KeyName
    Default: "eksworkshop"

  NodeImageId:
    Type: AWS::EC2::Image::Id
    Description: Find the latest AMI id here - https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html

  NodeInstanceType:
    Description: Default EC2 instance type for the node instances.
    Type: String
    Default: m4.large
    AllowedValues:
    - t2.small
    - t2.medium
    - t2.large
    - t2.xlarge
    - t2.2xlarge
    - t3.nano
    - t3.micro
    - t3.small
    - t3.medium
    - t3.large
    - t3.xlarge
    - t3.2xlarge
    - m3.medium
    - m3.large
    - m3.xlarge
    - m3.2xlarge
    - m4.large
    - m4.xlarge
    - m4.2xlarge
    - m4.4xlarge
    - m4.10xlarge
    - m5.large
    - m5.xlarge
    - m5.2xlarge
    - m5.4xlarge
    - m5.12xlarge
    - m5.24xlarge
    - c4.large
    - c4.xlarge
    - c4.2xlarge
    - c4.4xlarge
    - c4.8xlarge
    - c5.large
    - c5.xlarge
    - c5.2xlarge
    - c5.4xlarge
    - c5.9xlarge
    - c5.18xlarge
    - i3.large
    - i3.xlarge
    - i3.2xlarge
    - i3.4xlarge
    - i3.8xlarge
    - i3.16xlarge
    - r3.xlarge
    - r3.2xlarge
    - r3.4xlarge
    - r3.8xlarge
    - r4.large
    - r4.xlarge
    - r4.2xlarge
    - r4.4xlarge
    - r4.8xlarge
    - r4.16xlarge
    - x1.16xlarge
    - x1.32xlarge
    - p2.xlarge
    - p2.8xlarge
    - p2.16xlarge
    - p3.2xlarge
    - p3.8xlarge
    - p3.16xlarge
    - p3dn.24xlarge
    - r5.large
    - r5.xlarge
    - r5.2xlarge
    - r5.4xlarge
    - r5.12xlarge
    - r5.24xlarge
    - r5d.large
    - r5d.xlarge
    - r5d.2xlarge
    - r5d.4xlarge
    - r5d.12xlarge
    - r5d.24xlarge
    - z1d.large
    - z1d.xlarge
    - z1d.2xlarge
    - z1d.3xlarge
    - z1d.6xlarge
    - z1d.12xlarge
    ConstraintDescription: Must be a valid EC2 instance type

  NodeAutoScalingGroupMinSize:
    Type: Number
    Description: Minimum size of Node Group ASG.
    Default: 1

  NodeAutoScalingGroupDesiredSize:
    Type: Number
    Description: Desired size of Node Group ASG.
    Default: 3

  NodeAutoScalingGroupMaxSize:
    Type: Number
    Description: Maximum size of Node Group ASG.
    Default: 5

  ASGAutoAssignPublicIp:
    Type: String
    Description: "auto assign public IP address for ASG instances"
    AllowedValues:
      - "yes"
      - "no"
    Default: "yes"

  ClusterAutoscalerStatus:
    Type: String
    Description: "cluster-autoscaler status"
    AllowedValues:
      - "enabled"
      - "disabled"
    Default: "enabled"

  OnDemandBaseCapacity:
    Type: Number
    Description: "on-demand base capacity"
    Default: 1

  OnDemandPercentageAboveBaseCapacity:
    Type: Number
    Description: "on-demand percentage above base capacity(0-100)"
    Default: 0

  SpotInstancePools:
    Type: Number
    Description: "spot instance pools(1-20)"
    Default: 2

  InstanceTypesOverride:
    Type: String
    Description: "multiple spot instances to override(seperated by comma)"
    Default: "m4.large,c4.large,c5.large"

  UseExistingNodeSecurityGroups:
    Type: String
    Description: Please select 'yes' to attach existing SGs to nodegroup
    Default: "yes"
    AllowedValues:
      - "yes"
      - "no"
  ExistingNodeSecurityGroups:
    Type: String
    Description: Use the existing Security Group for your nodegroup
    Default: ""

  ClusterName:
    Description: The cluster name provided when the cluster was created.  If it is incorrect, nodes will not be able to join the cluster.
    Type: String
    Default: "eksworkshop-eksctl"

  BootstrapArgumentsForOnDemand:
    Description: Arguments to pass to the bootstrap script. See files/bootstrap.sh in https://github.com/awslabs/amazon-eks-ami
    Default: "--kubelet-extra-args --node-labels=lifecycle=OnDemand"
    Type: String

  BootstrapArgumentsForSpotFleet:
    Description: Arguments to pass to the bootstrap script. See files/bootstrap.sh in https://github.com/awslabs/amazon-eks-ami
    Default: "--kubelet-extra-args '--node-labels=lifecycle=Ec2Spot --register-with-taints=spotInstance=true:PreferNoSchedule'
"
    Type: String

  ClusterControlPlaneSecurityGroup:
    Description: The security group of the cluster control plane.
    Type: AWS::EC2::SecurityGroup::Id

  NodeGroupName:
    Description: Unique identifier for the Node Group.
    Type: String
    Default: "spotworkers"

Conditions:
  IsASGAutoAssignPublicIp: !Equals [ !Ref ASGAutoAssignPublicIp , "yes" ]
  AttachExistingNodeSG: !Equals [ !Ref UseExistingNodeSecurityGroups, "yes" ]
  CreateNewNodeSG: !Equals [ !Ref UseExistingNodeSecurityGroups, "no" ]


Resources:
  NodeSecurityGroup:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for all nodes in the cluster
      VpcId:
        !Ref VpcId
      Tags:
      - Key: !Sub "kubernetes.io/cluster/${ClusterName}"
        Value: 'owned'
      - Key: Name
        Value: !Sub "${ClusterName}-cluster/NodeSecurityGroup"

  NodeSecurityGroupIngress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow node to communicate with each other
      GroupId: !Ref NodeSecurityGroup
      SourceSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: '-1'
      FromPort: 0
      ToPort: 65535

  NodeSecurityGroupFromControlPlaneIngress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow worker Kubelets and pods to receive communication from the cluster control plane
      GroupId: !Ref NodeSecurityGroup
      SourceSecurityGroupId: !Ref ClusterControlPlaneSecurityGroup
      IpProtocol: tcp
      FromPort: 1025
      ToPort: 65535

  ControlPlaneEgressToNodeSecurityGroup:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupEgress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow the cluster control plane to communicate with worker Kubelet and pods
      GroupId: !Ref ClusterControlPlaneSecurityGroup
      DestinationSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: tcp
      FromPort: 1025
      ToPort: 65535

  NodeSecurityGroupFromControlPlaneOn443Ingress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow pods running extension API servers on port 443 to receive communication from cluster control plane
      GroupId: !Ref NodeSecurityGroup
      SourceSecurityGroupId: !Ref ClusterControlPlaneSecurityGroup
      IpProtocol: tcp
      FromPort: 443
      ToPort: 443

  ControlPlaneEgressToNodeSecurityGroupOn443:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupEgress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow the cluster control plane to communicate with pods running extension API servers on port 443
      GroupId: !Ref ClusterControlPlaneSecurityGroup
      DestinationSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: tcp
      FromPort: 443
      ToPort: 443

  ClusterControlPlaneSecurityGroupIngress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow pods to communicate with the cluster API Server
      GroupId: !Ref ClusterControlPlaneSecurityGroup
      SourceSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: tcp
      ToPort: 443
      FromPort: 443

  NodeGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      DesiredCapacity: !Ref NodeAutoScalingGroupDesiredSize
      #LaunchConfigurationName: !Ref NodeLaunchConfig
      # LaunchTemplate:
      #   LaunchTemplateId: !Ref MyLaunchTemplate
      #   Version: !GetAtt MyLaunchTemplate.LatestVersionNumber
      MixedInstancesPolicy:
        InstancesDistribution:
          OnDemandAllocationStrategy: prioritized
          OnDemandBaseCapacity: !Ref OnDemandBaseCapacity
          OnDemandPercentageAboveBaseCapacity: !Ref OnDemandPercentageAboveBaseCapacity
          SpotAllocationStrategy: lowest-price
          SpotInstancePools: !Ref SpotInstancePools
          # SpotMaxPrice: String
        LaunchTemplate:
          LaunchTemplateSpecification:
            LaunchTemplateId: !Ref MyLaunchTemplate
            # LaunchTemplateName: String
            Version: !GetAtt MyLaunchTemplate.LatestVersionNumber
          Overrides:
            - InstanceType: !Select [0, !Split [ ",", !Ref InstanceTypesOverride ] ]
            - InstanceType: !Select [1, !Split [ ",", !Ref InstanceTypesOverride ] ]
            - InstanceType: !Select [2, !Split [ ",", !Ref InstanceTypesOverride ] ]

      MinSize: !Ref NodeAutoScalingGroupMinSize
      MaxSize: !Ref NodeAutoScalingGroupMaxSize
      VPCZoneIdentifier:
        !Ref Subnets
      Tags:
      - Key: Name
        Value: !Sub "${ClusterName}-${NodeGroupName}-ASG-Node"
        PropagateAtLaunch: 'true'
      - Key: !Sub 'kubernetes.io/cluster/${ClusterName}'
        Value: 'owned'
        PropagateAtLaunch: 'true'
      - Key: Namespace
        Value: swat
        PropagateAtLaunch: 'true'
      - Key: Stage
        Value: stage
        PropagateAtLaunch: 'true'
      - Key: !Sub 'k8s.io/cluster-autoscaler/${ClusterAutoscalerStatus}'
        Value: 'true'
        PropagateAtLaunch: 'true'
    UpdatePolicy:
      AutoScalingRollingUpdate:
        MinInstancesInService: !Ref NodeAutoScalingGroupDesiredSize
        MaxBatchSize: '1'
        PauseTime: 'PT5M'

  LCH:
    Type: AWS::AutoScaling::LifecycleHook
    Properties:
      AutoScalingGroupName: !Ref NodeGroup
      HeartbeatTimeout: 60
      DefaultResult: CONTINUE
      LifecycleHookName: !Sub "${NodeGroupName}-LCH"
      LifecycleTransition: autoscaling:EC2_INSTANCE_TERMINATING

#
# Launch Template
#
  MyLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Sub "eksLaunchTemplate-${AWS::StackName}"
      LaunchTemplateData:
        # SecurityGroupIds:
        #   - !Ref NodeSecurityGroup
        TagSpecifications:
          -
            ResourceType: instance
            Tags:
              - Key: Name
                Value: !Sub "${ClusterName}-${NodeGroupName}-ASG-Node"
              - Key: KubernetesCluster
                Value: !Ref ClusterName
              - Key: !Sub 'kubernetes.io/cluster/${ClusterName}'
                Value: 'owned'
              - Key: Namespace
                Value: swat
              - Key: Stage
                Value: stage
              - Key: !Sub 'k8s.io/cluster-autoscaler/${ClusterAutoscalerStatus}'
                Value: 'true'
        UserData:
          Fn::Base64:
            !Sub |
            #!/bin/bash
            set -o xtrace
            iid=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
            export AWS_DEFAULT_REGION=${AWS::Region}
            ilc=`aws ec2 describe-instances --instance-ids  $iid  --query 'Reservations[0].Instances[0].InstanceLifecycle' --output text`
            if [ "$ilc" == "spot" ]; then
              /etc/eks/bootstrap.sh ${ClusterName} ${BootstrapArgumentsForSpotFleet}
            else
              /etc/eks/bootstrap.sh ${ClusterName} ${BootstrapArgumentsForOnDemand}
            fi
            # /etc/eks/bootstrap.sh ${ClusterName} $BootstrapArgumentsForOnDemand
            /opt/aws/bin/cfn-signal --exit-code $? \
                     --stack  ${AWS::StackName} \
                     --resource NodeGroup  \
                     --region ${AWS::Region}
        IamInstanceProfile:
          Arn: !Ref NodeInstanceProfile
        KeyName: !Ref KeyName
        NetworkInterfaces:
          -
            DeviceIndex: 0
            AssociatePublicIpAddress:
              !If
                - IsASGAutoAssignPublicIp
                - 'true'
                - 'false'
            SubnetId: !Select [0, !Ref Subnets]
            Groups:
              !If
                - CreateNewNodeSG
                -
                  - !Ref NodeSecurityGroup
                - !Split [ ",", !Ref ExistingNodeSecurityGroups ]
        ImageId: !Ref NodeImageId
        InstanceType: !Ref NodeInstanceType

Outputs:

  NodeGroup:
    Description: The node instance group
    Value: !Ref NodeGroup
amazon-eks-nodegroup-with-mixed-instances.yml
---
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Amazon EKS Node Group'
Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      -
        Label:
          default: "EKS Configuration"
        Parameters:
          - ClusterName
          - ClusterControlPlaneSecurityGroup
          - NodeInstanceProfile
          - UseExistingNodeSecurityGroups
          - ExistingNodeSecurityGroups
          - NodeImageId
          - VpcId
          - KeyName
          - NodeGroupName
          - Subnets
          - BootstrapArgumentsForOnDemand
          - BootstrapArgumentsForSpotFleet
      -
        Label:
          default: "Auto Scaling Configuration"
        Parameters:
          - NodeAutoScalingGroupMinSize
          - NodeAutoScalingGroupDesiredSize
          - NodeAutoScalingGroupMaxSize
          - NodeInstanceType
          - ASGAutoAssignPublicIp
          - OnDemandBaseCapacity
          - OnDemandPercentageAboveBaseCapacity
          - SpotInstancePools
          - InstanceTypesOverride

Parameters:
  VpcId:
    Description: The VPC of the worker instances
    Type: AWS::EC2::VPC::Id

  Subnets:
    Description: Select 3 subnets where workers can be created.
    Type: List<AWS::EC2::Subnet::Id>

  NodeInstanceProfile:
    Type: String
    Description: Use the existing Instance Profile ARN for your nodegroup
    Default: ""

  KeyName:
    Description: The EC2 Key Pair to allow SSH access to the instances
    Type: AWS::EC2::KeyPair::KeyName
    Default: "eksworkshop"

  NodeImageId:
    Type: AWS::EC2::Image::Id
    Description: Find the latest AMI id here - https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html

  NodeInstanceType:
    Description: Default EC2 instance type for the node instances.
    Type: String
    Default: m4.large
    AllowedValues:
    - t2.small
    - t2.medium
    - t2.large
    - t2.xlarge
    - t2.2xlarge
    - t3.nano
    - t3.micro
    - t3.small
    - t3.medium
    - t3.large
    - t3.xlarge
    - t3.2xlarge
    - m3.medium
    - m3.large
    - m3.xlarge
    - m3.2xlarge
    - m4.large
    - m4.xlarge
    - m4.2xlarge
    - m4.4xlarge
    - m4.10xlarge
    - m5.large
    - m5.xlarge
    - m5.2xlarge
    - m5.4xlarge
    - m5.12xlarge
    - m5.24xlarge
    - c4.large
    - c4.xlarge
    - c4.2xlarge
    - c4.4xlarge
    - c4.8xlarge
    - c5.large
    - c5.xlarge
    - c5.2xlarge
    - c5.4xlarge
    - c5.9xlarge
    - c5.18xlarge
    - i3.large
    - i3.xlarge
    - i3.2xlarge
    - i3.4xlarge
    - i3.8xlarge
    - i3.16xlarge
    - r3.xlarge
    - r3.2xlarge
    - r3.4xlarge
    - r3.8xlarge
    - r4.large
    - r4.xlarge
    - r4.2xlarge
    - r4.4xlarge
    - r4.8xlarge
    - r4.16xlarge
    - x1.16xlarge
    - x1.32xlarge
    - p2.xlarge
    - p2.8xlarge
    - p2.16xlarge
    - p3.2xlarge
    - p3.8xlarge
    - p3.16xlarge
    - p3dn.24xlarge
    - r5.large
    - r5.xlarge
    - r5.2xlarge
    - r5.4xlarge
    - r5.12xlarge
    - r5.24xlarge
    - r5d.large
    - r5d.xlarge
    - r5d.2xlarge
    - r5d.4xlarge
    - r5d.12xlarge
    - r5d.24xlarge
    - z1d.large
    - z1d.xlarge
    - z1d.2xlarge
    - z1d.3xlarge
    - z1d.6xlarge
    - z1d.12xlarge
    ConstraintDescription: Must be a valid EC2 instance type

  NodeAutoScalingGroupMinSize:
    Type: Number
    Description: Minimum size of Node Group ASG.
    Default: 1

  NodeAutoScalingGroupDesiredSize:
    Type: Number
    Description: Desired size of Node Group ASG.
    Default: 3

  NodeAutoScalingGroupMaxSize:
    Type: Number
    Description: Maximum size of Node Group ASG.
    Default: 5

  ASGAutoAssignPublicIp:
    Type: String
    Description: "auto assign public IP address for ASG instances"
    AllowedValues:
      - "yes"
      - "no"
    Default: "yes"

  OnDemandBaseCapacity:
    Type: Number
    Description: "on-demand base capacity"
    Default: 1

  OnDemandPercentageAboveBaseCapacity:
    Type: Number
    Description: "on-demand percentage above base capacity(0-100)"
    Default: 0

  SpotInstancePools:
    Type: Number
    Description: "spot instance pools(1-20)"
    Default: 2

  InstanceTypesOverride:
    Type: String
    Description: "multiple spot instances to override(seperated by comma)"
    Default: "m4.large,c4.large,c5.large"

  UseExistingNodeSecurityGroups:
    Type: String
    Description: Please select 'yes' to attach existing SGs to nodegroup
    Default: "yes"
    AllowedValues:
      - "yes"
      - "no"
  ExistingNodeSecurityGroups:
    Type: String
    Description: Use the existing Security Group for your nodegroup
    Default: ""

  ClusterName:
    Description: The cluster name provided when the cluster was created.  If it is incorrect, nodes will not be able to join the cluster.
    Type: String
    Default: "eksworkshop-eksctl"

  BootstrapArgumentsForOnDemand:
    Description: Arguments to pass to the bootstrap script. See files/bootstrap.sh in https://github.com/awslabs/amazon-eks-ami
    Default: "--kubelet-extra-args --node-labels=lifecycle=OnDemand"
    Type: String

  BootstrapArgumentsForSpotFleet:
    Description: Arguments to pass to the bootstrap script. See files/bootstrap.sh in https://github.com/awslabs/amazon-eks-ami
    Default: "--kubelet-extra-args '--node-labels=lifecycle=Ec2Spot --register-with-taints=spotInstance=true:PreferNoSchedule'
"
    Type: String

  ClusterControlPlaneSecurityGroup:
    Description: The security group of the cluster control plane.
    Type: AWS::EC2::SecurityGroup::Id

  NodeGroupName:
    Description: Unique identifier for the Node Group.
    Type: String
    Default: "spotworkers"

Conditions:
  IsASGAutoAssignPublicIp: !Equals [ !Ref ASGAutoAssignPublicIp , "yes" ]
  AttachExistingNodeSG: !Equals [ !Ref UseExistingNodeSecurityGroups, "yes" ]
  CreateNewNodeSG: !Equals [ !Ref UseExistingNodeSecurityGroups, "no" ]


Resources:
  NodeSecurityGroup:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for all nodes in the cluster
      VpcId:
        !Ref VpcId
      Tags:
      - Key: !Sub "kubernetes.io/cluster/${ClusterName}"
        Value: 'owned'
      - Key: Name
        Value: !Sub "${ClusterName}-cluster/NodeSecurityGroup"

  NodeSecurityGroupIngress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow node to communicate with each other
      GroupId: !Ref NodeSecurityGroup
      SourceSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: '-1'
      FromPort: 0
      ToPort: 65535

  NodeSecurityGroupFromControlPlaneIngress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow worker Kubelets and pods to receive communication from the cluster control plane
      GroupId: !Ref NodeSecurityGroup
      SourceSecurityGroupId: !Ref ClusterControlPlaneSecurityGroup
      IpProtocol: tcp
      FromPort: 1025
      ToPort: 65535

  ControlPlaneEgressToNodeSecurityGroup:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupEgress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow the cluster control plane to communicate with worker Kubelet and pods
      GroupId: !Ref ClusterControlPlaneSecurityGroup
      DestinationSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: tcp
      FromPort: 1025
      ToPort: 65535

  NodeSecurityGroupFromControlPlaneOn443Ingress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow pods running extension API servers on port 443 to receive communication from cluster control plane
      GroupId: !Ref NodeSecurityGroup
      SourceSecurityGroupId: !Ref ClusterControlPlaneSecurityGroup
      IpProtocol: tcp
      FromPort: 443
      ToPort: 443

  ControlPlaneEgressToNodeSecurityGroupOn443:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupEgress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow the cluster control plane to communicate with pods running extension API servers on port 443
      GroupId: !Ref ClusterControlPlaneSecurityGroup
      DestinationSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: tcp
      FromPort: 443
      ToPort: 443

  ClusterControlPlaneSecurityGroupIngress:
    Condition: CreateNewNodeSG
    Type: AWS::EC2::SecurityGroupIngress
    DependsOn: NodeSecurityGroup
    Properties:
      Description: Allow pods to communicate with the cluster API Server
      GroupId: !Ref ClusterControlPlaneSecurityGroup
      SourceSecurityGroupId: !Ref NodeSecurityGroup
      IpProtocol: tcp
      ToPort: 443
      FromPort: 443

  NodeGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      DesiredCapacity: !Ref NodeAutoScalingGroupDesiredSize
      #LaunchConfigurationName: !Ref NodeLaunchConfig
      # LaunchTemplate:
      #   LaunchTemplateId: !Ref MyLaunchTemplate
      #   Version: !GetAtt MyLaunchTemplate.LatestVersionNumber
      MixedInstancesPolicy:
        InstancesDistribution:
          OnDemandAllocationStrategy: prioritized
          OnDemandBaseCapacity: !Ref OnDemandBaseCapacity
          OnDemandPercentageAboveBaseCapacity: !Ref OnDemandPercentageAboveBaseCapacity
          SpotAllocationStrategy: lowest-price
          SpotInstancePools: !Ref SpotInstancePools
          # SpotMaxPrice: String
        LaunchTemplate:
          LaunchTemplateSpecification:
            LaunchTemplateId: !Ref MyLaunchTemplate
            # LaunchTemplateName: String
            Version: !GetAtt MyLaunchTemplate.LatestVersionNumber
          Overrides:
            - InstanceType: !Select [0, !Split [ ",", !Ref InstanceTypesOverride ] ]
            - InstanceType: !Select [1, !Split [ ",", !Ref InstanceTypesOverride ] ]
            - InstanceType: !Select [2, !Split [ ",", !Ref InstanceTypesOverride ] ]

      MinSize: !Ref NodeAutoScalingGroupMinSize
      MaxSize: !Ref NodeAutoScalingGroupMaxSize
      VPCZoneIdentifier:
        !Ref Subnets
      Tags:
      - Key: Name
        Value: !Sub "${ClusterName}-${NodeGroupName}-ASG-Node"
        PropagateAtLaunch: 'true'
      - Key: !Sub 'kubernetes.io/cluster/${ClusterName}'
        Value: 'owned'
        PropagateAtLaunch: 'true'
    UpdatePolicy:
      AutoScalingRollingUpdate:
        MinInstancesInService: !Ref NodeAutoScalingGroupDesiredSize
        MaxBatchSize: '1'
        PauseTime: 'PT5M'

  LCH:
    Type: AWS::AutoScaling::LifecycleHook
    Properties:
      AutoScalingGroupName: !Ref NodeGroup
      HeartbeatTimeout: 60
      DefaultResult: CONTINUE
      LifecycleHookName: !Sub "${NodeGroupName}-LCH"
      LifecycleTransition: autoscaling:EC2_INSTANCE_TERMINATING

#
# Launch Template
#
  MyLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Sub "eksLaunchTemplate-${AWS::StackName}"
      LaunchTemplateData:
        # SecurityGroupIds:
        #   - !Ref NodeSecurityGroup
        TagSpecifications:
          -
            ResourceType: instance
            Tags:
              - Key: Name
                Value: !Sub "${ClusterName}-${NodeGroupName}-ASG-Node"
              - Key: KubernetesCluster
                Value: !Ref ClusterName
              - Key: !Sub 'kubernetes.io/cluster/${ClusterName}'
                Value: 'owned'
        UserData:
          Fn::Base64:
            !Sub |
            #!/bin/bash
            set -o xtrace
            iid=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
            export AWS_DEFAULT_REGION=${AWS::Region}
            ilc=`aws ec2 describe-instances --instance-ids  $iid  --query 'Reservations[0].Instances[0].InstanceLifecycle' --output text`
            if [ "$ilc" == "spot" ]; then
              /etc/eks/bootstrap.sh ${ClusterName} ${BootstrapArgumentsForSpotFleet}
            else
              /etc/eks/bootstrap.sh ${ClusterName} ${BootstrapArgumentsForOnDemand}
            fi
            # /etc/eks/bootstrap.sh ${ClusterName} $BootstrapArgumentsForOnDemand
            /opt/aws/bin/cfn-signal --exit-code $? \
                     --stack  ${AWS::StackName} \
                     --resource NodeGroup  \
                     --region ${AWS::Region}
        IamInstanceProfile:
          Arn: !Ref NodeInstanceProfile
        KeyName: !Ref KeyName
        NetworkInterfaces:
          -
            DeviceIndex: 0
            AssociatePublicIpAddress:
              !If
                - IsASGAutoAssignPublicIp
                - 'true'
                - 'false'
            SubnetId: !Select [0, !Ref Subnets]
            Groups:
              !If
                - CreateNewNodeSG
                -
                  - !Ref NodeSecurityGroup
                - !Split [ ",", !Ref ExistingNodeSecurityGroups ]
        ImageId: !Ref NodeImageId
        InstanceType: !Ref NodeInstanceType
cfn-template-changes.diff
diff --git a/amazon-eks-nodegroup-with-mixed-instances.yml b/amazon-eks-nodegroup-with-mixed-instances-custom.yml
index a0a3c99..512c50f 100644
--- a/amazon-eks-nodegroup-with-mixed-instances.yml
+++ b/amazon-eks-nodegroup-with-mixed-instances-custom.yml
@@ -27,6 +27,7 @@ Metadata:
           - NodeAutoScalingGroupMinSize
           - NodeAutoScalingGroupDesiredSize
           - NodeAutoScalingGroupMaxSize
+          - ClusterAutoscalerStatus
           - NodeInstanceType
           - ASGAutoAssignPublicIp
           - OnDemandBaseCapacity
@@ -168,6 +169,14 @@ Parameters:
       - "no"
     Default: "yes"
 
+  ClusterAutoscalerStatus:
+    Type: String
+    Description: "cluster-autoscaler status"
+    AllowedValues:
+      - "enabled"
+      - "disabled"
+    Default: "enabled"
+
   OnDemandBaseCapacity:
     Type: Number
     Description: "on-demand base capacity"
@@ -354,6 +363,15 @@ Resources:
       - Key: !Sub 'kubernetes.io/cluster/${ClusterName}'
         Value: 'owned'
         PropagateAtLaunch: 'true'
+      - Key: Namespace
+        Value: swat
+        PropagateAtLaunch: 'true'
+      - Key: Stage
+        Value: stage
+        PropagateAtLaunch: 'true'
+      - Key: !Sub 'k8s.io/cluster-autoscaler/${ClusterAutoscalerStatus}'
+        Value: 'true'
+        PropagateAtLaunch: 'true'
     UpdatePolicy:
       AutoScalingRollingUpdate:
         MinInstancesInService: !Ref NodeAutoScalingGroupDesiredSize
@@ -389,6 +407,12 @@ Resources:
                 Value: !Ref ClusterName
               - Key: !Sub 'kubernetes.io/cluster/${ClusterName}'
                 Value: 'owned'
+              - Key: Namespace
+                Value: swat
+              - Key: Stage
+                Value: stage
+              - Key: !Sub 'k8s.io/cluster-autoscaler/${ClusterAutoscalerStatus}'
+                Value: 'true'
         UserData:
           Fn::Base64:
             !Sub |
@@ -427,3 +451,9 @@ Resources:
                 - !Split [ ",", !Ref ExistingNodeSecurityGroups ]
         ImageId: !Ref NodeImageId
         InstanceType: !Ref NodeInstanceType
+
+Outputs:
+
+  NodeGroup:
+    Description: The node instance group
+    Value: !Ref NodeGroup
cfn-template.tf
# workers cfn stack templates
locals {
  templates_bucket = "${module.cluster_label.id}-templates"

  mixed_instances_template = "amazon-eks-nodegroup-with-mixed-instances.yml"
}

resource "aws_s3_bucket" "templates" {
  acl           = "private"
  region        = "${var.aws_region}"
  bucket        = "${local.templates_bucket}"
  tags          = "${module.cluster_label.tags}"
  force_destroy = "true"
}

resource "aws_s3_bucket_object" "mixed_instances_template" {
  bucket  = "${aws_s3_bucket.templates.id}"
  key     = "${local.mixed_instances_template}"
  source = "templates/${local.mixed_instances_template}"
  etag    = "${filemd5("templates/${local.mixed_instances_template}")}"
}
cfn-tf-changes.diff
diff --git a/compute-workers-cfn-1.tf b/compute-workers-cfn-2.tf
index 4cc4ad2..ed45e07 100644
--- a/compute-workers-cfn-1.tf
+++ b/compute-workers-cfn-2.tf
@@ -17,6 +17,7 @@ resource "aws_cloudformation_stack" "workers" {
     NodeAutoScalingGroupMinSize         = "1"
     NodeAutoScalingGroupDesiredSize     = "3"
     NodeAutoScalingGroupMaxSize         = "9"
+    ClusterAutoscalerStatus             = "enabled"
     NodeInstanceType                    = "c5.2xlarge"
     ASGAutoAssignPublicIp               = "no"
     OnDemandBaseCapacity                = "1"
@@ -28,7 +29,7 @@ resource "aws_cloudformation_stack" "workers" {
     BootstrapArgumentsForOnDemand       = "--kubelet-extra-args '--node-labels=lifecycle=OnDemand,node-role.kubernetes.io/worker=true'"
   }
 
-  template_url = "https://s3.amazonaws.com/eksworkshop.com/templates/master/amazon-eks-nodegroup-with-mixed-instances.yml"
+  template_url = "https://${aws_s3_bucket.templates.bucket_regional_domain_name}/${local.mixed_instances_template}"
 
   lifecycle {
     ignore_changes = [
compute-workers-cfn-1.tf
# cluster name bohr
resource "aws_cloudformation_stack" "workers" {
  name = "${module.cluster_label.id}-compute-workers"

  parameters = {
    NodeGroupName = "${module.cluster_label.id}-compute-workers" # Unique identifier for the Node Group.
    
    ClusterName                         = "${module.cluster_label.id}"
    ClusterControlPlaneSecurityGroup    = "${aws_security_group.masters.id}"
    NodeImageId                         = "${data.aws_ami.worker.id}"
    NodeInstanceProfile                 = "${aws_iam_instance_profile.workers.arn}"
    UseExistingNodeSecurityGroups       = "yes"
    ExistingNodeSecurityGroups          = "${aws_security_group.workers.id}"
    VpcId                               = "${data.terraform_remote_state.shared.swat_staging_vpc_id}"
    KeyName                             = "${data.terraform_remote_state.staging.ec2_key_name}"
    Subnets                             = "${join(",",values(data.terraform_remote_state.staging.private_subnets_bohr))}"
    NodeAutoScalingGroupMinSize         = "1"
    NodeAutoScalingGroupDesiredSize     = "3"
    NodeAutoScalingGroupMaxSize         = "9"
    NodeInstanceType                    = "c5.2xlarge"
    ASGAutoAssignPublicIp               = "no"
    OnDemandBaseCapacity                = "1"
    OnDemandPercentageAboveBaseCapacity = "0" # (0-100)
    SpotInstancePools                   = "3" # (1-20)
    InstanceTypesOverride               = "c5.2xlarge,m5.2xlarge,c4.2xlarge"  # multiple spot instances to override (seperated by comma)

    BootstrapArgumentsForSpotFleet      = "--kubelet-extra-args '--node-labels=lifecycle=Ec2Spot,node-role.kubernetes.io/spot-worker=true --register-with-taints=spotInstance=true:PreferNoSchedule'"
    BootstrapArgumentsForOnDemand       = "--kubelet-extra-args '--node-labels=lifecycle=OnDemand,node-role.kubernetes.io/worker=true'"
  }

  template_url = "https://s3.amazonaws.com/eksworkshop.com/templates/master/amazon-eks-nodegroup-with-mixed-instances.yml"

  lifecycle {
    ignore_changes = [
      "parameters.NodeAutoScalingGroupDesiredSize",
    ]
  }
}
compute-workers-cfn-2.tf
# cluster name bohr
resource "aws_cloudformation_stack" "workers" {
  name = "${module.cluster_label.id}-compute-workers"

  parameters = {
    NodeGroupName = "${module.cluster_label.id}-compute-workers" # Unique identifier for the Node Group.
    
    ClusterName                         = "${module.cluster_label.id}"
    ClusterControlPlaneSecurityGroup    = "${aws_security_group.masters.id}"
    NodeImageId                         = "${data.aws_ami.worker.id}"
    NodeInstanceProfile                 = "${aws_iam_instance_profile.workers.arn}"
    UseExistingNodeSecurityGroups       = "yes"
    ExistingNodeSecurityGroups          = "${aws_security_group.workers.id}"
    VpcId                               = "${data.terraform_remote_state.shared.swat_staging_vpc_id}"
    KeyName                             = "${data.terraform_remote_state.staging.ec2_key_name}"
    Subnets                             = "${join(",",values(data.terraform_remote_state.staging.private_subnets_bohr))}"
    NodeAutoScalingGroupMinSize         = "1"
    NodeAutoScalingGroupDesiredSize     = "3"
    NodeAutoScalingGroupMaxSize         = "9"
    ClusterAutoscalerStatus             = "enabled"
    NodeInstanceType                    = "c5.2xlarge"
    ASGAutoAssignPublicIp               = "no"
    OnDemandBaseCapacity                = "1"
    OnDemandPercentageAboveBaseCapacity = "0" # (0-100)
    SpotInstancePools                   = "3" # (1-20)
    InstanceTypesOverride               = "c5.2xlarge,m5.2xlarge,c4.2xlarge"  # multiple spot instances to override (seperated by comma)

    BootstrapArgumentsForSpotFleet      = "--kubelet-extra-args '--node-labels=lifecycle=Ec2Spot,node-role.kubernetes.io/spot-worker=true --register-with-taints=spotInstance=true:PreferNoSchedule'"
    BootstrapArgumentsForOnDemand       = "--kubelet-extra-args '--node-labels=lifecycle=OnDemand,node-role.kubernetes.io/worker=true'"
  }

  template_url = "https://${aws_s3_bucket.templates.bucket_regional_domain_name}/${local.mixed_instances_template}"

  lifecycle {
    ignore_changes = [
      "parameters.NodeAutoScalingGroupDesiredSize",
    ]
  }
}
compute-workers-tf-1-asg.tf

resource "aws_autoscaling_group" "compute_workers" {
  name                = "${module.cluster_label.id}-compute-workers"
  vpc_zone_identifier = ["${values(data.terraform_remote_state.staging.private_subnets_bohr)}"]
  min_size            = 1
  desired_capacity    = 3
  max_size            = 18

  mixed_instances_policy {
    instances_distribution {
      on_demand_allocation_strategy            = "prioritized"  # Valid values: prioritized. Default: prioritized
      spot_allocation_strategy                 = "lowest-price" # Valid values: lowest-price. Default: lowest-price.
      on_demand_base_capacity                  = 1
      on_demand_percentage_above_base_capacity = 0 # this means everything else will be 100% spot and 0% onDemand (we have fixed capacity of 1 onDemand)

      # EC2 Auto Scaling selects the cheapest Spot pools and evenly allocates Spot capacity across the number of Spot pools that you specify.
      spot_instance_pools = 2 # Default: 2
    }

    launch_template {
      launch_template_specification {
        launch_template_id = "${aws_launch_template.compute_workers.id}"
        version            = "$$Latest"
      }

      override {
        instance_type = "c5.2xlarge"
      }

      override {
        instance_type = "m5a.2xlarge"
      }

      override {
        instance_type = "c5d.2xlarge"
      }
    }
  }

  tags = [
    {
      key                 = "Namespace"
      value               = "${var.namespace}"
      propagate_at_launch = true
    },
    {
      key                 = "Stage"
      value               = "${var.stage}"
      propagate_at_launch = true
    },
    {
      key                 = "Name"
      value               = "${module.cluster_label.id}-compute-workers-ASG-Node"
      propagate_at_launch = true
    },
    {
      key                 = "kubernetes.io/cluster/${module.cluster_label.id}"
      value               = "owned"
      propagate_at_launch = true
    },
    {
      key                 = "k8s.io/cluster-autoscaler/enabled"
      value               = "true"
      propagate_at_launch = true
    },
  ]

  # Allowed values are Launch, Terminate, HealthCheck, ReplaceUnhealthy, 
  # AZRebalance, AlarmNotification, ScheduledActions, AddToLoadBalancer.
  suspended_processes = [
    "AZRebalance",
  ]

  depends_on = ["aws_eks_cluster.main", "aws_iam_role_policy_attachment.workers_EKSWorkerNodePolicy", "aws_iam_role_policy_attachment.workers_EKS_CNI_Policy"]

  lifecycle {
    ignore_changes = ["desired_capacity"]
  }
}

resource "aws_autoscaling_lifecycle_hook" "compute_workers" {
  name                   = "${module.cluster_label.id}-compute-workers-nodedrainerLCH"
  autoscaling_group_name = "${aws_autoscaling_group.compute_workers.name}"
  default_result         = "CONTINUE"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
}
compute-workers-tf-1-launch-template.tf
resource "aws_launch_template" "compute_workers" {
  name          = "${module.cluster_label.id}-compute-workers"
  image_id      = "${data.aws_ami.worker.id}"
  instance_type = "c5.2xlarge"

  credit_specification {
    # T3 instances are launched as unlimited by default. T2 instances are launched as standard by default.
    cpu_credits = "standard" # Can be "standard" or "unlimited"
  }

  network_interfaces {
    security_groups             = ["${aws_security_group.workers.id}"]
    device_index                = 0
    associate_public_ip_address = false
  }

  iam_instance_profile {
    name = "${aws_iam_instance_profile.workers.name}"
  }

  tag_specifications {
    resource_type = "instance"

    tags = "${merge(module.cluster_label.tags,map(
      "Name","${module.cluster_label.id}-compute-worker-ASG-Node",
      "KubernetesCluster","${module.cluster_label.id}",
      "kubernetes.io/cluster/${module.cluster_label.id}","owned"
    ))}"
  }

  user_data = "${base64encode(data.template_file.compute_workers_user_data.rendered)}"
  key_name  = "${ data.terraform_remote_state.staging.ec2_key_name }"

  tags = "${module.cluster_label.tags}"
}
compute-workers-tf-1-user-data.tf
data "template_file" "compute_workers_user_data" {
  template = "${file("./templates/workers_user_data.tpl.sh")}"

  vars {
    aws_region   = "${var.aws_region}"
    cluster_name = "${module.cluster_label.id}"

    node_labels      = "lifecycle=OnDemand,node-role.kubernetes.io/worker=true"
    node_taints      = ""
    spot_node_labels = "lifecycle=Ec2Spot,node-role.kubernetes.io/spot-worker=true"
    spot_node_taints = "spotInstance=true:PreferNoSchedule"
    eviction_hard    = "memory.available<750Mi,nodefs.available<10%,nodefs.inodesFree<5%,imagefs.available<10%,imagefs.inodesFree<5%"
    kube_reserved    = "cpu=250m,memory=1Gi,ephemeral-storage=1Gi"
    system_reserved  = "cpu=250m,memory=0.2Gi,ephemeral-storage=1Gi"
  }
}
compute-workers-tf-2-data-structure.yaml
common:
  key_name: data.terraform_remote_state.staging.ec2_key_name
  subnets: data.terraform_remote_state.staging.private_subnets_bohr

workers:
  compute:
    instanceTypes:
      - c5.2xlarge
      - m5a.2xlarge
      - c5d.2xlarge
    autoscaling: true
    asg:
      minSize: 1
      desiredCapacity: 3
      maxSize: 18
      onDemandBaseCapacity: 1
      onDemandPercentageAboveBaseCapacity: 0
      spotInstancePools: 2
    taints: []
    labels:
      onDemand:
        - node-role.kubernetes.io/worker=true
      spot:
        - node-role.kubernetes.io/spot-worker=true
    evictionHard: "memory.available<750Mi,nodefs.available<10%,nodefs.inodesFree<5%,imagefs.available<10%,imagefs.inodesFree<5%"
    kubeReserved: "cpu=250m,memory=1Gi,ephemeral-storage=1Gi"
    systemReserved: "cpu=250m,memory=0.2Gi,ephemeral-storage=1Gi"
    securityGroups:
      - ${aws_security_group.workers.id}
    iamInstanceProfile: workers
    tfDependencies:
      - aws_eks_cluster.main
      - aws_iam_role_policy_attachment.workers_EKSWorkerNodePolicy
      - aws_iam_role_policy_attachment.workers_EKS_CNI_Policy
  edge:
    instanceTypes:
      - t3.small
      - t2.small
      - t3.medium
    autoscaling: true
    asg:
      minSize: 2
      desiredCapacity: 2
      maxSize: 3
      onDemandBaseCapacity: 1
      onDemandPercentageAboveBaseCapacity: 0
      spotInstancePools: 2
    taints:
      - edge=true:NoSchedule
    labels:
      onDemand:
        - node-role.kubernetes.io/edge=true
      spot:
        - node-role.kubernetes.io/spot-edge=true
    evictionHard: "memory.available<100Mi,nodefs.available<10%,nodefs.inodesFree<5%,imagefs.available<10%,imagefs.inodesFree<5%"
    kubeReserved: "cpu=250m,memory=150Mi,ephemeral-storage=1Gi"
    systemReserved: "cpu=250m,memory=150Mi,ephemeral-storage=1Gi"
    securityGroups:
      - ${aws_security_group.edge.id} # DMZ security groups
    iamInstanceProfile: workers
    tfDependencies:
      - aws_eks_cluster.main
      - aws_iam_role_policy_attachment.workers_EKSWorkerNodePolicy
      - aws_iam_role_policy_attachment.workers_EKS_CNI_Policy
compute-workers-tf-2-gotemplate.tf
{{$asg_config := yaml "../workers.yaml" -}}

# DO NOT EDIT THIS FILE DIRECTLY
## EDIT ./workers.yaml 
## RUN make workers.tf 

{{ range $workers_type, $workers_config := $asg_config.workers}}
data "template_file" "{{ $workers_type }}_workers_user_data" {
  template = "${file("./templates/workers_user_data.tpl.sh")}"

  vars {
    aws_region   = "${var.aws_region}"
    cluster_name = "${module.cluster_label.id}"

    node_labels      = "lifecycle=OnDemand,{{ join "," $workers_config.labels.onDemand }}"
    node_taints      = "{{ join "," $workers_config.taints}}"
    spot_node_labels = "lifecycle=Ec2Spot,{{ join "," $workers_config.labels.spot }}"
    {{- set $ "spot_node_taints" (prepend $workers_config.taints "spotInstance=true:PreferNoSchedule") }}
    spot_node_taints = "{{ join "," $.spot_node_taints }}"

    {{- with $workers_config.evictionHard }}
    eviction_hard = "{{ . }}"
    {{- end }}
    
    {{- with $workers_config.kubeReserved }}
    kube_reserved = "{{ . }}"
    {{- end }}
    
    {{- with $workers_config.systemReserved }}
    system_reserved = "{{ . }}"
    {{- end }}
  }
}

resource "aws_launch_template" "{{ $workers_type }}_workers" {
  name                   = "${module.cluster_label.id}-{{ $workers_type }}-workers"
  image_id               = "${data.aws_ami.worker.id}"
  instance_type          = "{{ index $workers_config.instanceTypes 0 }}"

  credit_specification {
    # T3 instances are launched as unlimited by default. T2 instances are launched as standard by default.
    cpu_credits = "standard"  # Can be "standard" or "unlimited"
  }

  network_interfaces {
    security_groups = {{ toHcl $workers_config.securityGroups }}
    device_index = 0
    associate_public_ip_address = false
  }

  iam_instance_profile   {
    name = "${aws_iam_instance_profile.{{$workers_config.iamInstanceProfile}}.name}"
  }

  tag_specifications {
    resource_type = "instance"
    tags = "${merge(module.cluster_label.tags,map(
      "Name","${module.cluster_label.id}-{{ $workers_type }}-worker-ASG-Node",
      "KubernetesCluster","${module.cluster_label.id}",
      "kubernetes.io/cluster/${module.cluster_label.id}","owned"
    ))}"
  }

  user_data              = "${base64encode(data.template_file.{{ $workers_type }}_workers_user_data.rendered)}"
  key_name               = "${ {{ $asg_config.common.key_name }} }"

  tags = "${module.cluster_label.tags}"
}

resource "aws_autoscaling_group" "{{ $workers_type }}_workers" {
  name                = "${module.cluster_label.id}-{{ $workers_type }}-workers"
  vpc_zone_identifier = ["${values({{ $asg_config.common.subnets }})}"]
  min_size            = {{ $workers_config.asg.minSize }}
  desired_capacity    = {{ $workers_config.asg.desiredCapacity }}
  max_size            = {{ $workers_config.asg.maxSize }}

  mixed_instances_policy {
    instances_distribution {
      on_demand_allocation_strategy            = "prioritized" # Valid values: prioritized. Default: prioritized
      spot_allocation_strategy                 = "lowest-price" # Valid values: lowest-price. Default: lowest-price.
      on_demand_base_capacity                  = {{ $workers_config.asg.onDemandBaseCapacity }}
      on_demand_percentage_above_base_capacity = {{ $workers_config.asg.onDemandPercentageAboveBaseCapacity }}
      # EC2 Auto Scaling selects the cheapest Spot pools and evenly allocates Spot capacity across the number of Spot pools that you specify.
      spot_instance_pools                      = {{ $workers_config.asg.spotInstancePools }} # Default: 2
    }

    launch_template {
      launch_template_specification {
        launch_template_id = "${aws_launch_template.{{ $workers_type }}_workers.id}"
        version            = "$$Latest"
      }
      {{- range $instanceType := $workers_config.instanceTypes }}
      override {
        instance_type = "{{ $instanceType }}"
      }
      {{- end}}
    }
  }

  tags = [
    {
      key                         = "Namespace"
      value                       = "${var.namespace}"
      propagate_at_launch         = true
    },
    {
      key                         = "Stage"
      value                       = "${var.stage}"
      propagate_at_launch         = true
    },
    {
      key                        = "Name"
      value                      = "${module.cluster_label.id}-{{ $workers_type }}-workers-ASG-Node"
      propagate_at_launch        = true
    },
    {
      key                        = "kubernetes.io/cluster/${module.cluster_label.id}"
      value                      = "owned"
      propagate_at_launch        = true
    },
    {{- if $workers_config.autoscaling }}
    {
      key                        = "k8s.io/cluster-autoscaler/enabled"
      value                      = "true"
      propagate_at_launch        = true
    },
    {{- end }}
  ]

  # Allowed values are Launch, Terminate, HealthCheck, ReplaceUnhealthy, 
  # AZRebalance, AlarmNotification, ScheduledActions, AddToLoadBalancer.
  suspended_processes = [
    "AZRebalance",
  ]

  depends_on = {{ toHcl $workers_config.tfDependencies }}

  {{- if $workers_config.autoscaling }}
  lifecycle {
    ignore_changes = [ "desired_capacity" ]
  }
  {{- end}}
}

resource "aws_autoscaling_lifecycle_hook" "{{ $workers_type }}_workers" {
  name                   = "${module.cluster_label.id}-{{ $workers_type }}-workers-nodedrainerLCH"
  autoscaling_group_name = "${aws_autoscaling_group.{{ $workers_type }}_workers.name}"
  default_result         = "CONTINUE"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
}
{{- end }}
compute-workers-tf-3-gotemplate.tf
{{$asg_config := yaml "../workers.yaml" -}}

# DO NOT EDIT THIS FILE DIRECTLY
## EDIT ./workers.yaml 
## RUN make workers.tf 

{{ range $workers_type, $workers_config := $asg_config.workers}}
data "template_file" "{{ $workers_type }}_workers_user_data" {
  template = "${file("./templates/workers_user_data.tpl.sh")}"

  vars {
    aws_region   = "${var.aws_region}"
    cluster_name = "${module.cluster_label.id}"

    node_labels      = "lifecycle=OnDemand,{{ join "," $workers_config.labels.onDemand }}"
    node_taints      = "{{ join "," $workers_config.taints}}"
    spot_node_labels = "lifecycle=Ec2Spot,{{ join "," $workers_config.labels.spot }}"
    {{- set $ "spot_node_taints" (prepend $workers_config.taints "spotInstance=true:PreferNoSchedule") }}
    spot_node_taints = "{{ join "," $.spot_node_taints }}"

    {{- with $workers_config.evictionHard }}
    eviction_hard = "{{ . }}"
    {{- end }}
    
    {{- with $workers_config.kubeReserved }}
    kube_reserved = "{{ . }}"
    {{- end }}
    
    {{- with $workers_config.systemReserved }}
    system_reserved = "{{ . }}"
    {{- end }}
  }
}

resource "aws_launch_template" "{{ $workers_type }}_workers" {
  name                   = "${module.cluster_label.id}-{{ $workers_type }}-workers"
  image_id               = "${data.aws_ami.worker.id}"
  instance_type          = "{{ index $workers_config.instanceTypes 0 }}"

  credit_specification {
    # T3 instances are launched as unlimited by default. T2 instances are launched as standard by default.
    cpu_credits = "standard"  # Can be "standard" or "unlimited"
  }

  network_interfaces {
    security_groups = {{ toHcl $workers_config.securityGroups }}
    device_index = 0
    associate_public_ip_address = false
  }

  iam_instance_profile   {
    name = "${aws_iam_instance_profile.{{$workers_config.iamInstanceProfile}}.name}"
  }

  tag_specifications {
    resource_type = "instance"
    tags = "${merge(module.cluster_label.tags,map(
      "Name","${module.cluster_label.id}-{{ $workers_type }}-worker-ASG-Node",
      "KubernetesCluster","${module.cluster_label.id}",
      "kubernetes.io/cluster/${module.cluster_label.id}","owned"
    ))}"
  }

  user_data              = "${base64encode(data.template_file.{{ $workers_type }}_workers_user_data.rendered)}"
  key_name               = "${ {{ $asg_config.common.key_name }} }"

  tags = "${module.cluster_label.tags}"
}

resource "aws_autoscaling_group" "{{ $workers_type }}_workers" {
  name                = "${module.cluster_label.id}-{{ $workers_type }}-workers"
  vpc_zone_identifier = ["${values({{ $asg_config.common.subnets }})}"]
  min_size            = {{ $workers_config.asg.minSize }}
  desired_capacity    = {{ $workers_config.asg.desiredCapacity }}
  max_size            = {{ $workers_config.asg.maxSize }}

  mixed_instances_policy {
    instances_distribution {
      on_demand_allocation_strategy            = "prioritized" # Valid values: prioritized. Default: prioritized
      spot_allocation_strategy                 = "lowest-price" # Valid values: lowest-price. Default: lowest-price.
      on_demand_base_capacity                  = {{ $workers_config.asg.onDemandBaseCapacity }}
      on_demand_percentage_above_base_capacity = {{ $workers_config.asg.onDemandPercentageAboveBaseCapacity }}
      # EC2 Auto Scaling selects the cheapest Spot pools and evenly allocates Spot capacity across the number of Spot pools that you specify.
      spot_instance_pools                      = {{ $workers_config.asg.spotInstancePools }} # Default: 2
    }

    launch_template {
      launch_template_specification {
        launch_template_id = "${aws_launch_template.{{ $workers_type }}_workers.id}"
        version            = "$$Latest"
      }
      {{- range $instanceType := $workers_config.instanceTypes }}
      override {
        instance_type = "{{ $instanceType }}"
      }
      {{- end}}
    }
  }

  tags = [
    {
      key                         = "Namespace"
      value                       = "${var.namespace}"
      propagate_at_launch         = true
    },
    {
      key                         = "Stage"
      value                       = "${var.stage}"
      propagate_at_launch         = true
    },
    {
      key                        = "Name"
      value                      = "${module.cluster_label.id}-{{ $workers_type }}-workers-ASG-Node"
      propagate_at_launch        = true
    },
    {
      key                        = "kubernetes.io/cluster/${module.cluster_label.id}"
      value                      = "owned"
      propagate_at_launch        = true
    },
    {{- if $workers_config.autoscaling }}
    {
      key                        = "k8s.io/cluster-autoscaler/enabled"
      value                      = "true"
      propagate_at_launch        = true
    },
    {{- end }}
  ]

  # Allowed values are Launch, Terminate, HealthCheck, ReplaceUnhealthy, 
  # AZRebalance, AlarmNotification, ScheduledActions, AddToLoadBalancer.
  suspended_processes = [
    "AZRebalance",
  ]

  depends_on = {{ toHcl $workers_config.tfDependencies }}

  {{- if $workers_config.autoscaling }}
  lifecycle {
    ignore_changes = [ "desired_capacity" ]
  }
  {{- end}}
}

resource "aws_autoscaling_lifecycle_hook" "{{ $workers_type }}_workers" {
  name                   = "${module.cluster_label.id}-{{ $workers_type }}-workers-nodedrainerLCH"
  autoscaling_group_name = "${aws_autoscaling_group.{{ $workers_type }}_workers.name}"
  default_result         = "CONTINUE"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"

  notification_target_arn = "${aws_sqs_queue.instance_termination.arn}"
  role_arn                = "${aws_iam_role.autoscaling_instance_termination_notifications.arn}"
}
{{- end }}
compute-workers-tf-gotemplate-1.diff
diff --git a/compute-workers-tf-2-gotemplate.tf b/compute-workers-tf-3-gotemplate.tf
index d6fd8f3..85773b0 100644
--- a/compute-workers-tf-2-gotemplate.tf
+++ b/compute-workers-tf-3-gotemplate.tf
@@ -148,5 +148,8 @@ resource "aws_autoscaling_lifecycle_hook" "{{ $workers_type }}_workers" {
   default_result         = "CONTINUE"
   heartbeat_timeout      = 300
   lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
+
+  notification_target_arn = "${aws_sqs_queue.instance_termination.arn}"
+  role_arn                = "${aws_iam_role.autoscaling_instance_termination_notifications.arn}"
 }
 {{- end }}
eks-iam-role-1.tf
resource "aws_iam_policy" "eks_full_access" {
  name        = "${module.eks_full_access_label.id}-policy"
  description = "Provides full access to Amazon EKS"

  policy = "${data.aws_iam_policy_document.eks_full_access.json}"
}

#Ref https://docs.aws.amazon.com/eks/latest/userguide/security_iam_id-based-policy-examples.html#security_iam_id-based-policy-examples-console
data "aws_iam_policy_document" "eks_full_access" {
  statement {
    sid       = "EKSFullAccess"
    effect    = "Allow"
    actions   = [
      "eks:*",
    ]
    resources = ["*"]
  }
  
  statement {
    sid       = "EKSPassrole"
    effect    = "Allow"
    actions   = [
      "iam:GetRole",
      "iam:PassRole",
    ]
    resources = ["*"]
  }
}
eks-iam-role-2.tf
data "aws_iam_policy_document" "current_account_trust" {
  statement = {
    principals = {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
    }

    actions = [
      "sts:AssumeRole",
    ]
  }
}

resource "aws_iam_role" "eks_full_access" {
  name               = "${module.eks_full_access_label.id}"
  assume_role_policy = "${data.aws_iam_policy_document.current_account_trust.json}"
}

resource "aws_iam_role_policy_attachment" "eks_full_access" {
  policy_arn = "${aws_iam_policy.eks_full_access.arn}"
  role       = "${aws_iam_role.eks_full_access.name}"
}

## expose role ARN to remote state
terraform {
  backend "s3" {
    # A project specific key
    key = "tf-shared/tfstate"
    ## ...
    ## Ref: https://www.terraform.io/docs/backends/config.html
  }
}

output "swat_eks_role_arn" {
  value = "${aws_iam_role.eks_full_access.arn}"
}
eks-iam-role-3.tf
resource "aws_iam_group" "eks_full_access" {
  name = "${module.eks_full_access_label.id}"
  path = "/"
}

resource "aws_iam_group_policy_attachment" "assume_eks_full_access" {
  group      = "${aws_iam_group.eks_full_access.name}"
  policy_arn = "${aws_iam_policy.assume_eks_full_access.arn}"
}

resource "aws_iam_policy" "assume_eks_full_access" {
  name        = "${aws_iam_group.eks_full_access.name}-assume-policy"
  description = "User policy to assume eks full access role"
  policy      = "${data.aws_iam_policy_document.assume_eks_full_access_role.json}"
}

# allow eks_full_access to assume the cluster role
data "aws_iam_policy_document" "assume_eks_full_access_role" {
  statement = {
    actions = [
      "sts:AssumeRole",
    ]

    resources = [
      "${aws_iam_role.eks_full_access.arn}",
    ]
  }
}
eks-iam-role-4.tf

provider "aws" {
  region  = "${var.aws_region}"
  version = "~> 2"
}

data "terraform_remote_state" "shared" {
  backend = "s3"
  config {
    key    = "tf-shared/tfstate"
    # bucket = "..."
  }
}

## EKS cluster created with eks role
module "cluster_label" {
  source    = "git::ssh://git@bitbucket.org/swatrider/tf-modules.git?ref=master//naming"
  namespace = "${var.namespace}"
  stage     = "${var.stage}"
  name      = "${var.cluster_name}"
}

provider "aws" {
  alias    = "eks"
  region   = "${var.aws_region}"
  assume_role {
    role_arn = "${data.terraform_remote_state.shared.swat_eks_role_arn}"
  }  
}

resource "aws_eks_cluster" "main" {
  provider        = "aws.eks" # assumes the EKS full access role
  name            = "${module.cluster_label.id}"
  role_arn        = "${aws_iam_role.masters.arn}"

  vpc_config {
    security_group_ids = ["${aws_security_group.masters.id}"]
    subnet_ids         = [
      "${values(data.terraform_remote_state.production.private_subnets_newton)}",
    ]
    # WARNING: Private EKS APIs across peered VPCs require DNS Resolvers!
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  depends_on = [
    "aws_iam_role_policy_attachment.masters_EKSCluster_policy",
    "aws_iam_role_policy_attachment.masters_EKSService_policy",
  ]
}

data "aws_ami" "worker" {
  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.eks_version}-v*"]
  }

  most_recent = true
  owners      = ["amazon"]
}
lch-sqs-1.tf
resource "aws_sqs_queue" "instance_termination" {
  name                      = "${module.cluster_label.id}-instance-termination"
  max_message_size          = 2048  # 2 kb  (default is 256KiB)
  message_retention_seconds = 86400 # 1 day (default is 4 days)
  receive_wait_time_seconds = 10    # long polling, default is 0 - instant return
  # # docs: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
  # redrive_policy            = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.terraform_queue_deadletter.arn}\",\"maxReceiveCount\":4}"

  tags = "${module.cluster_label.tags}"
}

resource "aws_iam_role" "autoscaling_instance_termination_notifications" {
  name = "${module.cluster_label.id}-instance-termination-notifications"

  assume_role_policy = "${data.aws_iam_policy_document.assume_autoscaling_role.json}"

  tags = "${module.cluster_label.tags}"
}

data "aws_iam_policy_document" "assume_autoscaling_role" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["autoscaling.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "autoscaling_instance_termination_notifications" {
  name        = "${module.cluster_label.id}-instance-termination-notifications"
  role        = "${aws_iam_role.autoscaling_instance_termination_notifications.id}"

  policy = "${data.aws_iam_policy_document.instance_termination_notifications.json}"
}

data "aws_iam_policy_document" "instance_termination_notifications" {
  statement {
    sid = "AllowWriteToNotificationsQueue"

    effect = "Allow"

    actions = [
      "sqs:SendMessage",
      "sqs:GetQueueUrl",
      "sns:Publish",
    ]

    resources = ["${aws_sqs_queue.instance_termination.arn}"]
  }
}
lch-sqs-2.tf
data "aws_iam_policy_document" "system_workers" {
  statement {
    sid       = "ClusterAutoScalerAll"
    effect    = "Allow"
    actions   = [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeTags", # for dynamic discovery, this verifies the cluster-name in the ASG Tags...
      ]
    # ref https://docs.aws.amazon.com/autoscaling/ec2/userguide/control-access-using-iam.html#policy-auto-scaling-resources
    resources = [
      "*",
    ]
  }
  statement {
    sid       = "ClusterAutoScalerSpecific"
    effect    = "Allow"
    actions   = [
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup",
      ]
    # ref https://docs.aws.amazon.com/autoscaling/ec2/userguide/control-access-using-iam.html#policy-auto-scaling-resources
    resources = [
      "${aws_autoscaling_group.edge_workers.arn}",
      "${aws_autoscaling_group.compute_workers.arn}",
    ]
  }
  # handle instance_termination_notifications
  statement {
    sid = "AllowReadInstanceTerminationNotificationsQueue"
    effect = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = ["${aws_sqs_queue.instance_termination.arn}"]
  }
  # required by rebuy/node-drainer
  statement {
    sid = "AllowEc2Describe"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
    ]
    resources = ["*"]
  }
  statement {
    sid = "AllowAsgLifeCycle"
    effect = "Allow"
    actions = [
      "autoscaling:CompleteLifecycleAction",
      "autoscaling:RecordLifecycleActionHeartbeat",
    ]
    resources = ["*"]
  }
}
user-data.tpl.sh
#!/bin/bash
set -o xtrace
iid=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
export AWS_DEFAULT_REGION=${aws_region}
ilc=`aws ec2 describe-instances --instance-ids  $${iid}  --query 'Reservations[0].Instances[0].InstanceLifecycle' --output text`
if [ "$${ilc}" == "spot" ]; then
  /etc/eks/bootstrap.sh ${cluster_name} --kubelet-extra-args '--node-labels=${spot_node_labels} --register-with-taints=${spot_node_taints}%{ if eviction_hard != "" } --eviction-hard ${eviction_hard}%{ endif }%{ if kube_reserved != "" } --kube-reserved ${kube_reserved}%{ endif }%{ if system_reserved != "" } --system-reserved ${system_reserved}%{ endif }'
else
  /etc/eks/bootstrap.sh ${cluster_name} --kubelet-extra-args '--node-labels=${node_labels}%{ if node_taints != "" } --register-with-taints=${node_taints}%{ endif }%{ if eviction_hard != "" } --eviction-hard ${eviction_hard}%{ endif }%{ if kube_reserved != "" } --kube-reserved ${kube_reserved}%{ endif }%{ if system_reserved != "" } --system-reserved ${system_reserved}%{ endif }'
fi
