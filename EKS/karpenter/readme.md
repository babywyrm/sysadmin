
##
#
Setup Karpenter On your Existing EKS Cluster.

##
#
https://medium.com/@shadracktanui47/setup-karpenter-on-your-existing-eks-cluster-98bf6e959863
#
##



This is a guide to setting up Karpenter for just-in-time node provisioning. Karpenter is an open-source node provisioning project built for Kubernetes. Adding Karpenter to a Kubernetes cluster can dramatically improve the efficiency and cost of running workloads on that cluster.

The following steps show you how to deploy Karpenter in an Amazon EKS cluster.

Resolution
Prerequisites
Before you begin, complete the following:

Install Helm client, 3.11.0 or above. See Helm Docs for more information on the installation procedures.
Install eksctl.
Install AWS CLI.
We will make the following assumptions in this guide:

You will use an existing EKS cluster
You will use existing VPC and subnets
You will use existing security groups
Your nodes are part of one or more node groups
Your workloads have pod disruption budgets that adhere to EKS best practices
Your cluster has an OIDC Provider for service accounts.
Set a variable for your cluster name.

CLUSTER_NAME=<your cluster name>
Set other variables from your cluster configuration.
```
AWS_PARTITION="aws" # if you are not using standard partitions, you may need to configure to aws-cn / aws-us-gov
AWS_REGION="$(aws configure list | grep region | tr -s " " | cut -d" " -f3)"
OIDC_ENDPOINT="$(aws eks describe-cluster --name ${CLUSTER_NAME} \
    --query "cluster.identity.oidc.issuer" --output text)"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' \
    --output text)
Use that information to create our IAM roles, inline policy, and trust relationship.

Create IAM roles
To get started with our setup we first need to create two new IAM roles for nodes provisioned with Karpenter and the Karpenter controller.

To create the Karpenter node role we will use the following policy and commands.

echo '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}' > node-trust-policy.json

aws iam create-role --role-name "KarpenterNodeRole-${CLUSTER_NAME}" \
    --assume-role-policy-document file://node-trust-policy.json
Now attach the required policies to the role

aws iam attach-role-policy --role-name "KarpenterNodeRole-${CLUSTER_NAME}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonEKSWorkerNodePolicy

aws iam attach-role-policy --role-name "KarpenterNodeRole-${CLUSTER_NAME}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonEKS_CNI_Policy

aws iam attach-role-policy --role-name "KarpenterNodeRole-${CLUSTER_NAME}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly

aws iam attach-role-policy --role-name "KarpenterNodeRole-${CLUSTER_NAME}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonSSMManagedInstanceCore
Attach the IAM role to an EC2 instance profile.

aws iam create-instance-profile \
— instance-profile-name “KarpenterNodeInstanceProfile-${CLUSTER_NAME}”

aws iam add-role-to-instance-profile \
— instance-profile-name “KarpenterNodeInstanceProfile-${CLUSTER_NAME}” \
— role-name “KarpenterNodeRole-${CLUSTER_NAME}”
```
Now we need to create an IAM role that the Karpenter controller will use to provision new instances. The controller will be using IAM Roles for Service Accounts (IRSA) which requires an OIDC endpoint.
```
cat << EOF > controller-trust-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:${AWS_PARTITION}:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_ENDPOINT#*//}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${OIDC_ENDPOINT#*//}:aud": "sts.amazonaws.com",
                    "${OIDC_ENDPOINT#*//}:sub": "system:serviceaccount:karpenter:karpenter"
                }
            }
        }
    ]
}
EOF

aws iam create-role --role-name KarpenterControllerRole-${CLUSTER_NAME} \
    --assume-role-policy-document file://controller-trust-policy.json

cat << EOF > controller-policy.json
{
    "Statement": [
        {
            "Action": [
                "ssm:GetParameter",
                "ec2:DescribeImages",
                "ec2:RunInstances",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeInstanceTypeOfferings",
                "ec2:DescribeAvailabilityZones",
                "ec2:DeleteLaunchTemplate",
                "ec2:CreateTags",
                "ec2:CreateLaunchTemplate",
                "ec2:CreateFleet",
                "ec2:DescribeSpotPriceHistory",
                "pricing:GetProducts"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "Karpenter"
        },
        {
            "Action": "ec2:TerminateInstances",
            "Condition": {
                "StringLike": {
                    "ec2:ResourceTag/karpenter.sh/provisioner-name": "*"
                }
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "ConditionalEC2Termination"
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:${AWS_PARTITION}:iam::${AWS_ACCOUNT_ID}:role/KarpenterNodeRole-${CLUSTER_NAME}",
            "Sid": "PassNodeIAMRole"
        },
        {
            "Effect": "Allow",
            "Action": "eks:DescribeCluster",
            "Resource": "arn:${AWS_PARTITION}:eks:${AWS_REGION}:${AWS_ACCOUNT_ID}:cluster/${CLUSTER_NAME}",
            "Sid": "EKSClusterEndpointLookup"
        }
    ],
    "Version": "2012-10-17"
}
```
EOF
```
aws iam put-role-policy --role-name KarpenterControllerRole-${CLUSTER_NAME} \
    --policy-name KarpenterControllerPolicy-${CLUSTER_NAME} \
    --policy-document file://controller-policy.json
Add tags to subnets and security groups
We need to add tags to our nodegroup subnets so Karpenter will know which subnets to use.

for NODEGROUP in $(aws eks list-nodegroups --cluster-name ${CLUSTER_NAME} \
    --query 'nodegroups' --output text); do aws ec2 create-tags \
        --tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}" \
        --resources $(aws eks describe-nodegroup --cluster-name ${CLUSTER_NAME} \
        --nodegroup-name $NODEGROUP --query 'nodegroup.subnets' --output text )
done
```

Add tags to our security groups. This command only tags the security groups for the first nodegroup in the cluster. If you have multiple nodegroups or multiple security groups you will need to decide which one Karpenter should use.
```
NODEGROUP=$(aws eks list-nodegroups --cluster-name ${CLUSTER_NAME} \
    --query 'nodegroups[0]' --output text)

LAUNCH_TEMPLATE=$(aws eks describe-nodegroup --cluster-name ${CLUSTER_NAME} \
    --nodegroup-name ${NODEGROUP} --query 'nodegroup.launchTemplate.{id:id,version:version}' \
    --output text | tr -s "\t" ",")

# If your EKS setup is configured to use only Cluster security group, then please execute -

SECURITY_GROUPS=$(aws eks describe-cluster \
    --name ${CLUSTER_NAME} --query "cluster.resourcesVpcConfig.clusterSecurityGroupId" --output text)

# If your setup uses the security groups in the Launch template of a managed node group, then :

SECURITY_GROUPS=$(aws ec2 describe-launch-template-versions \
    --launch-template-id ${LAUNCH_TEMPLATE%,*} --versions ${LAUNCH_TEMPLATE#*,} \
    --query 'LaunchTemplateVersions[0].LaunchTemplateData.[NetworkInterfaces[0].Groups||SecurityGroupIds]' \
    --output text)

aws ec2 create-tags \
    --tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}" \
    --resources ${SECURITY_GROUPS}
```

Update aws-auth ConfigMap
We need to allow nodes that are using the node IAM role we just created to join the cluster. To do that we have to modify the aws-auth ConfigMap in the cluster.

kubectl edit configmap aws-auth -n kube-system
You will need to add a section to the mapRoles that looks something like this. Replace the ${AWS_PARTITION} variable with the account partition, ${AWS_ACCOUNT_ID} variable with your account ID, and ${CLUSTER_NAME} variable with the cluster name, but do not replace the {{EC2PrivateDNSName}}.

- groups:
  - system:bootstrappers
  - system:nodes
  rolearn: arn:${AWS_PARTITION}:iam::${AWS_ACCOUNT_ID}:role/KarpenterNodeRole-${CLUSTER_NAME}
  username: system:node:{{EC2PrivateDNSName}}
The full aws-auth configmap should have two groups. One for your Karpenter node role and one for your existing node group.

Deploy Karpenter
First set the Karpenter release you want to deploy.

export KARPENTER_VERSION=v0.29.0
We can now generate a full Karpenter deployment yaml from the helm chart.

helm template karpenter oci://public.ecr.aws/karpenter/karpenter --version ${KARPENTER_VERSION} --namespace karpenter \
    --set settings.aws.defaultInstanceProfile=KarpenterNodeInstanceProfile-${CLUSTER_NAME} \
    --set settings.aws.clusterName=${CLUSTER_NAME} \
    --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:${AWS_PARTITION}:iam::${AWS_ACCOUNT_ID}:role/KarpenterControllerRole-${CLUSTER_NAME}" \
    --set controller.resources.requests.cpu=1 \
    --set controller.resources.requests.memory=1Gi \
    --set controller.resources.limits.cpu=1 \
    --set controller.resources.limits.memory=1Gi > karpenter.yaml
Modify the following lines in the karpenter.yaml file.

Set node affinity
Edit the karpenter.yaml file and find the karpenter deployment affinity rules. Modify the affinity so karpenter will run on one of the existing node group nodes.

The rules should look something like this. Modify the value to match your $NODEGROUP, one node group per line.
```
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
      - matchExpressions:
        - key: karpenter.sh/provisioner-name
          operator: DoesNotExist
      - matchExpressions:
        - key: eks.amazonaws.com/nodegroup
          operator: In
          values:
          - ${NODEGROUP}
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - topologyKey: "kubernetes.io/hostname"
```

Now that our deployment is ready we can create the karpenter namespace, create the provisioner CRD, and then deploy the rest of the karpenter resources.
```
kubectl create namespace karpenter
kubectl create -f \
    https://raw.githubusercontent.com/aws/karpenter/${KARPENTER_VERSION}/pkg/apis/crds/karpenter.sh_provisioners.yaml
kubectl create -f \
    https://raw.githubusercontent.com/aws/karpenter/${KARPENTER_VERSION}/pkg/apis/crds/karpenter.k8s.aws_awsnodetemplates.yaml
kubectl create -f \
    https://raw.githubusercontent.com/aws/karpenter/${KARPENTER_VERSION}/pkg/apis/crds/karpenter.sh_machines.yaml
kubectl apply -f karpenter.yaml
```


Create default provisioner
We need to create a default provisioner so Karpenter knows what types of nodes we want for unscheduled workloads.

```
cat <<EOF | kubectl apply -f -
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: default
spec:
  requirements:
    - key: karpenter.k8s.aws/instance-category
      operator: In
      values: [c, m, r]
    - key: karpenter.k8s.aws/instance-generation
      operator: Gt
      values: ["2"]
  providerRef:
    name: default
---
apiVersion: karpenter.k8s.aws/v1alpha1
kind: AWSNodeTemplate
metadata:
  name: default
spec:
  subnetSelector:
    karpenter.sh/discovery: "${CLUSTER_NAME}"
  securityGroupSelector:
    karpenter.sh/discovery: "${CLUSTER_NAME}"
EOF
```



Verify karpenter.

kubectl logs -f -n karpenter -c controller -l app.kubernetes.io/name=karpenter
Happy cost optimisation.

137-karpenter.sh

## 
## https://gist.github.com/vfarcic/baaf4adb25e9efaba886c17a2ad722a5
##


# Source: https://gist.github.com/baaf4adb25e9efaba886c17a2ad722a5

########################################################
# How To Auto-Scale Kubernetes Clusters With Karpenter #
# https://youtu.be/C-2v7HT-uSA                         #
########################################################

# Referenced videos:
# - Karpenter: https://karpenter.sh
# - GKE Autopilot - Fully Managed Kubernetes Service From Google: https://youtu.be/Zztufl4mFQ4

#########
# Setup #
#########
```
git clone https://github.com/vfarcic/karpenter-demo

cd karpenter-demo

export CLUSTER_NAME=devops-toolkit

# Replace `[...]` with your access key ID
export AWS_ACCESS_KEY_ID=[...]

# Replace `[...]` with your secret access key
export AWS_SECRET_ACCESS_KEY=[...]

export AWS_DEFAULT_REGION=us-east-1

cat cluster.yaml \
    | sed -e "s@name: .*@name: $CLUSTER_NAME@g" \
    | sed -e "s@region: .*@region: $AWS_DEFAULT_REGION@g" \
    | tee cluster.yaml

cat provisioner.yaml \
    | sed -e "s@instanceProfile: .*@instanceProfile: KarpenterNodeInstanceProfile-$CLUSTER_NAME@g" \
    | sed -e "s@.* # Zones@      values: [${AWS_DEFAULT_REGION}a, ${AWS_DEFAULT_REGION}b, ${AWS_DEFAULT_REGION}c] # Zones@g" \
    | tee provisioner.yaml

cat app.yaml \
    | sed -e "s@topology.kubernetes.io/zone: .*@topology.kubernetes.io/zone: ${AWS_DEFAULT_REGION}a@g" \
    | tee app.yaml

eksctl create cluster \
    --config-file cluster.yaml

export CLUSTER_ENDPOINT=$(aws eks describe-cluster \
    --name $CLUSTER_NAME \
    --query "cluster.endpoint" \
    --output json)

echo $CLUSTER_ENDPOINT

###########################
# Karpenter Prerequisites #
###########################

export SUBNET_IDS=$(\
    aws cloudformation describe-stacks \
    --stack-name eksctl-$CLUSTER_NAME-cluster \
    --query 'Stacks[].Outputs[?OutputKey==`SubnetsPrivate`].OutputValue' \
    --output text)

aws ec2 create-tags \
    --resources $(echo $SUBNET_IDS | tr ',' '\n') \
    --tags Key="kubernetes.io/cluster/$CLUSTER_NAME",Value=

curl -fsSL https://raw.githubusercontent.com/aws/karpenter/v0.30.0/website/content/en/preview/getting-started/getting-started-with-karpenter/cloudformation.yaml \
    | tee karpenter.yaml

aws cloudformation deploy \
    --stack-name Karpenter-$CLUSTER_NAME \
    --template-file karpenter.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides ClusterName=$CLUSTER_NAME

export AWS_ACCOUNT_ID=$(\
    aws sts get-caller-identity \
    --query Account \
    --output text)

eksctl create iamidentitymapping \
    --username system:node:{{EC2PrivateDNSName}} \
    --cluster  $CLUSTER_NAME \
    --arn arn:aws:iam::${AWS_ACCOUNT_ID}:role/KarpenterNodeRole-$CLUSTER_NAME \
    --group system:bootstrappers \
    --group system:nodes

eksctl create iamserviceaccount \
    --cluster $CLUSTER_NAME \
    --name karpenter \
    --namespace karpenter \
    --attach-policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/KarpenterControllerPolicy-$CLUSTER_NAME \
    --approve

# Execute only if this is the first time using spot instances in this account
aws iam create-service-linked-role \
    --aws-service-name spot.amazonaws.com

###########################################
# Applications Without Cluster Autoscaler #
###########################################

kubectl get nodes

cat app.yaml

kubectl apply --filename app.yaml

kubectl get pods,nodes

#####################
# Install Karpenter #
#####################

helm repo add karpenter \
    https://charts.karpenter.sh

helm repo update

helm upgrade --install \
    karpenter karpenter/karpenter \
    --namespace karpenter \
    --create-namespace \
    --set serviceAccount.create=false \
    --version 0.5.0 \
    --set controller.clusterName=$CLUSTER_NAME \
    --set controller.clusterEndpoint=$CLUSTER_ENDPOINT \
    --wait

kubectl --namespace karpenter get all

##############################################
# Scale Up Kubernetes Cluster With Karpenter #
##############################################

cat provisioner.yaml

# Open https://kubernetes.io/docs/reference/labels-annotations-taints/

kubectl apply \
    --filename provisioner.yaml

kubectl get pods,nodes

kubectl get pods,nodes

kubectl --namespace karpenter logs \
    --selector karpenter=controller

####################################################
# Scale Down The Kubernetes Cluster With Karpenter #
####################################################

kubectl delete --filename app.yaml

kubectl --namespace karpenter logs \
    --selector karpenter=controller

kubectl get nodes

###########
# Destroy #
###########

helm --namespace karpenter \
    uninstall karpenter

eksctl delete iamserviceaccount \
    --cluster $CLUSTER_NAME \
    --name karpenter \
    --namespace karpenter

aws cloudformation delete-stack \
    --stack-name Karpenter-$CLUSTER_NAME

# Install jq from https://stedolan.github.io/jq if you do not have it already

aws ec2 describe-launch-templates \
    | jq -r ".LaunchTemplates[].LaunchTemplateName" \
    | grep -i Karpenter-$CLUSTER_NAME \
    | xargs -I{} \
        aws ec2 delete-launch-template \
        --launch-template-name {}

eksctl delete cluster \
    --name $CLUSTER_NAME \
    --region $AWS_DEFAULT_REGION
```
###
###
###

@neeltom92
neeltom92 commented on Sep 22, 2022 • 
image

getting 404 for downloading the cloudformation template.
this link is working when checked :
curl -fsSL https://karpenter.sh/v0.13.2/getting-started/getting-started-with-eksctl/cloudformation.yaml | tee karpenter.yaml

@vfarcic
Author
vfarcic commented on Sep 23, 2022
The link changed. The command is now curl -fsSL https://karpenter.sh/v0.16.2/getting-started/getting-started-with-eksctl/cloudformation.yaml | tee karpenter.yaml. I updated the Gist.

@TonyMarzano
TonyMarzano commented on Sep 14
Hi vfarcic, this link was changed again? curl -fsSL https://karpenter.sh/v0.16.2/getting-started/getting-started-with-eksctl/cloudformation.yaml | tee karpenter.yaml

@vfarcic
Author
vfarcic commented on Sep 14
@TonyMarzano I hate when projects do that. It costs nothing to keep old links available.

Anyways... Thanks for letting me know. The Gist was updated. Please let me know if you encounter any other issues.
