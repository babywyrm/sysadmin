#!/usr/bin/env bash

set -o errexit
set -o errtrace
set -o nounset
set -o pipefail

###############################################################################
### xARM - Amazon EKS on Arm
### Installs an EKS cluster using Graviton2-based Arm worker nodes
### based on https://docs.aws.amazon.com/eks/latest/userguide/arm-support.html
###
### Dependencies: jq, aws, eksctl, kubectl
###
### Example usage (showing all positional CLI arguments):
###
### ./xarm-install-graviton2.sh myarm us-east-1 1
###
### Author: Michael Hausenblas, hausenbl@amazon.com
### Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
### SPDX-License-Identifier: Apache-2.0


###############################################################################
### Utility functions

function preflightcheck {
    if ! [ -x "$(command -v jq)" ]
    then
    echo "Please install jq via https://stedolan.github.io/jq/download/ and try again" >&2
    exit 1
    fi
    if ! [ -x "$(command -v aws)" ]
    then
    echo "Please install aws via https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html and try again" >&2
    exit 1
    fi
    if ! [ -x "$(command -v eksctl)" ]
    then
    echo "Please install eksctl via https://eksctl.io/introduction/installation/ and try again" >&2
    exit 1
    fi
    if ! [ -x "$(command -v kubectl)" ]
    then
    echo "Please install kubectl via https://kubernetes.io/docs/tasks/tools/install-kubectl/ and try again" >&2
    exit 1
    fi
}

###############################################################################
### User parameters that can be overwritten as CLI arguments

# choose a custom name for the cluster:
export XARM_CLUSTER_NAME="${1:-xarm2}"
# choose a region to deploy the cluster into:
export XARM_TARGET_REGION="${2:-eu-west-1}"
# choose number of worker nodes (between 1 and 4):
export XARM_NODES_INITIAL_NUM="${3:-1}" 


###############################################################################
### Script parameters (do not touch)
XARM_NODES_TYPE="m6g.medium"
CNI_MANIFEST_URL=https://raw.githubusercontent.com/aws/containers-roadmap/master/preview-programs/eks-arm-preview/aws-k8s-cni-arm64.yaml
KUBEPROXY_MANIFEST_URL=https://raw.githubusercontent.com/aws/containers-roadmap/master/preview-programs/eks-arm-preview/kube-proxy-arm-1.15.yaml
COREDNS_MANIFEST_URL=https://raw.githubusercontent.com/aws/containers-roadmap/master/preview-programs/eks-arm-preview/dns-arm-1.15.yaml
NODEGROUP_CF_URL=https://amazon-eks.s3.us-west-2.amazonaws.com/cloudformation/2020-06-10/amazon-eks-arm-nodegroup.yaml
AUTH_CONFIGMAP_URL=https://amazon-eks.s3.us-west-2.amazonaws.com/cloudformation/2019-11-15/aws-auth-cm.yaml

###############################################################################
### Main script

printf "Checking dependencies\n\n"

preflightcheck

printf "I will now provision an EKS cluster with the following parameters:\n" 
printf ' %s \e[34m%s\e[0m\n' "cluster name:" $XARM_CLUSTER_NAME
printf ' %s \e[34m%s\e[0m\n' "region:" $XARM_TARGET_REGION
printf ' %s \e[34m%s\e[0m\n' "number of worker nodes:" $XARM_NODES_INITIAL_NUM
printf ' %s \e[34m%s\e[0m\n\n' "instance type:" $XARM_NODES_TYPE

printf "Starting! This will take some 15 min to complete\n\n"

# create the control plane and gather some data we need for the node group:
echo Creating the control plane

eksctl create cluster \
       --name $XARM_CLUSTER_NAME \
       --version 1.15 \
       --region $XARM_TARGET_REGION \
       --without-nodegroup

ControlPlaneSecurityGroup=$(aws eks describe-cluster --name $XARM_CLUSTER_NAME --region $XARM_TARGET_REGION | jq .cluster.resourcesVpcConfig.securityGroupIds[0] -r)
VPCId=$(aws eks describe-cluster --name $XARM_CLUSTER_NAME --region $XARM_TARGET_REGION | jq .cluster.resourcesVpcConfig.vpcId -r)

# 172.31.32.0/20 and 172.31.80.0/20
PublicSubnets=$(aws cloudformation describe-stacks --stack-name eksctl-$XARM_CLUSTER_NAME-cluster --region $XARM_TARGET_REGION | jq -r '.Stacks[0].Outputs' | jq -c '.[] | select( .OutputKey == "SubnetsPublic" )' | jq -r '.OutputValue')

# update control plane (Arm it):
echo Updating control plane with Arm components

kubectl apply -f $COREDNS_MANIFEST_URL
kubectl apply -f $KUBEPROXY_MANIFEST_URL
kubectl apply -f $CNI_MANIFEST_URL

# launch worker nodes and gather some data to join nodes:
echo Launching worker nodes

tsnow=$(date +%s)
xarmkeyname=xarm-$tsnow
curl -o amazon-eks-arm-nodegroup.yaml $NODEGROUP_CF_URL

aws ec2 create-key-pair \
    --key-name "$xarmkeyname" \
    --region $XARM_TARGET_REGION | \
    jq -r ".KeyMaterial" > ~/.ssh/$xarmkeyname.pem

aws cloudformation deploy \
    --template-file amazon-eks-arm-nodegroup.yaml \
    --stack-name eksctl-$XARM_CLUSTER_NAME-ng \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides "ClusterControlPlaneSecurityGroup=$ControlPlaneSecurityGroup" \
                          "ClusterName=$XARM_CLUSTER_NAME" \
                          "KeyName=$xarmkeyname" \
                          "KubernetesVersion=1.15" \
                          "NodeAutoScalingGroupDesiredCapacity=$XARM_NODES_INITIAL_NUM" \
                          "NodeGroupName=xarmdng" \
                          "NodeInstanceType=$XARM_NODES_TYPE" \
                          "Subnets=$PublicSubnets" \
                          "VpcId=$VPCId" \
    --region $XARM_TARGET_REGION

NodeInstanceRole=$(aws cloudformation describe-stacks --stack-name eksctl-$XARM_CLUSTER_NAME-ng --region $XARM_TARGET_REGION | jq -r '.Stacks[0].Outputs' | jq -c '.[] | select( .OutputKey == "NodeInstanceRole" )' | jq -r '.OutputValue')

# add worker nodes to cluster
echo Adding worker nodes to cluster

curl -o aws-auth-cm.yaml $AUTH_CONFIGMAP_URL && \
     sed "s|<ARN of instance role (not instance profile)>|$NodeInstanceRole|g" aws-auth-cm.yaml > aws-auth-cm-arm.yaml && \
     kubectl apply -f aws-auth-cm-arm.yaml

echo DONE
