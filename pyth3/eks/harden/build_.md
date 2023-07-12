
##
#
https://levelup.gitconnected.com/build-a-kubernetes-police-to-enforce-aws-eks-best-practices-with-hardeneks-4a27896a50cc
#
##

Build a Kubernetes police to enforce AWS EKS best practices with Hardeneks
Hari Ohm Prasath
Level Up Coding

Hari Ohm Prasath
·

Follow
Published in

Level Up Coding
·
8 min read
·
May 14

    A comprehensive guide to improve AWS EKS security and compliance with Hardeneks

Introduction

AWS EKS is a managed Kubernetes service that makes it easy to run Kubernetes on AWS without installing, operating, and maintaining your own Kubernetes control plane or nodes. As creating a cluster sounds more fun and easy to do, it is not the case when it comes to managing them and enforcing the best practices for these clusters. Especially in a large enterprise environment where multiple users have access to these clusters, they can change the cluster configuration at any given time, which could lead to security issues and other vulnerabilities. So more than enforcing these standards as just part of the provisioning flow, we need to make sure that these standards are enforced continuously, and that is where Hardeneks comes in.

Before we start talking about Hardeneks, we need to understand what I mean by best practices. Best practices are rules you must follow to ensure your cluster is secure and compliant with industry standards. For example, you need to make sure that you are not using the default IAM role for your nodes, you need to make sure that you are not using the default security group for your nodes, etc. AWS has excellent documentation covering all the best practices you must follow when running EKS clusters. You can find the documentation [here].
AWS EKS and kubernetes best practices

In part of this article, we will go over the following topics:

    Hardeneks Overview — What is it, and why should I use it?
    Taking it for a spin — Setup EKS cluster and running Hardeneks locally on my machine?
    Setup Kubernetes Police — By building the infrastructure that can automate the process of running Hardeneks daily, which generates a report and pushes it to an S3 bucket.

So let's get started!
What is Hardeneks?

Hardeneks It is a tool that helps you to enforce the best practices on your EKS clusters. It is a simple tool you can run on your local machine or a CI/CD pipeline. It will scan your cluster and generate a report showing the issues you must fix. This will make the life of the cluster administrators and security engineers easy as the tool can be run regularly to ensure the cluster always stays compliant with the best practices.
Running Hardeneks locally
Prerequisites

    AWS Account — If you don’t have one, you can create one [here]
    EksCtl — You can install it from [here]
    python3 — You can install it from [here]
    pip — You can install it from [here]

Setup Hardeneks and test them locally

1. Install Hardeneks

python3 -m venv /tmp/.venv
source /tmp/.venv/bin/activate
pip install hardeneks
hardeneks --help

Output:

Usage: hardeneks [OPTIONS]

2. Create an EKS cluster

eksctl create cluster --name demo-cluster

Output:

[✔] EKS cluster "demo-cluster" in "us-east-1" region is ready

3. Run Hardeneks to scan the cluster and generate a report

hardeneks --cluster demo-cluster

    For list of all the options that you can pass to Hardeneks, you can run hardeneks --help, also you can find the documentation [here]

Output:
hardeneks scan results of EKS cluster

    As shown in the image above you would see the list of all issues grouped under individual categories. For example, you would see all the issues related to IAM under the security rules category. Rows marked in red requires immediate attention.

Setup the Kubernetes Police

In this section, we will build a Kubernetes police Hardeneks to enforce AWS EKS best practices.
Kubernetes police to stop you for not following best practices

We will do this by automating the process of running Hardeneks scans daily by building the infrastructure using ECS Fargate, Event bridge rule, and S3. The program will run hardeneks on all the EKS clusters in the given region and generate a report. The report will be pushed to a S3 bucket and will be available for 30 days.
Kubernetes policy architecture diagram

    Note: Even though we are using ECS Fargate to run Hardeneks, you can use any other compute service to do the same. The purpose of of this solution is to demonstrate the art of possibility when it comes to automation with kubernetes, feel free to update them based on your need and security guidelines

    Create an ECR repository

aws ecr create-repository --repository-name kubernetes-police-repo

2. Download the scripts, build the docker image, and push it to ECR

# Clone the repository
git clone https://github.com/hariohmprasath/kubernetes-police.git \
&& cd kubernetes-police

# Make sure to update the "AWS_SECRET_ACCESS_KEY" & "AWS_ACCESS_KEY_ID" in run.sh
# with the actual values used for creating the cluster. You can get this by 
# running aws configure get aws_secret_access_key/aws_access_key_id

# Set the AWS_ACCOUNT_ID variable
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account \
--output text)

# Login to ECR repository
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS \
--password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Build the docker image and push it to ECR
docker build --platform linux/amd64 -t kubernetes-police .
docker tag kubernetes-police:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/kubernetes-police-repo:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/kubernetes-police-repo:latest

3. Setup ECS cluster and task role

# Create ECS cluster
aws ecs create-cluster --cluster-name kubernetes-police \
--capacity-providers FARGATE

# Assume role document
cat <<EOF > assume-role.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create task role with admin permission
aws iam create-role --role-name kubernetes-police-task-role \
--assume-role-policy-document file://assume-role.json
aws iam attach-role-policy --role-name kubernetes-police-task-role \
--policy-arn arn:aws:iam::aws:policy/AdministratorAccess

4. Create an ECS Task definition and register it using the container image that we pushed to ECR in step 2

# Create ECS task definition
```
cat <<EOF > task.json
{
  "family": "kubernetes-police",
  "networkMode": "awsvpc",
  "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/kubernetes-police-task-role",
  "taskRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/kubernetes-police-task-role",
  "containerDefinitions": [
    {
      "name": "kubernetes-police",
      "image": "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/kubernetes-police-repo:latest",
      "essential": true,
      "memory": 512,
      "cpu": 256
    }
  ],
  "requiresCompatibilities": [
    "FARGATE"
  ],
  "cpu": "256",
  "memory": "512"
}
```

# Register the task definition
aws ecs register-task-definition --cli-input-json file://task.json

5. Setup AWS Event bridge rule to run the task daily

# 5.1 — Create a scheduled task
aws events put-rule --name kubernetes-police-scheduled-rule \
--schedule-expression 'cron(0 0 * * ? *)' --state ENABLED

# 5.2 - Get default vpc, subnets, security groups and export them as environment variables
export VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
--query 'Vpcs[].VpcId' --output text)
export SUBNET=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC_ID \
--query 'Subnets[0].SubnetId' --output text)
export SECURITY_GROUP=$(aws ec2 describe-security-groups \
--filters Name=vpc-id,Values=$VPC_ID --query 'SecurityGroups[0].GroupId' --output text)

## 5.3 - Assume role document for event bridge role
cat <<EOF > assume-role.json
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

aws iam create-role --role-name kubernetes-police-scheduled-role \
--assume-role-policy-document file://assume-role.json
aws iam attach-role-policy --role-name kubernetes-police-scheduled-role \
--policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 5.4 - Create the Event bridge target
cat <<EOF > ecs-target.json
[{
  "RoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/kubernetes-police-scheduled-role",
  "EcsParameters": {
    "TaskDefinitionArn": "arn:aws:ecs:${AWS_REGION}:${AWS_ACCOUNT_ID}:task-definition/kubernetes-police",
    "TaskCount": 1,
    "LaunchType": "FARGATE",
    "NetworkConfiguration": {
      "awsvpcConfiguration": {
        "Subnets": [
          "$SUBNET"
        ],
        "SecurityGroups": [
          "$SECURITY_GROUP"
        ],
        "AssignPublicIp": "ENABLED"
      }
    }
  },
  "Id": "kubernetes-police-scheduled-target",
  "Arn": "arn:aws:ecs:$AWS_REGION:${AWS_ACCOUNT_ID}:cluster/kubernetes-police",
  "Input": "{}"
}]
EOF

# 5.5 - Attach the target to the rule
aws events put-targets --rule kubernetes-police-scheduled-rule \
--targets file://ecs-target.json

6. ECS task will run daily, scan all the EKS clusters in the given region, generate the report, and push it to s3. You can see the output pushed to the S3 bucket s3://hardeneks-report-output-<<account-id>>/demo-cluster.txt
Cleanup

# Delete the ECS cluster
aws ecs delete-cluster --cluster kubernetes-police

# Delete the ECS task role
aws iam detach-role-policy --role-name kubernetes-police-task-role \
--policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name kubernetes-police-task-role

# Delete the ECS scheduled task role
aws iam detach-role-policy --role-name kubernetes-police-scheduled-role \
--policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name kubernetes-police-scheduled-role

# Delete the ECR repository
aws ecr delete-repository --repository-name kubernetes-police-repo --force

# Delete the S3 bucket
aws s3 rb s3://hardeneks-report-output-$AWS_ACCOUNT_ID --force

# Delete the event bridge rule
aws events remove-targets --rule kubernetes-police-scheduled-rule \
--ids kubernetes-police-scheduled-target

# Delete the event bridge rule
aws events delete-rule --name kubernetes-police-scheduled-rule

# Delete the EKS cluster
eksctl delete cluster --name kubernetes-police

Conclusion

In this guide, we have explored the various features of Hardeneks and how they can be used to enhance the security of your Kubernetes cluster. With the help of this tool, you can ensure that your cluster is protected against various security threats and comply with industry-standard best practices.

If you like the write-up and found it helpful, give a clap 👏 or leave a comment

Hi, I’m Hari. I write about technology and programming. To have stories sent directly to you, subscribe to my newsletter.
