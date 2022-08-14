Using AWS CLI to Gather Security Group Info
Various cmds to get security group information using the AWS CLI

Assumption
You already have all the necessary credentials to access EC2 services and have AWS CLI installed. If not installed, download and install the aws-cli for your platform https://docs.aws.amazon.com/cli/latest/userguide/awscli-install-bundle.html

Usage
Copy/paste command examples provided below in Linux shell.

Get a list of all security groups
(default region)
aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --output text | tr '\t' '\n'

(specific region)
aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --region us-east-1 --output text | tr '\t' '\n'

List all unused security groups
comm -23 <(aws ec2 describe-security-groups --query 'SecurityGroups[].GroupId' --region us-east-1 --output text | tr '\t' '\n'| sort) <(aws ec2 describe-instances --query 'Reservations[].Instances[].SecurityGroups[].GroupId' --region us-east-1 --output text | tr '\t' '\n' | sort | uniq)

List all security groups in use by instances
aws ec2 describe-instances --query 'Reservations[].Instances[].SecurityGroups[*].GroupId' --region us-east-1 --output text | tr '\t' '\n'

Describe and write to CSV
aws ec2 describe-security-groups --region us-east-1 --query 'SecurityGroups[*].[Description,GroupId,GroupName,OwnerId,VpcId ]' --output text >> security-groups-us-east.csv

Describe all security groups
for i in $( aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --region us-east-1 --output text | tr '\t' '\n') ; do aws ec2 describe-security-groups --region us-east-1 --output text --group-ids $i; done
