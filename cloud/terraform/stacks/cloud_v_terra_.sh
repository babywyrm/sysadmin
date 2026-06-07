#!/bin/bash

##
##

# make sure we have what we need

if [ -z "$AWS_ACCESS_KEY_ID" ] || \
   [ -z "$AWS_SECRET_ACCESS_KEY" ] || \
   [ -z "$AWS_DEFAULT_REGION" ] || \
   [ -z "$(which aws)" ] || \
   [ -z "$(which terraform)" ]
then
  echo "The following environment variables must be set to run this script:"
  echo "    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION"
  echo 
  echo "You must also have the 'aws' and 'terraform' commands in your \$PATH"

  exit 1
fi

# copy the vars so terraform can see them
export TF_VAR_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
export TF_VAR_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
export TF_VAR_DEFAULT_REGION=$AWS_DEFAULT_REGION

# generate a unique name for everythign we create as part of this demo
NAME="demo.sh "`date`; STACK_NAME="${NAME//[![:alnum:]]}"

# store everything in a tempdir and trash it when we are done
TMP_DIR=`mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir'`
function cleanup {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > $TMP_DIR/test.cf <<EOCF
{
  "AWSTemplateFormatVersion": "2010-09-09",
  
  "Resources": {
    "VPC": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "CidrBlock": "192.0.2.0/24"
      }
    },
    "SecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Sample CF Security Group",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": "12345",
            "ToPort": "12345",
            "CidrIp": "192.0.2.0/24"
          }
        ],
        "Tags": [{"Key": "created_by", "Value": "$STACK_NAME" }],
        "VpcId": {"Ref": "VPC"}
      }
    }
  }
}
EOCF

echo -e "\e[33;1m# Create a simple VPC and Security Group with CloudFormation:\e[0m"

echo -e "\e[2m$(cat $TMP_DIR/test.cf)\e[0m"

echo -e "\n\e[1m$ aws cloudformation create-stack\e[0m"

# execute the cloud formation and wait for it to complete
aws cloudformation create-stack --stack-name "$STACK_NAME" --template-body "$(cat $TMP_DIR/test.cf)" &> /dev/null

STATE="IN_PROGRESS"
while [[ $STATE == *"IN_PROGRESS"* ]]; do
    STATE=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" | jq -C .Stacks[0].StackStatus)
    sleep 1
done

echo -e "\n\e[33;1m# Now let's check our ingress rules:\e[0m"
echo -e "\n\e[1m$ aws ec2 describe-security-groups\e[0m"

aws ec2 describe-security-groups --filter "Name=tag-value,Values=$STACK_NAME" | jq -C .SecurityGroups[0].IpPermissions
SGID=$(aws ec2 describe-security-groups --filter "Name=tag-value,Values=$STACK_NAME" | jq -C -r .SecurityGroups[0].GroupId)

echo -e "\n\e[33;1m# Everything looks good so far.\e[0m"


echo -e "\n\e[31;1m# Oh no! At some point in the future an SRE manually changes the security group:\n"
set -x
aws ec2 authorize-security-group-ingress --group-id $SGID --ip-permissions IpProtocol=-1,IpRanges=[{CidrIp='0.0.0.0/0'}]

{ set +x; } 2>/dev/null

echo -e "\n\e[0m\e[33;1m# But it'll be ok... our CD pipeline keeps our stacks matching what's in our git repo on a regular basis\e[0m"
echo -e "\n\e[1m$ aws cloudformation update-stack\e[0m"

aws cloudformation update-stack --stack-name "$STACK_NAME" --template-body "$(cat $TMP_DIR/test.cf)"

echo -e "\n\e[33;1m# Wait what? Our ingress rules should be fixed...\e[0m"
echo -e "\n\e[1m$ aws ec2 describe-security-groups\e[0m"

aws ec2 describe-security-groups --filter "Name=tag-value,Values=$STACK_NAME" | jq -C .SecurityGroups[0].IpPermissions

echo -e "\n\e[33;1m# ...or not.  That's a serious fail with CloudFormation\e[0m"

# clean up
aws cloudformation delete-stack --stack-name $STACK_NAME

STACK_NAME="$STACK_NAME-tf"

cat > $TMP_DIR/test.tf <<'EOTF'
variable "ACCESS_KEY_ID" {}
variable "SECRET_ACCESS_KEY" {}
variable "DEFAULT_REGION" {}
provider "aws" {
  access_key = "${var.ACCESS_KEY_ID}"
  secret_key = "${var.SECRET_ACCESS_KEY}"
  region = "${var.DEFAULT_REGION}"
}
resource "aws_vpc" "v" {
  cidr_block = "192.0.2.0/24"
}
resource "aws_security_group" "s" {
  description = "Sample TF Security Group"
  vpc_id = "${aws_vpc.v.id}"
  ingress {
    from_port = 12345
    to_port = 12345
    protocol = "tcp"
    cidr_blocks = ["192.0.2.0/24"]
  }
  tags =  {
EOTF
echo -e "    created_by = \"$STACK_NAME\"\n  }\n}" >> $TMP_DIR/test.tf


echo -e "\n\e[33;1m# Let's try that again with Terraform:\e[0m"
echo -e "\e[2m$(cat $TMP_DIR/test.tf)\e[0m"
echo -e "\n\e[1m$ terraform apply\e[0m"

cd $TMP_DIR && terraform apply &>/dev/null; cd - &>/dev/null

echo -e "\n\e[33;1m# Now let's check our ingress rules:\e[0m"
echo -e "\n\e[1m$ aws ec2 describe-security-groups\e[0m"

aws ec2 describe-security-groups --filter "Name=tag-value,Values=$STACK_NAME" | jq -C .SecurityGroups[0].IpPermissions
SGID=$(aws ec2 describe-security-groups --filter "Name=tag-value,Values=$STACK_NAME" | jq -C -r .SecurityGroups[0].GroupId)

echo -e "\e[33;1m# So far so good...\e[0m"

echo -e "\n\e[31;1m# ...we really need to retrain this SRE who keeps adding rules manually!\n"

set -x

# simulate admin accidentally adding permissive rule
aws ec2 authorize-security-group-ingress --group-id $SGID --ip-permissions IpProtocol=-1,IpRanges=[{CidrIp='0.0.0.0/0'}]

{ set +x; } 2>/dev/null

echo -e "\n\e[0m\e[33;1m# But it'll be ok... our CD pipeline applies our Terraform configurations on a regular basis\e[0m"
echo -e "\n\e[1m$ terraform apply\e[0m"

cd $TMP_DIR && terraform apply &>/dev/null; cd - &>/dev/null

echo -e "\n\e[33;1m# Did that fix the ingress rules?\e[0m"
echo -e "\n\e[1m$ aws ec2 describe-security-groups\e[0m"

aws ec2 describe-security-groups --filter "Name=tag-value,Values=$STACK_NAME" | jq -C .SecurityGroups[0].IpPermissions

echo -e "\n\e[33;1m# \e[0m\e[32;1mTerraform: 1; \e[0m\e[31;1mCloudFormation: 0.\e[0m"

cd $TMP_DIR && terraform destroy --force &>/dev/null; cd - &>/dev/null

##
##
