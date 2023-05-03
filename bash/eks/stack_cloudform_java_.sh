#!/bin/bash

##
## https://github.com/aws-samples/amazon-eks-example-for-stateful-java-service
##

# This is a simple bash script.
# It basically glues together the parts running in loose coupling during the deployment and helps to speed things up which
# otherwise would have to be noted down and put into the command line.
# This can be migrated into real orchestration / automation toolsets if needed (e.g. Ansible, Puppet or Terraform)

# created by Bastian Klein - basklein@amazon.de
# Disclaimer: NOT FOR PRODUCTION USE - Only for demo and testing purposes

PREPSTACK="DevSourceBucket"
STACK="EKSJavaApplication"
ERROR_COUNT=0;

if [[ $# -lt 1 ]] ; then
    echo 'argument missing, please provide aws dev profile string (-p)'
    exit 1
fi

while getopts ":p:b:" opt; do
  case $opt in
    p) PROFILE="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

if ! [ -x "$(command -v aws)" ]; then
  echo 'Error: aws cli is not installed.' >&2
  exit 1
fi

echo "using AWS Profile $PROFILE"
echo "##################################################"

echo "Validating AWS CloudFormation templates..."
echo "##################################################"
# Loop through the YAML templates in this repository
for TEMPLATE in $(find ./cloudformation -name '*.yaml'); do

    # Validate the template with CloudFormation
    ERRORS=$(aws cloudformation validate-template --profile=$PROFILE --template-body file://$TEMPLATE 2>&1 >/dev/null);
    if [ "$?" -gt "0" ]; then
        ((ERROR_COUNT++));
        echo "[fail] $TEMPLATE: $ERRORS";
    else
        echo "[pass] $TEMPLATE";
    fi;

done;

# Error out if templates are not validate.
echo "$ERROR_COUNT template validation error(s)";
if [ "$ERROR_COUNT" -gt 0 ];
    then exit 1;
fi

echo "##################################################"
echo "Validating of AWS CloudFormation templates finished"
echo "##################################################"

# Deploy the Needed Buckets for the later build
echo "deploy the Prerequisites if needed"
echo "##################################################"
aws cloudformation deploy  --stack-name $PREPSTACK --profile=$PROFILE --template ./cloudformation/buildbucket.template.yaml
echo "##################################################"
echo "deployment done"

# get the s3 bucket name out of the deployment.
SOURCE=`aws cloudformation describe-stacks --profile=$PROFILE --query "Stacks[0].Outputs[0].OutputValue" --stack-name $PREPSTACK`
SOURCE=`echo "${SOURCE//\"}"`

# we will upload the needed CFN Templates to S3 containing the IaaC Code which deploys the actual infrastructure.
# This will error out if the source files are missing.
echo "##################################################"
echo "Copy Files to the S3 Bucket for further usage"
echo "##################################################"
if [ -e ./ ]
then
    echo "##################################################"
    echo "copy code source file"
    aws s3 sync --profile=$PROFILE ./cloudformation s3://$SOURCE

    echo "##################################################"
else
    echo "code source file missing"
    echo "##################################################"
    exit 1
fi
echo "##################################################"
echo "File Copy finished"

# Deploy of the CICD Codepipeline Based IaaC Deployment infrastructure.
echo "Building the DEV Environment"
echo "##################################################"
aws cloudformation deploy --profile=$PROFILE --stack-name $STACK --capabilities CAPABILITY_NAMED_IAM --parameter-overrides "TemplatePath=$SOURCE" --template ./cloudformation/main.template.yaml
echo "##################################################"
echo "Deployment finished"

exit 0


##
##


