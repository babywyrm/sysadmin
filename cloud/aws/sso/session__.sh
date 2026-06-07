#!/bin/bash -e

##
##

# Usage: aws-session <token> (account)
#  Sets up aws configuration for API access using temporary credentials
#  See: https://aws.amazon.com/premiumsupport/knowledge-center/authenticate-mfa-cli/
#       https://mharrison.org/post/aws_mfa/

usage(){
  cat <<EOF
Usage: aws-session [-r <region>] ([-i] | <token> (account))
  -r <region> - set the region
  -i - import temporary credentials into default credentials
Accounts: kubernetes, k8s-dev, k8s-sandbox
EOF
  exit 1
}

while getopts ":ir:" OPT; do
    case $OPT in
    i )
        IMPORT="true"
        ;;
    r )
        AWS_REGION=$OPTARG
        ;;
    \? | h)
        [ "$OPT" != "h" ] && echo "Invalid option: $OPTARG"
        usage
        exit 1
        ;;
    esac
done
shift $((OPTIND -1))

if [ "$IMPORT" ]
then
  if [ ! "$AWS_ACCESS_KEY_ID" ]
  then
      echo "ERROR: You need to manually set AWS_* vars for import"
      exit 1
  fi
  echo "Updating default AWS credentials..."
  aws --profile default configure set aws_access_key_id $AWS_ACCESS_KEY_ID
  aws --profile default configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
  aws --profile default configure set aws_session_token $AWS_SESSION_TOKEN
  if [ "$AWS_REGION" ]
  then
    aws --profile default configure set region $AWS_REGION
  fi

  echo "AWS session credentials updated."
  exit 0
fi

if [ $# -ne 1 -a $# -ne 2 ]
then
  echo -e "Not enough arguments.\n"
  usage
fi

# 8 hours (a workday)
TIMEOUT=${SESSION_TIMEOUT-28800}

if [ $# -eq 1 ]
then
  TOKEN=$1
else
  ACCOUNT=$1
  TOKEN=$2
fi

if ! aws --profile base configure get aws_access_key_id &>/dev/null
then
  echo "Base profile 'base' not found"
  exit 1
fi

echo -n "... getting caller identity: "
CALLER=$(aws --profile base --output json sts get-caller-identity)
if [ $? -ne 0 ]
then
    echo "Error getting caller identity"
    exit 1
fi

ARN=$(echo $CALLER | jq -r .Arn)
echo "$ARN"
ARN=${ARN/:user/:mfa}

parse-credentials(){
  local CREDS="$*"
  SECRETKEY=$(echo $CREDS | jq -r .Credentials.SecretAccessKey)
  TOKEN=$(echo $CREDS | jq -r .Credentials.SessionToken)
  KEYID=$(echo $CREDS | jq -r .Credentials.AccessKeyId)
}

if [ "$ACCOUNT" ]
then
  case "$ACCOUNT" in
  kubernetes)
    ROLE_ARN="arn:aws:iam::631824116433:role/KubernetesAccountAccessRole"
    ;;
  k8s-dev)
    ROLE_ARN="arn:aws:iam::068438446535:role/K8sDevAccountAccessRole"
    ;;
  k8s-sandbox)
    ROLE_ARN="arn:aws:iam::341081005506:role/K8sSandboxAccountAccessRole"
    ;;
  esac
  echo "... getting temporary credentials for '$ACCOUNT' account"
  parse-credentials $( \
    AWS_ACCESS_KEY_ID=$KEYID AWS_SECRET_ACCESS_KEY=$SECRETKEY AWS_SESSION_TOKEN=$TOKEN \
    aws --profile base sts assume-role --role-arn "$ROLE_ARN" \
    --role-session-name "$USER" --duration-seconds $TIMEOUT \
    --serial-number $ARN --token-code $TOKEN)
else
  echo "... getting temporary credentials for main account"
  parse-credentials $(aws --profile base sts get-session-token \
  --duration-seconds $TIMEOUT --serial-number $ARN --token-code $TOKEN)
fi

echo "... updating profile 'default'"
aws --profile default configure set aws_access_key_id $KEYID
aws --profile default configure set aws_secret_access_key $SECRETKEY
aws --profile default configure set aws_session_token $TOKEN
if [ "$AWS_REGION" ]
then
  aws --profile default configure set region $AWS_REGION
fi

echo "Profile 'default' updated with temporary credentials expiring in $TIMEOUT seconds"

##
##

#!/bin/bash

# This uses MFA devices to get temporary (eg 12 hour) credentials.  Requires
# a TTY for user input.
#
# GPL 2 or higher
grep -q mfa ~/.aws/config || (echo "writing mfa-profile to your config" && echo -e "[profile mfa] \nregion = eu-central-1 \noutput = json" >> ~/.aws/config)
echo "Please enter aws-profile name.(Leave blank if you use default profile)"
read aws_profile
if [ ! -t 0 ]
then
  echo Must be on a tty >&2
  exit 255
fi
if [ ! -z "$aws_profile" ]
then
  identity=$(aws sts get-caller-identity --profile $aws_profile --output json)
else
  identity=$(aws sts get-caller-identity --output json)
fi
username=$(echo -- "$identity" | sed -n 's!.*"arn:aws:iam::.*:user/\(.*\)".*!\1!p')
if [ -z "$username" ]
then
  echo "Can not identify who you are.  Looking for a line like
    arn:aws:iam::.....:user/FOO_BAR
but did not find one in the output of
  aws sts get-caller-identity
$identity" >&2
  exit 255
fi

echo You are: $username >&2
if [ ! -z "$aws_profile" ]
then
mfa=$(aws iam list-mfa-devices --user-name "$username" --profile $aws_profile --output json)
else
mfa=$(aws iam list-mfa-devices --user-name "$username" --output json)
fi
device=$(echo -- "$mfa" | sed -n 's!.*"SerialNumber": "\(.*\)".*!\1!p')
if [ -z "$device" ]
then
  echo "Can not find any MFA device for you.  Looking for a SerialNumber
but did not find one in the output of
  aws iam list-mfa-devices --username \"$username\"
$mfa" >&2
  exit 255
fi

echo Your MFA device is: $device >&2

echo -n "Enter your MFA code now: " >&2
read code
if [ ! -z "$aws_profile" ]
then
  tokens=$(aws sts get-session-token --serial-number "$device" --token-code $code --duration-seconds 129600 --output json)
else
  tokens=$(aws sts get-session-token --serial-number "$device" --token-code $code --duration-seconds 129600 --output json --profile $aws_profile)
fi
secret=$(echo -- "$tokens" | sed -n 's!.*"SecretAccessKey": "\(.*\)".*!\1!p')
session=$(echo -- "$tokens" | sed -n 's!.*"SessionToken": "\(.*\)".*!\1!p')
access=$(echo -- "$tokens" | sed -n 's!.*"AccessKeyId": "\(.*\)".*!\1!p')
expire=$(echo -- "$tokens" | sed -n 's!.*"Expiration": "\(.*\)".*!\1!p')

if [ -z "$secret" -o -z "$session" -o -z "$access" ]
then
  echo "Unable to get temporary credentials.  Could not find secret/access/session entries
$tokens" >&2
  exit 255
fi

echo 'Removing old mfa setting'
sed -i '/\[mfa\]/,$d' ~/.aws/credentials

echo 'Push new mfa token, key, id to credentials'
echo AWS_SESSION_TOKEN=$session
echo AWS_SECRET_ACCESS_KEY=$secret
echo AWS_ACCESS_KEY_ID=$access

echo [mfa] >> ~/.aws/credentials
echo AWS_SESSION_TOKEN=$session >> ~/.aws/credentials
echo AWS_SECRET_ACCESS_KEY=$secret >> ~/.aws/credentials
echo AWS_ACCESS_KEY_ID=$access >> ~/.aws/credentials

echo Keys valid until $expire >&2

##
##
