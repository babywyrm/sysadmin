#!/bin/bash
##
##
## https://github.com/stefansundin/aws/blob/master/ec2-metadata-dump.sh
##
##
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
# curl -fsSL https://raw.githubusercontent.com/stefansundin/aws/master/ec2-metadata-dump.sh | bash
# Also print user-data:
# curl -fsSL https://raw.githubusercontent.com/stefansundin/aws/master/ec2-metadata-dump.sh | bash -s user-data

METADATA_TOKEN=$(curl -fsS -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 600" http://169.254.169.254/latest/api/token)

function get {
  curl -fsS -H "X-aws-ec2-metadata-token: $METADATA_TOKEN" http://169.254.169.254/2021-07-15/$1 2> /dev/null
}

>&2 echo "Fetching metadata..."

DOMAIN=$(get meta-data/services/domain)
PARTITION=$(get meta-data/services/partition)
REGION=$(get meta-data/placement/region)
AZ=$(get meta-data/placement/availability-zone)
AZ_ID=$(get meta-data/placement/availability-zone-id)
INSTANCE_ID=$(get meta-data/instance-id)
INSTANCE_TYPE=$(get meta-data/instance-type)
PROFILE=$(get meta-data/profile)
AMI_ID=$(get meta-data/ami-id)
PUBLIC_KEY=$(get meta-data/public-keys/0/openssh-key)
HOSTNAME=$(get meta-data/hostname)
LOCAL_HOSTNAME=$(get meta-data/local-hostname)
LOCAL_IPV4=$(get meta-data/local-ipv4)
IPV6=$(get meta-data/ipv6)
PUBLIC_HOSTNAME=$(get meta-data/public-hostname)
if [ $? -eq 22 ]; then
  PUBLIC_HOSTNAME="N/A"
fi
PUBLIC_IPV4=$(get meta-data/public-ipv4)
if [ $? -eq 22 ]; then
  PUBLIC_IPV4="N/A"
fi
MAC=$(get meta-data/mac)
INTERFACE_ID=$(get meta-data/network/interfaces/macs/$MAC/interface-id)
VPC_ID=$(get meta-data/network/interfaces/macs/$MAC/vpc-id)
VPC_CIDR=$(get meta-data/network/interfaces/macs/$MAC/vpc-ipv4-cidr-block)
SUBNET_ID=$(get meta-data/network/interfaces/macs/$MAC/subnet-id)
SUBNET_CIDR=$(get meta-data/network/interfaces/macs/$MAC/subnet-ipv4-cidr-block)
SECURITY_GROUP_IDS=$(get meta-data/network/interfaces/macs/$MAC/security-group-ids)
SECURITY_GROUPS=$(get meta-data/network/interfaces/macs/$MAC/security-groups)
INSTANCE_IDENTITY=$(get dynamic/instance-identity/document)
IDENTITY_INFO=$(get meta-data/identity-credentials/ec2/info)
IDENTITY_CREDENTIALS=$(get meta-data/identity-credentials/ec2/security-credentials/ec2-instance)
EVENTS_HISTORY=$(get meta-data/events/maintenance/history)
EVENTS_SCHEDULED=$(get meta-data/events/maintenance/scheduled)

echo "domain: $DOMAIN"
echo "partition: $PARTITION"
echo "availability-zone: $AZ ($AZ_ID)"
echo "instance-id: $INSTANCE_ID"
echo "instance-type: $INSTANCE_TYPE"
echo "profile: $PROFILE"
echo "ami-id: $AMI_ID"
echo "ssh key: $PUBLIC_KEY"

ACTIVE_KEYS=$(get meta-data/managed-ssh-keys/active-keys/)
echo "$ACTIVE_KEYS" | while read -r username; do
  [ -z "$username" ] && continue
  echo
  echo "# managed-ssh-keys for user $username:"
  get meta-data/managed-ssh-keys/active-keys/$username/
done

echo
echo "hostname: $HOSTNAME"
echo "local-hostname: $LOCAL_HOSTNAME"
echo "local-ipv4: $LOCAL_IPV4"
echo "ipv6: $IPV6"
echo "public-hostname: $PUBLIC_HOSTNAME"
echo "public-ipv4: $PUBLIC_IPV4"
echo "mac: $MAC"
echo "interface-id: $INTERFACE_ID"
echo "vpc-id: $VPC_ID"
echo "subnet-id: $SUBNET_ID"
echo "vpc-cidr: $VPC_CIDR"
echo "subnet-cidr: $SUBNET_CIDR"
echo "security-group-ids: ${SECURITY_GROUP_IDS//$'\n'/ }"
echo "security-groups: ${SECURITY_GROUPS//$'\n'/ }"

IAM_INFO=$(get meta-data/iam/info)
if [ $? -eq 0 ]; then
  IAM_ROLE=$(get meta-data/iam/security-credentials/)
  IAM_CREDENTIALS=$(get meta-data/iam/security-credentials/$IAM_ROLE)
  echo
  echo "iam info: $IAM_INFO"
  echo "iam credentials: $IAM_CREDENTIALS"
fi

echo
# These are used by eic_harvest_hostkeys in ec2-instance-connect, not sure if they can be used for anything else
echo "identity-credentials info: $IDENTITY_INFO"
echo "identity-credentials credentials: $IDENTITY_CREDENTIALS"
echo
echo "historical events: $EVENTS_HISTORY"
echo "scheduled events: $EVENTS_SCHEDULED"
echo
echo "instance-identity: $INSTANCE_IDENTITY"

if [ $# -gt 0 ]; then echo; fi
for k in "$@"; do
  echo -n "$k: "
  get "$k"
done

echo
echo "https://$REGION.console.aws.amazon.com/ec2/v2/home?region=$REGION#Instances:instanceId=$INSTANCE_ID;sort=instanceId"

################
##
##
