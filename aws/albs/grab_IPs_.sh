#!/bin/bash

##
##

# shellcheck disable=SC1090
source ~/bin/aws_profile.sh
aws-profile org-main-e1

aws elbv2 describe-load-balancers | jq -r '.LoadBalancers[].DNSName'

# shellcheck disable=SC2086
aws apigateway get-rest-apis | jq -r '.items[] | "https://\(.id).execute-api.'${AWS_DEFAULT_REGION}'.amazonaws.com/\(.tags.STAGE)"'


##
##


# List of AWS account profiles
ACCOUNT_PROFILES=("profile1" "profile2" "profile3" "profile4")

# List of regions to check for ALBs
REGIONS=("us-east-1" "us-west-2" "eu-west-1")

# Array to store public IPs
PUBLIC_IPS=()

# Loop through all AWS account profiles and regions to get the public IPs of ALBs and Global Accelerators
for profile in "${ACCOUNT_PROFILES[@]}"; do
  for region in "${REGIONS[@]}"; do
    # Get public IPs of ALBs in the region
    ALB_IPS=$(aws elbv2 describe-load-balancers --region $region --profile $profile --query "LoadBalancers[].DNSName" --output text | xargs -I {} dig +short {} | sort -u)
    
    # Get public IPs of Global Accelerators in the region
    GA_IPS=$(aws ec2 describe-accelerators --region $region --profile $profile --query "Accelerators[].DnsName" --output text | xargs -I {} dig +short {} | sort -u)
    
    # Combine the list of ALB and Global Accelerator public IPs and add them to the PUBLIC_IPS array
    ALL_IPS=$(echo -e "${ALB_IPS}\n${GA_IPS}")
    for ip in $ALL_IPS; do
      if [ ! -z "$ip" ]; then
        PUBLIC_IPS+=($ip)
      fi
    done
  done
done

# Print the public IPs in JSON format
echo $(printf '{"public_ips": [ "%s" ]}\n' "${PUBLIC_IPS[@]}")

##
##
