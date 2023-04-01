#!/bin/bash

# Get a list of all AWS regions
regions=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)

# Iterate through each region
for region in $regions
do
  echo "Region: $region"
  
  # Get a list of all EC2 instances in the region
  instances=$(aws ec2 describe-instances --region $region --query "Reservations[*].Instances[*].{InstanceId:InstanceId,Tags:Tags[*]}" --output json)
  
  # Iterate through each instance
  for instance in $(echo "$instances" | jq -r '.[] | @base64')
  do
    _jq() {
      echo ${instance} | base64 --decode | jq -r ${1}
    }
    
    instance_id=$(_jq '.InstanceId')
    tags=$(_jq '.Tags')
    eks_cluster=$(echo "$tags" | jq -r '.[] | select(.Key=="eks:cluster-name") | .Value')
    
    echo -e "\tInstance: $instance_id (EKS Cluster: $eks_cluster)"
  done
done

##
##
