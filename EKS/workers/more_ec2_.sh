#!/bin/bash

##
##

# Retrieve the details of all EC2 instances in the current region
instances=$(aws ec2 describe-instances --query 'Reservations[*].Instances[*].{InstanceId:InstanceId,LaunchTime:LaunchTime,ImageId:ImageId,Cluster:Tags[?Key==`eks:cluster-name`]|[0].Value}' --output json)

# Print the details of each instance in a table format
echo "----------------------------------------------------------------"
echo "| Instance ID |  Launch Time          |  Cluster        |  AMI ID |"
echo "----------------------------------------------------------------"
echo "$instances" | jq -r '.[] | .[] | [.InstanceId, .LaunchTime, .Cluster, .ImageId] | @tsv' | while read -r instance_id launch_time cluster ami_id; do
  if [ ! -z "$cluster" ]; then
    echo "| $instance_id | $launch_time | $cluster   | $ami_id |"
  else
    echo "| $instance_id | $launch_time | standalone | $ami_id |"
  fi
done
echo "----------------------------------------------------------------"

##
##

