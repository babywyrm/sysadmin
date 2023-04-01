#!/bin/bash

##
##

# Get the list of regions for the account
regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

# Loop over each region
for region in $regions; do
    echo "Region: $region"

    # Get the list of instances in the region
    instances=$(aws ec2 describe-instances --region $region --query 'Reservations[].Instances[].[InstanceId, LaunchTime, Tags[?Key==`eks:cluster-name`].Value[]]' --output text)

    # Loop over each instance in the region
    while read instance launch_time cluster; do
        echo -e "\tInstance: $instance (Launched at: $launch_time)"

        # Check if the instance is part of an EKS cluster
        if [ -n "$cluster" ]; then
            echo -e "\t\tThis instance is part of the EKS cluster: $cluster"
        fi
    done <<< "$instances"
done

##
##
