#!/bin/bash
#
# Deploy script to manage Terraform lifecycle

# Function to handle cleanup
cleanup() {
    echo "Running cleanup script at $(date)" >> /tmp/terraform_cleanup.log
    ./cleanup.sh >> /tmp/terraform_cleanup.log 2>&1
    echo "Cleanup script completed at $(date)" >> /tmp/terraform_cleanup.log
}

# Function to handle Terraform destroy and cleanup
destroy_and_cleanup() {
    echo "Destroying Terraform resources..."
    terraform destroy -auto-approve
    cleanup
}

# Function to retrieve and print public IP
print_public_ip() {
    instance_id=$1
    public_ip=$(terraform state show aws_instance.my_instance | grep public_ip | awk '{print $3}')
    echo "Public IP address of instance ${instance_id}: ${public_ip}"
}

# Function to handle main deployment and lifecycle
deploy() {
    # Initialize Terraform (if not already initialized)
    terraform init

    # Apply Terraform configuration
    terraform apply -auto-approve

    # Get the duration for the instance to be up (in minutes)
    duration_minutes=$1

    # Print instance public IP
    instance_id=$(terraform state show aws_instance.my_instance | grep id | awk '{print $3}')
    print_public_ip "${instance_id}"

    # Sleep for the specified duration
    echo "Vulnerable Instance will be up for $duration_minutes minutes..."
    sleep "$((duration_minutes * 60))"  # Convert minutes to seconds

    # Call destroy_and_cleanup function
    destroy_and_cleanup
}

# Main execution starts here
if [ $# -ne 1 ]; then
    echo "Usage: $0 <duration_in_minutes>"
    exit 1
fi

# Assuming Terraform files are in the current directory where the script is run
deploy "$1"

##
##
#
