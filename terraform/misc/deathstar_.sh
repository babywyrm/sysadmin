#!/bin/bash

##
##

echo "Cleanup script started at $(date)"

# Function to clean up resources from the Terraform state
cleanup_state() {
  echo "Cleaning up remaining resources from state"
  while terraform state list | grep -q .; do
    for resource in $(terraform state list); do
      echo "Removing resource: $resource"
      terraform state rm "$resource"
    done
    echo "Sleeping for 20 seconds to ensure resources are being removed properly"
    sleep 7 
  done
}

# Initial destroy to attempt to remove all resources
echo "Starting initial terraform destroy at $(date)"
terraform destroy -auto-approve -lock=false
echo "Initial terraform destroy completed at $(date)"

# Cleanup state
cleanup_state

# Final destroy to ensure all resources are gone
echo "Starting final terraform destroy at $(date)"
terraform destroy -auto-approve -lock=false
echo "Final terraform destroy completed at $(date)"

# Remove any remaining AWS Secrets Manager secrets (if necessary)
AWS_REGION=$(aws configure get region)
echo "Using AWS region: $AWS_REGION"
aws secretsmanager list-secrets --region $AWS_REGION --query 'SecretList[].ARN' --output text | xargs -n1 -I {} aws secretsmanager delete-secret --secret-id {} --force-delete-without-recovery

# Verify no resources remain
terraform state list

##
###
echo "Cleanup script completed at $(date)"

##
