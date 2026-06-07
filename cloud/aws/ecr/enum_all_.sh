#!/bin/bash

# Script to list all images and tags in AWS ECR repositories for a specified profile and region.

# Function to display usage information
usage() {
    echo "Usage: $0 -p <AWS_PROFILE> -r <AWS_REGION>"
    echo "  -p  AWS CLI profile name"
    echo "  -r  AWS region"
    exit 1
}

# Parse input arguments for profile and region
while getopts ":p:r:" opt; do
    case $opt in
        p) AWS_PROFILE="$OPTARG" ;;
        r) AWS_REGION="$OPTARG" ;;
        *) usage ;;
    esac
done

# Ensure both profile and region are provided
if [[ -z "$AWS_PROFILE" || -z "$AWS_REGION" ]]; then
    usage
fi

# Validate that AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI is not installed. Please install it to use this script."
    exit 1
fi

echo "Listing all images from ECR repositories in region $AWS_REGION with profile $AWS_PROFILE..."

# Get a list of all ECR repositories
repos=$(aws ecr describe-repositories \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --query 'repositories[*].repositoryName' \
    --output text 2>/dev/null)

# Check if any repositories were found
if [[ -z "$repos" ]]; then
    echo "No repositories found in region $AWS_REGION for profile $AWS_PROFILE."
    exit 0
fi

# Iterate through each repository and list image tags
for repo in $repos; do
    echo "Repository: $repo"

    # Get all image tags for the repository
    image_tags=$(aws ecr list-images \
        --repository-name "$repo" \
        --profile "$AWS_PROFILE" \
        --region "$AWS_REGION" \
        --query 'imageIds[*].imageTag' \
        --output text 2>/dev/null)

    # Check if there are image tags
    if [[ -z "$image_tags" ]]; then
        echo "  No images found."
    else
        # Print each image tag
        for tag in $image_tags; do
            echo "  - Image Tag: $tag"
        done
    fi

    echo # Empty line for separation
done

