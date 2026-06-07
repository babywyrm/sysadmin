#!/bin/bash

##
## move based on base image of focal
##

source_registry="your_source_ecr_registry_url"
source_registry_user="your_source_ecr_registry_username"
source_registry_password="your_source_ecr_registry_password"
source_repository_prefix="your_source_ecr_repository_prefix"

destination_registry="your_destination_ecr_registry_url"
destination_registry_user="your_destination_ecr_registry_username"
destination_registry_password="your_destination_ecr_registry_password"
destination_repository_prefix="your_destination_ecr_repository_prefix"

##########
##########

# Authenticate to the source registry
echo "Authenticating to the source registry..."
aws ecr get-login-password --region your_region | docker login --username $source_registry_user --password-stdin $source_registry

# Authenticate to the destination registry
echo "Authenticating to the destination registry..."
aws ecr get-login-password --region your_region | docker login --username $destination_registry_user --password-stdin $destination_registry

# Get a list of all images in the source registry
echo "Getting a list of all images in the source registry..."
images=$(aws ecr list-images --region your_region --repository-name $source_repository_prefix --filter "tagStatus=TAGGED" --query 'imageIds[*]' --output json)

# Loop through each image and move it to the destination registry
echo "Moving images to the destination registry..."
for image in $(echo "${images}" | jq -r '.[].imageDigest'); do
    # Get the image tags
    tags=$(aws ecr describe-images --region your_region --repository-name $source_repository_prefix --image-ids imageDigest=$image --query 'imageDetails[*].imageTags' --output json)

    # Loop through each tag and move the image to the destination registry
    for tag in $(echo "${tags}" | jq -r '.[] | select(. != null)'); do
        # Check if the image has a parent image of Ubuntu Focal
        parent_image=$(docker inspect --format='{{.Parent}}' "$source_registry/$source_repository_prefix:$tag" | awk -F':' '{print $2}')
        if [[ "$parent_image" == "focal" ]]; then
            # Create the repository in the destination registry if it doesn't exist
            aws ecr describe-repositories --region your_region --repository-names $destination_repository_prefix > /dev/null 2>&1 || aws ecr create-repository --region your_region --repository-name $destination_repository_prefix

            # Pull the image from the source registry
            docker pull "$source_registry/$source_repository_prefix:$tag"

            # Tag the image with the destination registry and repository
            docker tag "$source_registry/$source_repository_prefix:$tag" "$destination_registry/$destination_repository_prefix:$tag"

            # Push the image to the destination registry
            docker push "$destination_registry/$destination_repository_prefix:$tag"

            # Remove the image from the local cache
            docker image rm "$source_registry/$source_repository_prefix:$tag"
            docker image rm "$destination_registry/$destination_repository_prefix:$tag"
        fi
    done
done

echo "Done."
