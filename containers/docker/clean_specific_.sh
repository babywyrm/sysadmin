#!/bin/bash

##
# Set the default list of images to exclude
exclude_images=("things" "morethings")

# Check if any command-line arguments are provided
if [ $# -gt 0 ]; then
    # Override the default list with the provided arguments
    exclude_images=("$@")
fi

# Get a list of all Docker image IDs
image_ids=$(docker images -q)

# Loop through each image ID
for image_id in $image_ids
do
    # Check if the image ID is not in the list of excluded images
    if [[ ! " ${exclude_images[@]} " =~ " ${image_id} " ]]; then
        # Delete the image by its ID
        docker image rm -f "$image_id"
    fi
done

##

