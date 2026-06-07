#!/bin/bash

#
# Define variables
###################

DOCKER_REGISTRY_URL="https://webhosting.lol:5000/v2/"
DOCKER_IMAGE_NAME="prod-app"
DOCKER_IMAGE_TAG="latest"
BEARER_TOKEN="asdfsfasfasdfasxxxxxxNNnwsxDR6U4Ff2UywR3PfQUZOasdflknasdfknL5aMwc6HkKOKhw"

# Get the Docker image manifest
MANIFEST=$(curl -k -sS --header "Authorization: Bearer $BEARER_TOKEN" "${DOCKER_REGISTRY_URL}${DOCKER_IMAGE_NAME}/manifests/${DOCKER_IMAGE_TAG}")

###################
###################

# Extract the layers' digests from the manifest
LAYER_DIGESTS=$(echo "$MANIFEST" | grep -oP '(?<="blobSum": ")[^"]+')

# Create a temporary directory to store the blobs
TMP_DIR=/var/tmp/BLOBS

# Download and extract each blob using tar
for DIGEST in $LAYER_DIGESTS; do
    LAYER_URL="${DOCKER_REGISTRY_URL}${DOCKER_IMAGE_NAME}/blobs/${DIGEST}"
    LAYER_TAR="$TMP_DIR/$(echo $DIGEST | cut -c 8-).tar"
    echo "Downloading blob: $LAYER_URL"
    curl -k -sS --header "Authorization: Bearer $BEARER_TOKEN" --output "$LAYER_TAR" "$LAYER_URL"

    # Extract the contents of the layer
    tar -xf "$LAYER_TAR" -C "$TMP_DIR"
    rm "$LAYER_TAR"
done

# Create the target directory (replace target_directory with the desired destination)
TARGET_DIR="target_directory"
mkdir -p "$TARGET_DIR"

# Move the contents to the target directory
mv "$TMP_DIR"/* "$TARGET_DIR"

# Remove the temporary directory
rmdir "$TMP_DIR"

echo "Blobs converted into files and directories successfully!"

##
##
##
