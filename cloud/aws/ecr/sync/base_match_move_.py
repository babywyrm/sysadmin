#!/usr/bin/python3

##
##

import os
import boto3
import docker

# Set the source and destination registry information
source_registry = "your_source_ecr_registry_url"
source_repository_prefix = "your_source_ecr_repository_prefix"
destination_registry = "your_destination_ecr_registry_url"
destination_repository_prefix = "your_destination_ecr_repository_prefix"

# Authenticate to the AWS ECR registries
session = boto3.Session(region_name='your_region')
source_ecr = session.client('ecr')
source_token = source_ecr.get_authorization_token()
source_registry_user = 'AWS'
source_registry_password = source_token['authorizationData'][0]['authorizationToken']
source_registry_password = base64.b64decode(source_registry_password).decode('utf-8').split(':')[1]
source_docker = docker.from_env()
source_docker.login(username=source_registry_user, password=source_registry_password, registry=source_registry)

destination_ecr = session.client('ecr')
destination_token = destination_ecr.get_authorization_token()
destination_registry_user = 'AWS'
destination_registry_password = destination_token['authorizationData'][0]['authorizationToken']
destination_registry_password = base64.b64decode(destination_registry_password).decode('utf-8').split(':')[1]
destination_docker = docker.from_env()
destination_docker.login(username=destination_registry_user, password=destination_registry_password, registry=destination_registry)

# Get a list of all images in the source registry
images = source_ecr.list_images(repositoryName=source_repository_prefix, filter={'tagStatus': 'TAGGED'})['imageIds']

# Loop through each image and move it to the destination registry
for image in images:
    # Get the image tags
    tags = source_ecr.describe_images(repositoryName=source_repository_prefix, imageIds=[{'imageDigest': image['imageDigest']}])['imageDetails'][0]['imageTags']

    # Loop through each tag and move the image to the destination registry
    for tag in tags:
        # Check if the image has a parent image of Ubuntu Focal
        image_info = source_docker.images.get(f"{source_registry}/{source_repository_prefix}:{tag}")
        parent_image = image_info.attrs['Parent'].split(':')[-1]
        if parent_image == 'focal':
            # Create the repository in the destination registry if it doesn't exist
            try:
                destination_ecr.describe_repositories(repositoryNames=[destination_repository_prefix])
            except:
                destination_ecr.create_repository(repositoryName=destination_repository_prefix)

            # Pull the image from the source registry
            source_docker.images.pull(f"{source_registry}/{source_repository_prefix}:{tag}")

            # Tag the image with the destination registry and repository
            destination_docker.images.get(f"{source_registry}/{source_repository_prefix}:{tag}").tag(f"{destination_registry}/{destination_repository_prefix}:{tag}")

            # Push the image to the destination registry
            destination_docker.images.push(f"{destination_registry}/{destination_repository_prefix}:{tag}")

            # Remove the image from the local cache
            source_docker.images.remove(f"{source_registry}/{source_repository_prefix}:{tag}")
            destination_docker.images.remove(f"{destination_registry}/{destination_repository_prefix}:{tag}")

print("Done.")

##
##
