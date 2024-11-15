#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import boto3
from botocore.exceptions import ClientError

##
##

def get_registry_id(args):
    # If the registry-id hasn't been set, fall back to the default one by fetching the account ID.
    if args.registry_id:
        return args.registry_id
    sts_client = boto3.client('sts')
    return sts_client.get_caller_identity()["Account"]

def list_untagged_images(ecr_client, registry_id, repository_name):
    try:
        # List untagged images in the specified repository
        response = ecr_client.describe_images(
            registryId=registry_id,
            repositoryName=repository_name,
            filter={'tagStatus': 'UNTAGGED'}
        )
        return response.get('imageDetails', [])
    except ClientError as e:
        print(f"Error retrieving untagged images: {e}")
        return []

def delete_images(ecr_client, registry_id, repository_name, image_ids):
    try:
        # Delete specified images from the repository
        response = ecr_client.batch_delete_image(
            registryId=registry_id,
            repositoryName=repository_name,
            imageIds=image_ids
        )
        print("Deleted images:", response.get('imageIds', []))
    except ClientError as e:
        print(f"Error deleting images: {e}")

def main():
    parser = argparse.ArgumentParser(description='Cleanup Docker images from ECR.')
    parser.add_argument('--repository-name', metavar='repo', dest='repository_name', required=True,
                        help='Repository name')
    parser.add_argument('--registry-id', metavar='registry', dest='registry_id', required=False,
                        help='Registry ID. If you do not specify a registry, the default registry is assumed.')
    parser.add_argument('--delete', dest='delete', action='store_true', default=False,
                        help='If set to true, delete the untagged images. Otherwise, only list them')
    args = parser.parse_args()

    # Initialize the ECR client
    ecr_client = boto3.client('ecr')
    registry_id = get_registry_id(args)

    # List untagged images
    image_details = list_untagged_images(ecr_client, registry_id, args.repository_name)
    image_ids = [{'imageDigest': image['imageDigest']} for image in image_details]

    # Print the untagged images
    if image_ids:
        for image in image_details:
            print(f"Untagged image pushed at '{image['imagePushedAt']}' with digest '{image['imageDigest']}'")
    else:
        print("No untagged images found.")

    # Delete images if --delete flag is set
    if args.delete:
        if image_ids:
            print("Starting to delete these images...")
            delete_images(ecr_client, registry_id, args.repository_name, image_ids)
        else:
            print("No matching images to delete.")
    else:
        print("Dry run, nothing has been deleted. Run the command again with the `--delete` argument to delete these images.")

if __name__ == "__main__":
    main()

##
##
