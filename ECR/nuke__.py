#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone

# Define age threshold (200 days)
AGE_THRESHOLD_DAYS = 200

def get_registry_id(args):
    """Retrieve the registry ID, falling back to the default account if not provided."""
    if args.registry_id:
        return args.registry_id
    sts_client = boto3.client('sts')
    return sts_client.get_caller_identity()["Account"]

def list_old_images(ecr_client, registry_id, repository_name, age_threshold_days):
    """Retrieve images older than the specified age threshold."""
    try:
        # Fetch all images from the repository
        response = ecr_client.describe_images(
            registryId=registry_id,
            repositoryName=repository_name
        )
        images = response.get('imageDetails', [])
        
        # Calculate the cutoff date for deletion, making it timezone-aware
        cutoff_date = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=age_threshold_days)
        
        # Filter images older than the cutoff date
        old_images = [
            image for image in images
            if 'imagePushedAt' in image and image['imagePushedAt'] < cutoff_date
        ]
        
        return old_images
    except ClientError as e:
        print(f"Error retrieving images: {e}")
        return []

def delete_images(ecr_client, registry_id, repository_name, image_ids):
    """Delete specified images from the repository."""
    try:
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
                        help='If set to true, delete the old and untagged images. Otherwise, only list them')
    args = parser.parse_args()

    # Initialize the ECR client
    ecr_client = boto3.client('ecr')
    registry_id = get_registry_id(args)

    # List images older than the threshold
    old_images = list_old_images(ecr_client, registry_id, args.repository_name, AGE_THRESHOLD_DAYS)
    image_ids = [{'imageDigest': image['imageDigest']} for image in old_images]

    # Print images older than the threshold
    if image_ids:
        for image in old_images:
            pushed_date = image['imagePushedAt'].strftime('%Y-%m-%d %H:%M:%S')
            print(f"Image older than {AGE_THRESHOLD_DAYS} days, pushed at '{pushed_date}', digest '{image['imageDigest']}'")
    else:
        print(f"No images older than {AGE_THRESHOLD_DAYS} days found.")

    # Delete images if --delete flag is set
    if args.delete:
        if image_ids:
            print(f"Starting to delete images older than {AGE_THRESHOLD_DAYS} days...")
            delete_images(ecr_client, registry_id, args.repository_name, image_ids)
        else:
            print("No matching images to delete.")
    else:
        print("Dry run, nothing has been deleted. Run the command again with the `--delete` argument to delete these images.")

if __name__ == "__main__":
    main()

##
##
