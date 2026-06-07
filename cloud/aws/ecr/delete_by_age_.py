##
##

import boto3
from datetime import datetime, timedelta
import os,sys,re

def delete_ecr_images_older_than_age(age_days):
    # Replace "your_region" with your AWS region (e.g., 'us-east-1')
    region = 'us-east-2' 

    # Create an ECR client
    ecr_client = boto3.client('ecr', region_name=region)

    # Get a list of all repositories
    response = ecr_client.describe_repositories()
    repositories = response['repositories']

    # Calculate the date 'age_days' days ago
    cutoff_date = datetime.now() - timedelta(days=age_days)

    # Loop through each repository and delete images older than 'age_days'
    for repo in repositories:
        repo_name = repo['repositoryName']
        print(f"Processing repository: {repo_name}")

        # Get the image list for the repository
        response = ecr_client.describe_images(repositoryName=repo_name)
        images = response['imageDetails']

        # Filter images older than 'age_days' and delete them
        for image in images:
            image_pushed_at = image['imagePushedAt']
            pushed_date = image_pushed_at.replace(tzinfo=None)

            if pushed_date < cutoff_date:
                image_digest = image['imageDigest']
                try:
                    ecr_client.batch_delete_image(
                        repositoryName=repo_name,
                        imageIds=[{'imageDigest': image_digest}]
                    )
                    print(f"  Deleted image: {image_digest}")
                except Exception as e:
                    print(f"  Failed to delete image: {image_digest} - {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <age_in_days>")
        sys.exit(1)

    try:
        age_days = int(sys.argv[1])
    except ValueError:
        print("Invalid age value. Please provide a valid integer value for age_in_days.")
        sys.exit(1)

    delete_ecr_images_older_than_age(age_days)

######
######
