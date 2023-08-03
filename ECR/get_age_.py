#!/usr/bin/python3

######
##
##

import boto3
from datetime import datetime, timedelta
import os,sys,re

def list_ecr_images_older_than_age(age_days):
    # Replace "your_region" with your AWS region (e.g., 'us-east-1')
    region = 'us-east-2'

    # Create an ECR client
    ecr_client = boto3.client('ecr', region_name=region)

    # Get a list of all repositories
    response = ecr_client.describe_repositories()
    repositories = response['repositories']

    # Calculate the date 'age_days' days ago
    cutoff_date = datetime.now() - timedelta(days=age_days)

    # Loop through each repository and list images older than 'age_days'
    for repo in repositories:
        repo_name = repo['repositoryName']
        print(f"Repository: {repo_name}")

        # Get the image list for the repository
        response = ecr_client.describe_images(repositoryName=repo_name)
        images = response['imageDetails']

        # Filter images older than 'age_days'
        for image in images:
            image_pushed_at = image['imagePushedAt']
            pushed_date = image_pushed_at.replace(tzinfo=None)

            if pushed_date < cutoff_date:
                image_tags = image['imageTags'] if 'imageTags' in image else ['<none>']
                print(f"  Tags: {', '.join(image_tags)}")
                print(f"  Pushed At: {pushed_date}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <age_in_days>")
        sys.exit(1)

    try:
        age_days = int(sys.argv[1])
    except ValueError:
        print("Invalid age value. Please provide a valid integer value for age_in_days.")
        sys.exit(1)

    list_ecr_images_older_than_age(age_days)

#####
#####

