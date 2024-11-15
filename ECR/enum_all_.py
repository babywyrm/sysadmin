import boto3
import argparse
import os,sys,re
from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError

##
##

def list_ecr_images(profile, region):
    # Initialize a session using the specified profile and region
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        ecr_client = session.client('ecr')
    except ProfileNotFound:
        print(f"Error: The AWS profile '{profile}' was not found.")
        sys.exit(1)
    except NoCredentialsError:
        print("Error: No valid AWS credentials found.")
        sys.exit(1)

    try:
        # Retrieve list of repositories
        response = ecr_client.describe_repositories()
        repositories = response.get('repositories', [])
        
        if not repositories:
            print(f"No repositories found in region '{region}' for profile '{profile}'.")
            return

        print(f"Listing all images from ECR repositories in region '{region}' with profile '{profile}':")
        
        # Iterate over repositories and list images
        for repo in repositories:
            repo_name = repo['repositoryName']
            print(f"Repository: {repo_name}")

            # List images in the repository
            images = ecr_client.list_images(repositoryName=repo_name)
            image_tags = [img['imageTag'] for img in images.get('imageIds', []) if 'imageTag' in img]
            
            if not image_tags:
                print("  No images found.")
            else:
                for tag in image_tags:
                    print(f"  - Image Tag: {tag}")
            print()  # Blank line for separation

    except ClientError as e:
        print(f"Error: Unable to retrieve repositories or images - {e}")
        sys.exit(1)

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="List all images in AWS ECR repositories for a specified profile and region.")
    parser.add_argument('-p', '--profile', required=True, help="AWS CLI profile name")
    parser.add_argument('-r', '--region', required=True, help="AWS region")

    args = parser.parse_args()

    # List ECR images based on provided arguments
    list_ecr_images(args.profile, args.region)

if __name__ == "__main__":
    main()
  
##
##
