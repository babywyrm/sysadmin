
######
######

import argparse
import requests

def search_for_package(base_url, repository, package_name):
    # Define API endpoint for listing Docker images
    api_endpoint = f"{base_url}/{repository}/v2/_catalog"

    # Make an HTTP GET request to list Docker images
    response = requests.get(api_endpoint)

    if response.status_code == 200:
        catalog = response.json()
        for image in catalog['repositories']:
            # Define the API endpoint for listing tags of each image
            image_tags_endpoint = f"{base_url}/{repository}/{image}/tags/list"
            response = requests.get(image_tags_endpoint)
            if response.status_code == 200:
                tags = response.json()
                if package_name in tags['tags']:
                    print(f"Image: {image}, Tag: {package_name}")
    else:
        print(f"Failed to list Docker images: {response.status_code}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search Docker images and tags for a specific package.")
    parser.add_argument("package_name", help="Name of the package to search for")
    parser.add_argument("--base-url", default="https://your-artifactory-url/artifactory", help="Artifactory base URL")
    parser.add_argument("--repository", default="docker-local", help="Docker repository name")

    args = parser.parse_args()

    search_for_package(args.base_url, args.repository, args.package_name)

######
######
##
##
