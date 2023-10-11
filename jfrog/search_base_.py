
##
##

import argparse
import requests

def search_for_base_image(base_url, repository, base_image):
    # Define API endpoint for listing Docker images
    api_endpoint = f"{base_url}/{repository}/v2/_catalog"

    # Make an HTTP GET request to list Docker images
    response = requests.get(api_endpoint)

    if response.status_code == 200:
        catalog = response.json()
        for image in catalog['repositories']:
            # Define the API endpoint for inspecting Docker image details
            image_inspect_endpoint = f"{base_url}/{repository}/{image}/manifests/latest"
            response = requests.get(image_inspect_endpoint, headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"})
            if response.status_code == 200:
                manifest = response.json()
                config = manifest['config']
                labels = config['config']['Labels']
                if 'io.cobe.base' in labels and 'node' in labels['io.cobe.base']:
                    print(f"Image: {image}, Base Image: {labels['io.cobe.base']}")
    else:
        print(f"Failed to list Docker images: {response.status_code}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search Docker images with a base image containing 'node'.")
    parser.add_argument("--base-url", default="https://your-artifactory-url/artifactory", help="Artifactory base URL")
    parser.add_argument("--repository", default="docker-local", help="Docker repository name")

    args = parser.parse_args()

    search_for_base_image(args.base_url, args.repository, "node")

##
##
