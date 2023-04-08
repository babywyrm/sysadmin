#!/usr/bin/python3 
import docker
import syft
import requests

# Define the Docker registry
registry_url = "registry.example.com"
registry_username = "user"
registry_password = "password"

# Create a Docker client
client = docker.from_env()

# Define a function to collect SBOM and send it to an external endpoint
def send_sbom(image_name, endpoint_url):
    # Pull the Docker image
    image = client.images.pull(image_name)
    
    # Get the image digest hash
    digest = image.attrs['RepoDigests'][0].split('@')[1]
    
    # Collect the SBOM using Syft
    sbom = syft.build_sbom(image_name, extra_options="--platform linux/amd64")
    
    # Define the headers and payload for the POST request
    headers = {"Content-Type": "application/json"}
    payload = {"digest": digest, "sbom": sbom}
    
    # Send the POST request to the external endpoint
    response = requests.post(endpoint_url, headers=headers, json=payload, auth=(registry_username, registry_password))
    
    # Check the response status code
    if response.status_code == 200:
        # Check if the SBOM already exists
        if response.json().get("status") == "SBOM already exists":
            print("SBOM already exists")
            return "failure"
        else:
            print("Success")
            return "success"
    else:
        print("Failure")
        return "failure"
      
###
###     
# You can use this function to send SBOMs to any external endpoint by passing in the image name and endpoint URL as arguments. 
# Here's an example:

image_name = "nginx:latest"
endpoint_url = "https://example.com/api/collect_sbom"
result = send_sbom(image_name, endpoint_url)

###
###
### Note that this script assumes that the Syft tool is installed on your system and can be called using the syft.build_sbom() function. 
### Additionally, you will need to replace the registry_url, registry_username, and registry_password variables with the appropriate values for your Docker registry. 
###Finally, you will need to replace the endpoint_url variable with the URL of the external endpoint where you want to send the SBOM.
