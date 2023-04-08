#!/usr/bin/python3

import docker
import syft
import requests

# Define the Docker registry
registry = "my-docker-registry.com"

# Connect to the Docker daemon
client = docker.from_env()

# Define the reusable function to generate SBOM and send it to an endpoint
def send_sbom(image_name, endpoint_url):
    # Load the image
    image = syft.load(f"{registry}/{image_name}")

    # Generate the SBOM
    sbom = image.generate_sbom()

    # Define the headers
    headers = {"Content-Type": "application/json"}

    # Define the payload
    payload = {"sbom": sbom}

    # Send the POST request
    response = requests.post(endpoint_url, json=payload, headers=headers)

    # Check if the request was successful
    if response.status_code == requests.codes.ok:
        print("Success")
    else:
        print(f"Failure: {response.status_code}")

# Call the function to send the SBOM and check for success
send_sbom("nginx:latest", "https://example.com/sbom")

###
###
