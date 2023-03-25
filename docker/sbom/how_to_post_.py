#!/usr/bin/python3

##########
##########
## This script first creates a Docker client object and retrieves a list of all images in the Docker registry. 
## It then loops through each image and generates an SBOM using anchore-engine's get_image_policy_evaluation function. 
## The SBOM is then converted to JSON and sent to the POST endpoint using requests.post. 
## Finally, the old image is deleted using client.images.remove. The script also prints a message when the process is complete.
## Note that you'll need to replace the values for docker_registry and post_endpoint_url with your own values. 
## You may also need to modify the code to handle authentication to the Docker registry and the POST endpoint, if required.

####
####

import docker
import anchore_engine.clients.services.common
import requests
import json

# Replace these with your own values
docker_registry = 'docker.io'
post_endpoint_url = 'https://example.com/sboms'

# Create Docker client
client = docker.from_env()

# Retrieve a list of all images in the Docker registry
images = client.images.list()

# Loop through each image and do the following:
#   * Generate an SBOM using anchore-engine
#   * Retag the image with a new tag
#   * Send the SBOM to the POST endpoint
#   * Delete the old image
for image in images:
    sbom = anchore_engine.clients.services.common.get_image_policy_evaluation(client, image.id)
    sbom_json = json.dumps(sbom, indent=4)
    new_tag = image.tags[0] + "-sbom"
    client.images.get(image.id).tag(new_tag)
    response = requests.post(post_endpoint_url, data=sbom_json)
    client.images.remove(image.id)

print("SBOM generation and upload complete.")




###
###

To get an SBOM (Software Bill of Materials) of each image in a Docker registry and then send each SBOM towards a POST endpoint after retagging each image, you can use the following steps:

Install the necessary tools:

Docker client
Trivy (SBOM generator)
jq (JSON processor)
curl (HTTP client)
Log in to the Docker registry using the Docker client.

php
Copy code
docker login <registry-url>
Retrieve a list of all images in the Docker registry using the Docker client.

arduino
Copy code
docker image ls --format "{{.Repository}}:{{.Tag}}" <registry-url>
Loop through each image and do the following:

Generate an SBOM using Trivy.
Retag the image with a new tag.
Send the SBOM to the POST endpoint using curl.
Delete the old image.
bash
Copy code
for image in $(docker image ls --format "{{.Repository}}:{{.Tag}}" <registry-url>); do
    sbom=$(trivy sbom --format json $image | jq -c '.')
    new_tag=$(echo $image | sed 's/:/-sbom:/')
    docker tag $image $new_tag
    curl -X POST -H "Content-Type: application/json" -d "$sbom" <post-endpoint-url>
    docker image



Travis Schaffner
with python3, get an SBOM of each image in a docker registry and then send each SBOM towards a POST endpoint after retagging each image 
To get an SBOM of each image in a Docker registry using Python3 and send each SBOM towards a POST endpoint after retagging each image, you can use the following steps:

Install the necessary Python packages:

docker (to interact with the Docker daemon)
anchore-engine (SBOM generator)
requests (to make HTTP requests)
Copy code
pip install docker anchore-engine requests
Create a Python script and import the necessary packages.

arduino
Copy code
import docker
import anchore_engine.clients.services.common
import requests
import json
Create a Docker client object to interact with the Docker daemon.

makefile
Copy code
client = docker.from_env()
Retrieve a list of all images in the Docker registry using the Docker client.

makefile
Copy code
images = client.images.list()
Loop through each image and do the following:

Generate an SBOM using anchore-engine.
Retag the image with a new tag.
Send the SBOM to the POST endpoint using requests.
Delete the old image.
css
Copy code
for image in images:
    sbom = anchore_engine.clients.services.common.get_image_policy_evaluation(client, image.id)
    sbom_json = json.dumps(sbom, indent=4)
    new_tag = image.tags[0] + "-sbom"
    client.images.get(image.id).tag(new_tag)
    response = requests.post("<post-endpoint-url>", data=sbom_json)
    client.images.remove(image.id)
Note: Replace <post-endpoint-url> with the URL of the endpoint where you want to send the SBOMs. You may also need to modify the code to handle authentication to the Docker registry and the POST endpoint, if required.
