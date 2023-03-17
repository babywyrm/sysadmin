## You can use Python and the requests library to search for all Docker images in Artifactory that have a parent image of Ubuntu Bionic, Focal, and Jammy.
##
##
#!/usr/bin/python

import os.sys.re
import requests

ARTIFACTORY_URL = 'https://<your-artifactory-url>/artifactory'
REPO_NAME = 'docker-repo'  # Replace with your repository name

def search_images(parent_image):
    search_url = f'{ARTIFACTORY_URL}/api/search/artifact'
    search_params = {'docker.parent': parent_image, 'repos': REPO_NAME}

    response = requests.get(search_url, params=search_params)
    if response.status_code == 200:
        results = response.json().get('results')
        return results
    else:
        print(f'Error: {response.status_code} - {response.reason}')
        return []

def search_all_images():
    bionic_images = search_images('ubuntu/bionic')
    focal_images = search_images('ubuntu/focal')
    jammy_images = search_images('ubuntu/jammy')
    return bionic_images + focal_images + jammy_images

all_images = search_all_images()
for image in all_images:
    print(image.get('name'))
    
    
#########
## In this example, we define a search_images function that takes in the name of a parent image (e.g., ubuntu/bionic) and returns a list of Docker images in the docker-repo repository that have that parent image. We then define a search_all_images function that calls search_images for each of the Ubuntu releases we want to search for (Bionic, Focal, and Jammy) and returns a combined list of all Docker images found. Finally, we call search_all_images and loop over the results to print out the name of each Docker image found.
## You can modify this script to perform different actions with the search results based on your specific use case.
