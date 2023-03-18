#!/usr/bin/python3

##
##

import requests
import json

class DockerAPI:
    def __init__(self, url):
        self.url = url

    def get_images(self):
        response = requests.get(self.url + '/images/json')
        return json.loads(response.text)

    def get_image_details(self, image_id):
        response = requests.get(self.url + '/images/' + image_id + '/json')
        return json.loads(response.text)

def find_vulnerable_images(docker_api):
    vulnerable_images = []
    images = docker_api.get_images()
    for image in images:
        image_details = docker_api.get_image_details(image['Id'])
        if 'nginx' in image_details['Config']['Cmd'] and any(version in image_details['Config']['Cmd'] for version in ['1.14', '1.15', '1.16']):
            vulnerable_images.append(image_details)
    return vulnerable_images

if __name__ == '__main__':
    docker_api = DockerAPI('http://localhost:2375')
    vulnerable_images = find_vulnerable_images(docker_api)
    print('Vulnerable images:')
    for image in vulnerable_images:
        print(image['RepoTags'])
        
        
##########
##
##        
##
##

import requests
import json
import mysql.connector

class DockerAPI:
    def __init__(self, url):
        self.url = url

    def get_images(self):
        response = requests.get(self.url + '/images/json')
        return json.loads(response.text)

    def get_image_details(self, image_id):
        response = requests.get(self.url + '/images/' + image_id + '/json')
        return json.loads(response.text)

def find_vulnerable_images(docker_api):
    vulnerable_images = []
    images = docker_api.get_images()
    for image in images:
        image_details = docker_api.get_image_details(image['Id'])
        if 'nginx' in image_details['Config']['Cmd'] and any(version in image_details['Config']['Cmd'] for version in ['1.14', '1.15', '1.16']):
            vulnerable_images.append(image_details)
    return vulnerable_images

def save_to_database(vulnerable_images):
    db = mysql.connector.connect(
        host="localhost",
        user="yourusername",
        password="yourpassword",
        database="yourdatabase"
    )
    cursor = db.cursor()
    for image in vulnerable_images:
        name = image['RepoTags'][0]
        version = ''
        for cmd in image['Config']['Cmd']:
            if cmd.startswith('nginx:'):
                version = cmd.split(':')[1]
                break
        cursor.execute("INSERT INTO images (name, version) VALUES (%s, %s)", (name, version))
    db.commit()
    cursor.close()
    db.close()

if __name__ == '__main__':
    docker_api = DockerAPI('http://localhost:2375')
    vulnerable_images = find_vulnerable_images(docker_api)
    print('Vulnerable images:')
    for image in vulnerable_images:
        print(image['RepoTags'])
    save_to_database(vulnerable_images)
    print('Saved vulnerable images to database')

    
###########
###########    

The script defines a DockerAPI class that encapsulates the Docker API calls to retrieve information about the images and their details. The find_vulnerable_images function uses the get_images and get_image_details methods of the DockerAPI class to iterate through all the images in the repository, and checks if they are based on a vulnerable version of Nginx (1.14, 1.15 or 1.16). Finally, the script prints the vulnerable images found.

Note that this script assumes that the Docker API is exposed on http://localhost:2375. You may need to modify the DockerAPI constructor to use a different URL if your Docker daemon is running on a different host or port. Also, make sure you have the requests module installed before running this script.
