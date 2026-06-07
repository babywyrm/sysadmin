#!/usr/bin/python3

import os,sys,re
import requests
import mysql.connector

##
##

ARTIFACTORY_URL = 'https://<your-artifactory-url>/artifactory'
REPO_NAME = 'docker-repo'  # Replace with your repository name

# Define MySQL connection
mysql_config = {
    'user': 'username',
    'password': 'password',
    'host': 'localhost',
    'database': 'database_name'
}
db_connection = mysql.connector.connect(**mysql_config)
db_cursor = db_connection.cursor()

# Create table for search results
db_cursor.execute("""
    CREATE TABLE IF NOT EXISTS docker_images (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        parent_image VARCHAR(255) NOT NULL
    )
""")

def search_images(parent_image, ubuntu_release):
    search_url = f'{ARTIFACTORY_URL}/api/search/artifact'
    search_params = {'docker.parent': parent_image, 'repos': REPO_NAME}

    response = requests.get(search_url, params=search_params)
    if response.status_code == 200:
        results = response.json().get('results')
        # Insert results into MySQL table
        for result in results:
            db_cursor.execute("""
                INSERT INTO docker_images (name, parent_image)
                VALUES (%s, %s)
            """, (result.get('name'), parent_image))
            db_connection.commit()
            print(f"Inserted {result.get('name')} for {ubuntu_release}")
        return results
    else:
        print(f'Error: {response.status_code} - {response.reason}')
        return []

def search_all_images():
    bionic_images = search_images('ubuntu/bionic', 'Bionic')
    focal_images = search_images('ubuntu/focal', 'Focal')
    jammy_images = search_images('ubuntu/jammy', 'Jammy')
    return bionic_images + focal_images + jammy_images

all_images = search_all_images()
for image in all_images:
    print(image.get('name'))

# Close MySQL connection
db_cursor.close()
db_connection.close()

###############
## In this example, we create a MySQL connection using the mysql-connector-python library and define a docker_images table with columns for the Docker image name and the parent image (Ubuntu release). We modify the search_images function to insert the search results into the docker_images table for the corresponding Ubuntu release. Finally, we call search_all_images to perform the search and save the results in the MySQL table.
## You will need to replace the username, password, host, and database_name values in the mysql_config dictionary with your own database connection details.
