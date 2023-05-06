#!/usr/bin/python3

import os,sys,re

from github import Github
from spdx.creationinfo import Tool
from spdx.document import Document, License
from spdx.package import Package
from spdx.version import Version
from spdx.file import File

###
###

# GitHub API access token
access_token = 'YOUR_ACCESS_TOKEN'
github_client = Github(access_token)

def get_docker_image_info(repository_name, image_name):
    repo = github_client.get_repo(repository_name)
    dockerfile_contents = repo.get_file_contents('Dockerfile').decoded_content.decode()

    # Extract relevant information from the Dockerfile contents or other relevant files
    # such as dependencies, packages, libraries, etc.
    
    # Example: Parsing dependencies from Dockerfile
    dependencies = []
    for line in dockerfile_contents.split('\n'):
        if 'RUN' in line and 'apt-get install' in line:
            packages = line.split('apt-get install')[1].strip().replace('\\', '').split()
            dependencies.extend(packages)

    return {
        'repository': repository_name,
        'image': image_name,
        'dependencies': dependencies,
        # Add more relevant information as needed
    }

def generate_spdx_sbom(repository_name, image_name):
    image_info = get_docker_image_info(repository_name, image_name)

    # Create SPDX document
    document = Document()
    document.version = Version(2, 1)
    document.creation_info = Tool('OpenAI ChatGPT')

    # Create SPDX package
    package = Package(f'{repository_name}::{image_name}')
    package.conc_lics = [License.from_identifier('NOASSERTION')]

    # Add dependencies as files
    for dependency in image_info['dependencies']:
        file_ = File(dependency)
        package.add_file(file_)

    # Add package to document
    document.add_package(package)

    # Generate SPDX SBOM
    spdx_sbom = document.to_tagged_value()

    return spdx_sbom

def generate_sbom_for_repositories(repositories):
    for repository in repositories:
        repository_name, image_name = repository
        spdx_sbom = generate_spdx_sbom(repository_name, image_name)
        spdx_file_name = f"{repository_name}_{image_name}.spdx"

        with open(spdx_file_name, 'w') as spdx_file:
            spdx_file.write(spdx_sbom)

        print(f"SBOM generated for {repository_name}::{image_name} and saved to {spdx_file_name}")

# List of repositories in the format ('repository_name', 'image_name')
repositories_list = [
    ('your/repository1', 'image1'),
    ('your/repository2', 'image2'),
    ('your/repository3', 'image3')
]

generate_sbom_for_repositories(repositories_list)


###
###

Make sure to replace 'YOUR_ACCESS_TOKEN', 'your/repository1', 'your/repository2', etc., with your actual values. The repositories_list variable holds the list of repositories and their respective image names for which you want to generate SBOMs.

This script utilizes the spdx library to create SPDX documents, packages, and files. It fetches the Dockerfile from each GitHub repository, extracts the relevant information (in this case, dependencies), and generates SPDX SBOMs in SPDX format for each repository. The generated SBOMs are saved as separate SPDX files with names based on the repository and image names.

Note: The SPDX format is an open standard for software bill of materials. You may need to install the spdx library using `pip install sp
