#!/usr/bin/python3

##
##

import os,sys,re
import subprocess
import json

# Set the AWS region and repository name
region = "us-west-2"
repository_name = "my-ecr-repo"

# Authenticate with AWS ECR
auth_cmd = f"aws ecr get-login --no-include-email --region {region}"
subprocess.call(auth_cmd, shell=True)

# Get the list of images and tags in the repository
inventory_cmd = f"syft inventory aws_ecr:{region}/{repository_name} -o json"
inventory_output = subprocess.check_output(inventory_cmd, shell=True)
inventory = json.loads(inventory_output)

# Loop through each image and tag in the repository
for image in inventory:
    image_uri = image["image"]
    tags = image["tags"]

    # Loop through each tag for the current image
    for tag in tags:
        # Scan the image for vulnerabilities using Gruype
        scan_cmd = f"grype -r aws-ecr:{region}/{repository_name}:{tag} -o json"
        scan_output = subprocess.check_output(scan_cmd, shell=True)
        vulnerabilities = json.loads(scan_output)

        # Save the results to a dictionary
        results = {
            "image": image_uri,
            "tag": tag,
            "vulnerabilities": vulnerabilities
        }

        # Print the results to the screen
        print(json.dumps(results, indent=4))

        # Save the results to a file
        with open("ecr_report.json", "a") as report_file:
            json.dump(results, report_file)
            report_file.write("\n")
            
            
##  This script should scan every image and tag in the specified AWS ECR repository, report vulnerabilities in neat JSON format,
##   and print the results to the screen and save them to a file named "ecr_report.json" in the same directory as the script.
      
