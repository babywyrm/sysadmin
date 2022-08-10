#!/usr/bin/env python
##################################
##
##

# -*- coding: UTF-8 -*-

import argparse
import boto3

parser = argparse.ArgumentParser(description='Cleanup Docker images form ECR.')
parser.add_argument('--repository-name', metavar='repo', dest='repository_name', required=True, help='Repository name')
parser.add_argument('--registry-id', metavar='registry', dest='registry_id', required=False, help='Registry ID.If you do not specify a registry, the default registry is assumed.')
parser.add_argument('--delete', dest='delete', required=False, default=False, action='store_true', help='If set to true, delete the untagged images. Otherwise (default), only list them')
args = parser.parse_args()

ecr_client = boto3.client('ecr')

# If the registry-id hasn't been set, fallabck to the default one
registry_id = args.registry_id
if not registry_id:
    sts_client = boto3.client('sts')
    registry_id = sts_client.get_caller_identity()["Account"]
    # Boto-way to retrieve the account, like with the CLI:
    # aws sts get-caller-identity --output text --query 'Account'

# List untagged images
response = ecr_client.describe_images(
    registryId=registry_id,
    repositoryName=args.repository_name,
    filter={
        'tagStatus': 'UNTAGGED'
    }
)


imageIds = []
for imageDetail in response['imageDetails']:
    print "Untagged image pushed at '{date}' with digest '{digest}'".format(digest = imageDetail['imageDigest'], date=imageDetail['imagePushedAt'])
    imageIds.append(
        {
            'imageDigest': imageDetail['imageDigest'],
        }
    )

if args.delete:
    if not len(imageIds):
        print 'No matching image to delete.'
    else:
        print 'Starting to delete these images...'
        response = ecr_client.batch_delete_image(
            registryId=registry_id,
            repositoryName=args.repository_name,
            imageIds=imageIds
        )
        print response

else:
    print 'Dry run, nothing has been deleted. Run the command again with the `--delete` argument to delete these images.'
    
    
##################################
##
##    
