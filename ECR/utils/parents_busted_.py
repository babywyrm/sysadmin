  1 import boto3
  2 import json
  3 
  4 # Set up the ECR client
  5 ecr = boto3.client('ecr')
  6 
  7 # Get a list of all the ECR repositories
  8 response = ecr.describe_repositories()
  9 repositories = response['repositories']
 10 
 11 # Loop through each repository
 12 results = {}
 13 for repo in repositories:
 14     repo_name = repo['repositoryName']
 15     print(f'Inspecting repository: {repo_name}')
 16 
 17     # Get a list of all the images in the repository
 18     response = ecr.list_images(repositoryName=repo_name)
 19     image_ids = response['imageIds']
 20 
 21     # Loop through each image in the repository
 22     for image_id in image_ids:
 23         image_digest = image_id['imageDigest']
 24         image_tag = image_id.get('imageTag', 'None')
 25 
 26         # Get the manifest for the image
 27         response = ecr.batch_get_image(
 28             repositoryName=repo_name,
 29             imageIds=[{'imageDigest': image_digest}]
 30         )
 31         image_manifest = response['images'][0]['imageManifest']
 32 
 33         # Parse the manifest to get the upstream and parent images
 34         manifest_json = json.loads(image_manifest)
 35         upstream_image = manifest_json.get('config', {}).get('Labels', {}).get('upstream_image', 'None')
 36         parent_image = manifest_json.get('config', {}).get('Labels', {}).get('parent_image', 'None')
 37 
 38         # Add the image, tag, upstream image, and parent image to the results dictionary
 39         results[f'{repo_name}:{image_tag}'] = {
 40             'upstream_image': upstream_image,
 41             'parent_image': parent_image
 42         }
 43 
 44 # Save the results to disk in a nice and pretty JSON format
 45 with open('ecr_images.json', 'w') as outfile:
 46     json.dump(results, outfile, indent=4)
 47 
~                                                                                                                                                                                                                                       
~                                                                                                                                                                                                                                       
~                                                                                                                                                                                                                                       
~                 
