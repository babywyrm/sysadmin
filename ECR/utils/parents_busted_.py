import boto3
import json

# Set up the ECR client
ecr = boto3.client('ecr')

# Get a list of all the ECR repositories
response = ecr.describe_repositories()
repositories = response['repositories']

# Loop through each repository
results = {}
for repo in repositories:
    repo_name = repo['repositoryName']
    print(f'Inspecting repository: {repo_name}')

    # Get a list of all the images in the repository
    response = ecr.list_images(repositoryName=repo_name)
    image_ids = response['imageIds']

    # Loop through each image in the repository
    for image_id in image_ids:
        image_digest = image_id['imageDigest']
        image_tag = image_id.get('imageTag', 'None')

        # Get the manifest for the image
        response = ecr.batch_get_image(
            repositoryName=repo_name,
            imageIds=[{'imageDigest': image_digest}]
        )
        image_manifest = response['images'][0]['imageManifest']

        # Parse the manifest to get the upstream and parent images
        manifest_json = json.loads(image_manifest)
        upstream_image = manifest_json.get('config', {}).get('Labels', {}).get('upstream_image', 'None')
        parent_image = manifest_json.get('config', {}).get('Labels', {}).get('parent_image', 'None')

        # Add the image, tag, upstream image, and parent image to the results dictionary
        results[f'{repo_name}:{image_tag}'] = {
            'upstream_image': upstream_image,
            'parent_image': parent_image
        }

# Save the results to disk in a nice and pretty JSON format
with open('ecr_images.json', 'w') as outfile:
    json.dump(results, outfile, indent=4)


##
##

~                                                                                                                                                                                                                                       
~                 
