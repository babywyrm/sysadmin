import boto3

# Create an ECR client
ecr = boto3.client('ecr')

def list_repositories():
    """
    List all ECR repositories
    """
    return ecr.describe_repositories()['repositories']

def list_images(repository_name):
    """
    List all images in a given ECR repository
    """
    image_details = ecr.list_images(repositoryName=repository_name, filter={'tagStatus': 'TAGGED'})['imageIds']
    return [image_detail.get('imageTag', 'untagged') for image_detail in image_details]

def get_image_manifest(repository_name, image_tag='latest'):
    """
    Get the manifest for a specific image tag in a given ECR repository
    """
    return ecr.batch_get_image(repositoryName=repository_name, imageIds=[{'imageTag': image_tag}], acceptedMediaTypes=['application/vnd.docker.distribution.manifest.v2+json'])['images'][0]['imageManifest']

def get_image_history(repository_name, image_manifest):
    """
    Get the history for a specific image manifest in a given ECR repository
    """
    image_history = list(map(lambda x: x['image'], ecr.get_download_url_for_layer(repositoryName=repository_name, layerDigest=image_manifest)['urls']))
    return image_history

def get_parent_image(repository_name, image_history):
    """
    Get the parent image for a given image history in a given ECR repository
    """
    parent_image = 'unknown'
    for layer in image_history:
        layer_manifest = ecr.batch_get_image(repositoryName=repository_name, imageIds=[{'imageDigest': layer}], acceptedMediaTypes=['application/vnd.docker.distribution.manifest.v2+json'])['images'][0]['imageManifest']
        layer_config = ecr.batch_get_image(repositoryName=repository_name, imageIds=[{'imageDigest': layer}], acceptedMediaTypes=['application/vnd.docker.container.image.v1+json'])['images'][0]['imageManifest']
        parent_image = layer_config.get('config', {}).get('Image', '').replace('sha256:', '')
        if parent_image:
            break
    return parent_image

def print_parent_images():
    """
    Loop through all images in each repository in a remote ECR registry and print each parent image for each image to the screen
    """
    repositories = list_repositories()
    for repo in repositories:
        repository_name = repo['repositoryName']
        images = list_images(repository_name)
        for image in images:
            image_manifest = get_image_manifest(repository_name, image)
            image_history = get_image_history(repository_name, image_manifest)
            parent_image = get_parent_image(repository_name, image_history)
            print(f"{repository_name}:{image} -> {parent_image}")



print_parent_images()

##
