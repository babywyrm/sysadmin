#!/bin/bash


#!/bin/sh

# Returns boolean indicates whether designated tagged-image exists.
  # arg1: repository name
  # arg2: tag name
function image_exists() {
  image=$(docker image ls -a | grep $1 | grep $2)

  if [ "$image" ]; then
    return 0;
  else
    return 1;
  fi
}

# Builds new image.
  # arg1: tag in the form like ${repository}:${tag}
  # arg2: Path to Dockerfile
function build_image() {
  docker build -t $1 -f $2 .
}

# Work on master branch
git checkout master

# Get latest master revision
revision=$(git rev-parse --short HEAD)

echo "Current master revision is ${revision}\n"

# Set constants
readonly repository=your-repository-name
readonly ecr_repository=************.dkr.ecr.<region>.amazonaws.com
readonly revised_repository=$repository:$revision
readonly ecr_revised_repository=$ecr_repository/$revised_repository
readonly path_to_dockerfile=<relative-path-to-dockerfile>

echo "local-repository: ${repository}
ecr-repository: ${ecr_repository}
local-revised-repository: ${revised_repository}
ecr-revised-repository: ${ecr_revised_repository}\n"

# Build current source if revision not exists
if image_exists $repository $revision; then
  # Do nothing.
  echo "local-revised-repository already exists. Skip build.\n"
  true;
else
  echo "Start building local-revised-repository."
  build_image $revised_repository $path_to_dockerfile;
fi

# Generate ecr-repository-tagged image if not exists
if image_exists $ecr_repository $revision; then
  # Do nothing.
  echo "ecr-revised-repository already exists. Skip tagging.\n"
  true;
else
  docker tag $revised_repository $ecr_revised_repository;
fi

#Set AWS credentials in this area as needed

# Login to ECR
aws ecr get-login-password --region <region> \
  | docker login --username AWS --password-stdin $ecr_repository

# Push new image to ECR
docker push $ecr_revised_repository

echo "Done.\n"

##########################
##
##
