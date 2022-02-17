#!/bin/bash

#### Functions ###
display_usage() { 
	echo "This script must be run with Docker capable privileges and you should login to your registry before pushing!" 
	echo -e "\nUsage:\n$0 <saved_image> [--push]\n" 
	echo -e " <saved_image>\t\t\tThe image file to load and push" 
	echo -e " [--push]\t\t\tPush to registry" 	
	echo -e "\nExample: $0 /mydir/ubuntu.tar --push "
} 

# Check params
if [  $# -le 0 ] 
then 
	display_usage
	exit 1
fi 

# Check Docker command executable exit code
docker images > /dev/null 2>&1; rc=$?;
if [[ $rc != 0 ]]; then 
	display_usage
	exit 1
fi

echo -e "\nLoading $1..." 

# Load image and save output
RESULT=$(docker load -i $1)

# Get image name and registry
IMAGE=${RESULT#*: }
REGISTRY=${IMAGE#*\/}

echo $RESULT 

# Push if flag provided
if [[ $* == *--push* ]]; then

	echo -e "\nPushing $IMAGE to $REGISTRY..." 
	docker push $IMAGE

	# Check result
	if [[ $rc != 0 ]]; then 
		echo -e "\nERROR: Push failed, are you logged in to $REGISTRY? (e.g. \$ docker login $REGISTRY)" 
		exit 1
	fi

fi

echo "Done!"
exit 0
