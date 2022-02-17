#!/bin/bash

#### Functions ###
display_usage() { 
	echo "This script must be run with Docker capable privileges!" 
	echo -e "\nUsage:\n$0 <image> <save_to_file> [retag_name] \n" 
	echo -e " <image>\t\t\tThe image to pull" 
	echo -e " <save_to_file>\t\t\tFilename to save the image to" 
	echo -e " [retag_name]\t\t\t(Optional) new name (tag) for image" 
	echo -e "\nExample: $0 mysql/mysql-server:latest /mydir/mysql.tar my.private.registry/mysql/mysql-server:latest"
} 

# Check params
if [  $# -le 1 ] 
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

# Pull image
docker pull $1

# Set image name to save
IMAGE=$1

# Retag image if retag name give
if [ ! -z "$3" ]; then
	docker tag $1 $3
	echo "Retaged $1 to $3" 
	
	# Overwrite image to save
	IMAGE=$3
fi

# Save to output file
docker save -o $2 $IMAGE
echo "Saved $IMAGE to $2" 

# Untag image if retag name give
if [ ! -z "$3" ]; then
	docker rm $IMAGE
fi

echo "Done!"
exit 0
