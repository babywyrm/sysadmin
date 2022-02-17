#!/bin/bash


display_usage() { 
	echo "This script must be run with Docker capable privileges and you should login to your registry before pushing!" 
	echo -e "\nUsage:\n$0 [--dir <dir_with_images>] [--file <saved_image>] [--registry <registry-url>] --auto-delete\n" 
	echo -e " -h,--help\t\t\t\t\tDisplay this help"
	echo -e " -f,--file <saved_image>\t\t\tThe image file to load and push"
	echo -e " -d,--dir <dir_with_images>\t\t\tThe directory containing images file to load and push"
	echo -e " [--registry <registry-url>]\t\t\tPush to specific registry"
	echo -e " --auto-delete\t\t\t\t\tDelete tar file after upload"
	echo -e "\nExample: $0 /mydir/ubuntu.tar --push --registry"
}

print_error() {
  echo -e "\e[1;31mError: $@\e[0m"
}
print_warning() {
	echo -e "\e[1;33m$@\e[0m"
}

ctrl_c_handler() {
	print_warning "CTRL-C detected, aborting..."
	exit 1
}

delete_file() {
	local docker_tar=$1

	echo -e "\nDeleting $docker_tar..." 

	rm $docker_tar

	echo -e "\nDeleted"
}

load_docker_tar() {
	local docker_tar=$1

	echo -e "\nLoading $docker_tar..." 

	# Load image and save output
	RESULT=$(docker load -i $docker_tar)

	# Get image name and registry
	IMAGE=${RESULT#*: }
	REGISTRY=${IMAGE#*\/}

	# Push if flag provided
	if [ ! -z "$REGISTRY_URL" ]; then

		echo -e "\nPushing $IMAGE to $REGISTRY_URL..."
		docker tag $IMAGE $REGISTRY_URL/$IMAGE
		docker push $REGISTRY_URL/$IMAGE

		echo -e "\nPushed"

		# Check result
		if [[ $rc != 0 ]]; then 
			print_error "\nERROR: Push failed, are you logged in to $REGISTRY? (e.g. \$ docker login $REGISTRY)" 
			exit 1
		fi

	fi

	if [[ $AUTO_DELETE == 0 ]]; then
		delete_file $docker_tar
	fi
}


# Listen to CTRL-C
trap ctrl_c_handler 2
trap ctrl_c_handler SIGINT

# Check params
if [  $# -le 0 ] 
then 
	print_warning "### no params specified ###"
	display_usage
	exit 1
fi 

# Check Docker command executable exit code
docker images > /dev/null 2>&1; rc=$?;
if [[ $rc != 0 ]]; then 
	print_error "### Docker images command return error ###"
	exit 1
fi

# Get path arguments
while [ $# -gt 0 ]; do
	case "$1" in
		--file*|-f*)
			if [[ "$1" != *=* ]]; then shift;
			fi # Value is next arg if no `=` (equal sign)
			DOCKER_TAR="${1#*=}"
			;;
		--dir*|-d*)
			if [[ "$1" != *=* ]]; then shift;
			fi # Value is next arg if no `=` (equal sign)
			FOLDER_WITH_DOCKER_TARS="${1#*=}"
			;;
		--registry*)
			if [[ "$1" != *=* ]]; then shift;
			fi # Value is next arg if no `=` (equal sign)
			REGISTRY_URL="${1#*=}"
			;;
		--auto-delete)
			AUTO_DELETE=0
			;;
		--help|-h)
			display_usage
			exit 0
			;;
		*)
		  >&2 printf "Error: Invalid argument $@\n"
		  exit 1
		  ;;
	esac
	shift
done


if [ ! -f "$DOCKER_TAR" ] && [ ! -d "$FOLDER_WITH_DOCKER_TARS" ] && [[ ! -n "$FOLDER_WITH_DOCKER_TARS" ]]; then
	print_error "The file $DOCKER_TAR or the folder $FOLDER_WITH_DOCKER_TARS doesn't exist"
	exit 1
fi

if [ -f "$DOCKER_TAR" ]; then
	load_docker_tar $DOCKER_TAR
fi

if [ -d "$FOLDER_WITH_DOCKER_TARS" ] && [[ -n "$FOLDER_WITH_DOCKER_TARS" ]]; then
	for docker_tar_file in $FOLDER_WITH_DOCKER_TARS/*.tar; do
		load_docker_tar "$docker_tar_file"
	done
fi



echo "Done!"
exit 0
