
##
##
##########Shell script to add/remove tags to an AWS ECR image.
##
ecr_tag.sh
#!/bin/bash
set -e

function help() {
	echo "Not enough arguments supplied..."
	echo
	echo "Usage: $0 aws_repo_name {add|delete} tag [to_image_id_query]"
	echo
	echo "Example: $0 ecr_repo add v1.0.0 imageTag=production"
	echo "Example: $0 ecr_repo remove v1.0.0.beta"
	echo
	exit 1
}

if [ $# -lt 3 ]; then
	help
fi

AWS_REPO_NAME="$1"
AWS_ACTION="$2"
AWS_TAG="$3"

case "$AWS_ACTION" in
add)
	AWS_IMAGE_IDS_QUERY="$4"
	MANIFEST=$(aws ecr batch-get-image --repository-name "$AWS_REPO_NAME" --image-ids "$AWS_IMAGE_IDS_QUERY" --query 'images[].imageManifest' --output text)
	aws ecr put-image --repository-name "$AWS_REPO_NAME" --image-tag "$AWS_TAG" --image-manifest "$MANIFEST" >/dev/null
	;;
remove)
	aws ecr batch-delete-image --repository-name "$AWS_REPO_NAME" --image-ids imageTag="$AWS_TAG" >/dev/null
	;;
*)
	help
	;;
esac

aws ecr describe-images --repository-name "$AWS_REPO_NAME"
