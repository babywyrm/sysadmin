########find-ecr-image.sh
https://gist.github.com/outofcoffee/8f40732aefacfded14cce8a45f6e5eb1
#########

#!/usr/bin/env bash
# Example:
#    ./find-ecr-image.sh foo/bar mytag

if [[ $# -lt 2 ]]; then
    echo "Usage: $( basename $0 ) <repository-name> <image-tag>"
    exit 1
fi

IMAGE_META="$( aws ecr describe-images --repository-name=$1 --image-ids=imageTag=$2 2> /dev/null )"

if [[ $? == 0 ]]; then
    IMAGE_TAGS="$( echo ${IMAGE_META} | jq '.imageDetails[0].imageTags[0]' -r )"
    echo "$1:$2 found"
else
    echo "$1:$2 not found"
    exit 1
fi
@amitsaha
amitsaha commented on Nov 8, 2018
Thanks, AWS CLI goes out of it's way to make things less obvious -

@rmurillo21
rmurillo21 commented on Dec 19, 2018
Some may need --output json on the aws ecr describe-images lines, if you have other output format defaults. thanks!

@alextes
alextes commented on Aug 11, 2019 • 
No need to echo things into commands, most commands accept input redirection:

    IMAGE_TAGS="$( echo ${IMAGE_META} | jq '.imageDetails[0].imageTags[0]' -r )"
    IMAGE_TAGS="$( jq '.imageDetails[0].imageTags[0]' -r < ${IMAGE_META})"
Thanks for the script, saved me 30min of crawling docs 🙏 !

@botjaeger
botjaeger commented on Aug 18, 2019 • 
I am getting "not found"

EDIT:
I used the reposiotry URI instead of using the actual repository name. my bad. xD

thanks!

@maxdbn
maxdbn commented on Jan 1, 2020
IMAGE_META="$( aws ecr describe-images --repository-name=$1 --image-ids=imageTag=$2 2> /dev/null )" will still return an error code
I recommend using ||: instead

IMAGE_META="$( aws ecr describe-images --repository-name=$1 --image-ids=imageTag=$2 ||: )"

@bethesque
bethesque commented on Apr 24, 2020
Thanks for this! Very handy.

@mcindea
mcindea commented on Apr 28, 2020
@maxdbn I wouldn't recommend using ||: because that will result in a false positive: The script will say "found" even though the aws command returns a non-zero exit code.
You can test this by adding a "typo" in the aws command:

IMAGE_META="$( awsz ecr describe-images --registry-id $REGISTRY_ID --repository-name=$REPOSITORY --image-ids=imageTag=$IMAGE_TAG 2> /dev/null ||: )"
Doing this, the script will always say it's found.

@jeevanshu
jeevanshu commented on Jul 12, 2020 • 
Thank you so much for this!!

For adding help message you can make use of this in script, I picked this up from a hackernews thread few days ago

USAGE="find-ecr-image — Check ECR for existing docker image

    Usage:
      ./find-ecr-image <repository-name> <image-tag>
    Example:
      ./find-ecr-image.sh foo/bar mytag

    Options:
      <repository-name>   ECR repository name
      <image-tag>         ECR image tag 
      -h                  Show this message
  "
  help() {
    echo "$USAGE"
  }

if [[ $# -lt 2 ]] || [[ "$1" == "-h" ]]; then
    help
    exit 1
fi 
@kevinold
kevinold commented on Feb 10, 2021
Thanks for this script!

I've expanded it to include support for public repositories, using the -p or --public flag and incorporated the usage block from @jeevanshu

#!/usr/bin/env bash
# Example:
#    ./find-ecr-image.sh foo/bar mytag
# via https://gist.github.com/outofcoffee/8f40732aefacfded14cce8a45f6e5eb1

USAGE="find-ecr-image — Check ECR for existing docker image

    Usage:
      ./find-ecr-image <repository-name> <image-tag>
    Example:
      ./find-ecr-image.sh foo/bar mytag
      ./find-ecr-image.sh -p public/repo mytag

    Options:
      <repository-name>   ECR repository name
      <image-tag>         ECR image tag 
      -h                  Show this message
      -p / --pubic        Public Repository (optional)
  "
  help() {
    echo "$USAGE"
  }

if [[ $# -lt 2 ]] || [[ "$1" == "-h" ]]; then
    help
    exit 1
fi

if [[ "$3" == "-p" ]] || [[ "$3" == "--public" ]]; then
    # public repository
    IMAGE_META="$( aws ecr-public describe-images --repository-name=$1 --image-ids=imageTag=$2 2> /dev/null )"
else
    # private repository
    IMAGE_META="$( aws ecr describe-images --repository-name=$1 --image-ids=imageTag=$2 2> /dev/null )"
fi

if [[ $? == 0 ]]; then
    IMAGE_TAGS="$( echo ${IMAGE_META} | jq '.imageDetails[0].imageTags[0]' -r )"
    echo "$1:$2 found"
else
    echo "$1:$2 not found"
    exit 1
fi
@aliusmiles
aliusmiles commented on Sep 22, 2021
The following command worked out a bit better for me as it won't fail if tag not present, but will fail if repo not found or on aws cli error:

aws ecr batch-get-image --repository-name=$1 --image-ids=imageTag=$2 --query 'images[].imageId.imageTag' --output text
@sanchojaf
sanchojaf commented on Oct 28, 2021
similar, don't fail if tag not present:
aws ecr list-images --repository-name $1 --query 'imageIds[?imageTag=='$2'].imageTag' --output text

@EnriqueHormilla
EnriqueHormilla commented on Nov 23, 2021
I used the first command, update the behavior to sent null if the tag is not present:

cmd="$(aws ecr describe-images --repository-name="NAME" --image-ids=imageTag="TAG" ||:)"
if [[ ! -z "$cmd" ]]; then
XX
else
XX
fi

@Startouf
Startouf commented on Dec 1, 2021
Thanks you @sanchojaf yours is the best answer that will work for images that may have multiple tags

However your code had some quote issues, the working one is

aws ecr list-images \
    --repository-name ${REPO_NAME} \
    --query "imageIds[?imageTag=='${GIT_SHA1}'].imageTag" \
    --output text
@JSakhamuri
JSakhamuri commented on Jan 6
The following would push only if the image with the tag does not exist.
aws ecr list-images --repository-name {GIT_SHA1}'].imageTag" --output text | docker push {AWS_REGION}.amazonaws.com/{GIT_SHA1}

@sarthak
sarthak commented on Jun 15
Thanks for this script!

I've expanded it to include support for public repositories, using the -p or --public flag and incorporated the usage block from @jeevanshu

aws ecr-public commands only work in us-east-1 region, therefore the correct command should be

    IMAGE_META="$( aws ecr-public --region=us-east-1 describe-images --repository-name=$1 --image-ids=imageTag=$2 2> /dev/null )"
