#!/bin/bash

##
## https://gist.github.com/wtait1/e1500652435fe7a192e4592e120d9ce9
##

# Source: https://gist.github.com/wtait1/e1500652435fe7a192e4592e120d9ce9
# 
# Requirements:
#   - pip (this script will install other things for you)
#   - Docker (for Localstack - https://github.com/localstack/localstack)
# 
# Usage:
#   export BUCKET_NAME=my-test-bucket
#   ./s3-localstack.sh


PIP=$(which pip)
LOCALSTACK=$(which localstack)
CLI=$(which awslocal)

BUCKET=${BUCKET_NAME}
MAX_NUM_TIMEOUTS=10
TIMEOUT_WAIT=3


if [[ -z ${LOCALSTACK} ]]; then
    echo "localstack not found, installing…"
    if [[ -z ${PIP} ]]; then
        echo "Couldn't find pip!! Exiting..."
        exit 1
    fi
    ${PIP} install localstack
    echo "Done"
elif [[ -z ${CLI} ]]; then
    echo "awslocal (localstack wrapper for AWS CLI) not found, installing..."
    ${PIP} install awscli-local
    echo "Done"
fi

timeouts=0
wait_and_create_bucket() {
    until ${CLI} s3 ls; do
        echo "waiting for localstack..."
        sleep $TIMEOUT_WAIT
        ((timeouts++))
        if (( ${timeouts} >= $MAX_NUM_TIMEOUTS )); then
            echo "Waited too long for localstack, exiting"
            exit 1
        fi
    done


    echo "Creating bucket ${BUCKET}..."
    ${CLI} s3api create-bucket --bucket ${BUCKET}
    ${CLI} s3api put-bucket-acl --bucket ${BUCKET} --acl public-read


    echo "Created bucket $BUCKET"
}

wait_and_create_bucket &

SERVICES=s3 START_WEB=0 ${LOCALSTACK} start

##
##
