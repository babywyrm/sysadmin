#!/bin/bash

# Set variables
REPO_NAME="your_repository_name"
POLICY_NAME="your_policy_name"
MAX_AGE="200"

# Set lifecycle policy
aws ecr put-lifecycle-policy \
    --repository-name "$REPO_NAME" \
    --lifecycle-policy-text "{\"rules\":[{\"rulePriority\":1,\"description\":\"Delete images over $MAX_AGE days old\",\"selection\":{\"tagStatus\":\"any\",\"countType\":\"sinceImagePushed\",\"countUnit\":\"days\",\"countNumber\":$MAX_AGE},\"action\":{\"type\":\"expire\"}}]}" \
    --registry-id "your_registry_id" \
    --policy-text-version "1" \
    --lifecycle-policy-preview-enabled

# Enable lifecycle policy
aws ecr put-image-lifecycle-policy \
    --repository-name "$REPO_NAME" \
    --lifecycle-policy-text "{\"rules\":[{\"rulePriority\":1,\"description\":\"Delete images over $MAX_AGE days old\",\"selection\":{\"tagStatus\":\"any\",\"countType\":\"sinceImagePushed\",\"countUnit\":\"days\",\"countNumber\":$MAX_AGE},\"action\":{\"type\":\"expire\"}}]}" \
    --registry-id "your_registry_id" \
    --force

##
##
