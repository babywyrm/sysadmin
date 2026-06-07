import boto3

##
##

# Set variables
REPO_NAME = "your_repository_name"
POLICY_NAME = "your_policy_name"
MAX_AGE = 200

# Set lifecycle policy
ecr_client = boto3.client('ecr')
policy_text = {
    "rules": [
        {
            "rulePriority": 1,
            "description": f"Delete images over {MAX_AGE} days old",
            "selection": {
                "tagStatus": "any",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": MAX_AGE
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
ecr_client.put_lifecycle_policy(
    repositoryName=REPO_NAME,
    lifecyclePolicyText=str(policy_text),
    registryId="your_registry_id",
    policyTextVersion="1",
    lifecyclePolicyPreviewEnabled=True
)

# Enable lifecycle policy
ecr_client.put_image_lifecycle_policy(
    repositoryName=REPO_NAME,
    lifecyclePolicyText=str(policy_text),
    registryId="your_registry_id",
    force=True
)

##
##
