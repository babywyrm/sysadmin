#!/usr/bin/env python3
import boto3
import json
import logging
import sys
from typing import Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

def update_kms_key_policy(key_id: str, policy: Dict, policy_name: str = "default") -> None:
    """
    Updates the key policy for the specified AWS KMS key.
    
    :param key_id: The ID or ARN of the KMS key.
    :param policy: A dictionary representing the key policy.
    :param policy_name: The name of the policy to update (default is "default").
    """
    kms_client = boto3.client("kms")
    try:
        response = kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName=policy_name,
            Policy=json.dumps(policy)
        )
        logging.info("Policy updated successfully: %s", response)
    except Exception as e:
        logging.error("Error updating key policy: %s", e)
        sys.exit(1)

def get_kms_key_policy(key_id: str, policy_name: str = "default") -> Dict:
    """
    Retrieves the key policy for the specified AWS KMS key.
    
    :param key_id: The ID or ARN of the KMS key.
    :param policy_name: The name of the policy to retrieve (default is "default").
    :return: The key policy as a dictionary.
    """
    kms_client = boto3.client("kms")
    try:
        response = kms_client.get_key_policy(
            KeyId=key_id,
            PolicyName=policy_name
        )
        policy = json.loads(response["Policy"])
        logging.info("Retrieved key policy successfully.")
        return policy
    except Exception as e:
        logging.error("Error retrieving key policy: %s", e)
        sys.exit(1)

def main() -> None:
    # Replace with your actual KMS key ID or ARN.
    key_id = "your-kms-key-id-here"
    
    # Define the key policy (as provided)
    policy = {
        "Version": "2012-10-17",
        "Id": "cassandra-key-policy",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::09876512345:root"
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow access for Key Administrators",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::09876512345:user/ben@whaletech.co"
                },
                "Action": [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow use of the key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::09876512345:role/my-iam-role"
                    ]
                },
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource": "*"
            },
            {
                "Sid": "Allow attachment of persistent resources",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::09876512345:role/my-iam-role"
                    ]
                },
                "Action": [
                    "kms:CreateGrant",
                    "kms:ListGrants",
                    "kms:RevokeGrant"
                ],
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "kms:GrantIsForAWSResource": "true"
                    }
                }
            }
        ]
    }
    
    # Update the key policy
    update_kms_key_policy(key_id, policy)
    
    # Retrieve and display the key policy to verify the update
    current_policy = get_kms_key_policy(key_id)
    print("Current KMS Key Policy:")
    print(json.dumps(current_policy, indent=4))

if __name__ == "__main__":
    main()
