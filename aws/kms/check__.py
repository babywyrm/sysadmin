#!/usr/bin/env python3
import argparse
import boto3
import json
import logging
import sys
from typing import Any, Dict

# Configure logging for clear, timestamped output.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def list_secrets(region: str) -> None:
    """
    List all secrets in Secrets Manager for the specified region.
    """
    secrets_client = boto3.client("secretsmanager", region_name=region)
    try:
        paginator = secrets_client.get_paginator("list_secrets")
        secrets_list = []
        for page in paginator.paginate():
            secrets_list.extend(page.get("SecretList", []))
        print(f"----- Secrets in region {region} -----")
        print(json.dumps(secrets_list, indent=4, default=str))
    except Exception as e:
        logging.error("Error listing secrets in region %s: %s", region, e)
        sys.exit(1)


def list_kms_keys(region: str) -> None:
    """
    List all KMS keys in the specified region.
    """
    kms = boto3.client("kms", region_name=region)
    try:
        paginator = kms.get_paginator("list_keys")
        keys = []
        for page in paginator.paginate():
            keys.extend(page.get("Keys", []))
        print(f"----- KMS Keys in region {region} -----")
        print(json.dumps(keys, indent=4, default=str))
    except Exception as e:
        logging.error("Error listing KMS keys in region %s: %s", region, e)
        sys.exit(1)


def describe_key(key_id: str, region: str) -> None:
    """
    Retrieve and print details about a KMS key including its metadata and rotation status.
    """
    kms = boto3.client("kms", region_name=region)
    try:
        response = kms.describe_key(KeyId=key_id)
        key_metadata: Dict[str, Any] = response["KeyMetadata"]
        print("----- KMS Key Description -----")
        print(json.dumps(key_metadata, indent=4, default=str))
    except Exception as e:
        logging.error("Error describing key %s in region %s: %s", key_id, region, e)
        sys.exit(1)

    try:
        rotation = kms.get_key_rotation_status(KeyId=key_id)
        rotation_enabled = rotation.get("KeyRotationEnabled", False)
        print("\nKey Rotation Enabled:", rotation_enabled)
    except Exception as e:
        logging.error("Error getting key rotation status for %s in region %s: %s", key_id, region, e)


def enable_key_rotation(key_id: str, region: str) -> None:
    """
    Enable automatic key rotation for a specified KMS key.
    """
    kms = boto3.client("kms", region_name=region)
    try:
        kms.enable_key_rotation(KeyId=key_id)
        logging.info("Enabled key rotation for key: %s in region %s", key_id, region)
    except Exception as e:
        logging.error("Error enabling key rotation for %s in region %s: %s", key_id, region, e)
        sys.exit(1)


def check_key_rotation(key_id: str, region: str) -> None:
    """
    Check and print whether key rotation is enabled for a given KMS key.
    """
    kms = boto3.client("kms", region_name=region)
    try:
        response = kms.get_key_rotation_status(KeyId=key_id)
        enabled = response.get("KeyRotationEnabled", False)
        print(f"Key Rotation Enabled for {key_id} in region {region}: {enabled}")
    except Exception as e:
        logging.error("Error checking key rotation for %s in region %s: %s", key_id, region, e)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="List Secrets Manager secrets or KMS keys, and perform common KMS operations."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: list-secrets
    list_secrets_parser = subparsers.add_parser("list-secrets", help="List Secrets Manager secrets")
    list_secrets_parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")

    # Subcommand: list-kms
    list_kms_parser = subparsers.add_parser("list-kms", help="List KMS keys")
    list_kms_parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")

    # Subcommand: describe-kms
    describe_kms_parser = subparsers.add_parser("describe-kms", help="Describe a KMS key")
    describe_kms_parser.add_argument("key_id", help="The ID or ARN of the KMS key")
    describe_kms_parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")

    # Subcommand: enable-rotation
    enable_rotation_parser = subparsers.add_parser("enable-rotation", help="Enable key rotation for a KMS key")
    enable_rotation_parser.add_argument("key_id", help="The ID or ARN of the KMS key")
    enable_rotation_parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")

    # Subcommand: check-rotation
    check_rotation_parser = subparsers.add_parser("check-rotation", help="Check key rotation status for a KMS key")
    check_rotation_parser.add_argument("key_id", help="The ID or ARN of the KMS key")
    check_rotation_parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")

    args = parser.parse_args()

    if args.command == "list-secrets":
        list_secrets(args.region)
    elif args.command == "list-kms":
        list_kms_keys(args.region)
    elif args.command == "describe-kms":
        describe_key(args.key_id, args.region)
    elif args.command == "enable-rotation":
        enable_key_rotation(args.key_id, args.region)
    elif args.command == "check-rotation":
        check_key_rotation(args.key_id, args.region)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

##
##
