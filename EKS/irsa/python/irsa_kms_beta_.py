#!/usr/bin/env python3
"""
AWS KMS IRSA Encryption/Decryption Tool for Security Testing

This script demonstrates how to perform encryption and decryption using AWS KMS,
leveraging credentials provided via IRSA (IAM Roles for Service Accounts) when run in EKS.

Prerequisites:
- The environment must have AWS credentials available via IRSA (or another method).
- The environment variable KMS_KEY_ID must be set to the desired AWS KMS key ID or alias.
- boto3 must be installed (pip install boto3).

Usage:
    To encrypt a plaintext string:
        python kms_irsa_beta_.py encrypt "your plaintext here"

    To decrypt a base64-encoded ciphertext:
        python kms_irsa_beta_.py decrypt "base64_ciphertext_here"
"""

import boto3
import argparse
import base64
import os
import sys

def get_kms_client():
    """
    Create a KMS client using boto3.
    If running in EKS with IRSA, boto3 automatically uses the provided temporary credentials.
    """
    return boto3.client('kms')

def encrypt_text(plaintext, key_id):
    """
    Encrypt the provided plaintext using AWS KMS.

    :param plaintext: The plaintext string to encrypt.
    :param key_id: The KMS key ID or alias.
    :return: A base64 encoded ciphertext string.
    """
    kms = get_kms_client()
    response = kms.encrypt(
        KeyId=key_id,
        Plaintext=plaintext.encode('utf-8')
    )
    ciphertext_blob = response['CiphertextBlob']
    # Encode the binary ciphertext into a base64 string for easier handling.
    ciphertext_b64 = base64.b64encode(ciphertext_blob).decode('utf-8')
    return ciphertext_b64

def decrypt_text(ciphertext_b64):
    """
    Decrypt the provided base64 encoded ciphertext using AWS KMS.

    :param ciphertext_b64: The base64 encoded ciphertext string.
    :return: The decrypted plaintext string.
    """
    kms = get_kms_client()
    # Decode the base64 ciphertext to get the binary blob.
    ciphertext_blob = base64.b64decode(ciphertext_b64)
    response = kms.decrypt(
        CiphertextBlob=ciphertext_blob
    )
    plaintext = response['Plaintext'].decode('utf-8')
    return plaintext

def main():
    # Set up command-line argument parsing.
    parser = argparse.ArgumentParser(
        description="AWS KMS IRSA Encryption/Decryption Tool for CTF"
    )
    subparsers = parser.add_subparsers(dest="command", required=True,
                                       help="Specify whether to 'encrypt' or 'decrypt' data.")

    # Subparser for the 'encrypt' command.
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a plaintext string.")
    encrypt_parser.add_argument("plaintext", help="The plaintext string to encrypt.")

    # Subparser for the 'decrypt' command.
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a base64-encoded ciphertext.")
    decrypt_parser.add_argument("ciphertext", help="The base64-encoded ciphertext to decrypt.")

    args = parser.parse_args()

    # Retrieve the KMS Key ID from the environment variable.
    key_id = os.getenv("KMS_KEY_ID")
    if not key_id:
        sys.exit("Error: The KMS_KEY_ID environment variable is not set.")

    # Execute the appropriate command.
    if args.command == "encrypt":
        ciphertext = encrypt_text(args.plaintext, key_id)
        print("Encrypted Ciphertext (base64 encoded):")
        print(ciphertext)
    elif args.command == "decrypt":
        plaintext = decrypt_text(args.ciphertext)
        print("Decrypted Plaintext:")
        print(plaintext)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

##
##

#!/usr/bin/env python3
"""
AWS KMS IRSA & Assume Role Demo for Security Testing

This script demonstrates:
  1. How to view the caller identity when using IRSA credentials.
  2. How to optionally assume an additional role using AWS STS.
  3. How to perform KMS encryption/decryption using the credentials
     from either the default IRSA-provided session or the assumed role.

Usage:
  To encrypt a plaintext string using the default IRSA credentials:
      python kms_irsa_assume.py encrypt "your plaintext here"

  To decrypt a base64-encoded ciphertext:
      python kms_irsa_assume.py decrypt "base64_ciphertext_here"

  To assume a different role (in addition to IRSA), provide the --assume-role flag:
      python kms_irsa_assume.py encrypt "your plaintext here" --assume-role arn:aws:iam::123456789012:role/CustomerRole [--external-id YourExternalID]

Prerequisites:
  - Running in an EKS pod with IRSA: the pod’s service account has an IAM role.
  - The environment variable KMS_KEY_ID must be set (e.g., "alias/ctf-key" or a key ID).
  - boto3 must be installed (pip install boto3).
"""

import boto3
import argparse
import base64
import os
import sys

def get_caller_identity(sts_client):
    """
    Retrieve and print the caller identity using the provided STS client.
    This helps confirm which IAM role the current session is using.
    """
    identity = sts_client.get_caller_identity()
    print("Caller Identity:")
    print(identity)
    return identity

def assume_role(role_arn, session_name, external_id=None, duration_seconds=900):
    """
    Assume a new role using the AWS STS API.

    :param role_arn: The ARN of the role to assume.
    :param session_name: A name for the assumed session.
    :param external_id: Optional external ID if required by the role.
    :param duration_seconds: The duration, in seconds, for the temporary credentials.
    :return: Temporary credentials (dict) from the assumed role.
    """
    sts_client = boto3.client('sts')
    assume_kwargs = {
        'RoleArn': role_arn,
        'RoleSessionName': session_name,
        'DurationSeconds': duration_seconds
    }
    if external_id:
        assume_kwargs['ExternalId'] = external_id

    response = sts_client.assume_role(**assume_kwargs)
    return response['Credentials']

def encrypt_text(kms_client, plaintext, key_id):
    """
    Encrypt plaintext using AWS KMS.

    :param kms_client: A boto3 KMS client.
    :param plaintext: The plaintext string to encrypt.
    :param key_id: The KMS key ID or alias.
    :return: Base64 encoded ciphertext.
    """
    response = kms_client.encrypt(
        KeyId=key_id,
        Plaintext=plaintext.encode('utf-8')
    )
    ciphertext_blob = response['CiphertextBlob']
    return base64.b64encode(ciphertext_blob).decode('utf-8')

def decrypt_text(kms_client, ciphertext_b64):
    """
    Decrypt a base64 encoded ciphertext using AWS KMS.

    :param kms_client: A boto3 KMS client.
    :param ciphertext_b64: The base64 encoded ciphertext.
    :return: The decrypted plaintext string.
    """
    ciphertext_blob = base64.b64decode(ciphertext_b64)
    response = kms_client.decrypt(CiphertextBlob=ciphertext_blob)
    return response['Plaintext'].decode('utf-8')

def main():
    parser = argparse.ArgumentParser(
        description="AWS KMS IRSA & Assume Role Demo for CTF"
    )
    parser.add_argument(
        "command", choices=["encrypt", "decrypt"],
        help="Specify whether to 'encrypt' plaintext or 'decrypt' ciphertext."
    )
    parser.add_argument("data", help="Plaintext (for encryption) or base64 ciphertext (for decryption)")
    parser.add_argument(
        "--assume-role", dest="assume_role_arn",
        help="(Optional) ARN of the role to assume (e.g., a customer-specific role)."
    )
    parser.add_argument(
        "--external-id", dest="external_id",
        help="(Optional) External ID required to assume the role."
    )
    parser.add_argument(
        "--session-name", default="CTFSession",
        help="(Optional) Session name for the assumed role (default: CTFSession)."
    )
    args = parser.parse_args()

    # Create a default boto3 session.
    # In EKS with IRSA, this session automatically uses the pod's temporary credentials.
    default_session = boto3.Session()
    default_sts = default_session.client('sts')
    print("=== Default (IRSA) Credentials ===")
    get_caller_identity(default_sts)

    # Determine which session to use for KMS operations.
    session_to_use = default_session

    # If --assume-role is provided, assume that role.
    if args.assume_role_arn:
        print(f"\n=== Assuming Role: {args.assume_role_arn} ===")
        creds = assume_role(
            role_arn=args.assume_role_arn,
            session_name=args.session_name,
            external_id=args.external_id
        )
        # Create a new session using the temporary credentials from the assumed role.
        session_to_use = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
        assumed_sts = session_to_use.client('sts')
        print("=== Assumed Role Credentials ===")
        get_caller_identity(assumed_sts)

    # Retrieve the KMS Key ID from the environment variable.
    key_id = os.getenv("KMS_KEY_ID")
    if not key_id:
        sys.exit("Error: The KMS_KEY_ID environment variable is not set.")

    # Create a KMS client using the chosen session.
    kms_client = session_to_use.client('kms')

    # Execute the desired command.
    if args.command == "encrypt":
        ciphertext = encrypt_text(kms_client, args.data, key_id)
        print("\nEncrypted Ciphertext (base64 encoded):")
        print(ciphertext)
    elif args.command == "decrypt":
        plaintext = decrypt_text(kms_client, args.data)
        print("\nDecrypted Plaintext:")
        print(plaintext)

if __name__ == "__main__":
    main()

##
##

apiVersion: v1
kind: ServiceAccount
metadata:
  name: ctf-sa
  namespace: default
  annotations:
    # Replace with your IAM role ARN that has the necessary permissions (e.g., KMS and STS)
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/YourIRSARole

##
##

apiVersion: v1
kind: Pod
metadata:
  name: ctf-pod
  namespace: default
spec:
  serviceAccountName: ctf-sa
  containers:
    - name: ctf-container
      image: your-docker-image:latest
      env:
        - name: KMS_KEY_ID
          value: "alias/ctf-key"  # Set your KMS key alias or ID here.

##
##
