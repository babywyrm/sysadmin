import boto3
import argparse
from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError
from datetime import datetime, timedelta
import os,sys,re

##
##

def write_output(output_file, content):
    """
    Write content to a file if the output_file argument is provided.
    Otherwise, print to the console.
    """
    if output_file:
        with open(output_file, "a") as f:
            f.write(content + "\n")
    else:
        print(content)


def analyze_iam_roles(profile_name, output_file=None):
    """
    Analyze IAM roles for elevated permissions in the given AWS profile.
    This function checks attached and inline policies for potential security risks.
    """
    try:
        # Initialize session for the profile
        session = boto3.Session(profile_name=profile_name)
        iam_client = session.client('iam')

        write_output(output_file, f"\nAnalyzing IAM roles for profile: {profile_name}")

        # List IAM roles
        roles = iam_client.list_roles()
        for role in roles['Roles']:
            role_name = role['RoleName']
            write_output(output_file, f"Role: {role_name}")

            # Check attached policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies['AttachedPolicies']:
                policy_name = policy['PolicyName']
                write_output(output_file, f"  Attached Policy: {policy_name}")

                # Flag AdministratorAccess or overly permissive policies
                if "AdministratorAccess" in policy_name:
                    write_output(output_file, f"    WARNING: Role {role_name} has AdministratorAccess policy!")

            # Check inline policies
            inline_policies = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_policies['PolicyNames']:
                write_output(output_file, f"  Inline Policy: {policy_name}")

                # Retrieve policy document
                try:
                    policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    statements = policy_document.get('PolicyDocument', {}).get('Statement', [])

                    # Ensure statements are a list
                    if not isinstance(statements, list):
                        statements = [statements]

                    for statement in statements:
                        if isinstance(statement, dict):  # Ensure statement is a dictionary
                            if statement.get('Effect') == 'Allow' and statement.get('Action') == '*' and statement.get('Resource') == '*':
                                write_output(output_file, f"    WARNING: Role {role_name} has overly permissive inline policy!")
                        else:
                            write_output(output_file, f"    WARNING: Unexpected statement format in policy {policy_name} for role {role_name}: {statement}")
                except ClientError as e:
                    write_output(output_file, f"    ERROR: Unable to retrieve policy document for {policy_name}: {e}")

        write_output(output_file, "-----------------------------")

    except ProfileNotFound:
        write_output(output_file, f"Profile {profile_name} not found.")
    except NoCredentialsError:
        write_output(output_file, f"No credentials found for profile {profile_name}.")
    except ClientError as e:
        write_output(output_file, f"Error accessing IAM for profile {profile_name}: {e}")


def analyze_access_keys(profile_name, output_file=None):
    """
    Analyze IAM access keys for elevated permissions and potential issues in the given AWS profile.
    This function checks for inactive keys, long-lived keys, and keys with elevated permissions.
    """
    try:
        # Initialize session for the profile
        session = boto3.Session(profile_name=profile_name)
        iam_client = session.client('iam')

        write_output(output_file, f"\nAnalyzing IAM access keys for profile: {profile_name}")

        # List IAM users
        users = iam_client.list_users()
        for user in users['Users']:
            user_name = user['UserName']
            write_output(output_file, f"User: {user_name}")

            # List access keys for the user
            access_keys = iam_client.list_access_keys(UserName=user_name)
            for key in access_keys['AccessKeyMetadata']:
                key_id = key['AccessKeyId']
                status = key['Status']
                create_date = key['CreateDate']
                write_output(output_file, f"  Access Key: {key_id}")
                write_output(output_file, f"    Status: {status}")
                write_output(output_file, f"    Created: {create_date}")

                # Check for long-lived keys
                if (datetime.now() - create_date.replace(tzinfo=None)).days > 90:
                    write_output(output_file, f"    WARNING: Access key {key_id} is older than 90 days!")

                # Check for unused keys
                last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                if 'LastUsedDate' not in last_used['AccessKeyLastUsed']:
                    write_output(output_file, f"    WARNING: Access key {key_id} has never been used!")
                else:
                    write_output(output_file, f"    Last Used: {last_used['AccessKeyLastUsed']['LastUsedDate']}")

                # Check for elevated permissions
                attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
                for policy in attached_policies['AttachedPolicies']:
                    policy_name = policy['PolicyName']
                    write_output(output_file, f"    Attached Policy: {policy_name}")

                    if "AdministratorAccess" in policy_name:
                        write_output(output_file, f"    WARNING: Access key {key_id} has AdministratorAccess policy!")

        write_output(output_file, "-----------------------------")

    except ProfileNotFound:
        write_output(output_file, f"Profile {profile_name} not found.")
    except NoCredentialsError:
        write_output(output_file, f"No credentials found for profile {profile_name}.")
    except ClientError as e:
        write_output(output_file, f"Error accessing IAM for profile {profile_name}: {e}")


def main():
    """
    Main function to loop through AWS profiles or check a specific profile.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Analyze IAM roles and access keys for elevated permissions.")
    parser.add_argument(
        "--profile",
        type=str,
        help="Specify a single AWS profile to analyze. If not provided, all profiles will be analyzed."
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Specify a file to export the results. If not provided, results will be printed to the console."
    )
    args = parser.parse_args()

    try:
        # If a specific profile is provided, analyze only that profile
        if args.profile:
            print(f"Analyzing specified profile: {args.profile}")
            analyze_iam_roles(args.profile, args.output)
            analyze_access_keys(args.profile, args.output)
        else:
            # Otherwise, loop through all profiles
            session = boto3.Session()
            profiles = session.available_profiles

            for profile in profiles:
                print(f"Profile: {profile}")
                analyze_iam_roles(profile, args.output)
                analyze_access_keys(profile, args.output)

    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
