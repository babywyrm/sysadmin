#!/usr/bin/env python3

"""
AWS Security Analyzer Beta Family Edition

A tool to analyze AWS profiles for security issues including:
- IAM roles with elevated permissions
- Access key age and usage
- Cross-account access key usage

Examples:
  # Analyze all available profiles
  python aws_security_analyzer.py

  # Analyze specific profiles
  python aws_security_analyzer.py --profiles prod-account dev-account

  # Analyze specific profiles with cross-account access checks
  python aws_security_analyzer.py --profiles prod-account dev-account --cross-account

  # Analyze all profiles and save results to a file
  python aws_security_analyzer.py --output security_report.txt --cross-account

  # Analyze a single profile (cross-account will be skipped)
  python aws_security_analyzer.py --profiles production-account
"""

import boto3
import argparse
from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError
from datetime import datetime, timedelta
import os, sys, re

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


def analyze_cross_account_key_usage(profiles, output_file=None):
    """
    Analyze CloudTrail logs across all profiles to detect access keys from one account
    being used to access resources in other accounts.
    """
    write_output(output_file, "\n========== CROSS-ACCOUNT ACCESS KEY USAGE ANALYSIS ==========")
    
    # First, collect all access keys from all profiles
    access_keys_by_profile = {}
    
    for profile in profiles:
        try:
            session = boto3.Session(profile_name=profile)
            iam_client = session.client('iam')
            
            # Get account ID for the profile
            sts_client = session.client('sts')
            account_id = sts_client.get_caller_identity()["Account"]
            
            # Store access keys with the profile and account ID
            access_keys_by_profile[profile] = {
                "account_id": account_id,
                "keys": {}
            }
            
            # List IAM users
            users = iam_client.list_users()
            for user in users['Users']:
                user_name = user['UserName']
                
                # List access keys for the user
                access_keys = iam_client.list_access_keys(UserName=user_name)
                for key in access_keys['AccessKeyMetadata']:
                    key_id = key['AccessKeyId']
                    access_keys_by_profile[profile]["keys"][key_id] = {
                        "user": user_name,
                        "status": key['Status']
                    }
            
            write_output(output_file, f"Collected {len(access_keys_by_profile[profile]['keys'])} access keys from profile {profile} (Account: {account_id})")
            
        except Exception as e:
            write_output(output_file, f"Error collecting access keys for profile {profile}: {e}")
    
    # Now search CloudTrail logs in each profile for access keys from other profiles
    for target_profile in profiles:
        try:
            write_output(output_file, f"\nSearching for cross-account access in profile: {target_profile}")
            
            session = boto3.Session(profile_name=target_profile)
            cloudtrail_client = session.client('cloudtrail')
            target_account_id = access_keys_by_profile.get(target_profile, {}).get("account_id", "Unknown")
            
            # Look at logs from the past 90 days (CloudTrail limitation)
            end_time = datetime.now()
            start_time = end_time - timedelta(days=90)
            
            # For each source profile's keys, check if they've accessed this account
            for source_profile, profile_data in access_keys_by_profile.items():
                # Skip the same account
                if source_profile == target_profile:
                    continue
                
                source_account_id = profile_data.get("account_id", "Unknown")
                
                for key_id, key_info in profile_data["keys"].items():
                    try:
                        # Look for events where this key was used in the target account
                        response = cloudtrail_client.lookup_events(
                            LookupAttributes=[
                                {
                                    'AttributeKey': 'AccessKeyId',
                                    'AttributeValue': key_id
                                }
                            ],
                            StartTime=start_time,
                            EndTime=end_time
                        )
                        
                        if response['Events']:
                            write_output(output_file, f"  ALERT: Access key {key_id} from profile {source_profile} (Account: {source_account_id})")
                            write_output(output_file, f"         User: {key_info['user']}")
                            write_output(output_file, f"         Has accessed resources in profile {target_profile} (Account: {target_account_id})")
                            write_output(output_file, f"         Found {len(response['Events'])} events in CloudTrail")
                            
                            # Provide details about most recent events
                            for i, event in enumerate(response['Events'][:5]):  # Show first 5 events
                                write_output(output_file, f"         Event {i+1}: {event.get('EventName')} on {event.get('EventTime')}")
                                write_output(output_file, f"                   Resource: {event.get('Resources', [{'ResourceName': 'Unknown'}])[0].get('ResourceName', 'Unknown')}")
                    
                    except Exception as e:
                        write_output(output_file, f"  Error checking key {key_id} in profile {target_profile}: {e}")
            
        except Exception as e:
            write_output(output_file, f"Error searching CloudTrail for profile {target_profile}: {e}")
    
    write_output(output_file, "\n=========================================================")


def main():
    """
    Main function to analyze AWS profiles with options for specific profiles or all profiles.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Analyze AWS profiles for security issues including IAM roles, access keys, and cross-account access.",
        epilog="""
Examples:
  # Analyze all available profiles
  python aws_security_analyzer.py

  # Analyze specific profiles
  python aws_security_analyzer.py --profiles prod-account dev-account

  # Analyze specific profiles with cross-account access checks
  python aws_security_analyzer.py --profiles prod-account dev-account --cross-account

  # Analyze all profiles and save results to a file
  python aws_security_analyzer.py --output security_report.txt --cross-account

  # Analyze a single profile (cross-account will be skipped)
  python aws_security_analyzer.py --profiles production-account
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--profiles",
        type=str,
        nargs="+",  # This allows multiple profiles to be specified
        help="Specify one or more AWS profiles to analyze. If not provided, all profiles will be analyzed."
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Specify a file to export the results. If not provided, results will be printed to the console."
    )
    parser.add_argument(
        "--cross-account",
        action="store_true",
        help="Enable cross-account access analysis (may take longer to run)"
    )
    args = parser.parse_args()

    try:
        # Determine which profiles to analyze
        if args.profiles:
            profiles = args.profiles
            write_output(args.output, f"Analyzing specified profiles: {', '.join(profiles)}")
        else:
            # Use all available profiles
            session = boto3.Session()
            profiles = session.available_profiles
            write_output(args.output, f"Analyzing all {len(profiles)} available profiles")
        
        # Run standard analysis for each profile
        for profile in profiles:
            write_output(args.output, f"\nProfile: {profile}")
            analyze_iam_roles(profile, args.output)
            analyze_access_keys(profile, args.output)
        
        # If cross-account analysis is requested, run it
        if args.cross_account:
            if len(profiles) > 1:
                analyze_cross_account_key_usage(profiles, args.output)
            else:
                write_output(args.output, "Cross-account analysis requires multiple profiles. Skipping.")

    except Exception as e:
        write_output(args.output, f"Unexpected error: {e}")
        import traceback
        write_output(args.output, traceback.format_exc())

if __name__ == "__main__":
    main()
