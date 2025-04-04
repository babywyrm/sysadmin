#!/usr/bin/env python3
"""
AWS Security Analyzer

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

import argparse
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any

import boto3
from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError


class OutputHandler:
    """Handles writing output to file or console."""
    
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file
        if output_file:
            # Create or clear the output file at initialization
            Path(output_file).write_text("")
    
    def write(self, content: str) -> None:
        """Write content to either file or console."""
        if self.output_file:
            with open(self.output_file, "a") as f:
                f.write(f"{content}\n")
        else:
            print(content)


class AWSSecurityAnalyzer:
    """Main analyzer class for AWS security checks."""
    
    def __init__(self, profiles: List[str], output_handler: OutputHandler):
        self.profiles = profiles
        self.output = output_handler
        self.session_cache: Dict[str, boto3.Session] = {}
    
    def get_session(self, profile_name: str) -> boto3.Session:
        """Get or create a session for the specified profile."""
        if profile_name not in self.session_cache:
            self.session_cache[profile_name] = boto3.Session(profile_name=profile_name)
        return self.session_cache[profile_name]
    
    def analyze_iam_roles(self, profile_name: str) -> None:
        """Analyze IAM roles for elevated permissions."""
        try:
            self.output.write(f"\nAnalyzing IAM roles for profile: {profile_name}")
            session = self.get_session(profile_name)
            iam_client = session.client('iam')
            
            # List IAM roles
            paginator = iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_name = role['RoleName']
                    self.output.write(f"Role: {role_name}")
                    
                    # Check attached policies
                    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                    for policy in attached_policies['AttachedPolicies']:
                        policy_name = policy['PolicyName']
                        self.output.write(f"  Attached Policy: {policy_name}")
                        
                        if "AdministratorAccess" in policy_name:
                            self.output.write(f"    WARNING: Role {role_name} has AdministratorAccess policy!")
                    
                    # Check inline policies
                    inline_policies = iam_client.list_role_policies(RoleName=role_name)
                    for policy_name in inline_policies['PolicyNames']:
                        self.output.write(f"  Inline Policy: {policy_name}")
                        
                        # Retrieve policy document
                        try:
                            policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            statements = policy_document.get('PolicyDocument', {}).get('Statement', [])
                            
                            # Ensure statements are a list
                            if not isinstance(statements, list):
                                statements = [statements]
                            
                            for statement in statements:
                                if isinstance(statement, dict):
                                    effect = statement.get('Effect')
                                    action = statement.get('Action')
                                    resource = statement.get('Resource')
                                    
                                    if effect == 'Allow' and action == '*' and resource == '*':
                                        self.output.write(f"    WARNING: Role {role_name} has overly permissive inline policy!")
                                else:
                                    self.output.write(f"    WARNING: Unexpected statement format in policy {policy_name} for role {role_name}")
                        except ClientError as e:
                            self.output.write(f"    ERROR: Unable to retrieve policy document for {policy_name}: {e}")
            
            self.output.write("-----------------------------")
            
        except ProfileNotFound:
            self.output.write(f"Profile {profile_name} not found.")
        except NoCredentialsError:
            self.output.write(f"No credentials found for profile {profile_name}.")
        except ClientError as e:
            self.output.write(f"Error accessing IAM for profile {profile_name}: {e}")
        except Exception as e:
            self.output.write(f"Unexpected error analyzing IAM roles for {profile_name}: {e}")
    
    def analyze_access_keys(self, profile_name: str) -> None:
        """Analyze IAM access keys for potential security issues."""
        try:
            self.output.write(f"\nAnalyzing IAM access keys for profile: {profile_name}")
            session = self.get_session(profile_name)
            iam_client = session.client('iam')
            
            # List IAM users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    self.output.write(f"User: {user_name}")
                    
                    # List access keys for the user
                    access_keys = iam_client.list_access_keys(UserName=user_name)
                    for key in access_keys['AccessKeyMetadata']:
                        key_id = key['AccessKeyId']
                        status = key['Status']
                        create_date = key['CreateDate']
                        
                        self.output.write(f"  Access Key: {key_id}")
                        self.output.write(f"    Status: {status}")
                        self.output.write(f"    Created: {create_date}")
                        
                        # Check for long-lived keys
                        key_age_days = (datetime.now() - create_date.replace(tzinfo=None)).days
                        if key_age_days > 90:
                            self.output.write(f"    WARNING: Access key {key_id} is {key_age_days} days old!")
                        
                        # Check for unused keys
                        last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                        last_used_info = last_used['AccessKeyLastUsed']
                        
                        if 'LastUsedDate' not in last_used_info:
                            self.output.write(f"    WARNING: Access key {key_id} has never been used!")
                        else:
                            self.output.write(f"    Last Used: {last_used_info['LastUsedDate']}")
                            # Check for inactive keys
                            days_since_use = (datetime.now() - last_used_info['LastUsedDate'].replace(tzinfo=None)).days
                            if days_since_use > 30 and status == 'Active':
                                self.output.write(f"    WARNING: Active key {key_id} hasn't been used in {days_since_use} days!")
                        
                        # Check for elevated permissions
                        attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
                        for policy in attached_policies['AttachedPolicies']:
                            policy_name = policy['PolicyName']
                            self.output.write(f"    Attached Policy: {policy_name}")
                            
                            if "AdministratorAccess" in policy_name:
                                self.output.write(f"    WARNING: Access key {key_id} has AdministratorAccess policy!")
            
            self.output.write("-----------------------------")
            
        except ProfileNotFound:
            self.output.write(f"Profile {profile_name} not found.")
        except NoCredentialsError:
            self.output.write(f"No credentials found for profile {profile_name}.")
        except ClientError as e:
            self.output.write(f"Error accessing IAM for profile {profile_name}: {e}")
        except Exception as e:
            self.output.write(f"Unexpected error analyzing access keys for {profile_name}: {e}")
    
    def collect_access_keys(self) -> Dict[str, Dict[str, Any]]:
        """Collect all access keys from all profiles."""
        access_keys_by_profile = {}
        
        for profile in self.profiles:
            try:
                self.output.write(f"Collecting access keys from profile: {profile}")
                session = self.get_session(profile)
                iam_client = session.client('iam')
                
                # Get account ID for the profile
                sts_client = session.client('sts')
                account_id = sts_client.get_caller_identity()["Account"]
                
                # Store access keys with the profile and account ID
                access_keys_by_profile[profile] = {
                    "account_id": account_id,
                    "keys": {}
                }
                
                # List IAM users and their keys
                paginator = iam_client.get_paginator('list_users')
                for page in paginator.paginate():
                    for user in page['Users']:
                        user_name = user['UserName']
                        
                        # List access keys for the user
                        access_keys = iam_client.list_access_keys(UserName=user_name)
                        for key in access_keys['AccessKeyMetadata']:
                            key_id = key['AccessKeyId']
                            access_keys_by_profile[profile]["keys"][key_id] = {
                                "user": user_name,
                                "status": key['Status'],
                                "created": key['CreateDate']
                            }
                
                key_count = len(access_keys_by_profile[profile]["keys"])
                self.output.write(f"Collected {key_count} access keys from profile {profile} (Account: {account_id})")
                
            except Exception as e:
                self.output.write(f"Error collecting access keys for profile {profile}: {e}")
        
        return access_keys_by_profile
    
    def analyze_cross_account_key_usage(self) -> None:
        """Analyze CloudTrail logs to detect cross-account access key usage."""
        if len(self.profiles) <= 1:
            self.output.write("Cross-account analysis requires multiple profiles. Skipping.")
            return
        
        self.output.write("\n========== CROSS-ACCOUNT ACCESS KEY USAGE ANALYSIS ==========")
        
        # First, collect all access keys from all profiles
        access_keys_by_profile = self.collect_access_keys()
        
        # Now search CloudTrail logs in each profile for access keys from other profiles
        with ThreadPoolExecutor(max_workers=min(10, len(self.profiles))) as executor:
            executor.map(
                lambda p: self._check_profile_for_cross_account_access(p, access_keys_by_profile),
                self.profiles
            )
        
        self.output.write("\n=========================================================")
    
    def _check_profile_for_cross_account_access(self, target_profile: str, access_keys_by_profile: Dict[str, Dict[str, Any]]) -> None:
        """Check a specific profile for cross-account access."""
        try:
            self.output.write(f"\nSearching for cross-account access in profile: {target_profile}")
            
            session = self.get_session(target_profile)
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
                            self.output.write(f"  ALERT: Access key {key_id} from profile {source_profile} (Account: {source_account_id})")
                            self.output.write(f"         User: {key_info['user']}")
                            self.output.write(f"         Has accessed resources in profile {target_profile} (Account: {target_account_id})")
                            self.output.write(f"         Found {len(response['Events'])} events in CloudTrail")
                            
                            # Provide details about most recent events
                            for i, event in enumerate(response['Events'][:5]):  # Show first 5 events
                                event_time = event.get('EventTime', 'Unknown time')
                                event_name = event.get('EventName', 'Unknown event')
                                
                                resource_name = 'Unknown'
                                if event.get('Resources'):
                                    resource_name = event['Resources'][0].get('ResourceName', 'Unknown')
                                
                                self.output.write(f"         Event {i+1}: {event_name} on {event_time}")
                                self.output.write(f"                   Resource: {resource_name}")
                    
                    except Exception as e:
                        self.output.write(f"  Error checking key {key_id} in profile {target_profile}: {e}")
            
        except Exception as e:
            self.output.write(f"Error searching CloudTrail for profile {target_profile}: {e}")
            self.output.write(traceback.format_exc())


def main() -> None:
    """Main function to handle command line arguments and run the analyzer."""
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
        nargs="+",
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
        # Set up output handler
        output = OutputHandler(args.output)
        
        # Determine which profiles to analyze
        if args.profiles:
            profiles = args.profiles
            output.write(f"Analyzing specified profiles: {', '.join(profiles)}")
        else:
            # Use all available profiles
            try:
                session = boto3.Session()
                profiles = session.available_profiles
                output.write(f"Analyzing all {len(profiles)} available profiles")
            except Exception as e:
                output.write(f"Error retrieving available profiles: {e}")
                output.write("Please check your AWS configuration and credentials.")
                return
        
        # Initialize the analyzer
        analyzer = AWSSecurityAnalyzer(profiles, output)
        
        # Run analyses
        for profile in profiles:
            output.write(f"\nProfile: {profile}")
            analyzer.analyze_iam_roles(profile)
            analyzer.analyze_access_keys(profile)
        
        # If cross-account analysis is requested, run it
        if args.cross_account:
            analyzer.analyze_cross_account_key_usage()
        
        output.write("\nAnalysis complete!")

    except Exception as e:
        if args.output:
            with open(args.output, "a") as f:
                f.write(f"\nUnexpected error: {e}\n")
                f.write(traceback.format_exc())
        else:
            print(f"\nUnexpected error: {e}")
            print(traceback.format_exc())


if __name__ == "__main__":
    main()


