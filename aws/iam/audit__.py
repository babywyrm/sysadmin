#!/usr/bin/env python3
"""
Export IAM User Permissions with Static Access Key Creation Dates - Beta Edition

This script retrieves IAM users and their associated permission statements 
(from inline and managed policies, including those attached via groups) and 
also retrieves the creation dates of any static access keys for each user.
The results are output to CSV and/or Markdown files as specified on the command line,
or printed to the console.

Usage Examples:
  Export to CSV and Markdown using profile "target-tenant":
    python3 export_iam_permissions.py --profile target-tenant --csv iam_perms.csv --md iam_perms.md

  Print results to the console only:
    python3 export_iam_permissions.py --profile target-tenant
"""

import argparse
import boto3
import csv
import json
from datetime import datetime
from io import StringIO

def get_static_access_keys(iam_client, user):
    """
    Retrieve static (long-term) access keys for the given user along with creation dates.
    Returns a newline-delimited string of key IDs and creation dates,
    or an empty string if no access keys are present.
    """
    try:
        response = iam_client.list_access_keys(UserName=user['UserName'])
    except Exception as e:
        print(f"Error listing access keys for {user['UserName']}: {e}")
        return ""
    
    keys = response.get("AccessKeyMetadata", [])
    key_info = []
    for key in keys:
        # Format: keyID (created: YYYY-MM-DD HH:MM:SS)
        created = key.get("CreateDate")
        # Convert datetime to string if necessary
        if isinstance(created, datetime):
            created = created.strftime("%Y-%m-%d %H:%M:%S")
        key_info.append(f"{key.get('AccessKeyId')} (created: {created})")
    return "\n".join(key_info)

def process_inline_user_policies(iam_client, user):
    """
    Process inline policies for a given user.
    Returns a list of rows (dictionaries) each representing one permission statement.
    """
    rows = []
    try:
        response = iam_client.list_user_policies(UserName=user['UserName'])
    except Exception as e:
        print(f"Error listing inline policies for {user['UserName']}: {e}")
        return rows

    for policy_name in response.get('PolicyNames', []):
        try:
            policy_detail = iam_client.get_user_policy(UserName=user['UserName'], PolicyName=policy_name)
        except Exception as e:
            print(f"Error getting inline policy {policy_name} for {user['UserName']}: {e}")
            continue
        doc = policy_detail.get('PolicyDocument', {})
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):  # Single statement as dict
            statements = [statements]
        for stmt in statements:
            rows.append({
                "UserName": user['UserName'],
                "Effect": stmt.get("Effect", ""),
                "Action": stmt.get("Action", ""),
                "NotAction": stmt.get("NotAction", ""),
                "Resource": stmt.get("Resource", ""),
                "Condition": stmt.get("Condition", ""),
                "Permission Source": "User Inline Policy",
                "StaticAccessKeys": get_static_access_keys(iam_client, user)
            })
    return rows

def process_managed_user_policies(iam_client, user):
    """
    Process managed policies attached to a user.
    Returns a list of rows, each representing one permission statement.
    """
    rows = []
    try:
        response = iam_client.list_attached_user_policies(UserName=user['UserName'])
    except Exception as e:
        print(f"Error listing managed policies for {user['UserName']}: {e}")
        return rows

    for policy in response.get('AttachedPolicies', []):
        policy_arn = policy.get('PolicyArn')
        try:
            policy_detail = iam_client.get_policy(PolicyArn=policy_arn)
            version_id = policy_detail['Policy']['DefaultVersionId']
            version_detail = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        except Exception as e:
            print(f"Error retrieving policy version for {policy_arn}: {e}")
            continue
        doc = version_detail.get("PolicyVersion", {}).get("Document", {})
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            rows.append({
                "UserName": user['UserName'],
                "Effect": stmt.get("Effect", ""),
                "Action": stmt.get("Action", ""),
                "NotAction": stmt.get("NotAction", ""),
                "Resource": stmt.get("Resource", ""),
                "Condition": stmt.get("Condition", ""),
                "Permission Source": "User Managed Policy",
                "StaticAccessKeys": get_static_access_keys(iam_client, user)
            })
    return rows

def process_group_policies(iam_client, user):
    """
    Process group permissions for groups that a user belongs to.
    Returns a list of rows representing permission statements.
    """
    rows = []
    try:
        groups_response = iam_client.list_groups_for_user(UserName=user['UserName'])
    except Exception as e:
        print(f"Error listing groups for {user['UserName']}: {e}")
        return rows
    
    for group in groups_response.get('Groups', []):
        group_name = group.get("GroupName")
        # Process inline policies for the group
        try:
            group_inline = iam_client.list_group_policies(GroupName=group_name)
        except Exception as e:
            print(f"Error listing inline policies for group {group_name}: {e}")
            group_inline = {}
        for policy_name in group_inline.get('PolicyNames', []):
            try:
                policy_detail = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
            except Exception as e:
                print(f"Error getting group inline policy {policy_name} for group {group_name}: {e}")
                continue
            doc = policy_detail.get('PolicyDocument', {})
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                rows.append({
                    "UserName": user['UserName'],
                    "Effect": stmt.get("Effect", ""),
                    "Action": stmt.get("Action", ""),
                    "NotAction": stmt.get("NotAction", ""),
                    "Resource": stmt.get("Resource", ""),
                    "Condition": stmt.get("Condition", ""),
                    "Permission Source": "Group Inline Policy",
                    "StaticAccessKeys": get_static_access_keys(iam_client, user)
                })
        # Process managed policies for the group
        try:
            group_managed = iam_client.list_attached_group_policies(GroupName=group_name)
        except Exception as e:
            print(f"Error listing managed policies for group {group_name}: {e}")
            group_managed = {}
        for policy in group_managed.get('AttachedPolicies', []):
            policy_arn = policy.get("PolicyArn")
            try:
                policy_detail = iam_client.get_policy(PolicyArn=policy_arn)
                version_id = policy_detail['Policy']['DefaultVersionId']
                version_detail = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            except Exception as e:
                print(f"Error retrieving group managed policy {policy_arn}: {e}")
                continue
            doc = version_detail.get("PolicyVersion", {}).get("Document", {})
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                rows.append({
                    "UserName": user['UserName'],
                    "Effect": stmt.get("Effect", ""),
                    "Action": stmt.get("Action", ""),
                    "NotAction": stmt.get("NotAction", ""),
                    "Resource": stmt.get("Resource", ""),
                    "Condition": stmt.get("Condition", ""),
                    "Permission Source": "Group Managed Policy",
                    "StaticAccessKeys": get_static_access_keys(iam_client, user)
                })
    return rows

def write_csv(rows, output_file):
    """
    Write the list of row dictionaries to a CSV file.
    """
    fieldnames = ["UserName", "Effect", "Action", "NotAction", "Resource",
                  "Condition", "Permission Source", "StaticAccessKeys"]
    try:
        with open(output_file, "w", newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        print(f"CSV output written to: {output_file}")
    except Exception as e:
        print(f"Error writing CSV file: {e}")

def write_markdown(rows, output_file):
    """
    Write the list of row dictionaries to a Markdown file as a table.
    """
    headers = ["UserName", "Effect", "Action", "NotAction", "Resource", "Condition",
               "Permission Source", "StaticAccessKeys"]
    # Create the header row with markdown table formatting.
    md_lines = []
    md_lines.append("| " + " | ".join(headers) + " |")
    md_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        # For each row, convert values to string, replace newlines with <br> for markdown
        line = "| " + " | ".join(str(row.get(h, "")).replace("\n", "<br>") for h in headers) + " |"
        md_lines.append(line)
    
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))
        print(f"Markdown output written to: {output_file}")
    except Exception as e:
        print(f"Error writing Markdown file: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Export IAM user and group permissions with static access key creation dates to CSV and Markdown.",
        epilog="Example: python3 export_iam_permissions.py --profile things-ro --csv iam_perms.csv --md iam_perms.md"
    )
    parser.add_argument("--profile", required=True, help="AWS profile to use (e.g. things-ro)")
    parser.add_argument("--csv", help="CSV file to output permissions")
    parser.add_argument("--md", help="Markdown file to output permissions")
    
    args = parser.parse_args()
    
    # Create boto3 session and IAM client.
    session = boto3.Session(profile_name=args.profile)
    iam_client = session.client("iam")
    
    all_rows = []
    print("Exporting IAM permissions...")
    
    # Use paginator to list all IAM users.
    paginator = iam_client.get_paginator('list_users')
    for page in paginator.paginate(PaginationConfig={'PageSize': 1000}):
        users = page.get("Users", [])
        for user in users:
            print(f"Processing {user['UserName']} ...")
            # Process user inline policies.
            all_rows.extend(process_inline_user_policies(iam_client, user))
            # Process user managed policies.
            all_rows.extend(process_managed_user_policies(iam_client, user))
            # Process group policies.
            all_rows.extend(process_group_policies(iam_client, user))
    
    if not all_rows:
        print("No permissions found.")
    else:
        # If CSV output is specified, write CSV.
        if args.csv:
            write_csv(all_rows, args.csv)
        # If Markdown output is specified, write Markdown.
        if args.md:
            write_markdown(all_rows, args.md)
        # Also, print a summary to the console.
        print("Exported permission rows:")
        for row in all_rows:
            print(json.dumps(row, default=str, indent=2))
    
    print("Export completed.")

if __name__ == "__main__":
    main()
