#!/usr/bin/env python3
"""
Export IAM User Permissions & Assumable Roles -- RC1

This script retrieves IAM users and their permission statements (from inline, managed,
and group policies), collects creation dates for static access keys, and determines which
IAM roles a user can assume by scanning trust policies. The results are exported to CSV 
and/or Markdown files, or printed to the console.

Usage Examples:
  Export permissions and roles using profile "example":
    python3 export_iam_permissions.py --profile example --csv iam_perms.csv --md iam_perms.md

  Print results to console only:
    python3 export_iam_permissions.py --profile example
"""

import argparse
import boto3
import csv
import json
from datetime import datetime
import xlsxwriter  # Only needed if you want Excel output; not used in current CSV/Markdown functions.
from io import StringIO

### Helper Functions ###

def get_static_access_keys(iam_client, user):
    """
    Retrieve static (long-term) access keys for the given user along with creation dates.

    :param iam_client: boto3 IAM client.
    :param user: Dictionary representing the IAM user.
    :return: Newline-delimited string of key IDs with creation dates (or empty string if none).
    """
    try:
        response = iam_client.list_access_keys(UserName=user['UserName'])
    except Exception as e:
        print(f"Error listing access keys for {user['UserName']}: {e}")
        return ""
    
    keys = response.get("AccessKeyMetadata", [])
    key_info = []
    for key in keys:
        created = key.get("CreateDate")
        if isinstance(created, datetime):
            created = created.strftime("%Y-%m-%d %H:%M:%S")
        key_info.append(f"{key.get('AccessKeyId')} (created: {created})")
    return "\n".join(key_info)

def process_inline_user_policies(iam_client, user):
    """
    Process inline policies attached directly to a user.

    :param iam_client: boto3 IAM client.
    :param user: Dictionary representing the IAM user.
    :return: List of rows (dictionaries) for this user's inline policies.
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
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            rows.append({
                "UserName": user['UserName'],
                "Permission": stmt,
                "Source": "User Inline Policy",
                "StaticAccessKeys": get_static_access_keys(iam_client, user)
            })
    return rows

def process_managed_user_policies(iam_client, user):
    """
    Process managed policies attached to a user.

    :param iam_client: boto3 IAM client.
    :param user: Dictionary representing the IAM user.
    :return: List of rows (dictionaries) for this user's managed policies.
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
            print(f"Error retrieving managed policy {policy_arn}: {e}")
            continue
        doc = version_detail.get("PolicyVersion", {}).get("Document", {})
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            rows.append({
                "UserName": user['UserName'],
                "Permission": stmt,
                "Source": "User Managed Policy",
                "StaticAccessKeys": get_static_access_keys(iam_client, user)
            })
    return rows

def process_group_policies(iam_client, user):
    """
    Process policies for the groups that a user belongs to (both inline and managed).

    :param iam_client: boto3 IAM client.
    :param user: Dictionary representing the IAM user.
    :return: List of rows (dictionaries) for group policies applicable to the user.
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
                    "Permission": stmt,
                    "Source": "Group Inline Policy",
                    "StaticAccessKeys": get_static_access_keys(iam_client, user)
                })
        # Process managed policies for the group
        try:
            group_managed = iam_client.list_attached_group_policies(GroupName=group_name)
        except Exception as e:
            print(f"Error listing managed policies for group {group_name}: {e}")
            group_managed = {}
        for policy in group_managed.get('AttachedPolicies', []):
            policy_arn = policy.get('PolicyArn')
            try:
                policy_detail = iam_client.get_policy(PolicyArn=policy_arn)
                version_id = policy_detail['Policy']['DefaultVersionId']
                version_detail = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            except Exception as e:
                print(f"Error retrieving managed policy {policy_arn}: {e}")
                continue
            doc = version_detail.get("PolicyVersion", {}).get("Document", {})
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                rows.append({
                    "UserName": user['UserName'],
                    "Permission": stmt,
                    "Source": "Group Managed Policy",
                    "StaticAccessKeys": get_static_access_keys(iam_client, user)
                })
    return rows

def get_all_roles(iam_client):
    """
    Retrieve all IAM roles in the account using a paginator.

    :param iam_client: boto3 IAM client.
    :return: List of role dictionaries.
    """
    roles = []
    paginator = iam_client.get_paginator('list_roles')
    for page in paginator.paginate(PaginationConfig={'PageSize': 100}):
        roles.extend(page.get("Roles", []))
    return roles

def process_assumable_roles_for_user(user, roles):
    """
    Determine which roles a user is allowed to assume by scanning each role's trust
    policy (AssumeRolePolicyDocument) to see if the user's ARN appears in the Principal.

    :param user: The IAM user dictionary.
    :param roles: List of all IAM roles in the account.
    :return: List of rows (dictionaries) representing assumable roles for the user.
    """
    rows = []
    user_arn = user.get("Arn", "")
    for role in roles:
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        statements = trust_policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        allowed = False
        for stmt in statements:
            principal = stmt.get("Principal", {})
            aws_principal = principal.get("AWS", "")
            # aws_principal can be a string or list
            if isinstance(aws_principal, str):
                if user_arn.lower() == aws_principal.lower():
                    allowed = True
                    break
            elif isinstance(aws_principal, list):
                for arn in aws_principal:
                    if user_arn.lower() == arn.lower():
                        allowed = True
                        break
            if allowed:
                break
        if allowed:
            rows.append({
                "UserName": user['UserName'],
                "Permission": {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role.get("Arn", "")},
                "Source": "Assumable Role",
                "StaticAccessKeys": ""  # Not applicable for role rows.
            })
    return rows

def write_csv(rows, output_file):
    """
    Write the list of permission rows to a CSV file.
    
    :param rows: List of row dictionaries.
    :param output_file: Output CSV file path.
    """
    fieldnames = ["UserName", "Effect", "Action", "NotAction", "Resource",
                  "Condition", "Permission Source", "StaticAccessKeys"]
    try:
        with open(output_file, "w", newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({
                    "UserName": row.get("UserName", ""),
                    "Effect": row.get("Permission", {}).get("Effect", ""),
                    "Action": row.get("Permission", {}).get("Action", ""),
                    "NotAction": row.get("Permission", {}).get("NotAction", ""),
                    "Resource": row.get("Permission", {}).get("Resource", ""),
                    "Condition": row.get("Permission", {}).get("Condition", ""),
                    "Permission Source": row.get("Source", ""),
                    "StaticAccessKeys": row.get("StaticAccessKeys", "")
                })
        print(f"CSV output written to: {output_file}")
    except Exception as e:
        print(f"Error writing CSV file: {e}")

def write_markdown(rows, output_file):
    """
    Write the list of permission rows to a Markdown file as a table.
    
    :param rows: List of row dictionaries.
    :param output_file: Output Markdown file path.
    """
    headers = ["UserName", "Effect", "Action", "NotAction", "Resource", "Condition",
               "Permission Source", "StaticAccessKeys"]
    md_lines = []
    md_lines.append("| " + " | ".join(headers) + " |")
    md_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
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
        description="Export IAM user and group permissions (and assumable roles) to CSV and Markdown for forensic analysis.",
        epilog="Example: python3 export_iam_permissions.py --profile example --csv iam_perms.csv --md iam_perms.md"
    )
    parser.add_argument("--profile", required=True, help="AWS profile to use (e.g. example)")
    parser.add_argument("--csv", help="CSV file to output permissions (e.g. iam_perms.csv)")
    parser.add_argument("--md", help="Markdown file to output permissions (e.g. iam_perms.md)")
    
    args = parser.parse_args()
    
    # Create boto3 session and IAM client.
    session = boto3.Session(profile_name=args.profile)
    iam_client = session.client("iam")
    
    # Fetch all roles to determine assumable roles later.
    print("Fetching all IAM roles...")
    all_roles = []
    try:
        paginator_roles = iam_client.get_paginator('list_roles')
        for page in paginator_roles.paginate(PaginationConfig={'PageSize': 100}):
            all_roles.extend(page.get("Roles", []))
    except Exception as e:
        print("Error retrieving roles:", e)
    
    all_rows = []
    print("Exporting IAM permissions...")
    
    # Use paginator to list all IAM users.
    paginator = iam_client.get_paginator('list_users')
    for page in paginator.paginate(PaginationConfig={'PageSize': 1000}):
        users = page.get("Users", [])
        for user in users:
            print(f"Processing permissions for user: {user['UserName']}")
            # Process inline user policies.
            all_rows.extend(process_inline_user_policies(iam_client, user))
            # Process managed user policies.
            all_rows.extend(process_managed_user_policies(iam_client, user))
            # Process group policies.
            all_rows.extend(process_group_policies(iam_client, user))
            # Process assumable roles.
            all_rows.extend(process_assumable_roles_for_user(user, all_roles))
    
    if not all_rows:
        print("No permissions found.")
    else:
        # Write CSV if specified.
        if args.csv:
            write_csv(all_rows, args.csv)
        # Write Markdown if specified.
        if args.md:
            write_markdown(all_rows, args.md)
        # Always print a summary to the console.
        print("Exported permission rows:")
        for row in all_rows:
            print(json.dumps(row, default=str, indent=2))
    
    print("Export completed.")

if __name__ == "__main__":
    main()
