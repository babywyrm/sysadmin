#!/usr/bin/env python3
"""
Evaluate the usage and properties of a secret from AWS Secrets Manager
and check if an ArgoCD-deployed application is using it.

The script performs the following:
  - Retrieves secret metadata (including age) from AWS Secrets Manager.
  - Queries an ArgoCD application via its API to see its sync status.
  - (Optional) Inspects a Kubernetes deployment to check which secret is referenced.
  
Requirements:
  - boto3: pip install boto3
  - requests: pip install requests
  - kubernetes (optional): pip install kubernetes

Usage:
  python evaluate_secret.py --secret-id /prod/db/password \
    --argocd-app my-app --argocd-server http://argocd.example.com
"""

import argparse
import datetime
import os,sys,re

import boto3
import requests

# If needed, uncomment the following lines to use the Kubernetes client.
# from kubernetes import client, config


def get_secret_metadata(secret_id, region_name="us-west-2"):
    """
    Retrieve metadata for a given secret from AWS Secrets Manager.
    
    Returns a dictionary with secret details such as CreatedDate.
    """
    client_ = boto3.client("secretsmanager", region_name=region_name)
    try:
        response = client_.describe_secret(SecretId=secret_id)
    except Exception as e:
        sys.exit(f"Error retrieving secret metadata: {e}")
    
    return response


def evaluate_secret_age(metadata, max_age_days=90):
    """
    Evaluate the age of a secret and return a tuple of (is_acceptable, age_in_days).
    
    A secret is considered acceptable if its age (in days) is less than max_age_days.
    """
    created_date = metadata.get("CreatedDate")
    if not created_date:
        print("CreatedDate is not available in secret metadata.")
        return False, None

    # If required, you could also check LastChangedDate if available.
    now = datetime.datetime.now(datetime.timezone.utc)
    age = now - created_date
    age_days = age.days
    is_acceptable = age_days <= max_age_days

    return is_acceptable, age_days


def query_argocd_app(argocd_server, app_name, token):
    """
    Query ArgoCD to get the sync status and health status for a given application.
    
    Returns a dictionary with application status.
    """
    url = f"{argocd_server}/api/v1/applications/{app_name}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except Exception as e:
        sys.exit(f"Error querying ArgoCD application: {e}")
    
    return response.json()


def main():
    parser = argparse.ArgumentParser(
        description=("Evaluate AWS Secret age and ArgoCD usage for a given secret")
    )
    parser.add_argument(
        "--secret-id",
        required=True,
        help="The AWS Secrets Manager secret id (ARN or name)",
    )
    parser.add_argument(
        "--region",
        default="us-west-2",
        help="The AWS region for the secret (default: us-west-2)",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=90,
        help="Maximum acceptable secret age in days (default: 90)",
    )
    parser.add_argument(
        "--argocd-app",
        required=True,
        help="The name of the ArgoCD application to evaluate",
    )
    parser.add_argument(
        "--argocd-server",
        required=True,
        help="The ArgoCD server URL (e.g., https://argocd.example.com)",
    )
    parser.add_argument(
        "--argocd-token",
        required=True,
        help="ArgoCD API token with proper access",
    )
    # Optionally add arguments for Kubernetes client configuration if needed
    # parser.add_argument('--kubeconfig', help='Path to kubeconfig file', default="~/.kube/config")

    args = parser.parse_args()

    # 1. Retrieve secret metadata from AWS Secrets Manager.
    secret_metadata = get_secret_metadata(args.secret_id, region_name=args.region)
    acceptable, age_days = evaluate_secret_age(secret_metadata, max_age_days=args.max_age_days)
    print(f"Secret {args.secret_id} age: {age_days} days")
    if acceptable:
        print("Secret age is acceptable.")
    else:
        print("Warning: Secret is older than the allowed maximum age!")

    # 2. Query ArgoCD and verify application status.
    app_status = query_argocd_app(args.argocd_server, args.argocd_app, args.argocd_token)

    # Extract some key status information. Customize field names as required.
    sync_status = app_status.get("status", {}).get("sync", {}).get("status", "Unknown")
    health_status = app_status.get("status", {}).get("health", {}).get("status", "Unknown")
    print(
        f"ArgoCD Application '{args.argocd_app}': Sync Status = {sync_status}, Health Status = {health_status}"
    )

    # 3. Optionally inspect Kubernetes deployment.
    # Uncomment and configure the following block if you wish to tie into the K8s API.
    """
    try:
        config.load_kube_config(args.kubeconfig)
    except Exception as e:
        sys.exit(f"Error loading kubeconfig: {e}")
    
    k8s_client = client.AppsV1Api()
    deployment = k8s_client.read_namespaced_deployment(
        name=args.argocd_app, namespace="my-app"
    )
    # Check if the deployment's containers reference the expected secret
    secret_references = []
    for container in deployment.spec.template.spec.containers:
        for env in container.env or []:
            if env.value_from and env.value_from.secret_key_ref:
                secret_references.append(env.value_from.secret_key_ref.name)
    
    print("Secret(s) referenced in deployment:", ", ".join(set(secret_references)))
    """

    # Final evaluation: You could decide overall success if the secret age is within limits
    # and the ArgoCD app is Healthy and Synced. Customize your policy as needed.
    if acceptable and sync_status.lower() == "synced" and health_status.lower() == "healthy":
        print("Overall evaluation: SUCCESS")
    else:
        print("Overall evaluation: ISSUE DETECTED")
        sys.exit(1)


if __name__ == "__main__":
    main()
