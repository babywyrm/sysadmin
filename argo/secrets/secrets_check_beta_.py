#!/usr/bin/env python3
"""
Advanced Evaluation Script for AWS Secrets Manager and ArgoCD Deployments (Testing...)

This script performs the following:
  - Retrieves detailed metadata for a given secret from AWS Secrets Manager,
    including its creation date, last changed date, and tags for rotation policies.
  - Evaluates if the secret is within acceptable age limits.
  - Checks if the secret includes a specific tag (e.g., 'RotationPolicy') to indicate
    that rotation is enabled.
  - Queries an ArgoCD application via its API to fetch sync and health statuses.
  - Optionally inspects a Kubernetes deployment to verify which secret(s) are referenced.
  - Logs detailed debug information at each step.

Requirements:
  - boto3: pip install boto3
  - requests: pip install requests
  - kubernetes (optional): pip install kubernetes

Usage:
  python advanced_evaluate_secret.py --secret-id /prod/db/password \
    --argocd-app my-app --argocd-server https://argocd.example.com \
    --argocd-token xxxxxxxxxxxx
"""

import argparse
import datetime
import logging
import sys
from typing import Tuple, Optional

import boto3
import requests

# Uncomment if you plan to use the Kubernetes integration.
# from kubernetes import client, config

# Configure logging for the script.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def get_secret_metadata(secret_id: str, region_name: str = "us-west-2") -> dict:
    """
    Retrieves metadata for a given secret from AWS Secrets Manager.
    
    Returns:
        A dictionary with secret details including CreatedDate, LastChangedDate,
        and Tags.
    """
    logger.debug("Connecting to AWS Secrets Manager in region %s", region_name)
    client_ = boto3.client("secretsmanager", region_name=region_name)
    try:
        response = client_.describe_secret(SecretId=secret_id)
        logger.debug("Retrieved secret metadata: %s", response)
    except Exception as e:
        logger.error("Failed to retrieve secret metadata for %s: %s", secret_id, e)
        sys.exit(1)
    return response


def evaluate_secret_age(
    metadata: dict, max_age_days: int = 90
) -> Tuple[bool, Optional[int]]:
    """
    Evaluates the age of a secret using CreatedDate and optionally LastChangedDate.
    
    Args:
        metadata: Metadata dictionary from AWS Secrets Manager.
        max_age_days: Maximum acceptable age in days.
    
    Returns:
        A tuple (is_acceptable, age_in_days). `is_acceptable` is True if the age of
        the secret is within the limit.
    """
    created_date = metadata.get("CreatedDate")
    if not created_date:
        logger.warning("CreatedDate is missing in the secret metadata.")
        return False, None

    now = datetime.datetime.now(datetime.timezone.utc)
    age_delta = now - created_date
    age_days = age_delta.days
    is_acceptable = age_days <= max_age_days

    logger.debug(
        "Secret created on %s (age: %d days; max allowed: %d days)",
        created_date.isoformat(),
        age_days,
        max_age_days,
    )
    return is_acceptable, age_days


def check_secret_rotation(metadata: dict, expected_tag: str = "RotationPolicy") -> bool:
    """
    Checks if the secret has the proper tag for secret rotation.
    
    Args:
        metadata: Metadata dictionary from AWS Secrets Manager.
        expected_tag: The tag key that should be present.
    
    Returns:
        True if the expected tag is present, False otherwise.
    """
    tags = metadata.get("Tags", [])
    tag_keys = {tag["Key"]: tag.get("Value", "") for tag in tags}
    logger.debug("Secret tags: %s", tag_keys)
    if expected_tag in tag_keys:
        logger.debug("Secret contains expected tag: %s", expected_tag)
        return True
    else:
        logger.warning("Secret is missing the expected tag: %s", expected_tag)
        return False


def query_argocd_app(argocd_server: str, app_name: str, token: str) -> dict:
    """
    Queries the ArgoCD API to get details about a given application deployment.
    
    Args:
        argocd_server: The ArgoCD server URL.
        app_name: The name of the application to query.
        token: The API token for authentication.
    
    Returns:
        A dictionary with ArgoCD application status and details.
    """
    url = f"{argocd_server}/api/v1/applications/{app_name}"
    headers = {"Authorization": f"Bearer {token}"}
    logger.debug("Querying ArgoCD application at URL: %s", url)
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        app_data = response.json()
        logger.debug("ArgoCD application response: %s", app_data)
    except Exception as e:
        logger.error("Failed to query ArgoCD application: %s", e)
        sys.exit(1)
    return app_data


def inspect_k8s_deployment(app_name: str, namespace: str, kubeconfig: str = None):
    """
    Inspects a Kubernetes deployment to determine which secrets are referenced
    in the containers' environment variables.
    
    Args:
        app_name: The Kubernetes deployment name.
        namespace: The namespace where the deployment is located.
        kubeconfig: Path to the kubeconfig file if needed.
    
    This function is optional and commented out by default.
    """
    try:
        # Load kubeconfig (default location or specified file)
        # config.load_kube_config(kubeconfig)
        pass  # Remove this pass statement when enabling the K8s code below.
    except Exception as e:
        logger.error("Error loading kubeconfig: %s", e)
        sys.exit(1)
    
    # Uncomment the following block if using the Kubernetes client.
    """
    k8s_client = client.AppsV1Api()
    try:
        deployment = k8s_client.read_namespaced_deployment(name=app_name, namespace=namespace)
    except Exception as e:
        logger.error("Failed to read Kubernetes deployment %s: %s", app_name, e)
        return []
    
    secret_references = []
    for container in deployment.spec.template.spec.containers:
        for env in container.env or []:
            if env.value_from and env.value_from.secret_key_ref:
                secret_references.append(env.value_from.secret_key_ref.name)
    
    unique_secrets = list(set(secret_references))
    logger.debug("Secrets referenced in deployment %s: %s", app_name, unique_secrets)
    return unique_secrets
    """
    return []  # Temporary placeholder if Kubernetes check is disabled.


def main():
    parser = argparse.ArgumentParser(
        description="Advanced evaluation of AWS Secrets Manager and ArgoCD usage."
    )
    parser.add_argument(
        "--secret-id", required=True, help="The AWS Secrets Manager secret id (ARN or name)"
    )
    parser.add_argument(
        "--region", default="us-west-2", help="The AWS region for the secret (default: us-west-2)"
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=90,
        help="Maximum acceptable secret age in days (default: 90)",
    )
    parser.add_argument(
        "--argocd-app", required=True, help="The name of the ArgoCD application to evaluate"
    )
    parser.add_argument(
        "--argocd-server",
        required=True,
        help="The ArgoCD server URL (e.g., https://argocd.example.com)",
    )
    parser.add_argument(
        "--argocd-token",
        required=True,
        help="ArgoCD API token with appropriate permissions",
    )
    parser.add_argument(
        "--namespace",
        default="default",
        help="The Kubernetes namespace for the deployment (optional, default: default)",
    )
    parser.add_argument(
        "--kubeconfig",
        help="Path to kubeconfig file (optional, for Kubernetes inspection)",
        default="~/.kube/config",
    )
    args = parser.parse_args()

    # 1. Retrieve AWS Secrets Manager metadata.
    secret_metadata = get_secret_metadata(args.secret_id, region_name=args.region)

    # 2. Evaluate the secret age.
    is_age_ok, secret_age = evaluate_secret_age(secret_metadata, max_age_days=args.max_age_days)
    if secret_age is not None:
        logger.info("Secret '%s' age: %d days", args.secret_id, secret_age)
    if not is_age_ok:
        logger.warning("Secret '%s' is older than the allowed maximum age!", args.secret_id)

    # 3. Check if secret rotation is enabled via a specific tag.
    if check_secret_rotation(secret_metadata, expected_tag="RotationPolicy"):
        logger.info("Secret '%s' has rotation enabled.", args.secret_id)
    else:
        logger.warning("Secret '%s' does NOT have rotation enabled.", args.secret_id)

    # 4. Query the ArgoCD application and evaluate its status.
    app_status = query_argocd_app(args.argocd_server, args.argocd_app, args.argocd_token)
    sync_status = (
        app_status.get("status", {})
        .get("sync", {})
        .get("status", "Unknown")
        .lower()
    )
    health_status = (
        app_status.get("status", {})
        .get("health", {})
        .get("status", "Unknown")
        .lower()
    )
    logger.info(
        "ArgoCD Application '%s': Sync Status = %s, Health Status = %s",
        args.argocd_app,
        sync_status,
        health_status,
    )

    # 5. Optionally inspect the Kubernetes deployment to check for secret references.
    k8s_secrets = inspect_k8s_deployment(args.argocd_app, args.namespace, args.kubeconfig)
    if k8s_secrets:
        logger.info(
            "Kubernetes deployment '%s' in namespace '%s' references secrets: %s",
            args.argocd_app,
            args.namespace,
            ", ".join(k8s_secrets),
        )
    else:
        logger.debug("No Kubernetes secret references found or inspection disabled.")

    # 6. Final evaluation summary.
    evaluation_ok = True
    if not is_age_ok:
        evaluation_ok = False
    if sync_status != "synced" or health_status != "healthy":
        evaluation_ok = False

    if evaluation_ok:
        logger.info("Overall evaluation: SUCCESS")
    else:
        logger.error("Overall evaluation: ISSUES DETECTED")
        sys.exit(1)


if __name__ == "__main__":
    main()

