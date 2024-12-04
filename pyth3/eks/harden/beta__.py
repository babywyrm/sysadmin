import boto3
from kubernetes import client, config
from tabulate import tabulate
import argparse
from time import time

##
##

def init_clients(cluster_name, region_name):
    """Initialize AWS and Kubernetes clients."""
    # Initialize AWS EKS client
    eks_client = boto3.client("eks", region_name=region_name)

    # Verify cluster exists in AWS
    try:
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        print(f"Cluster found: {cluster_info['cluster']['name']} in region {region_name}")
    except Exception as e:
        print(f"Error: {e}")
        print(f"Check if the cluster name '{cluster_name}' and region '{region_name}' are correct.")
        exit(1)

    # Load Kubernetes configuration for the correct context
    context_name = f"arn:aws:eks:{region_name}:14432323233:cluster/{cluster_name}"
    try:
        config.load_kube_config(context=context_name)
        print(f"Using kubectl context: {context_name}")
    except Exception as e:
        print(f"Error loading kubeconfig for context '{context_name}': {e}")
        exit(1)

    k8s_client = client.CoreV1Api()
    return k8s_client, eks_client


def check_k8s_version(eks_client, cluster_name):
    """Check Kubernetes version."""
    cluster_info = eks_client.describe_cluster(name=cluster_name)
    version = cluster_info["cluster"]["version"]
    print(f"Kubernetes Version: {version}")


def validate_namespaces(k8s_client):
    """Validate namespaces for security configurations."""
    namespaces = k8s_client.list_namespace()
    findings = []
    for ns in namespaces.items:
        name = ns.metadata.name
        annotations = ns.metadata.annotations
        if name == "default" and not annotations:
            findings.append((name, "No security annotations"))
        else:
            findings.append((name, "Annotations found" if annotations else "No annotations"))
    return findings


def check_public_services(k8s_client):
    """Check for public-facing services."""
    services = k8s_client.list_service_for_all_namespaces()
    findings = []
    for svc in services.items:
        if svc.spec.type == "LoadBalancer":
            findings.append((svc.metadata.name, "Public LoadBalancer detected"))
        else:
            findings.append((svc.metadata.name, "No public LoadBalancer"))
    return findings


def validate_rbac(k8s_client):
    """Validate RBAC configuration."""
    rbac_api = client.RbacAuthorizationV1Api()
    roles = rbac_api.list_cluster_role()
    findings = []
    for role in roles.items:
        findings.append((role.metadata.name, "System role" if "system:" in role.metadata.name else "Custom role"))
    return findings


def main():
    parser = argparse.ArgumentParser(description="EKS Security Assessment Script")
    parser.add_argument("--cluster-name", required=True, help="EKS Cluster Name")
    parser.add_argument("--region", required=True, help="AWS Region of the EKS Cluster")
    args = parser.parse_args()

    cluster_name = args.cluster_name
    region_name = args.region

    k8s_client, eks_client = init_clients(cluster_name, region_name)

    print("\n--- Validating EKS Security ---")

    # Check Kubernetes version
    check_k8s_version(eks_client, cluster_name)

    # Validate namespaces
    print("\nNamespace Validation:")
    namespace_findings = validate_namespaces(k8s_client)
    print(tabulate(namespace_findings, headers=["Namespace", "Finding"]))

    # Check public-facing services
    print("\nPublic Services Validation:")
    service_findings = check_public_services(k8s_client)
    print(tabulate(service_findings, headers=["Service Name", "Finding"]))

    # Validate RBAC roles
    print("\nRBAC Validation:")
    rbac_findings = validate_rbac(k8s_client)
    print(tabulate(rbac_findings, headers=["Role Name", "Finding"]))


if __name__ == "__main__":
    main()

##
##
