#!/usr/bin/env python3
"""
EKS/Kubernetes Security and Compliance Validation Script  ***( Still In Testing )***

This script performs automated security and compliance checks against an
EKS cluster to support the production readiness checklist.

Requirements:
- kubectl configured with access to your cluster
- Python 3.7+
- Required packages: kubernetes, boto3, pyyaml, tabulate

Usage:
    python eks_security_validation.py --cluster-name your-cluster-name --region us-west-2
    python eks_security_validation.py --cluster-name your-cluster-name --region us-west-2 --include-kube-bench
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Any, Tuple

import boto3
import yaml
from kubernetes import client, config
from tabulate import tabulate

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

class EKSSecurityValidator:
    def __init__(self, cluster_name: str, region: str):
        self.cluster_name = cluster_name
        self.region = region
        self.results = {}
        self.k8s_api = None
        self.k8s_apps_api = None
        self.k8s_rbac_api = None
        self.k8s_core_api = None
        self.session = None
        self.eks_client = None
        
    def initialize(self):
        """Initialize connections to AWS and Kubernetes"""
        try:
            # Set up AWS session
            self.session = boto3.Session(region_name=self.region)
            self.eks_client = self.session.client('eks')
            
            # Get EKS cluster details
            cluster_info = self.eks_client.describe_cluster(name=self.cluster_name)
            logger.info(f"Connected to EKS cluster: {self.cluster_name}")
            
            # Set up Kubernetes client
            config.load_kube_config()
            self.k8s_core_api = client.CoreV1Api()
            self.k8s_apps_api = client.AppsV1Api()
            self.k8s_rbac_api = client.RbacAuthorizationV1Api()
            self.k8s_api = client.ApiextensionsV1Api()
            
            # Basic connectivity test
            namespaces = self.k8s_core_api.list_namespace()
            logger.info(f"Successfully connected to Kubernetes API. Found {len(namespaces.items)} namespaces.")
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize connections: {str(e)}")
            return False
    
    def run_all_checks(self, include_kube_bench=False):
        """Run all security and compliance checks"""
        if not self.initialize():
            return False
        
        # Container Security Checks
        self.results["container_security"] = {
            "title": "Container Security",
            "checks": [
                self.check_privileged_containers(),
                self.check_host_pid_ipc_network(),
                self.check_resource_limits(),
                self.check_image_pull_policy(),
                self.check_liveness_readiness_probes(),
            ]
        }
        
        # RBAC Checks
        self.results["rbac_security"] = {
            "title": "RBAC & Access Control",
            "checks": [
                self.check_cluster_admin_bindings(),
                self.check_service_account_tokens(),
                self.check_default_service_accounts(),
            ]
        }
        
        # Network Security
        self.results["network_security"] = {
            "title": "Network Security",
            "checks": [
                self.check_network_policies(),
                self.check_exposed_services(),
            ]
        }
        
        # Secrets Management
        self.results["secrets_management"] = {
            "title": "Secrets Management",
            "checks": [
                self.check_secrets_encryption(),
                self.check_secrets_as_env_vars(),
            ]
        }
        
        # Cluster Configuration
        self.results["cluster_configuration"] = {
            "title": "Cluster Configuration",
            "checks": [
                self.check_kubernetes_version(),
                self.check_control_plane_logging(),
                self.check_cluster_encryption(),
                self.check_pod_security_standards(),
            ]
        }
        
        # Run kube-bench if enabled
        if include_kube_bench:
            self.results["cis_benchmark"] = {
                "title": "CIS Kubernetes Benchmark",
                "checks": [
                    self.add_kube_bench_support(),
                ]
            }
        
        return True
        
    def check_privileged_containers(self) -> Dict:
        """Check for privileged containers running in the cluster"""
        try:
            pods = self.k8s_core_api.list_pod_for_all_namespaces(watch=False)
            privileged_pods = []
            
            for pod in pods.items:
                for container in pod.spec.containers:
                    if (container.security_context and 
                        container.security_context.privileged):
                        privileged_pods.append({
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name
                        })
            
            status = "PASS" if len(privileged_pods) == 0 else "FAIL"
            return {
                "name": "Privileged Containers Check",
                "status": status,
                "description": "Checks for containers running with privileged security context",
                "details": f"Found {len(privileged_pods)} privileged containers" if privileged_pods else "No privileged containers found",
                "items": privileged_pods
            }
        except Exception as e:
            return {
                "name": "Privileged Containers Check",
                "status": "ERROR",
                "description": "Checks for containers running with privileged security context",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_host_pid_ipc_network(self) -> Dict:
        """Check for pods using hostPID, hostIPC, or hostNetwork"""
        try:
            pods = self.k8s_core_api.list_pod_for_all_namespaces(watch=False)
            problematic_pods = []
            
            for pod in pods.items:
                issues = []
                if pod.spec.host_pid:
                    issues.append("hostPID")
                if pod.spec.host_ipc:
                    issues.append("hostIPC")
                if pod.spec.host_network:
                    issues.append("hostNetwork")
                
                if issues:
                    problematic_pods.append({
                        "namespace": pod.metadata.namespace,
                        "pod": pod.metadata.name,
                        "issues": ", ".join(issues)
                    })
            
            status = "PASS" if len(problematic_pods) == 0 else "FAIL"
            return {
                "name": "Host Namespace Isolation",
                "status": status,
                "description": "Checks for pods using host namespaces (hostPID, hostIPC, hostNetwork)",
                "details": f"Found {len(problematic_pods)} pods with host namespace issues" if problematic_pods else "No pods using host namespaces found",
                "items": problematic_pods
            }
        except Exception as e:
            return {
                "name": "Host Namespace Isolation",
                "status": "ERROR",
                "description": "Checks for pods using host namespaces (hostPID, hostIPC, hostNetwork)",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_resource_limits(self) -> Dict:
        """Check for containers without resource limits defined"""
        try:
            pods = self.k8s_core_api.list_pod_for_all_namespaces(watch=False)
            pods_without_limits = []
            total_containers = 0
            
            for pod in pods.items:
                for container in pod.spec.containers:
                    total_containers += 1
                    if (not container.resources or 
                        not container.resources.limits):
                        pods_without_limits.append({
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name
                        })
            
            # Allowing some pods without limits is acceptable, but warn if >20% lack limits
            percentage = (len(pods_without_limits) / total_containers * 100) if total_containers > 0 else 0
            status = "PASS" if percentage < 20 else "WARN" if percentage < 50 else "FAIL"
            
            return {
                "name": "Resource Limits Check",
                "status": status,
                "description": "Checks for containers without resource limits set",
                "details": f"Found {len(pods_without_limits)} containers ({percentage:.1f}%) without resource limits",
                "items": pods_without_limits[:10] if len(pods_without_limits) > 10 else pods_without_limits
            }
        except Exception as e:
            return {
                "name": "Resource Limits Check",
                "status": "ERROR",
                "description": "Checks for containers without resource limits set",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_image_pull_policy(self) -> Dict:
        """Check for containers using 'latest' tag or with improper pull policy"""
        try:
            pods = self.k8s_core_api.list_pod_for_all_namespaces(watch=False)
            problematic_containers = []
            
            for pod in pods.items:
                for container in pod.spec.containers:
                    issues = []
                    
                    # Check for 'latest' tag
                    if container.image and (":latest" in container.image or ":" not in container.image):
                        issues.append("uses 'latest' tag or no tag")
                    
                    # Check pull policy - should be Always if using latest
                    if container.image_pull_policy != "Always" and (":latest" in container.image or ":" not in container.image):
                        issues.append("should use 'Always' pull policy with latest tag")
                    
                    if issues:
                        problematic_containers.append({
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "image": container.image,
                            "issues": ", ".join(issues)
                        })
            
            status = "PASS" if len(problematic_containers) == 0 else "WARN"
            return {
                "name": "Image Tag and Pull Policy",
                "status": status,
                "description": "Checks for containers using 'latest' tag or improper pull policy",
                "details": f"Found {len(problematic_containers)} containers with image tag/pull policy issues",
                "items": problematic_containers[:10] if len(problematic_containers) > 10 else problematic_containers
            }
        except Exception as e:
            return {
                "name": "Image Tag and Pull Policy",
                "status": "ERROR",
                "description": "Checks for containers using 'latest' tag or improper pull policy",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_liveness_readiness_probes(self) -> Dict:
        """Check for containers without liveness and readiness probes"""
        try:
            deployments = self.k8s_apps_api.list_deployment_for_all_namespaces(watch=False)
            containers_without_probes = []
            total_containers = 0
            
            for deployment in deployments.items:
                # Skip certain system deployments where probes might not be necessary
                if deployment.metadata.namespace in ["kube-system"]:
                    continue
                    
                for container in deployment.spec.template.spec.containers:
                    total_containers += 1
                    missing = []
                    
                    if not container.liveness_probe:
                        missing.append("liveness")
                    if not container.readiness_probe:
                        missing.append("readiness")
                    
                    if missing:
                        containers_without_probes.append({
                            "namespace": deployment.metadata.namespace,
                            "deployment": deployment.metadata.name,
                            "container": container.name,
                            "missing": ", ".join(missing)
                        })
            
            # Calculate percentage for severity determination
            percentage = (len(containers_without_probes) / total_containers * 100) if total_containers > 0 else 0
            status = "PASS" if percentage < 20 else "WARN" if percentage < 50 else "FAIL"
            
            return {
                "name": "Liveness/Readiness Probes",
                "status": status,
                "description": "Checks for containers without liveness/readiness probes",
                "details": f"Found {len(containers_without_probes)} containers ({percentage:.1f}%) without proper probes",
                "items": containers_without_probes[:10] if len(containers_without_probes) > 10 else containers_without_probes
            }
        except Exception as e:
            return {
                "name": "Liveness/Readiness Probes",
                "status": "ERROR",
                "description": "Checks for containers without liveness/readiness probes",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_cluster_admin_bindings(self) -> Dict:
        """Check for excessive use of cluster-admin role bindings"""
        try:
            # Get cluster role bindings
            cluster_role_bindings = self.k8s_rbac_api.list_cluster_role_binding()
            admin_bindings = []
            
            for binding in cluster_role_bindings.items:
                if binding.role_ref.name == "cluster-admin":
                    subjects = []
                    if binding.subjects:
                        for subject in binding.subjects:
                            subjects.append({
                                "kind": subject.kind,
                                "name": subject.name,
                                "namespace": subject.namespace if hasattr(subject, "namespace") else "N/A"
                            })
                    
                    admin_bindings.append({
                        "name": binding.metadata.name,
                        "subjects": subjects
                    })
            
            # Some cluster-admin bindings are necessary, but too many is a red flag
            status = "PASS" if len(admin_bindings) < 5 else "WARN" if len(admin_bindings) < 10 else "FAIL"
            
            return {
                "name": "Cluster Admin Role Bindings",
                "status": status,
                "description": "Checks for excessive use of cluster-admin role bindings",
                "details": f"Found {len(admin_bindings)} cluster-admin role bindings",
                "items": admin_bindings
            }
        except Exception as e:
            return {
                "name": "Cluster Admin Role Bindings",
                "status": "ERROR",
                "description": "Checks for excessive use of cluster-admin role bindings",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_service_account_tokens(self) -> Dict:
        """Check for service accounts with automountServiceAccountToken enabled"""
        try:
            service_accounts = self.k8s_core_api.list_service_account_for_all_namespaces(watch=False)
            auto_mounting_accounts = []
            
            for sa in service_accounts.items:
                # If automountServiceAccountToken is explicitly True or not set (which defaults to True)
                if sa.automount_service_account_token is None or sa.automount_service_account_token:
                    auto_mounting_accounts.append({
                        "namespace": sa.metadata.namespace,
                        "name": sa.metadata.name,
                        "explicitly_enabled": sa.automount_service_account_token is True
                    })
            
            # It's normal for some SAs to automount tokens, but it should be limited
            percentage = len(auto_mounting_accounts) / len(service_accounts.items) * 100 if service_accounts.items else 0
            status = "PASS" if percentage < 50 else "WARN" if percentage < 80 else "FAIL"
            
            return {
                "name": "Service Account Token Automounting",
                "status": status,
                "description": "Checks for service accounts that automatically mount tokens",
                "details": f"Found {len(auto_mounting_accounts)} service accounts ({percentage:.1f}%) with token automounting enabled",
                "items": auto_mounting_accounts[:10] if len(auto_mounting_accounts) > 10 else auto_mounting_accounts
            }
        except Exception as e:
            return {
                "name": "Service Account Token Automounting",
                "status": "ERROR",
                "description": "Checks for service accounts that automatically mount tokens",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_default_service_accounts(self) -> Dict:
        """Check if default service accounts have any role bindings"""
        try:
            namespaces = self.k8s_core_api.list_namespace()
            role_bindings = self.k8s_rbac_api.list_role_binding_for_all_namespaces()
            cluster_role_bindings = self.k8s_rbac_api.list_cluster_role_binding()
            
            default_sa_bindings = []
            
            # Check role bindings
            for rb in role_bindings.items:
                if rb.subjects:
                    for subject in rb.subjects:
                        if subject.kind == "ServiceAccount" and subject.name == "default":
                            default_sa_bindings.append({
                                "namespace": rb.metadata.namespace,
                                "binding_name": rb.metadata.name,
                                "binding_type": "RoleBinding",
                                "role_name": rb.role_ref.name
                            })
            
            # Check cluster role bindings
            for crb in cluster_role_bindings.items:
                if crb.subjects:
                    for subject in crb.subjects:
                        if subject.kind == "ServiceAccount" and subject.name == "default":
                            default_sa_bindings.append({
                                "namespace": subject.namespace if hasattr(subject, "namespace") else "N/A",
                                "binding_name": crb.metadata.name,
                                "binding_type": "ClusterRoleBinding",
                                "role_name": crb.role_ref.name
                            })
            
            status = "PASS" if len(default_sa_bindings) == 0 else "FAIL"
            
            return {
                "name": "Default Service Account Usage",
                "status": status,
                "description": "Checks if default service accounts have role bindings",
                "details": f"Found {len(default_sa_bindings)} role bindings to default service accounts",
                "items": default_sa_bindings
            }
        except Exception as e:
            return {
                "name": "Default Service Account Usage",
                "status": "ERROR",
                "description": "Checks if default service accounts have role bindings",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_network_policies(self) -> Dict:
        """Check for namespaces without NetworkPolicy resources"""
        try:
            namespaces = self.k8s_core_api.list_namespace()
            
            # Try to get NetworkPolicy API - it might not be available if CNI doesn't support it
            try:
                network_policies = subprocess.check_output(
                    ["kubectl", "get", "networkpolicies", "--all-namespaces", "-o", "json"]
                )
                network_policies = json.loads(network_policies)
            except:
                return {
                    "name": "Network Policies",
                    "status": "WARN",
                    "description": "Checks for namespaces without NetworkPolicy resources",
                    "details": "Unable to check NetworkPolicies - your CNI might not support them",
                    "items": []
                }
            
            # Build a map of namespaces with network policies
            ns_with_policies = {}
            for policy in network_policies.get("items", []):
                ns = policy["metadata"]["namespace"]
                if ns not in ns_with_policies:
                    ns_with_policies[ns] = []
                ns_with_policies[ns].append(policy["metadata"]["name"])
            
            # Identify namespaces without network policies
            namespaces_without_policies = []
            for ns in namespaces.items:
                # Skip kube-system and other system namespaces
                if ns.metadata.name in ["kube-system", "kube-public", "kube-node-lease"]:
                    continue
                    
                if ns.metadata.name not in ns_with_policies:
                    namespaces_without_policies.append({
                        "namespace": ns.metadata.name,
                        "created": ns.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S") if ns.metadata.creation_timestamp else "Unknown"
                    })
            
            status = "PASS" if len(namespaces_without_policies) == 0 else "WARN"
            
            return {
                "name": "Network Policies",
                "status": status,
                "description": "Checks for namespaces without NetworkPolicy resources",
                "details": f"Found {len(namespaces_without_policies)} namespaces without NetworkPolicies",
                "items": namespaces_without_policies
            }
        except Exception as e:
            return {
                "name": "Network Policies",
                "status": "ERROR",
                "description": "Checks for namespaces without NetworkPolicy resources",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_exposed_services(self) -> Dict:
        """Check for services exposed with type LoadBalancer or NodePort"""
        try:
            services = self.k8s_core_api.list_service_for_all_namespaces(watch=False)
            exposed_services = []
            
            for svc in services.items:
                if svc.spec.type in ["LoadBalancer", "NodePort"]:
                    ports = []
                    for port in svc.spec.ports:
                        ports.append({
                            "port": port.port,
                            "target_port": port.target_port,
                            "node_port": port.node_port if hasattr(port, "node_port") else None,
                            "protocol": port.protocol
                        })
                    
                    exposed_services.append({
                        "namespace": svc.metadata.namespace,
                        "name": svc.metadata.name,
                        "type": svc.spec.type,
                        "ports": ports
                    })
            
            # Some exposed services are expected, this is just informational
            status = "INFO"
            
            return {
                "name": "Exposed Services",
                "status": status,
                "description": "Checks for services exposed with LoadBalancer or NodePort",
                "details": f"Found {len(exposed_services)} exposed services",
                "items": exposed_services
            }
        except Exception as e:
            return {
                "name": "Exposed Services",
                "status": "ERROR",
                "description": "Checks for services exposed with LoadBalancer or NodePort",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_secrets_encryption(self) -> Dict:
        """Check if EKS cluster has secrets encryption enabled"""
        try:
            cluster_info = self.eks_client.describe_cluster(name=self.cluster_name)
            encryption_config = cluster_info['cluster'].get('encryptionConfig', [])
            
            if not encryption_config:
                return {
                    "name": "Secrets Encryption",
                    "status": "FAIL",
                    "description": "Checks if EKS cluster has secrets encryption enabled",
                    "details": "The cluster does not have secrets encryption enabled",
                    "items": []
                }
            
            # If we get here, encryption is configured
            resources = []
            for config in encryption_config:
                for resource in config.get('resources', []):
                    resources.append(resource)
            
            status = "PASS" if "secrets" in resources else "WARN"
            
            return {
                "name": "Secrets Encryption",
                "status": status,
                "description": "Checks if EKS cluster has secrets encryption enabled",
                "details": f"The cluster has encryption enabled for: {', '.join(resources)}",
                "items": encryption_config
            }
        except Exception as e:
            return {
                "name": "Secrets Encryption",
                "status": "ERROR",
                "description": "Checks if EKS cluster has secrets encryption enabled",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_secrets_as_env_vars(self) -> Dict:
        """Check for pods using secrets directly as environment variables"""
        try:
            pods = self.k8s_core_api.list_pod_for_all_namespaces(watch=False)
            pods_with_secret_envs = []
            
            for pod in pods.items:
                for container in pod.spec.containers:
                    if container.env:
                        for env in container.env:
                            if env.value_from and env.value_from.secret_key_ref:
                                pods_with_secret_envs.append({
                                    "namespace": pod.metadata.namespace,
                                    "pod": pod.metadata.name,
                                    "container": container.name,
                                    "env_var": env.name,
                                    "secret_name": env.value_from.secret_key_ref.name,
                                    "secret_key": env.value_from.secret_key_ref.key
                                })
            
            # This is not always a problem but worth noting
            status = "INFO" if len(pods_with_secret_envs) > 0 else "PASS"
            
            return {
                "name": "Secrets as Environment Variables",
                "status": status,
                "description": "Checks for pods using secrets directly as environment variables",
                "details": f"Found {len(pods_with_secret_envs)} instances of secrets used as environment variables",
                "items": pods_with_secret_envs[:10] if len(pods_with_secret_envs) > 10 else pods_with_secret_envs
            }
        except Exception as e:
            return {
                "name": "Secrets as Environment Variables",
                "status": "ERROR",
                "description": "Checks for pods using secrets directly as environment variables",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_kubernetes_version(self) -> Dict:
        """Check Kubernetes version for known vulnerabilities and EOL status"""
        try:
            cluster_info = self.eks_client.describe_cluster(name=self.cluster_name)
            version = cluster_info['cluster']['version']
            
            # Define version support timeline (update this periodically)
            support_end_dates = {
                "1.19": "2021-08-02",
                "1.20": "2021-11-02",
                "1.21": "2022-02-28",
                "1.22": "2022-06-28",
                "1.23": "2022-10-11",
                "1.24": "2023-01-28",
                "1.25": "2023-05-28",
                "1.26": "2023-09-28",
                "1.27": "2024-01-28",
                "1.28": "2024-05-28",
                "1.29": "2024-09-28",
            }
            
            # Check for EOL status
            major_minor = ".".join(version.split(".")[:2])
            if major_minor in support_end_dates:
                eol_date = datetime.strptime(support_end_dates[major_minor], "%Y-%m-%d")
                now = datetime.now()
                
                days_to_eol = (eol_date - now).days if eol_date > now else 0
                
                if days_to_eol <= 0:
                    status = "FAIL"
                    details = f"Kubernetes v{version} is past end of support ({support_end_dates[major_minor]})"
                elif days_to_eol < 30:
                    status = "WARN"
                    details = f"Kubernetes v{version} is approaching end of support in {days_to_eol} days ({support_end_dates[major_minor]})"
                else:
                    status = "PASS"
                    details = f"Kubernetes v{version} is supported until {support_end_dates[major_minor]} ({days_to_eol} days remaining)"
            else:
                status = "WARN"
                details = f"Kubernetes v{version} support status is unknown"
            
            return {
                "name": "Kubernetes Version",
                "status": status,
                "description": "Checks Kubernetes version for EOL status",
                "details": details,
                "items": [{"version": version}]
            }
        except Exception as e:
            return {
                "name": "Kubernetes Version",
                "status": "ERROR",
                "description": "Checks Kubernetes version for EOL status",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_control_plane_logging(self) -> Dict:
        """Check if control plane logging is enabled for EKS"""
        try:
            cluster_info = self.eks_client.describe_cluster(name=self.cluster_name)
            logging = cluster_info['cluster'].get('logging', {})
            cluster_logging = logging.get('clusterLogging', [])
            
            enabled_log_types = []
            disabled_log_types = []
            
            for log_type in cluster_logging:
                if log_type.get('enabled', False):
                    enabled_log_types.extend(log_type.get('types', []))
                else:
                    disabled_log_types.extend(log_type.get('types', []))
            
            # All log types should be enabled for optimal security monitoring
            all_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
            missing_types = [t for t in all_types if t not in enabled_log_types]
            
            if not enabled_log_types:
                status = "FAIL"
                details = "No control plane logging is enabled"
            elif missing_types:
                status = "WARN"
                details = f"Some control plane logs are not enabled: {', '.join(missing_types)}"
            else:
                status = "PASS"
                details = "All control plane logging types are enabled"
            
            return {
                "name": "Control Plane Logging",
                "status": status,
                "description": "Checks if control plane logging is enabled for EKS",
                "details": details,
                "items": [{
                    "enabled": enabled_log_types,
                    "disabled": disabled_log_types
                }]
            }
        except Exception as e:
            return {
                "name": "Control Plane Logging",
                "status": "ERROR",
                "description": "Checks if control plane logging is enabled for EKS",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_cluster_encryption(self) -> Dict:
        """Check if envelope encryption is enabled for EKS with KMS"""
        try:
            cluster_info = self.eks_client.describe_cluster(name=self.cluster_name)
            encryption_config = cluster_info['cluster'].get('encryptionConfig', [])
            
            if not encryption_config:
                return {
                    "name": "Cluster Encryption",
                    "status": "FAIL",
                    "description": "Checks if envelope encryption is enabled for EKS with KMS",
                    "details": "Envelope encryption is not enabled for the cluster",
                    "items": []
                }
            
            # Check the provider
            kms_key_ids = []
            for config in encryption_config:
                provider = config.get('provider', {})
                if provider and 'keyArn' in provider:
                    kms_key_ids.append(provider['keyArn'])
            
            status = "PASS" if kms_key_ids else "FAIL"
            details = f"Envelope encryption is enabled with {len(kms_key_ids)} KMS keys" if kms_key_ids else "Envelope encryption configuration exists but no KMS keys found"
            
            return {
                "name": "Cluster Encryption",
                "status": status,
                "description": "Checks if envelope encryption is enabled for EKS with KMS",
                "details": details,
                "items": [{"kms_key_arns": kms_key_ids}]
            }
        except Exception as e:
            return {
                "name": "Cluster Encryption",
                "status": "ERROR",
                "description": "Checks if envelope encryption is enabled for EKS with KMS",
                "details": f"Error during check: {str(e)}",
                "items": []
            }
    
    def check_pod_security_standards(self) -> Dict:
        """Check if Pod Security Standards are enforced"""
        try:
            # Check for Pod Security Standards admission controller
            # Try with kubectl since client-go doesn't have a simple way to check this
            try:
                psa_result = subprocess.check_output(
                    ["kubectl", "get", "podsecuritystandards", "--all-namespaces"],
                    stderr=subprocess.STDOUT
                )
                psa_enabled = True
            except:
                # Check for Pod Security admission webhook
                try:
                    psa_result = subprocess.check_output(
                        ["kubectl", "get", "ns", "-o", "jsonpath='{.items[*].metadata.labels.pod-security\\.kubernetes\\.io/enforce}'"],
                        stderr=subprocess.STDOUT
                    )
                    psa_labels = psa_result.decode('utf-8').strip("'").split()
                    psa_enabled = len(psa_labels) > 0
                except:
                    psa_enabled = False
            
            if not psa_enabled:
                # Check for PodSecurityPolicy (deprecated but might still be in use)
                try:
                    psp_result = subprocess.check_output(
                        ["kubectl", "get", "psp", "--all-namespaces"],
                        stderr=subprocess.STDOUT
                    )
                    psp_enabled = "No resources found" not in psp_result.decode('utf-8')
                except:
                    psp_enabled = False
                
                if psp_enabled:
                    status = "WARN"
                    details = "PodSecurityPolicy (deprecated) is enabled, but Pod Security Standards are not"
                else:
                    status = "FAIL"
                    details = "No Pod Security enforcement mechanisms detected"
            else:
                status = "PASS"
                details = "Pod Security Standards are enforced"
            
            return {
                "name": "Pod Security Standards",
                "status": status,
                "description": "Checks if Pod Security Standards are enforced",
                "details": details,
                "items": []
            }
        except Exception as e:
            return {
                "name": "Pod Security Standards",
                "status": "ERROR",
                "description": "Checks if Pod Security Standards are enforced",
                "details": f"Error during check: {str(e)}",
                "items": []
            }

    def add_kube_bench_support(self) -> Dict:
        """
        Run kube-bench and incorporate its results into our report
        
        Returns a dictionary with the kube-bench check results
        """
        try:
            logger.info("Running kube-bench to check CIS Benchmark compliance...")
            
            # Check if kube-bench is installed
            try:
                subprocess.run(["kube-bench", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.error("kube-bench is not installed or not in PATH. Please install it first: https://github.com/aquasecurity/kube-bench")
                return {
                    "name": "CIS Kubernetes Benchmark",
                    "status": "ERROR",
                    "description": "Checks for compliance with CIS Kubernetes Benchmark using kube-bench",
                    "details": "kube-bench is not installed or not in PATH",
                    "items": []
                }
            
            # Run kube-bench with JSON output
            kb_result = subprocess.run(
                ["kube-bench", "--json"], 
                capture_output=True, 
                text=True
            )
            
            if kb_result.returncode != 0:
                logger.error(f"kube-bench failed with return code {kb_result.returncode}: {kb_result.stderr}")
                return {
                    "name": "CIS Kubernetes Benchmark",
                    "status": "ERROR",
                    "description": "Checks for compliance with CIS Kubernetes Benchmark using kube-bench",
                    "details": f"kube-bench failed: {kb_result.stderr}",
                    "items": []
                }
            
            # Parse the JSON output
            try:
                kb_data = json.loads(kb_result.stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse kube-bench output: {e}")
                return {
                    "name": "CIS Kubernetes Benchmark",
                    "status": "ERROR",
                    "description": "Checks for compliance with CIS Kubernetes Benchmark using kube-bench",
                    "details": f"Failed to parse kube-bench output: {e}",
                    "items": []
                }
            
            # Summarize the results
            total_checks = 0
            passed_checks = 0
            failed_checks = 0
            warned_checks = 0
            
            # Process test results from all sections
            check_items = []
            
            for section in kb_data.get('Controls', []):
                section_id = section.get('id', 'Unknown')
                section_text = section.get('text', 'Unknown')
                
                for test in section.get('tests', []):
                    test_desc = test.get('desc', 'Unknown test')
                    section_name = f"{section_id} {section_text}"
                    
                    for result in test.get('results', []):
                        total_checks += 1
                        status = result.get('status', 'UNKNOWN')
                        
                        if status == 'PASS':
                            passed_checks += 1
                        elif status == 'FAIL':
                            failed_checks += 1
                        elif status == 'WARN':
                            warned_checks += 1
                        
                        check_items.append({
                            "section": section_name,
                            "test": test_desc,
                            "check_id": result.get('test_number', 'Unknown'),
                            "check_desc": result.get('test_desc', 'Unknown'),
                            "status": status,
                            "remediation": result.get('remediation', 'No remediation provided')
                        })
            
            # Determine overall status
            if failed_checks > 0:
                status = "FAIL"
                details = f"Failed {failed_checks} of {total_checks} CIS Benchmark checks"
            elif warned_checks > 0:
                status = "WARN"
                details = f"Passed {passed_checks} checks but has {warned_checks} warnings out of {total_checks} CIS Benchmark checks"
            else:
                status = "PASS"
                details = f"Passed all {total_checks} CIS Benchmark checks"
            
            # Limit items to a reasonable number to avoid overwhelming the report
            limited_items = check_items
            if len(check_items) > 20:
                # Show only failed and warned checks if there are too many
                limited_items = [item for item in check_items if item['status'] in ['FAIL', 'WARN']]
                if len(limited_items) > 20:
                    limited_items = limited_items[:20]
            
            return {
                "name": "CIS Kubernetes Benchmark",
                "status": status,
                "description": "Checks for compliance with CIS Kubernetes Benchmark using kube-bench",
                "details": details,
                "items": limited_items,
                "full_report": kb_data  # Store the full report for optional detailed output
            }
        except Exception as e:
            logger.error(f"Error running kube-bench: {str(e)}")
            return {
                "name": "CIS Kubernetes Benchmark",
                "status": "ERROR",
                "description": "Checks for compliance with CIS Kubernetes Benchmark using kube-bench",
                "details": f"Error running kube-bench: {str(e)}",
                "items": []
            }
    
    def generate_report(self, output_file=None):
        """Generate a formatted report of all check results"""
        if not self.results:
            logger.error("No results to report. Run checks first.")
            return False
            
        print("\n" + "=" * 80)
        print(f"EKS SECURITY VALIDATION REPORT: {self.cluster_name}")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        summary_data = []
        status_counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0, "ERROR": 0}
        
        for section_key, section in self.results.items():
            print(f"\n\n{section['title']}")
            print("-" * len(section['title']))
            
            for check in section['checks']:
                status = check['status']
                status_counts[status] = status_counts.get(status, 0) + 1
                
                summary_data.append([
                    check['name'], 
                    status, 
                    check['description'],
                    check['details']
                ])
                
                # Print the check details
                status_color = {
                    "PASS": "\033[92m",  # Green
                    "WARN": "\033[93m",  # Yellow
                    "FAIL": "\033[91m",  # Red
                    "INFO": "\033[94m",  # Blue
                    "ERROR": "\033[95m"  # Purple
                }
                reset_color = "\033[0m"
                
                print(f"\n{check['name']}: {status_color.get(status, '')}{status}{reset_color}")
                print(f"  {check['details']}")
                
                # Print items if any and not too many
                if check['items'] and len(check['items']) > 0:
                    if len(check['items']) <= 5:
                        for item in check['items']:
                            print(f"  - {item}")
                    else:
                        print(f"  - {len(check['items'])} items found. First 5:")
                        for item in check['items'][:5]:
                            print(f"    * {item}")
        
        # Print summary
        print("\n\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"PASS: {status_counts['PASS']}  WARN: {status_counts['WARN']}  FAIL: {status_counts['FAIL']}  INFO: {status_counts['INFO']}  ERROR: {status_counts['ERROR']}")
        
        # Calculate overall status
        if status_counts['FAIL'] > 0 or status_counts['ERROR'] > 0:
            overall_status = "FAIL"
        elif status_counts['WARN'] > 0:
            overall_status = "WARN"
        else:
            overall_status = "PASS"
            
        print(f"\nOverall Status: {overall_status}")
        
        # Save report to file
        if output_file:
            filename = output_file
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"eks_security_report_{self.cluster_name}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                "cluster_name": self.cluster_name,
                "region": self.region,
                "timestamp": datetime.now().isoformat(),
                "overall_status": overall_status,
                "status_counts": status_counts,
                "results": self.results
            }, f, indent=2)
        
        print(f"\nDetailed report saved to: {filename}")
        
        # Generate a special kube-bench HTML report if it was included
        if "cis_benchmark" in self.results and len(self.results["cis_benchmark"]["checks"]) > 0:
            kb_check = self.results["cis_benchmark"]["checks"][0]
            if "full_report" in kb_check and kb_check["full_report"]:
                html_filename = filename.replace('.json', '_kube_bench.html')
                try:
                    self._generate_kube_bench_html_report(kb_check["full_report"], html_filename)
                    print(f"Kube-bench detailed report saved to: {html_filename}")
                except Exception as e:
                    logger.error(f"Failed to generate HTML report for kube-bench: {str(e)}")
        
        return True

    def _generate_kube_bench_html_report(self, kb_data, filename):
        """Generate a detailed HTML report for kube-bench results"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Kube-bench CIS Benchmark Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin-bottom: 20px; }}
        .test {{ margin-bottom: 15px; background: #f5f5f5; padding: 10px; border-radius: 5px; }}
        .result {{ margin: 5px 0; padding: 5px; border-radius: 3px; }}
        .pass {{ background-color: #dff0d8; }}
        .warn {{ background-color: #fcf8e3; }}
        .fail {{ background-color: #f2dede; }}
        .remediation {{ font-style: italic; margin-top: 5px; color: #666; }}
    </style>
</head>
<body>
    <h1>Kube-bench CIS Benchmark Report</h1>
    <p>Cluster: {self.cluster_name}</p>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    """
    
    # Process test results from all sections
    for section in kb_data.get('Controls', []):
        section_id = section.get('id', 'Unknown')
        section_text = section.get('text', 'Unknown')
        
        html += f'<div class="section">'
        html += f'<h2>{section_id}: {section_text}</h2>'
        
        for test in section.get('tests', []):
            test_desc = test.get('desc', 'Unknown test')
            
            html += f'<div class="test">'
            html += f'<h3>{test_desc}</h3>'
            
            for result in test.get('results', []):
                status = result.get('status', 'UNKNOWN')
                status_class = status.lower() if status in ['PASS', 'WARN', 'FAIL'] else ''
                
                html += f'<div class="result {status_class}">'
                html += f'<strong>{result.get("test_number", "")}</strong>: {result.get("test_desc", "Unknown")}'
                html += f'<div>Status: <strong>{status}</strong></div>'
                
                if result.get('remediation'):
                    html += f'<div class="remediation">Remediation: {result.get("remediation")}</div>'
                
                html += '</div>'
            
            html += '</div>'
        
        html += '</div>'
    
    html += """
</body>
</html>
    """
    
    with open(filename, 'w') as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(description="EKS Security Validation Script")
    parser.add_argument("--cluster-name", required=True, help="Name of the EKS cluster")
    parser.add_argument("--region", required=True, help="AWS region of the EKS cluster")
    parser.add_argument("--include-kube-bench", action="store_true", help="Include kube-bench CIS Benchmark checks")
    parser.add_argument("--output-file", help="Output file path for the report (default: auto-generated)")
    args = parser.parse_args()
    
    validator = EKSSecurityValidator(args.cluster_name, args.region)
    validator.run_all_checks(include_kube_bench=args.include_kube_bench)
    
    if args.output_file:
        validator.generate_report(output_file=args.output_file)
    else:
        validator.generate_report()


if __name__ == "__main__":
    main()

##
