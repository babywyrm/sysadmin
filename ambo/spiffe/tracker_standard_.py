#!/usr/bin/env python3
"""
Kubernetes Service Identity Tracker for EKS

A utility to track service identities in standard EKS ** without ** SPIFFE/Istio.
"""

import argparse
import kubernetes as k8s
from kubernetes.client.rest import ApiException
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

class K8sIdentityTracker:
    """Track service identities in a standard Kubernetes/EKS cluster."""
    
    def __init__(self, kube_config=None):
        self.console = Console()
        
        # Initialize Kubernetes client
        try:
            if kube_config:
                k8s.config.load_kube_config(kube_config)
            else:
                try:
                    k8s.config.load_incluster_config()
                except k8s.config.config_exception.ConfigException:
                    k8s.config.load_kube_config()
            
            self.k8s_client = k8s.client.CoreV1Api()
            self.k8s_apps_client = k8s.client.AppsV1Api()
            self.console.print("[bold green]✓[/] Connected to Kubernetes cluster")
        except Exception as e:
            self.console.print(f"[bold red]✗[/] Failed to connect to Kubernetes cluster: {e}")
            raise
    
    def list_service_accounts(self, namespace=None):
        """List all service accounts in the specified namespace or all namespaces."""
        try:
            if namespace:
                sa_list = self.k8s_client.list_namespaced_service_account(namespace)
            else:
                sa_list = self.k8s_client.list_service_account_for_all_namespaces()
            
            table = Table(title="Kubernetes Service Accounts")
            table.add_column("Namespace", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Secrets", style="yellow")
            table.add_column("IRSA Annotation", style="magenta")
            
            for sa in sa_list.items:
                # Check for IRSA annotation
                irsa_role = sa.metadata.annotations.get('eks.amazonaws.com/role-arn', 'None') if sa.metadata.annotations else 'None'
                
                table.add_row(
                    sa.metadata.namespace,
                    sa.metadata.name,
                    str(len(sa.secrets)) if sa.secrets else "0",
                    irsa_role
                )
            
            self.console.print(table)
        except ApiException as e:
            self.console.print(f"[bold red]Error listing service accounts:[/] {e}")
    
    def list_pods_with_identity(self, namespace=None):
        """List pods with their identity information."""
        try:
            if namespace:
                pod_list = self.k8s_client.list_namespaced_pod(namespace)
            else:
                pod_list = self.k8s_client.list_pod_for_all_namespaces()
            
            table = Table(title="Pod Identity Information")
            table.add_column("Namespace", style="cyan")
            table.add_column("Pod", style="green")
            table.add_column("Service Account", style="yellow")
            table.add_column("Status", style="magenta")
            
            for pod in pod_list.items:
                table.add_row(
                    pod.metadata.namespace,
                    pod.metadata.name,
                    pod.spec.service_account_name,
                    pod.status.phase
                )
            
            self.console.print(table)
        except ApiException as e:
            self.console.print(f"[bold red]Error listing pods:[/] {e}")
    
    def display_identity_tree(self):
        """Display hierarchical view of services, deployments, and identities."""
        # Get all namespaces
        namespaces = self.k8s_client.list_namespace()
        
        # Create tree
        tree = Tree("[bold blue]Kubernetes Identity Hierarchy")
        
        for ns in namespaces.items:
            ns_name = ns.metadata.name
            ns_branch = tree.add(f"[bold cyan]Namespace: {ns_name}")
            
            # Get service accounts in this namespace
            try:
                sa_list = self.k8s_client.list_namespaced_service_account(ns_name)
                sa_branch = ns_branch.add("[yellow]Service Accounts")
                
                for sa in sa_list.items:
                    sa_branch.add(f"[green]{sa.metadata.name}")
                
                # Get deployments using these service accounts
                try:
                    deploy_list = self.k8s_apps_client.list_namespaced_deployment(ns_name)
                    deploy_branch = ns_branch.add("[yellow]Deployments")
                    
                    for deploy in deploy_list.items:
                        sa_name = deploy.spec.template.spec.service_account_name
                        deploy_branch.add(f"[green]{deploy.metadata.name} → SA: {sa_name}")
                except ApiException:
                    pass
            except ApiException:
                pass
        
        self.console.print(tree)
    
    def check_for_service_mesh(self):
        """Check if a service mesh like Istio is installed that might provide SPIFFE identities."""
        has_istio = False
        has_linkerd = False
        has_consul = False
        
        # Check for Istio
        try:
            namespaces = self.k8s_client.list_namespace()
            for ns in namespaces.items:
                if ns.metadata.name == 'istio-system':
                    has_istio = True
                elif ns.metadata.name == 'linkerd':
                    has_linkerd = True
                elif ns.metadata.name == 'consul':
                    has_consul = True
        except ApiException:
            pass
        
        # Check for Istio sidecars in any pods
        try:
            pods = self.k8s_client.list_pod_for_all_namespaces()
            for pod in pods.items:
                if any(container.name == 'istio-proxy' for container in pod.spec.containers):
                    has_istio = True
                    break
        except ApiException:
            pass
        
        table = Table(title="Service Mesh Detection")
        table.add_column("Service Mesh", style="cyan")
        table.add_column("Detected", style="green")
        table.add_column("SPIFFE Support", style="yellow")
        
        table.add_row("Istio", "Yes" if has_istio else "No", "Yes (if installed)")
        table.add_row("Linkerd", "Yes" if has_linkerd else "No", "Yes (if installed)")
        table.add_row("Consul Connect", "Yes" if has_consul else "No", "Partial")
        
        self.console.print(table)
        
        if not (has_istio or has_linkerd or has_consul):
            self.console.print("\n[bold yellow]No service mesh detected.[/] SPIFFE identities are likely not in use.")
            self.console.print("To use SPIFFE identities, you could install:")
            self.console.print("1. SPIRE (the reference SPIFFE implementation)")
            self.console.print("2. A service mesh like Istio or Linkerd")
            self.console.print("\nStandard EKS uses Kubernetes service accounts and IRSA for identity.")
        elif has_istio:
            self.console.print("\n[bold green]Istio detected![/] SPIFFE identities are likely in use with the format:")
            self.console.print("spiffe://cluster.local/ns/{namespace}/sa/{service-account}")

def main():
    parser = argparse.ArgumentParser(description="Kubernetes Identity Tracker for EKS")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--namespace", help="Kubernetes namespace to focus on")
    parser.add_argument("--command", choices=["list-sa", "list-pods", "tree", "check-mesh"],
                      default="tree", help="Command to execute")
    
    args = parser.parse_args()
    
    tracker = K8sIdentityTracker(args.kubeconfig)
    
    if args.command == "list-sa":
        tracker.list_service_accounts(args.namespace)
    elif args.command == "list-pods":
        tracker.list_pods_with_identity(args.namespace)
    elif args.command == "tree":
        tracker.display_identity_tree()
    elif args.command == "check-mesh":
        tracker.check_for_service_mesh()

if __name__ == "__main__":
    main()
