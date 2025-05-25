#!/usr/bin/env python3
"""
SPIFFE Identity Tracker for EKS Microservices ( Beta )

This utility helps track and visualize SPIFFE identity flows through
a Kubernetes/EKS cluster with a service mesh like Istio.
"""

import argparse
import base64
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set

import jwt
import kubernetes as k8s
import pandas as pd
import plotly.express as px
import requests
from kubernetes.client.rest import ApiException
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree


@dataclass
class SpiffeId:
    """Represents a parsed SPIFFE ID with its components."""
    
    trust_domain: str
    namespace: str
    service_account: str
    workload_name: Optional[str] = None
    
    @classmethod
    def from_uri(cls, uri: str) -> 'SpiffeId':
        """Parse a SPIFFE ID URI into its components.
        
        Example: spiffe://cluster.local/ns/default/sa/my-service
        """
        pattern = r'spiffe://([^/]+)/ns/([^/]+)/sa/([^/]+)(?:/([^/]+))?'
        match = re.match(pattern, uri)
        
        if not match:
            raise ValueError(f"Invalid SPIFFE ID format: {uri}")
        
        return cls(
            trust_domain=match.group(1),
            namespace=match.group(2),
            service_account=match.group(3),
            workload_name=match.group(4)
        )
    
    def __str__(self) -> str:
        """Return the string representation of the SPIFFE ID."""
        base = f"spiffe://{self.trust_domain}/ns/{self.namespace}/sa/{self.service_account}"
        if self.workload_name:
            return f"{base}/{self.workload_name}"
        return base


class SpiffeTracker:
    """Main class for tracking SPIFFE identities in an EKS cluster."""
    
    def __init__(self, kube_config=None):
        """Initialize the SPIFFE tracker.
        
        Args:
            kube_config: Path to kubeconfig file. If None, tries to use in-cluster config
                         or the default ~/.kube/config
        """
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
        
        # Track identity flows
        self.identity_flows = []
    
    def list_service_accounts(self, namespace=None) -> List[dict]:
        """List all service accounts in the specified namespace or all namespaces."""
        result = []
        
        try:
            if namespace:
                sa_list = self.k8s_client.list_namespaced_service_account(namespace)
            else:
                sa_list = self.k8s_client.list_service_account_for_all_namespaces()
            
            for sa in sa_list.items:
                result.append({
                    'name': sa.metadata.name,
                    'namespace': sa.metadata.namespace,
                    'spiffe_id': f"spiffe://cluster.local/ns/{sa.metadata.namespace}/sa/{sa.metadata.name}",
                    'secrets': [s.name for s in sa.secrets] if sa.secrets else []
                })
            
            return result
        except ApiException as e:
            self.console.print(f"[bold red]Error listing service accounts:[/] {e}")
            return []
    
    def list_pods_with_service_accounts(self, namespace=None) -> List[dict]:
        """List all pods with their associated service accounts."""
        result = []
        
        try:
            if namespace:
                pod_list = self.k8s_client.list_namespaced_pod(namespace)
            else:
                pod_list = self.k8s_client.list_pod_for_all_namespaces()
            
            for pod in pod_list.items:
                # Check if pod has Istio sidecar
                has_istio = any("istio-proxy" in container.name for container in pod.spec.containers)
                
                result.append({
                    'name': pod.metadata.name,
                    'namespace': pod.metadata.namespace,
                    'service_account': pod.spec.service_account_name,
                    'spiffe_id': f"spiffe://cluster.local/ns/{pod.metadata.namespace}/sa/{pod.spec.service_account_name}/{pod.metadata.name}",
                    'has_istio_sidecar': has_istio,
                    'status': pod.status.phase,
                    'ip': pod.status.pod_ip
                })
            
            return result
        except ApiException as e:
            self.console.print(f"[bold red]Error listing pods:[/] {e}")
            return []
    
    def parse_jwt_token(self, token: str) -> Dict:
        """Parse a JWT token and extract identity information."""
        try:
            # Just decode without verification for inspection purposes
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Look for SPIFFE identity claims
            spiffe_id = None
            if 'sub' in decoded and decoded['sub'].startswith('spiffe://'):
                spiffe_id = decoded['sub']
            elif 'spiffe_id' in decoded:
                spiffe_id = decoded['spiffe_id']
                
            return {
                'decoded': decoded,
                'spiffe_id': spiffe_id,
                'issuer': decoded.get('iss'),
                'subject': decoded.get('sub'),
                'audience': decoded.get('aud'),
                'expiration': datetime.fromtimestamp(decoded.get('exp', 0)),
                'issued_at': datetime.fromtimestamp(decoded.get('iat', 0)),
            }
        except Exception as e:
            self.console.print(f"[bold red]Error parsing JWT token:[/] {e}")
            return {'error': str(e)}
    
    def extract_identity_from_envoy_proxy(self, pod_name, pod_namespace):
        """Extract SPIFFE identity information from Envoy proxy in the pod."""
        try:
            # Port-forward to the Envoy admin interface
            # This requires the 'kubectl' command to be available
            import subprocess
            
            cmd = [
                "kubectl", "port-forward",
                f"pod/{pod_name}", "15000:15000",
                "-n", pod_namespace
            ]
            
            # Start port-forwarding in the background
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Give it a moment to establish
            time.sleep(2)
            
            try:
                # Request the certificate information from Envoy
                response = requests.get("http://localhost:15000/certs", timeout=5)
                cert_data = response.json()
                
                # Extract SPIFFE ID from certificates
                spiffe_ids = set()
                for cert in cert_data.get('certificates', []):
                    for cert_chain in cert.get('cert_chain', []):
                        if 'uri_san' in cert_chain:
                            for uri in cert_chain['uri_san']:
                                if uri.startswith('spiffe://'):
                                    spiffe_ids.add(uri)
                
                return {
                    'pod': pod_name,
                    'namespace': pod_namespace,
                    'spiffe_ids': list(spiffe_ids),
                    'cert_data': cert_data
                }
            finally:
                # Clean up port-forwarding
                process.terminate()
                process.wait()
        
        except Exception as e:
            self.console.print(f"[bold red]Error extracting identity from Envoy proxy:[/] {e}")
            return {'error': str(e)}
    
    def track_identity_flow(self, source_spiffe_id, target_spiffe_id, timestamp=None, request_id=None):
        """Record an identity flow from one service to another."""
        if timestamp is None:
            timestamp = datetime.now()
            
        flow = {
            'timestamp': timestamp,
            'source_id': source_spiffe_id,
            'target_id': target_spiffe_id,
            'request_id': request_id
        }
        
        self.identity_flows.append(flow)
        return flow
    
    def visualize_identity_flows(self):
        """Visualize the recorded identity flows as a graph."""
        if not self.identity_flows:
            self.console.print("[yellow]No identity flows recorded yet.[/]")
            return
        
        # Convert to DataFrame for visualization
        df = pd.DataFrame(self.identity_flows)
        
        # Create a visualization of flows
        fig = px.line(df, x='timestamp', y=['source_id', 'target_id'], 
                     title='SPIFFE Identity Flows Over Time',
                     labels={'value': 'SPIFFE ID', 'variable': 'Flow Type'})
        
        # Show interactive plot
        fig.show()
    
    def display_spiffe_id_tree(self):
        """Display a tree view of SPIFFE IDs in the cluster by namespace and service account."""
        service_accounts = self.list_service_accounts()
        
        # Group by namespace
        namespaces = {}
        for sa in service_accounts:
            ns = sa['namespace']
            if ns not in namespaces:
                namespaces[ns] = []
            namespaces[ns].append(sa)
        
        # Create tree
        tree = Tree("[bold blue]SPIFFE IDs by Namespace")
        
        for ns, sas in sorted(namespaces.items()):
            ns_branch = tree.add(f"[bold cyan]Namespace: {ns}")
            
            for sa in sorted(sas, key=lambda x: x['name']):
                sa_branch = ns_branch.add(f"[green]SA: {sa['name']}")
                sa_branch.add(f"[yellow]{sa['spiffe_id']}")
        
        self.console.print(tree)
    
    def display_service_connections(self):
        """Display service-to-service connections based on network policies and service mesh."""
        # This would require integration with Istio or other service mesh API
        # For demonstration, we'll show a mock visualization
        
        table = Table(title="Service-to-Service Connections with SPIFFE Identity")
        
        table.add_column("Source Service", style="cyan")
        table.add_column("Source SPIFFE ID", style="green")
        table.add_column("Target Service", style="cyan")
        table.add_column("Target SPIFFE ID", style="green")
        table.add_column("Authentication", style="magenta")
        
        # Sample data - in a real implementation, this would come from service mesh telemetry
        table.add_row(
            "frontend/webapp", 
            "spiffe://cluster.local/ns/frontend/sa/webapp",
            "api/userservice",
            "spiffe://cluster.local/ns/api/sa/userservice",
            "mTLS + JWT"
        )
        
        table.add_row(
            "api/userservice", 
            "spiffe://cluster.local/ns/api/sa/userservice",
            "database/mongodb",
            "spiffe://cluster.local/ns/database/sa/mongodb",
            "mTLS"
        )
        
        self.console.print(table)
    
    def inject_spiffe_identity_extractor(self, namespace):
        """Inject a sidecar container that extracts and logs SPIFFE identity information.
        
        This is for demonstration/debugging - in production, use proper Istio telemetry.
        """
        # This would create a Kubernetes DaemonSet that monitors for SPIFFE identities
        # For the demo, we'll just show what this would do
        
        extractor_yaml = f"""
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spiffe-identity-extractor
  namespace: {namespace}
spec:
  selector:
    matchLabels:
      app: spiffe-identity-extractor
  template:
    metadata:
      labels:
        app: spiffe-identity-extractor
    spec:
      hostNetwork: true
      containers:
      - name: extractor
        image: python:3.9-slim
        command:
        - /bin/bash
        - -c
        - |
          pip install requests pyyaml kubernetes
          
          cat > /tmp/extractor.py << 'EOF'
          #!/usr/bin/env python3
          import os
          import time
          import yaml
          import requests
          from kubernetes import client, config
          
          # Load in-cluster config
          config.load_incluster_config()
          v1 = client.CoreV1Api()
          
          # Find all pods with Istio sidecar
          def list_pods_with_istio():
              pods = []
              for pod in v1.list_namespaced_pod(namespace="").items:
                  if any(container.name == "istio-proxy" for container in pod.spec.containers):
                      pods.append((pod.metadata.name, pod.metadata.namespace, pod.status.pod_ip))
              return pods
          
          # Main monitoring loop
          while True:
              pods = list_pods_with_istio()
              for name, namespace, ip in pods:
                  try:
                      # Connect to Envoy admin port
                      if ip:
                          url = f"http://{ip}:15000/certs"
                          resp = requests.get(url, timeout=5)
                          if resp.status_code == 200:
                              data = resp.json()
                              # Look for SPIFFE IDs in certificates
                              for cert in data.get('certificates', []):
                                  for chain in cert.get('cert_chain', []):
                                      if 'uri_san' in chain:
                                          for uri in chain['uri_san']:
                                              if uri.startswith('spiffe://'):
                                                  print(f"Pod {namespace}/{name} has SPIFFE ID: {uri}")
                  except Exception as e:
                      print(f"Error for pod {namespace}/{name}: {e}")
              
              time.sleep(60)  # Check every minute
          EOF
          
          python /tmp/extractor.py
        securityContext:
          privileged: true
      serviceAccountName: spiffe-identity-extractor
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spiffe-identity-extractor
  namespace: {namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: spiffe-identity-extractor
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spiffe-identity-extractor
subjects:
- kind: ServiceAccount
  name: spiffe-identity-extractor
  namespace: {namespace}
roleRef:
  kind: ClusterRole
  name: spiffe-identity-extractor
  apiGroup: rbac.authorization.k8s.io
"""
        
        self.console.print(Panel(extractor_yaml, title="SPIFFE Identity Extractor DaemonSet", 
                                border_style="green"))
        
        self.console.print("\n[bold yellow]Note:[/] This is a demonstration DaemonSet that would extract SPIFFE "
                          "identities from Istio-enabled pods. In a production environment, you should "
                          "use proper Istio telemetry and observability tools instead.")


def main():
    parser = argparse.ArgumentParser(description="SPIFFE Identity Tracker for EKS Microservices")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--namespace", help="Kubernetes namespace to focus on")
    parser.add_argument("--command", choices=["list-sa", "list-pods", "visualize", "tree", "connections", 
                                           "inject-extractor", "parse-jwt"],
                      default="tree", help="Command to execute")
    parser.add_argument("--token", help="JWT token to parse (for parse-jwt command)")
    
    args = parser.parse_args()
    
    tracker = SpiffeTracker(args.kubeconfig)
    
    if args.command == "list-sa":
        service_accounts = tracker.list_service_accounts(args.namespace)
        tracker.console.print(service_accounts)
    
    elif args.command == "list-pods":
        pods = tracker.list_pods_with_service_accounts(args.namespace)
        tracker.console.print(pods)
    
    elif args.command == "visualize":
        # Add some sample flows for demonstration
        tracker.track_identity_flow(
            "spiffe://cluster.local/ns/frontend/sa/webapp",
            "spiffe://cluster.local/ns/api/sa/userservice"
        )
        tracker.track_identity_flow(
            "spiffe://cluster.local/ns/api/sa/userservice",
            "spiffe://cluster.local/ns/database/sa/mongodb"
        )
        tracker.visualize_identity_flows()
    
    elif args.command == "tree":
        tracker.display_spiffe_id_tree()
    
    elif args.command == "connections":
        tracker.display_service_connections()
    
    elif args.command == "inject-extractor":
        namespace = args.namespace or "default"
        tracker.inject_spiffe_identity_extractor(namespace)
    
    elif args.command == "parse-jwt":
        if not args.token:
            tracker.console.print("[bold red]Error:[/] --token is required for parse-jwt command")
            return
        
        parsed = tracker.parse_jwt_token(args.token)
        tracker.console.print(parsed)


if __name__ == "__main__":
    main()
##
