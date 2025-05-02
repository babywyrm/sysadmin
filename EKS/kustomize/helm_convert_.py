#!/usr/bin/env python3
"""
helm2kustomize - Convert Helm charts to Kustomize bases for ArgoCD (Testing..)
-----------------------------------------------------------------

This script:
1. Takes a Helm chart and values
2. Templates it to raw Kubernetes manifests
3. Organizes the manifests into a Kustomize base structure
4. Adds a kustomization.yaml file

Examples:
  # Basic conversion with default values
  ./helm2kustomize.py \
    --chart bitnami/nginx \
    --output-dir ./k8s/bases/nginx

  # With custom values file
  ./helm2kustomize.py \
    --chart bitnami/nginx \
    --values ./my-values.yaml \
    --output-dir ./k8s/bases/nginx-prod
"""

import os,sys,re
import json
import argparse
import subprocess
import yaml
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

# Resource types that should be separated into individual files
RESOURCE_TYPES = {
    "Deployment": "deployments",
    "Service": "services",
    "ConfigMap": "configmaps",
    "Secret": "secrets",
    "Ingress": "ingress",
    "PersistentVolumeClaim": "pvcs",
    "StatefulSet": "statefulsets",
    "DaemonSet": "daemonsets",
    "Job": "jobs",
    "CronJob": "cronjobs",
    "ServiceAccount": "serviceaccounts",
    "HorizontalPodAutoscaler": "hpas",
}

def run_command(command: List[str], cwd: Optional[str] = None) -> str:
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True,
            cwd=cwd
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(command)}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)

def check_helm_installed():
    """Verify that Helm is installed."""
    try:
        run_command(["helm", "version", "--short"])
    except FileNotFoundError:
        print("Error: helm executable not found. Please install Helm.")
        sys.exit(1)

def template_helm_chart(chart: str, values_files: List[str], set_values: List[str], 
                        release: str, namespace: str, version: Optional[str] = None) -> str:
    """Use Helm template to generate Kubernetes manifests from a chart."""
    cmd = ["helm", "template", release, chart, "--namespace", namespace]
    
    # Add values files
    for values_file in values_files:
        cmd.extend(["-f", values_file])
    
    # Add --set values
    for set_value in set_values:
        cmd.extend(["--set", set_value])
    
    # Add version if specified
    if version:
        cmd.extend(["--version", version])
    
    return run_command(cmd)

def split_resources(manifests: str) -> Dict[str, List[Dict]]:
    """Split a multi-document YAML into separate resources by type."""
    docs = yaml.safe_load_all(manifests)
    resources_by_type = {}
    
    for doc in docs:
        if not doc:
            continue  # Skip empty documents
            
        kind = doc.get("kind", "Unknown")
        directory = RESOURCE_TYPES.get(kind, "other")
        
        if directory not in resources_by_type:
            resources_by_type[directory] = []
            
        resources_by_type[directory].append(doc)
        
    return resources_by_type

def sanitize_filename(name: str) -> str:
    """Convert a resource name to a valid filename."""
    return name.replace(':', '_').replace('/', '_').replace('\\', '_')

def write_resources(resources_by_type: Dict[str, List[Dict]], output_dir: str):
    """Write resources to files organized by type."""
    base_dir = Path(output_dir)
    
    for resource_type, resources in resources_by_type.items():
        # Create directory for this resource type
        type_dir = base_dir / resource_type
        type_dir.mkdir(parents=True, exist_ok=True)
        
        for resource in resources:
            name = resource.get("metadata", {}).get("name", "unnamed")
            filename = f"{sanitize_filename(name)}.yaml"
            
            with open(type_dir / filename, "w") as f:
                yaml.dump(resource, f, default_flow_style=False)

def create_kustomization(output_dir: str, resources_by_type: Dict[str, List[Dict]]):
    """Create a kustomization.yaml file pointing to all resources."""
    kustomization = {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": [],
        "commonLabels": {
            "app.kubernetes.io/managed-by": "helm2kustomize",
            "app.kubernetes.io/created-at": datetime.now().strftime("%Y-%m-%d")
        }
    }
    
    # Add paths to all resources
    for resource_type, resources in resources_by_type.items():
        for resource in resources:
            name = resource.get("metadata", {}).get("name", "unnamed")
            filename = f"{sanitize_filename(name)}.yaml"
            path = f"{resource_type}/{filename}"
            kustomization["resources"].append(path)
    
    # Write kustomization file
    with open(os.path.join(output_dir, "kustomization.yaml"), "w") as f:
        yaml.dump(kustomization, f, default_flow_style=False)

def create_overlay_example(output_dir: str, name: str, namespace: str):
    """Create an example overlay directory structure."""
    overlay_dir = os.path.join(output_dir, "..", "overlays", namespace)
    os.makedirs(overlay_dir, exist_ok=True)
    
    kustomization = {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": ["../../bases/" + os.path.basename(output_dir)],
        "namespace": namespace,
        "commonLabels": {
            "environment": namespace
        }
    }
    
    with open(os.path.join(overlay_dir, "kustomization.yaml"), "w") as f:
        yaml.dump(kustomization, f, default_flow_style=False)
        
    # Create a README with instructions
    readme = f"""# {name} Overlay for {namespace}

This is an example overlay for the {name} application in the {namespace} environment.

## Usage with ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: {name}-{namespace}
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/your-repo.git
    targetRevision: HEAD
    path: k8s/overlays/{namespace}
  destination:
    server: https://kubernetes.default.svc
    namespace: {namespace}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
"""
with open(os.path.join(overlay_dir, "README.md"), "w") as f:
f.write(readme)
def main():
parser = argparse.ArgumentParser(
description="Convert Helm charts to Kustomize bases for ArgoCD",
formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("--chart", required=True, help="Helm chart name (e.g., bitnami/nginx)")
parser.add_argument("--output-dir", required=True, help="Output directory for the Kustomize base")
parser.add_argument("--values", action="append", default=[],
help="Values files to use (can be specified multiple times)")
parser.add_argument("--release", default="release", help="Release name for Helm template")
parser.add_argument("--namespace", default="default", help="Namespace for resources")
parser.add_argument("--version", help="Specific chart version to use")
parser.add_argument("--set", action="append", default=[],
help="Set values on the command line (can be specified multiple times)")
parser.add_argument("--create-overlay", action="store_true",
help="Create an example overlay for this base")
parser.add_argument("--no-organize", action="store_true",
help="Don't organize resources by type, keep them flat")
parser.add_argument("--dry-run", action="store_true",
help="Print what would be done without writing files")
textargs = parser.parse_args()

# Verify helm is installed
check_helm_installed()

print(f"[1/4] Templating Helm chart {args.chart}...")
manifests = template_helm_chart(
    args.chart, 
    args.values, 
    args.set, 
    args.release, 
    args.namespace,
    args.version
)

print(f"[2/4] Splitting resources by type...")
resources_by_type = split_resources(manifests)

if args.dry_run:
    print("\nDry run - the following resources would be created:")
    for resource_type, resources in resources_by_type.items():
        print(f"\n{resource_type}/")
        for resource in resources:
            name = resource.get("metadata", {}).get("name", "unnamed")
            print(f"  {sanitize_filename(name)}.yaml")
    return

print(f"[3/4] Writing {sum(len(r) for r in resources_by_type.values())} resources to {args.output_dir}...")

# Create the output directory if it doesn't exist
os.makedirs(args.output_dir, exist_ok=True)

if args.no_organize:
    # Flatten all resources into a single directory
    flat_resources = {}
    for resources in resources_by_type.values():
        for resource in resources:
            kind = resource.get("kind", "Unknown").lower()
            name = resource.get("metadata", {}).get("name", "unnamed")
            key = f"{kind}-{sanitize_filename(name)}"
            if key not in flat_resources:
                flat_resources[key] = []
            flat_resources[key].append(resource)
    
    for key, resources in flat_resources.items():
        with open(os.path.join(args.output_dir, f"{key}.yaml"), "w") as f:
            yaml.dump_all(resources, f, default_flow_style=False)
    
    # Create a simple kustomization.yaml file
    kustomization = {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": [f"{key}.yaml" for key in flat_resources.keys()]
    }
    with open(os.path.join(args.output_dir, "kustomization.yaml"), "w") as f:
        yaml.dump(kustomization, f, default_flow_style=False)
else:
    # Organize resources by type into subdirectories
    write_resources(resources_by_type, args.output_dir)
    create_kustomization(args.output_dir, resources_by_type)

# Create an example overlay if requested
if args.create_overlay:
    print(f"[4/4] Creating example overlay in ../overlays/{args.namespace}...")
    create_overlay_example(args.output_dir, os.path.basename(args.chart.split('/')[-1]), args.namespace)
else:
    print(f"[4/4] Done! Kustomize base is ready at {os.path.abspath(args.output_dir)}")

if name == "main":
main()


"""

# Push this directory to your Git repository

Create an Application in ArgoCD:

apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
name: {os.path.basename(args.chart.split('/')[-1])}
namespace: argocd
spec:
project: default
source:
repoURL: https://github.com/your-org/your-repo.git
targetRevision: HEAD
path: {os.path.relpath(args.output_dir)}
destination:
server: https://kubernetes.default.svc
namespace: {args.namespace}
syncPolicy:
automated:
prune: true
selfHeal: true


## Key Features

1. **Helm Chart to Kustomize Conversion**
   - Takes any Helm chart and converts it to static Kubernetes YAML
   - Organizes resources by type (deployments, services, etc.)
   - Creates a proper kustomization.yaml file

2. **ArgoCD Friendly**
   - Produces a stable base that works well with ArgoCD
   - Creates example overlay directories with appropriate structure
   - Generates sample ArgoCD Application resources

3. **Flexible Configuration**
   - Support for custom values files (--values)
   - Specific chart version selection (--version)
   - Value overrides via command line (--set)

4. **Organization Options**
   - By default, organizes by resource type
   - Optional flat organization with --no-organize flag

5. **Developer Experience**
   - Dry-run mode to preview output
   - Creates overlay examples automatically

##
## Usage Examples

# Basic conversion
./helm2kustomize.py --chart bitnami/nginx --output-dir ./k8s/bases/nginx

# With custom values and specific version
./helm2kustomize.py --chart bitnami/nginx --values ./prod-values.yaml --version 9.5.0 --output-dir ./k8s/bases/nginx-prod

# Create with example overlay
./helm2kustomize.py --chart bitnami/nginx --output-dir ./k8s/bases/nginx --create-overlay --namespace production

# Set values directly
./helm2kustomize.py --chart bitnami/nginx --output-dir ./k8s/bases/nginx --set replicaCo
