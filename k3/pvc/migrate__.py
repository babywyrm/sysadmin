#!/usr/bin/env python3
"""
k8s-node-migrator.py - Kubernetes Node Migration Helper, Probably

This script helps migrate PVs and PVCs when node hostnames change.
It creates new PVs with updated nodeAffinity and rebinds existing PVCs.

Usage:
  ./k8s-node-migrator.py [--old-node OLD_NODE] [--new-node NEW_NODE] [--namespace NAMESPACE] [--dry-run]

Examples:
  # Detect changes and show what would change
  ./k8s-node-migrator.py --dry-run
  
  # Migrate from "old-node" to "new-node" in default namespace
  ./k8s-node-migrator.py --old-node old-node --new-node new-node
  
  # Migrate in a specific namespace
  ./k8s-node-migrator.py --namespace wordpress --old-node old-node --new-node new-node
"""
import argparse
import json
import os,sys,re
import subprocess
import tempfile

def run_command(cmd, return_output=False, allow_fail=False):
    """Run a shell command and handle errors"""
    print(f"Running: {' '.join(cmd)}")
    if return_output:
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            return result.strip()
        except subprocess.CalledProcessError as e:
            if allow_fail:
                return None
            print(f"Error running command: {e.output}", file=sys.stderr)
            sys.exit(1)
    else:
        result = subprocess.run(cmd)
        if result.returncode != 0 and not allow_fail:
            print(f"Error running command, exit code: {result.returncode}", file=sys.stderr)
            sys.exit(1)
        return result.returncode

def get_nodes():
    """Get list of nodes in the cluster"""
    nodes_json = run_command(["kubectl", "get", "nodes", "-o", "json"], return_output=True)
    return json.loads(nodes_json)["items"]

def get_pvs():
    """Get list of PVs in the cluster"""
    pvs_json = run_command(["kubectl", "get", "pv", "-o", "json"], return_output=True)
    return json.loads(pvs_json)["items"]

def get_pvcs(namespace=None):
    """Get list of PVCs in the namespace (or all if None)"""
    cmd = ["kubectl", "get", "pvc"]
    if namespace:
        cmd.extend(["-n", namespace])
    cmd.extend(["-o", "json"])
    pvcs_json = run_command(cmd, return_output=True)
    return json.loads(pvcs_json)["items"]

def detect_node_change():
    """Try to detect node name changes based on hostname and Ready nodes"""
    current_hostname = run_command(["hostname"], return_output=True)
    nodes = get_nodes()
    
    # Identify Ready nodes
    ready_nodes = []
    not_ready_nodes = []
    
    for node in nodes:
        name = node["metadata"]["name"]
        for condition in node["status"]["conditions"]:
            if condition["type"] == "Ready":
                if condition["status"] == "True":
                    ready_nodes.append(name)
                else:
                    not_ready_nodes.append(name)
    
    # Detect potential name changes
    if current_hostname in ready_nodes:
        print(f"Current hostname {current_hostname} matches a Ready node. No migration needed.")
        return None, None
    
    # If hostname doesn't match any node, but we have NotReady nodes
    if not_ready_nodes and current_hostname not in ready_nodes + not_ready_nodes:
        print(f"Current hostname {current_hostname} doesn't match any node.")
        print(f"NotReady nodes detected: {', '.join(not_ready_nodes)}")
        print("These might be old node names that need migration.")
        
        if len(ready_nodes) == 1:
            return not_ready_nodes[0] if not_ready_nodes else None, ready_nodes[0]
    
    return None, None

def migrate_pvs(old_node, new_node, namespace=None, dry_run=False):
    """Migrate PVs from old_node to new_node"""
    pvs = get_pvs()
    pvcs = get_pvcs(namespace)
    
    affected_pvs = []
    
    # Find PVs with nodeAffinity to old_node
    for pv in pvs:
        pv_name = pv["metadata"]["name"]
        if "nodeAffinity" in pv["spec"] and "required" in pv["spec"]["nodeAffinity"]:
            for term in pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"]:
                for expr in term["matchExpressions"]:
                    if expr["key"] == "kubernetes.io/hostname" and old_node in expr["values"]:
                        affected_pvs.append(pv)
                        print(f"PV {pv_name} has nodeAffinity to {old_node}")
    
    if not affected_pvs:
        print(f"No PVs with nodeAffinity to {old_node} found.")
        return
    
    print(f"\nFound {len(affected_pvs)} PVs to migrate from {old_node} to {new_node}")
    
    for pv in affected_pvs:
        pv_name = pv["metadata"]["name"]
        
        # Check if PV is bound to a PVC
        bound_pvc = None
        if "claimRef" in pv["spec"]:
            bound_ns = pv["spec"]["claimRef"]["namespace"]
            bound_name = pv["spec"]["claimRef"]["name"]
            
            if namespace and bound_ns != namespace:
                print(f"Skipping PV {pv_name} as it's bound to PVC in namespace {bound_ns}, not {namespace}")
                continue
                
            print(f"PV {pv_name} is bound to PVC {bound_ns}/{bound_name}")
            bound_pvc = f"{bound_ns}/{bound_name}"
        
        # Create a new PV with updated nodeAffinity
        new_pv_name = f"{pv_name}-{new_node}"
        new_pv = pv.copy()
        new_pv["metadata"]["name"] = new_pv_name
        
        # Remove resourceVersion and other auto-generated fields
        if "resourceVersion" in new_pv["metadata"]:
            del new_pv["metadata"]["resourceVersion"]
        if "uid" in new_pv["metadata"]:
            del new_pv["metadata"]["uid"]
        if "creationTimestamp" in new_pv["metadata"]:
            del new_pv["metadata"]["creationTimestamp"]
        
        # Update nodeAffinity
        for term in new_pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"]:
            for expr in term["matchExpressions"]:
                if expr["key"] == "kubernetes.io/hostname":
                    expr["values"] = [new_node]
        
        # Remove claimRef first - we'll add it back after creating the PV
        if "claimRef" in new_pv["spec"]:
            claim_ref = new_pv["spec"]["claimRef"].copy()
            del new_pv["spec"]["claimRef"]
        else:
            claim_ref = None
        
        # Write the new PV to a temp file
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        json.dump(new_pv, temp_file)
        temp_file.close()
        
        if dry_run:
            print(f"Would create new PV {new_pv_name} with nodeAffinity to {new_node}")
            if bound_pvc:
                print(f"Would update PVC {bound_pvc} to bind to {new_pv_name}")
        else:
            # Create the new PV
            print(f"Creating new PV {new_pv_name} with nodeAffinity to {new_node}")
            run_command(["kubectl", "create", "-f", temp_file.name])
            
            if bound_pvc and claim_ref:
                # Unbind original PV
                print(f"Removing claimRef from original PV {pv_name}")
                run_command(["kubectl", "patch", "pv", pv_name, "--type=json",
                             "-p=[{\"op\":\"remove\",\"path\":\"/spec/claimRef\"}]"], allow_fail=True)
                
                # Wait a moment
                import time
                time.sleep(2)
                
                # Add claimRef to new PV
                print(f"Adding claimRef to new PV {new_pv_name}")
                claim_ref_json = json.dumps({"spec": {"claimRef": claim_ref}})
                run_command(["kubectl", "patch", "pv", new_pv_name, "--type=merge",
                             f"-p={claim_ref_json}"])
        
        # Clean up temp file
        os.unlink(temp_file.name)
        
        if not dry_run:
            print(f"Successfully migrated PV {pv_name} to {new_pv_name} for node {new_node}")
            
            # Delete the old PV if requested
            answer = input(f"Delete old PV {pv_name}? (y/N): ").lower()
            if answer == 'y':
                run_command(["kubectl", "delete", "pv", pv_name])
                print(f"Deleted PV {pv_name}")

def main():
    parser = argparse.ArgumentParser(description="Kubernetes Node Migration Helper")
    parser.add_argument("--old-node", help="Original node name")
    parser.add_argument("--new-node", help="New node name")
    parser.add_argument("--namespace", help="Namespace to target (default: all namespaces)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    
    args = parser.parse_args()
    
    # Try to auto-detect if not specified
    if not args.old_node or not args.new_node:
        detected_old, detected_new = detect_node_change()
        
        if not args.old_node and detected_old:
            args.old_node = detected_old
            print(f"Auto-detected old node name: {args.old_node}")
        
        if not args.new_node and detected_new:
            args.new_node = detected_new
            print(f"Auto-detected new node name: {args.new_node}")
    
    if not args.old_node or not args.new_node:
        parser.error("Both --old-node and --new-node are required if auto-detection fails")
    
    if args.dry_run:
        print("Running in dry-run mode - no changes will be made")
    
    print(f"Migrating PVs from node {args.old_node} to {args.new_node}")
    if args.namespace:
        print(f"Targeting namespace: {args.namespace}")
    
    migrate_pvs(args.old_node, args.new_node, args.namespace, args.dry_run)

if __name__ == "__main__":
    main()
