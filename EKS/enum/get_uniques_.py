import subprocess
import json

##
##

def run_kubectl_command(command):
    """Run a kubectl command and return the output as JSON."""
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running command {' '.join(command)}: {e.stderr.decode()}")
        return None

def get_namespaces():
    """Get a list of all namespaces."""
    command = ["kubectl", "get", "namespaces", "-o", "json"]
    return run_kubectl_command(command)

def get_pods(namespace):
    """Get a list of pods in the specified namespace."""
    command = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
    return run_kubectl_command(command)

def extract_container_info(pods):
    """Extract container images and other relevant info from the list of pods."""
    container_info = {}
    for pod in pods['items']:
        pod_name = pod['metadata']['name']
        pod_status = pod['status']['phase']
        creation_timestamp = pod['metadata']['creationTimestamp']
        labels = pod['metadata'].get('labels', {})
        annotations = pod['metadata'].get('annotations', {})
        
        print(f"Pod: {pod_name} (Status: {pod_status}, Created: {creation_timestamp})")
        print(f"  Labels: {labels}")
        print(f"  Annotations: {annotations}")

        for container in pod['spec']['containers']:
            image = container['image']
            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            limits = resources.get('limits', {})
            
            if image not in container_info:
                container_info[image] = {
                    "pods": [],
                    "requests": requests,
                    "limits": limits
                }
            container_info[image]["pods"].append(pod_name)

    return container_info

def main():
    # Get all namespaces
    namespaces = get_namespaces()
    
    if namespaces:
        for ns in namespaces['items']:
            namespace = ns['metadata']['name']
            print(f"\nFetching pods from namespace: {namespace}")
            pods = get_pods(namespace)
            if pods:
                container_info = extract_container_info(pods)
                print("\nUnique Container Images and their Pods:")
                for image, info in container_info.items():
                    print(f"  - Image: {image}")
                    print(f"    Pods: {', '.join(info['pods'])}")
                    print(f"    Requests: {info['requests']}")
                    print(f"    Limits: {info['limits']}")

if __name__ == "__main__":
    main()
  
##
##
