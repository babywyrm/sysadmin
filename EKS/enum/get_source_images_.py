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

def extract_container_images(pods):
    """Extract container images from the list of pods."""
    images = []
    for pod in pods['items']:
        pod_name = pod['metadata']['name']
        print(f"Pod: {pod_name}")
        for container in pod['spec']['containers']:
            images.append(container['image'])
            print(f"  - Image: {container['image']}")
    return images

def main():
    # Get all namespaces
    namespaces = get_namespaces()
    
    if namespaces:
        print("Available namespaces:")
        for ns in namespaces['items']:
            print(f" - {ns['metadata']['name']}")
        
        # Ask user to select a namespace
        selected_namespace = input("Enter the namespace you want to check (or type 'all' for all namespaces): ").strip()
        
        if selected_namespace.lower() == 'all':
            # Iterate through all namespaces
            for ns in namespaces['items']:
                namespace = ns['metadata']['name']
                print(f"\nFetching pods from namespace: {namespace}")
                pods = get_pods(namespace)
                if pods:
                    extract_container_images(pods)
        else:
            # Fetch pods from the selected namespace
            pods = get_pods(selected_namespace)
            if pods:
                extract_container_images(pods)
            else:
                print(f"No pods found in namespace: {selected_namespace}")

if __name__ == "__main__":
    main()

##
##
