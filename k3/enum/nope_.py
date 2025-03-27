import ssl
import socket

##
## possibly has ssl problems, easily sorted
##

API_SERVER = "localhost"  # Use localhost if port-forwarding, or the K8s API server address
API_PORT = 6443  # Default port for Kubernetes API
API_PATH = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"

# Get the service account token (this is the path to the Kubernetes service account token)
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
with open(TOKEN_PATH, 'r') as token_file:
    TOKEN = token_file.read().strip()

# Define the verbs and resources to check
verbs = ["get", "list", "watch", "create", "update", "patch", "delete"]
resources = ["pods", "deployments", "services", "configmaps", "secrets", 
             "persistentvolumeclaims", "events", "endpoints", "ingresses", 
             "jobs", "cronjobs", "statefulsets", "daemonsets", "replicasets", 
             "nodes", "namespaces", "clusterroles", "clusterrolebindings"]

# Define function to get the API group for each resource
def get_api_group(resource):
    if resource in ["deployments", "daemonsets", "statefulsets", "replicasets"]:
        return "apps"
    elif resource == "ingresses":
        return "networking.k8s.io"
    elif resource in ["cronjobs", "jobs"]:
        return "batch"
    elif resource in ["pods", "services", "configmaps", "secrets", 
                      "persistentvolumeclaims", "events", "endpoints"]:
        return ""
    elif resource in ["nodes", "namespaces"]:
        return "core"
    elif resource in ["clusterroles", "clusterrolebindings"]:
        return "rbac.authorization.k8s.io"
    return ""

# Function to perform the permission check
def check_permission(verb, resource, namespace="default"):
    group = get_api_group(resource)

    # Construct JSON payload
    payload = f'''
    {{
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {{
            "resourceAttributes": {{
                "namespace": "{namespace}",
                "verb": "{verb}",
                "resource": "{resource}",
                "group": "{group}"
            }}
        }}
    }}
    '''

    # Construct the HTTP request (using plain socket)
    request = f"POST {API_PATH} HTTP/1.1\r\n"
    request += f"Host: {API_SERVER}:{API_PORT}\r\n"
    request += f"Authorization: Bearer {TOKEN}\r\n"
    request += f"Content-Type: application/json\r\n"
    request += f"Content-Length: {len(payload)}\r\n"
    request += "\r\n"
    request += payload

    # Create a secure SSL context and open a socket to the API server
    context = ssl.create_default_context()
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=API_SERVER)

    # Connect to the Kubernetes API server
    connection.connect((API_SERVER, API_PORT))

    # Send the request
    connection.sendall(request.encode('utf-8'))

    # Receive the response
    response = connection.recv(4096).decode('utf-8')

    # Close the connection
    connection.close()

    # Check if the response contains "allowed": true
    if '"allowed": true' in response:
        print(f"=> Allowed: {verb} on {resource} in {namespace}")
    else:
        print(f"=> Denied: {verb} on {resource} in {namespace}")

    # Print the raw response (optional)
    print(f"Raw response (truncated): {response[:200]}...")

# Loop over all verbs and resources, checking permissions
for resource in resources:
    for verb in verbs:
        check_permission(verb, resource)

print("Permission check complete.")
