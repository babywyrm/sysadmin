python3 - <<'EOF'
#!/usr/bin/env python3
import os, subprocess, json, sys
from pathlib import Path

# Kubernetes service account paths
SA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount")
APISERVER = "https://kubernetes.default.svc"
CACERT = SA_PATH / "ca.crt"
TOKEN_FILE = SA_PATH / "token"
NAMESPACE_FILE = SA_PATH / "namespace"

# ANSI colors
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

# Check if we're in a pod
if not all(f.exists() for f in [CACERT, TOKEN_FILE, NAMESPACE_FILE]):
    print(f"{Colors.RED}❌ Not running in a Kubernetes pod with service account{Colors.RESET}")
    sys.exit(1)

TOKEN = TOKEN_FILE.read_text().strip()
NAMESPACE = NAMESPACE_FILE.read_text().strip()

print(f"{Colors.CYAN}🔍 Kubernetes Permission Enumerator{Colors.RESET}")
print(f"{Colors.BLUE}Current namespace: {NAMESPACE}{Colors.RESET}\n")

VERBS = ["get", "list", "create", "update", "patch", "delete", "watch"]

# Comprehensive resource lists
CORE_RESOURCES = [
    "pods", "services", "endpoints", "configmaps", "secrets", 
    "persistentvolumeclaims", "serviceaccounts", "events"
]

APPS_RESOURCES = [
    "deployments", "replicasets", "daemonsets", "statefulsets"
]

RBAC_RESOURCES = [
    "roles", "rolebindings"
]

NETWORKING_RESOURCES = [
    "networkpolicies", "ingresses"
]

CLUSTER_RESOURCES = [
    "nodes", "namespaces", "clusterroles", "clusterrolebindings",
    "persistentvolumes", "storageclasses", "customresourcedefinitions"
]

# High-impact resources for privilege escalation
HIGH_IMPACT = {
    "secrets", "configmaps", "pods", "serviceaccounts", "roles", 
    "rolebindings", "clusterroles", "clusterrolebindings", "nodes"
}

# High-impact verbs
HIGH_IMPACT_VERBS = {"create", "update", "patch", "delete"}

def curl_k8s(endpoint, method="GET", payload=None):
    """Make authenticated request to Kubernetes API"""
    cmd = [
        "curl", "-s", "--cacert", str(CACERT),
        "-H", f"Authorization: Bearer {TOKEN}",
        "-X", method
    ]
    
    if payload:
        cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(payload)])
    
    cmd.append(f"{APISERVER}{endpoint}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return json.loads(result.stdout) if result.stdout else None
    except Exception as e:
        return None

def check_access(resource, verb, namespace=None, group="", version="v1"):
    """Check if current service account can perform verb on resource"""
    payload = {
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {
            "resourceAttributes": {
                "verb": verb,
                "resource": resource,
                "group": group,
                "version": version
            }
        }
    }
    
    if namespace:
        payload["spec"]["resourceAttributes"]["namespace"] = namespace
    
    response = curl_k8s("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "POST", payload)
    return response and response.get("status", {}).get("allowed", False)

def get_accessible_namespaces():
    """Get list of namespaces we can access"""
    if check_access("namespaces", "list"):
        response = curl_k8s("/api/v1/namespaces")
        if response and "items" in response:
            return [item["metadata"]["name"] for item in response["items"]]
    return [NAMESPACE]

def format_permissions(resource, permissions, is_high_impact=False):
    """Format permission output with colors and flags"""
    if not permissions:
        return f"{resource:<25} -> {Colors.RED}NONE{Colors.RESET}"
    
    perm_str = ",".join(permissions)
    color = Colors.GREEN
    flags = []
    
    if is_high_impact:
        color = Colors.YELLOW
        flags.append("⚠️  HIGH IMPACT")
    
    if any(verb in HIGH_IMPACT_VERBS for verb in permissions):
        flags.append("🔥 WRITE ACCESS")
    
    if "get" in permissions and "list" in permissions:
        flags.append("👁️  READ ACCESS")
    
    flag_str = f" {' '.join(flags)}" if flags else ""
    return f"{resource:<25} -> {color}{perm_str}{Colors.RESET}{flag_str}"

def check_resource_group(resources, group_name, namespaces=None, group="", version="v1"):
    """Check permissions for a group of resources"""
    print(f"\n{Colors.BOLD}=== {group_name} ==={Colors.RESET}")
    
    if namespaces:
        for ns in namespaces:
            if len(namespaces) > 1:
                print(f"\n{Colors.CYAN}📁 Namespace: {ns}{Colors.RESET}")
            
            for resource in resources:
                permissions = []
                for verb in VERBS:
                    if check_access(resource, verb, ns, group, version):
                        permissions.append(verb)
                
                is_high_impact = resource in HIGH_IMPACT
                print(format_permissions(resource, permissions, is_high_impact))
    else:
        for resource in resources:
            permissions = []
            for verb in VERBS:
                if check_access(resource, verb, None, group, version):
                    permissions.append(verb)
            
            is_high_impact = resource in HIGH_IMPACT
            print(format_permissions(resource, permissions, is_high_impact))

def check_special_permissions():
    """Check for special high-privilege permissions"""
    print(f"\n{Colors.BOLD}=== SPECIAL CHECKS ==={Colors.RESET}")
    
    special_checks = [
        ("Pod exec", "pods", "create", "pods/exec"),
        ("Pod logs", "pods", "get", "pods/log"),
        ("Pod port-forward", "pods", "create", "pods/portforward"),
        ("Node proxy", "nodes", "create", "nodes/proxy"),
        ("Service proxy", "services", "create", "services/proxy"),
    ]
    
    for name, resource, verb, subresource in special_checks:
        # This is a simplified check - real subresource checking is more complex
        has_access = check_access(resource, verb)
        color = Colors.YELLOW if has_access else Colors.RED
        status = "✅ ALLOWED" if has_access else "❌ DENIED"
        print(f"{name:<25} -> {color}{status}{Colors.RESET}")

def main():
    try:
        # Get accessible namespaces
        namespaces = get_accessible_namespaces()
        print(f"{Colors.BLUE}Accessible namespaces: {', '.join(namespaces)}{Colors.RESET}")
        
        # Check core resources
        check_resource_group(CORE_RESOURCES, "CORE RESOURCES", namespaces)
        
        # Check apps resources
        check_resource_group(APPS_RESOURCES, "APPS RESOURCES", namespaces, "apps", "v1")
        
        # Check RBAC resources
        check_resource_group(RBAC_RESOURCES, "RBAC RESOURCES", namespaces, "rbac.authorization.k8s.io", "v1")
        
        # Check networking resources
        check_resource_group(NETWORKING_RESOURCES, "NETWORKING RESOURCES", namespaces, "networking.k8s.io", "v1")
        
        # Check cluster resources
        check_resource_group(CLUSTER_RESOURCES, "CLUSTER RESOURCES")
        
        # Check special permissions
        check_special_permissions()
        
        print(f"\n{Colors.GREEN}✅ Permission enumeration complete!{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
EOF
