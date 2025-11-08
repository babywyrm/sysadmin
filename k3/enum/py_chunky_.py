python3 - <<'EOF'
#!/usr/bin/env python3
import os, subprocess, json, sys, time
from pathlib import Path
from collections import defaultdict

# Kubernetes service account paths
SA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount")
APISERVER = "https://kubernetes.default.svc"
CACERT = SA_PATH / "ca.crt"
TOKEN_FILE = SA_PATH / "token"
NAMESPACE_FILE = SA_PATH / "namespace"

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

print(f"{Colors.CYAN}🔍 Advanced Kubernetes Permission Enumerator{Colors.RESET}")
print(f"{Colors.BLUE}Current namespace: {NAMESPACE}{Colors.RESET}\n")

VERBS = ["get", "list", "create", "update", "patch", "delete", "watch", "deletecollection"]

# Comprehensive resource groups
RESOURCE_GROUPS = {
    "Core Resources": {
        "resources": ["pods", "services", "endpoints", "configmaps", "secrets", 
                     "persistentvolumeclaims", "serviceaccounts", "events", "limitranges", "resourcequotas"],
        "group": "", "version": "v1", "namespaced": True
    },
    "Apps Resources": {
        "resources": ["deployments", "replicasets", "daemonsets", "statefulsets"],
        "group": "apps", "version": "v1", "namespaced": True
    },
    "Batch Resources": {
        "resources": ["jobs", "cronjobs"],
        "group": "batch", "version": "v1", "namespaced": True
    },
    "Autoscaling": {
        "resources": ["horizontalpodautoscalers", "verticalpodautoscalers"],
        "group": "autoscaling", "version": "v2", "namespaced": True
    },
    "RBAC Resources": {
        "resources": ["roles", "rolebindings"],
        "group": "rbac.authorization.k8s.io", "version": "v1", "namespaced": True
    },
    "Networking": {
        "resources": ["networkpolicies", "ingresses", "ingressclasses"],
        "group": "networking.k8s.io", "version": "v1", "namespaced": True
    },
    "Storage": {
        "resources": ["volumesnapshots", "volumesnapshotcontents", "volumesnapshotclasses"],
        "group": "snapshot.storage.k8s.io", "version": "v1", "namespaced": False
    },
    "Policy": {
        "resources": ["poddisruptionbudgets", "podsecuritypolicies"],
        "group": "policy", "version": "v1", "namespaced": True
    },
    "Metrics": {
        "resources": ["nodes", "pods"],
        "group": "metrics.k8s.io", "version": "v1beta1", "namespaced": False
    },
    "Certificates": {
        "resources": ["certificates", "certificaterequests", "issuers", "clusterissuers"],
        "group": "cert-manager.io", "version": "v1", "namespaced": True
    },
    "Monitoring (Prometheus)": {
        "resources": ["servicemonitors", "podmonitors", "prometheusrules", "alertmanagers", "prometheuses"],
        "group": "monitoring.coreos.com", "version": "v1", "namespaced": True
    }
}

CLUSTER_RESOURCES = {
    "Cluster Core": {
        "resources": ["nodes", "namespaces", "persistentvolumes", "storageclasses", 
                     "priorityclasses", "runtimeclasses", "csidrivers", "csinodes"],
        "group": "", "version": "v1"
    },
    "Cluster RBAC": {
        "resources": ["clusterroles", "clusterrolebindings"],
        "group": "rbac.authorization.k8s.io", "version": "v1"
    },
    "API Extensions": {
        "resources": ["customresourcedefinitions", "apiservices"],
        "group": "apiextensions.k8s.io", "version": "v1"
    },
    "Admission Control": {
        "resources": ["validatingadmissionwebhooks", "mutatingadmissionwebhooks"],
        "group": "admissionregistration.k8s.io", "version": "v1"
    },
    "Scheduling": {
        "resources": ["priorityclasses", "runtimeclasses", "schedulingconfigs"],
        "group": "scheduling.k8s.io", "version": "v1"
    }
}

# Critical subresources to check
SUBRESOURCES = [
    ("pods/exec", "pods", "create"),
    ("pods/log", "pods", "get"),
    ("pods/portforward", "pods", "create"),
    ("pods/attach", "pods", "create"),
    ("services/proxy", "services", "create"),
    ("nodes/proxy", "nodes", "create"),
    ("pods/status", "pods", "patch"),
    ("services/status", "services", "patch"),
    ("deployments/scale", "deployments", "patch"),
    ("replicasets/scale", "replicasets", "patch"),
]

# High-impact resources for privilege escalation
CRITICAL_RESOURCES = {
    "secrets", "configmaps", "pods", "serviceaccounts", "roles", "rolebindings", 
    "clusterroles", "clusterrolebindings", "nodes", "customresourcedefinitions",
    "validatingadmissionwebhooks", "mutatingadmissionwebhooks", "podsecuritypolicies"
}

DANGEROUS_VERBS = {"create", "update", "patch", "delete", "deletecollection"}

def curl_k8s(endpoint, method="GET", payload=None, timeout=5):
    """Make authenticated request to Kubernetes API"""
    cmd = [
        "curl", "-s", "--cacert", str(CACERT),
        "-H", f"Authorization: Bearer {TOKEN}",
        "-X", method, "--connect-timeout", "5", "--max-time", str(timeout)
    ]
    
    if payload:
        cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(payload)])
    
    cmd.append(f"{APISERVER}{endpoint}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except Exception:
        pass
    return None

def check_access(resource, verb, namespace=None, group="", version="v1"):
    """Check if current service account can perform verb on resource"""
    payload = {
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {
            "resourceAttributes": {
                "verb": verb,
                "resource": resource
            }
        }
    }
    
    if group:
        payload["spec"]["resourceAttributes"]["group"] = group
    if version:
        payload["spec"]["resourceAttributes"]["version"] = version
    if namespace:
        payload["spec"]["resourceAttributes"]["namespace"] = namespace
    
    response = curl_k8s("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "POST", payload)
    return response and response.get("status", {}).get("allowed", False)

def discover_api_resources():
    """Discover available API resources in the cluster"""
    print(f"{Colors.CYAN}🔍 Discovering available API resources...{Colors.RESET}")
    
    discovered = defaultdict(list)
    
    # Core API
    response = curl_k8s("/api/v1")
    if response and "resources" in response:
        for resource in response["resources"]:
            if "/" not in resource["name"]:  # Skip subresources for now
                discovered["Core API v1"].append(resource["name"])
    
    # API groups
    response = curl_k8s("/apis")
    if response and "groups" in response:
        for group in response["groups"][:10]:  # Limit to first 10 to avoid spam
            group_name = group["name"]
            if group["versions"]:
                version = group["versions"][0]["version"]
                api_response = curl_k8s(f"/apis/{group_name}/{version}")
                if api_response and "resources" in api_response:
                    resources = [r["name"] for r in api_response["resources"] if "/" not in r["name"]]
                    if resources:
                        discovered[f"{group_name}/{version}"].append(resources[:5])  # Limit resources
    
    return discovered

def check_dangerous_pod_permissions():
    """Check for dangerous pod-related permissions"""
    print(f"\n{Colors.BOLD}=== 🚨 DANGEROUS POD PERMISSIONS ==={Colors.RESET}")
    
    dangerous_checks = [
        ("Create privileged pods", "Can bypass security contexts"),
        ("Mount host filesystem", "Can access host files via hostPath"),
        ("Use host network", "Can sniff network traffic"),
        ("Use host PID namespace", "Can see all host processes"),
        ("Create pods with any serviceAccount", "Can escalate privileges"),
    ]
    
    pod_create = check_access("pods", "create", NAMESPACE)
    
    for check_name, description in dangerous_checks:
        # If we can create pods, we potentially have these abilities
        has_access = pod_create
        color = Colors.RED if has_access else Colors.GREEN
        status = "⚠️  POSSIBLE" if has_access else "✅ BLOCKED"
        print(f"{check_name:<35} -> {color}{status}{Colors.RESET} ({description})")

def check_secret_access():
    """Check access to different types of secrets"""
    print(f"\n{Colors.BOLD}=== 🔐 SECRET ACCESS ANALYSIS ==={Colors.RESET}")
    
    if not check_access("secrets", "list", NAMESPACE):
        print(f"Cannot list secrets in {NAMESPACE}")
        return
    
    # Try to list secrets and analyze types
    response = curl_k8s(f"/api/v1/namespaces/{NAMESPACE}/secrets")
    if not response or "items" not in response:
        print("No secrets found or access denied")
        return
    
    secret_types = defaultdict(int)
    for secret in response["items"]:
        secret_type = secret.get("type", "Opaque")
        secret_types[secret_type] += 1
    
    print(f"Found {len(response['items'])} secrets:")
    for secret_type, count in secret_types.items():
        risk_level = "🔥 HIGH RISK" if "token" in secret_type.lower() else "⚠️  MEDIUM RISK"
        print(f"  {secret_type:<40} {count:>3} secrets {risk_level}")

def check_pvc_access():
    """Check PVC access and storage implications"""
    print(f"\n{Colors.BOLD}=== 💾 STORAGE ACCESS ANALYSIS ==={Colors.RESET}")
    
    pvc_perms = []
    for verb in VERBS:
        if check_access("persistentvolumeclaims", verb, NAMESPACE):
            pvc_perms.append(verb)
    
    if not pvc_perms:
        print("❌ No PVC access")
        return
    
    print(f"PVC Permissions: {Colors.YELLOW}{', '.join(pvc_perms)}{Colors.RESET}")
    
    if "create" in pvc_perms:
        print("  🚨 Can create PVCs - potential for storage exhaustion attacks")
    if "delete" in pvc_perms:
        print("  ⚠️  Can delete PVCs - potential data loss")
    if "list" in pvc_perms:
        response = curl_k8s(f"/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims")
        if response and "items" in response:
            print(f"  📊 Found {len(response['items'])} existing PVCs")

def analyze_privilege_escalation():
    """Analyze potential privilege escalation paths"""
    print(f"\n{Colors.BOLD}=== ⬆️  PRIVILEGE ESCALATION ANALYSIS ==={Colors.RESET}")
    
    escalation_paths = []
    
    # Check if we can modify our own serviceaccount or others
    if check_access("serviceaccounts", "patch", NAMESPACE):
        escalation_paths.append("🔥 Can modify ServiceAccounts - potential token manipulation")
    
    # Check if we can create/modify roles
    if check_access("roles", "create", NAMESPACE):
        escalation_paths.append("🚨 Can create Roles - direct privilege escalation")
    
    if check_access("rolebindings", "create", NAMESPACE):
        escalation_paths.append("🚨 Can create RoleBindings - can bind to higher privileges")
    
    # Check cluster-level escalation
    if check_access("clusterroles", "create"):
        escalation_paths.append("💥 Can create ClusterRoles - cluster-wide privilege escalation")
    
    if check_access("clusterrolebindings", "create"):
        escalation_paths.append("💥 Can create ClusterRoleBindings - cluster admin possible")
    
    # Check for pod-based escalation
    if check_access("pods", "create", NAMESPACE):
        escalation_paths.append("⚠️  Can create Pods - potential container breakout")
    
    # Check for configmap/secret access
    if check_access("configmaps", "get", NAMESPACE) and check_access("secrets", "get", NAMESPACE):
        escalation_paths.append("🔍 Can read ConfigMaps and Secrets - credential harvesting")
    
    if escalation_paths:
        print(f"{Colors.RED}Found {len(escalation_paths)} potential escalation paths:{Colors.RESET}")
        for path in escalation_paths:
            print(f"  {path}")
    else:
        print(f"{Colors.GREEN}✅ No obvious privilege escalation paths found{Colors.RESET}")

def format_permissions(resource, permissions, is_critical=False):
    """Enhanced permission formatting"""
    if not permissions:
        return f"{resource:<30} -> {Colors.RED}NONE{Colors.RESET}"
    
    perm_str = ",".join(permissions)
    color = Colors.GREEN
    flags = []
    
    if is_critical:
        color = Colors.YELLOW
        flags.append("⚠️")
    
    dangerous_perms = [p for p in permissions if p in DANGEROUS_VERBS]
    if dangerous_perms:
        flags.append("🔥")
        if len(dangerous_perms) >= 3:
            color = Colors.RED
    
    if "get" in permissions and "list" in permissions:
        flags.append("👁️")
    
    if "watch" in permissions:
        flags.append("📡")
    
    flag_str = f" {''.join(flags)}" if flags else ""
    return f"{resource:<30} -> {color}{perm_str}{Colors.RESET}{flag_str}"

def check_resource_group(group_name, config, namespaces=None):
    """Check permissions for a resource group with enhanced output"""
    print(f"\n{Colors.BOLD}=== {group_name} ==={Colors.RESET}")
    
    resources = config["resources"]
    group = config.get("group", "")
    version = config.get("version", "v1")
    namespaced = config.get("namespaced", True)
    
    target_namespaces = namespaces if namespaced else [None]
    
    for ns in target_namespaces:
        if ns and len(namespaces) > 1:
            print(f"\n{Colors.CYAN}📁 Namespace: {ns}{Colors.RESET}")
        
        for resource in resources:
            permissions = []
            for verb in VERBS:
                try:
                    if check_access(resource, verb, ns, group, version):
                        permissions.append(verb)
                except:
                    continue  # Skip failed checks
            
            is_critical = resource in CRITICAL_RESOURCES
            print(format_permissions(resource, permissions, is_critical))

def main():
    try:
        start_time = time.time()
        
        # Get accessible namespaces
        namespaces = [NAMESPACE]
        if check_access("namespaces", "list"):
            response = curl_k8s("/api/v1/namespaces")
            if response and "items" in response:
                namespaces = [item["metadata"]["name"] for item in response["items"]]
        
        print(f"{Colors.BLUE}Accessible namespaces: {', '.join(namespaces[:5])}" + 
              (f" (+{len(namespaces)-5} more)" if len(namespaces) > 5 else "") + f"{Colors.RESET}")
        
        # Discover available APIs
        discovered_apis = discover_api_resources()
        if discovered_apis:
            print(f"\n{Colors.MAGENTA}Available API Groups: {', '.join(list(discovered_apis.keys())[:5])}{Colors.RESET}")
        
        # Check all resource groups
        for group_name, config in RESOURCE_GROUPS.items():
            try:
                check_resource_group(group_name, config, namespaces if config.get("namespaced") else None)
            except Exception as e:
                print(f"{Colors.RED}Error checking {group_name}: {e}{Colors.RESET}")
        
        # Check cluster resources
        for group_name, config in CLUSTER_RESOURCES.items():
            try:
                check_resource_group(group_name, config)
            except Exception as e:
                print(f"{Colors.RED}Error checking {group_name}: {e}{Colors.RESET}")
        
        # Enhanced security analysis
        check_dangerous_pod_permissions()
        check_secret_access()
        check_pvc_access()
        analyze_privilege_escalation()
        
        # Subresource checks
        print(f"\n{Colors.BOLD}=== 🔧 SUBRESOURCE ACCESS ==={Colors.RESET}")
        for subres_name, resource, verb in SUBRESOURCES:
            has_access = check_access(resource, verb, NAMESPACE)
            color = Colors.YELLOW if has_access else Colors.RED
            status = "✅ ALLOWED" if has_access else "❌ DENIED"
            print(f"{subres_name:<25} -> {color}{status}{Colors.RESET}")
        
        elapsed = time.time() - start_time
        print(f"\n{Colors.GREEN}✅ Advanced enumeration complete in {elapsed:.1f}s!{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
EOF
