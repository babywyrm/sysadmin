python3 - <<'EOF'
#!/usr/bin/env python3
import os, subprocess, json, sys
from pathlib import Path

# Connectivity Setup
SA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount")
APISERVER = "https://kubernetes.default.svc"
CACERT, TOKEN_FILE, NS_FILE = SA_PATH/"ca.crt", SA_PATH/"token", SA_PATH/"namespace"

class Colors:
    G, R, Y, B, M, C, BOLD, NC = "\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[1m", "\033[0m"

if not all(f.exists() for f in [CACERT, TOKEN_FILE, NS_FILE]):
    print(f"{Colors.R}❌ Not in a K8s SA environment.{Colors.NC}"); sys.exit(1)

TOKEN = TOKEN_FILE.read_text().strip()
MY_NS = NS_FILE.read_text().strip()

def curl(ep, method="GET", data=None):
    cmd = ["curl", "-s", "--cacert", str(CACERT), "-H", f"Authorization: Bearer {TOKEN}", "-X", method]
    if data: cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
    cmd.append(f"{APISERVER}{ep}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return json.loads(r.stdout) if r.stdout else None
    except: return None

def can(res, verb, ns=None, group="", sub=""):
    p = {"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":verb,"resource":res,"group":group,"subresource":sub}}}
    if ns: p["spec"]["resourceAttributes"]["namespace"] = ns
    r = curl("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "POST", p)
    return r and r.get("status", {}).get("allowed", False)

def get_ns():
    r = curl("/api/v1/namespaces")
    if r and "items" in r: return [i["metadata"]["name"] for i in r["items"]]
    found = [MY_NS]
    for g in ["default", "kube-system", "kube-public", "internal", "dev-internal", "staging", "prod", "ops", "orthanc", "wordpress"]:
        if g != MY_NS and curl(f"/api/v1/namespaces/{g}/pods"): found.append(g)
    return list(set(found))

def probe():
    print(f"{Colors.BOLD}{Colors.C}--- K8S OMNI-HUNTER: FULL AUDIT MODE ---{Colors.NC}")
    if can("*", "*"): print(f"{Colors.R}{Colors.BOLD}🔥 CLUSTER-ADMIN DETECTED 🔥{Colors.NC}")

    schema = [
        ("pods", "", "v1", False), ("secrets", "", "v1", False), ("configmaps", "", "v1", False),
        ("services", "", "v1", False), ("serviceaccounts", "", "v1", False),
        ("deployments", "apps", "v1", False), ("daemonsets", "apps", "v1", False),
        ("statefulsets", "apps", "v1", False), ("jobs", "batch", "v1", False),
        ("roles", "rbac.authorization.k8s.io", "v1", False),
        ("rolebindings", "rbac.authorization.k8s.io", "v1", False),
        ("networkpolicies", "networking.k8s.io", "v1", False),
        ("ingresses", "networking.k8s.io", "v1", False),
        ("nodes", "", "v1", True), ("namespaces", "", "v1", True),
        ("clusterroles", "rbac.authorization.k8s.io", "v1", True),
        ("clusterrolebindings", "rbac.authorization.k8s.io", "v1", True)
    ]

    nss = get_ns()
    print(f"{Colors.B}Probing {len(nss)} Namespaces...{Colors.NC}")

    for ns in nss:
        print(f"\n{Colors.BOLD}{Colors.M}📁 NAMESPACE: {ns}{Colors.NC}")
        for res, group, ver, cluster_scoped in schema:
            if cluster_scoped and ns != nss[0]: continue 
            
            check_ns = None if cluster_scoped else ns
            allowed = [v for v in ["list", "get", "create", "update", "delete"] if can(res, v, check_ns, group)]
            
            meta = ""
            if "list" in allowed:
                path = f"/api/v1/{res}" if not group else f"/apis/{group}/{ver}/{res}"
                if not cluster_scoped:
                    path = f"/api/v1/namespaces/{ns}/{res}" if not group else f"/apis/{group}/{ver}/namespaces/{ns}/{res}"
                data = curl(path)
                if data and "items" in data:
                    names = [i["metadata"]["name"] for i in data["items"]]
                    if names: meta = f" {Colors.Y}({len(names)}: {', '.join(names[:2])}...){Colors.NC}"
            
            label = f"[C] {res}" if cluster_scoped else res
            if allowed:
                color = Colors.R if res in ["secrets", "rolebindings", "clusterrolebindings"] else Colors.G
                print(f"  {label:<25} -> {color}{','.join(allowed)}{Colors.NC}{meta}")
            else:
                print(f"  {label:<25} -> {Colors.R}DENIED{Colors.NC}")

    print(f"\n{Colors.BOLD}{Colors.C}--- ESCALATION PATHS ---{Colors.NC}")
    for s in [("exec","create"), ("log","get"), ("portforward","create"), ("attach","create")]:
        st = f"{Colors.G}✅ ALLOWED" if can("pods", s[1], MY_NS, "", s[0]) else f"{Colors.R}❌ DENIED"
        print(f"  pods/{s[0]:<15} -> {st}{Colors.NC}")

if __name__ == "__main__": probe()
EOF
