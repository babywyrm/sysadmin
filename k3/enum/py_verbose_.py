python3 - <<'EOF'
import os, subprocess, json

APISERVER = "https://kubernetes.default.svc"
CACERT = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TOKEN = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
NAMESPACE = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read().strip()

# ANSI colors
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"

verbs = ["get","list","create","update","delete","patch"]

# Some common namespaced resources
resources = ["configmaps","secrets","pods","services",
             "deployments","daemonsets","statefulsets",
             "roles","rolebindings"]
# Cluster resources
cluster_resources = ["nodes","namespaces","clusterroles","clusterrolebindings"]

def kcurl(url, payload):
    cmd = [
        "curl", "-s", "--cacert", CACERT,
        "-H", f"Authorization: Bearer {TOKEN}",
        "-H", "Content-Type: application/json",
        "-X", "POST", url, "-d", json.dumps(payload)
    ]
    return subprocess.check_output(cmd, text=True)

def check_access(resource, verb, namespace=None):
    payload = {
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {"resourceAttributes": {"verb": verb, "resource": resource}}
    }
    if namespace:
        payload["spec"]["resourceAttributes"]["namespace"] = namespace
    try:
        out = kcurl(f"{APISERVER}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", payload)
        resp = json.loads(out)
        allowed = resp.get("status", {}).get("allowed", False)
        return allowed, resp.get("status", {})
    except Exception as e:
        return False, {"error": str(e)}

def get_namespaces():
    # Try to list namespaces, otherwise fall back to the current one
    payload = {
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {"resourceAttributes": {"verb": "list", "resource": "namespaces"}}
    }
    try:
        allowed, _ = check_access("namespaces", "list")
        if allowed:
            out = subprocess.check_output([
                "curl","-s","--cacert",CACERT,
                "-H",f"Authorization: Bearer {TOKEN}",
                f"{APISERVER}/api/v1/namespaces"
            ], text=True)
            items = json.loads(out).get("items", [])
            return [i["metadata"]["name"] for i in items]
    except Exception:
        pass
    return [NAMESPACE]

def summarize(resources, scope="namespace", namespaces=None):
    print(f"\n=== {scope.upper()} RESOURCES ===")
    if scope == "namespace":
        for ns in namespaces:
            print(f"\n-- Namespace: {ns} --")
            for r in resources:
                results = []
                for v in verbs:
                    allowed, proof = check_access(r, v, ns)
                    results.append((v, allowed, proof))
                allowed_verbs = [v for v,a,_ in results if a]
                if allowed_verbs:
                    flag = " <<!! ESCALATION !!>>" if (
                        r in ["secrets","configmaps","pods"]
                        or any(v in ["create","update","delete","patch"] for v in allowed_verbs)
                    ) else ""
                    print(f"{r:<20} -> " + GREEN + ",".join(allowed_verbs) + RESET + flag)
                else:
                    print(f"{r:<20} -> " + RED + "NONE" + RESET)
                # Dump proof JSON under each verb
                for v,a,pf in results:
                    if a or pf:
                        color = GREEN if a else RED
                        print(f"   {v.upper():<8}: {color}{a}{RESET}")
                        print(json.dumps(pf, indent=6))
    else:
        for r in resources:
            results = []
            for v in verbs:
                allowed, proof = check_access(r, v)
                results.append((v, allowed, proof))
            allowed_verbs = [v for v,a,_ in results if a]
            if allowed_verbs:
                print(f"{r:<20} -> " + GREEN + ",".join(allowed_verbs) + RESET)
            else:
                print(f"{r:<20} -> " + RED + "NONE" + RESET)
            for v,a,pf in results:
                if a or pf:
                    color = GREEN if a else RED
                    print(f"   {v.upper():<8}: {color}{a}{RESET}")
                    print(json.dumps(pf, indent=6))

# Run checks
namespaces = get_namespaces()
summarize(resources, scope="namespace", namespaces=namespaces)
summarize(cluster_resources, scope="cluster")
EOF
