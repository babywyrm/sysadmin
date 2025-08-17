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

verbs = ["get", "list", "create", "update", "delete"]

# Some common core + namespaced resources
resources = ["configmaps","secrets","pods","services","deployments","daemonsets","statefulsets","roles","rolebindings"]
# Some cluster-wide resources
cluster_resources = ["nodes","namespaces","clusterroles","clusterrolebindings"]

def check_access(resource, verb, namespace=None):
    payload = {
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {"resourceAttributes": {"verb": verb, "resource": resource}}
    }
    if namespace:
        payload["spec"]["resourceAttributes"]["namespace"] = namespace
    cmd = [
        "curl", "-s", "--cacert", CACERT,
        "-H", f"Authorization: Bearer {TOKEN}",
        "-H", "Content-Type: application/json",
        "-X", "POST",
        f"{APISERVER}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "-d", json.dumps(payload)
    ]
    try:
        out = subprocess.check_output(cmd, text=True)
        resp = json.loads(out)
        return resp.get("status", {}).get("allowed", False)
    except Exception as e:
        return False

def summarize(resources, scope="namespace"):
    print(f"\n=== {scope.upper()} RESOURCES ===")
    for r in resources:
        results = []
        for v in verbs:
            allowed = check_access(r, v, NAMESPACE if scope=="namespace" else None)
            results.append((v, allowed))
        allowed_verbs = [v for v,a in results if a]
        if allowed_verbs:
            print(f"{r:<20} -> " + GREEN + ",".join(allowed_verbs) + RESET)
        else:
            print(f"{r:<20} -> " + RED + "NONE" + RESET)

# Run checks
summarize(resources, scope="namespace")
summarize(cluster_resources, scope="cluster")
EOF

