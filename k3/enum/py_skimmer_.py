python3 - <<'EOF'
import os, subprocess, json

APISERVER = "https://kubernetes.default.svc"
CACERT = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TOKEN = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
NAMESPACE = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read().strip()

resources = ["configmaps", "secrets", "pods", "services", "deployments", "nodes"]
verbs = ["get", "list", "create", "update", "delete"]

for r in resources:
    for v in verbs:
        payload = {
            "kind": "SelfSubjectAccessReview",
            "apiVersion": "authorization.k8s.io/v1",
            "spec": {
                "resourceAttributes": {
                    "namespace": NAMESPACE,
                    "verb": v,
                    "resource": r
                }
            }
        }
        cmd = [
            "curl", "-s", "--cacert", CACERT,
            "-H", f"Authorization: Bearer {TOKEN}",
            "-H", "Content-Type: application/json",
            "-X", "POST",
            f"{APISERVER}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            "-d", json.dumps(payload)
        ]
        out = subprocess.check_output(cmd, text=True)
        resp = json.loads(out)
        allowed = resp.get("status", {}).get("allowed", False)
        reason = resp.get("status", {}).get("reason", "")
        print(f"{v.upper():<6} {r:<12} -> {allowed} {reason}")
EOF
