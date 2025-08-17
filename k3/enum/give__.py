#!/usr/bin/env python3
import os, subprocess, json

## this is beta as heck ##

APISERVER = "https://kubernetes.default.svc"
CACERT = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TOKEN = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
NAMESPACE = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read().strip()

# Common verbs to check
VERBS = ["get", "list", "create", "update", "delete", "patch", "watch"]

def kcurl(path, method="GET", payload=None):
    cmd = [
        "curl", "-s", "--cacert", CACERT,
        "-H", f"Authorization: Bearer {TOKEN}",
        "-H", "Content-Type: application/json",
        "-X", method, f"{APISERVER}{path}"
    ]
    if payload:
        cmd += ["-d", json.dumps(payload)]
    return subprocess.check_output(cmd, text=True)

def get_api_resources():
    resources = []
    # Core API (v1)
    try:
        core = json.loads(kcurl("/api/v1"))
        for r in core.get("resources", []):
            if not r.get("name").endswith("/status"):  # skip noise
                resources.append(("v1", r["name"]))
    except Exception:
        pass

    # Group APIs
    groups = json.loads(kcurl("/apis"))
    for g in groups.get("groups", []):
        for v in g.get("versions", []):
            gv = v["groupVersion"]
            try:
                api = json.loads(kcurl(f"/apis/{gv}"))
                for r in api.get("resources", []):
                    if not r.get("name").endswith("/status"):
                        resources.append((gv, r["name"]))
            except Exception:
                continue
    return resources

def check_access(resource, verb, namespace=None, group=""):
    ns = namespace or NAMESPACE
    payload = {
        "kind": "SelfSubjectAccessReview",
        "apiVersion": "authorization.k8s.io/v1",
        "spec": {
            "resourceAttributes": {
                "namespace": ns,
                "verb": verb,
                "resource": resource.split("/")[0], # base resource
                "subresource": resource.split("/")[1] if "/" in resource else "",
                "group": group
            }
        }
    }
    out = kcurl("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "POST", payload)
    resp = json.loads(out)
    allowed = resp.get("status", {}).get("allowed", False)
    reason = resp.get("status", {}).get("reason", "")
    return allowed, reason

def main():
    print("[*] Discovering API resources ...")
    resources = get_api_resources()
    print(f"[*] Found {len(resources)} resources to test")

    # Try to list namespaces for broader testing
    namespaces = [NAMESPACE]
    try:
        out = json.loads(kcurl("/api/v1/namespaces"))
        namespaces = [ns["metadata"]["name"] for ns in out.get("items", [])]
        print(f"[*] Enumerating across {len(namespaces)} namespaces")
    except Exception:
        print("[*] Falling back to current namespace only")

    results = []
    for gv, res in resources:
        group = gv.split("/")[0] if "/" in gv else ""
        for ns in namespaces:
            for verb in VERBS:
                try:
                    allowed, reason = check_access(res, verb, ns, group)
                    if allowed:
                        critical = ""
                        if res in ["secrets", "pods/exec", "pods/attach", "pods/portforward", "pods/proxy"] or verb in ["create", "update", "delete"]:
                            critical = "!!ESCALATION!!"
                        results.append((ns, verb.upper(), res, allowed, reason, critical))
                        print(f"{ns:<12} {verb.upper():<8} {res:<30} -> {allowed} {reason} {critical}")
                except Exception as e:
                    continue

    # Save JSON
    with open("rbac_enum.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n[*] Results saved to rbac_enum.json")

if __name__ == "__main__":
    main()
