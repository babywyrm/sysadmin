python3 <<'EOF'
import os,sys,json,requests,csv
requests.packages.urllib3.disable_warnings()

APISERVER="https://kubernetes.default.svc"
TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
NAMESPACE_PATH="/var/run/secrets/kubernetes.io/serviceaccount/namespace"
OUT="/tmp/rbac-out"
os.makedirs(OUT,exist_ok=True)

try:TOKEN=open(TOKEN_PATH).read().strip()
except:sys.exit("no token found")
def call(m,p,b=None):
  h={"Authorization":f"Bearer {TOKEN}","Accept":"application/json"}
  r=requests.request(m,f"{APISERVER}{p}",headers=h,json=b,verify=False,timeout=20)
  return r.json() if r.ok else {}
def dump(p,o):os.makedirs(os.path.dirname(p),exist_ok=True);json.dump(o,open(p,"w"),indent=2)

print("[+] fetching clusterroles / bindings")
cr=call("GET","/apis/rbac.authorization.k8s.io/v1/clusterroles");dump(f"{OUT}/clusterroles.json",cr)
crb=call("GET","/apis/rbac.authorization.k8s.io/v1/clusterrolebindings");dump(f"{OUT}/clusterrolebindings.json",crb)

nss=[]
try:
  j=call("GET","/api/v1/namespaces");nss=[i["metadata"]["name"] for i in j.get("items",[])]
except:
  nss=[open(NAMESPACE_PATH).read().strip() if os.path.exists(NAMESPACE_PATH) else "default"]
print(f"[+] namespaces: {nss}")

for ns in nss:
  nd=f"{OUT}/{ns}";os.makedirs(nd,exist_ok=True)
  for r in ["roles","rolebindings"]:
    dump(f"{nd}/{r}.json",call("GET",f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/{r}"))
  body={"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":ns}}
  dump(f"{nd}/selfsubjectrules.json",call("POST","/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",body))

print("[+] analyzing ...")
F=open(f"{OUT}/findings.csv","w",newline="");w=csv.writer(F)
w.writerow(["id","principal","subject_kind","namespace","capability","impact"])
fid=1
for i in crb.get("items",[]):
  if i.get("roleRef",{}).get("name")=="cluster-admin":
    for s in i.get("subjects",[]):
      w.writerow([fid,f"{s['kind']}:{s['name']}",s["kind"],s.get("namespace","cluster"),
                  "cluster-admin binding","High"]);fid+=1
for i in cr.get("items",[]):
  for r in i.get("rules",[]):
    if "*" in r.get("verbs",[]) or "*" in r.get("resources",[]):
      w.writerow([fid,f"ClusterRole:{i['metadata']['name']}","ClusterRole","cluster",
                  "wildcard verbs/resources","High"]);fid+=1;break
for ns in nss:
  rb=json.load(open(f"{OUT}/{ns}/rolebindings.json")).get("items",[])
  for i in rb:
    for s in i.get("subjects",[]):
      if s.get("kind")=="ServiceAccount":
        w.writerow([fid,f"ServiceAccount:{s['name']}@{ns}","ServiceAccount",ns,
                    f"rolebinding:{i['metadata']['name']}","Medium"]);fid+=1
  ssr=json.load(open(f"{OUT}/{ns}/selfsubjectrules.json")).get("rules",[])
  for r in ssr:
    if {"create","patch","update"}&set(r.get("verbs",[])) and \
       {"rolebindings","clusterrolebindings","secrets"}&set(r.get("resources",[])):
      w.writerow([fid,"current-token","Token",ns,
                  "sensitive verbs on sensitive resources","High"]);fid+=1
F.close()
print(open(f"{OUT}/findings.csv").read())
print(f"[+] results saved under {OUT}")
EOF

