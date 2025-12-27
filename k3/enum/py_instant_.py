python3 - <<'EOF'
#!/usr/bin/env python3
import os, subprocess, json, sys; from pathlib import Path
P=Path("/var/run/secrets/kubernetes.io/serviceaccount"); A="https://kubernetes.default.svc"
C,T,N=P/"ca.crt",P/"token",P/"namespace"
class Col: G,R,Y,B,M,C,BOLD,NC="\033[92m","\033[91m","\033[93m","\033[94m","\033[95m","\033[96m","\033[1m","\033[0m"
if not all(f.exists() for f in [C,T,N]): print(f"{Col.R}❌ No K8s SA{Col.NC}"); sys.exit(1)
TOK=T.read_text().strip(); MNS=N.read_text().strip()
def curl(e, m="GET", d=None):
    c=["curl","-s","--cacert",str(C),"-H",f"Authorization: Bearer {TOK}","-X",m]
    if d: c.extend(["-H","Content-Type: application/json","-d",json.dumps(d)])
    c.append(f"{A}{e}"); r=subprocess.run(c,capture_output=True,text=True,timeout=5)
    return json.loads(r.stdout) if r.stdout else None
def can(r, v, n=None, g="", s=""):
    p={"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":v,"resource":r,"group":g,"subresource":s}}}
    if n: p["spec"]["resourceAttributes"]["namespace"]=n
    res=curl("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews","POST",p)
    return res and res.get("status",{}).get("allowed",False)
def get_ns():
    r=curl("/api/v1/namespaces"); nss=[MNS]
    if r and "items" in r: return [i["metadata"]["name"] for i in r["items"]]
    for g in ["default","kube-system","kube-public","internal","dev-internal","staging","prod","orthanc","wordpress"]:
        if g!=MNS and curl(f"/api/v1/namespaces/{g}/pods"): nss.append(g)
    return list(set(nss))
def probe():
    print(f"{Col.BOLD}{Col.C}--- K8S OMNI-HUNTER ---{Col.NC}"); nss=get_ns()
    if can("*","*"): print(f"{Col.R}{Col.BOLD}🔥 CLUSTER-ADMIN DETECTED 🔥{Col.NC}")
    schema=[("pods","","v1",0),("secrets","","v1",0),("configmaps","","v1",0),("services","","v1",0),("serviceaccounts","","v1",0),("deployments","apps","v1",0),("daemonsets","apps","v1",0),("roles","rbac.authorization.k8s.io","v1",0),("rolebindings","rbac.authorization.k8s.io","v1",0),("nodes","","v1",1),("namespaces","","v1",1),("clusterroles","rbac.authorization.k8s.io","v1",1),("clusterrolebindings","rbac.authorization.k8s.io","v1",1)]
    for ns in nss:
        print(f"\n{Col.BOLD}{Col.M}📁 NAMESPACE: {ns}{Col.NC}")
        for res, grp, ver, clus in schema:
            if clus and ns!=nss[0]: continue
            c_ns=None if clus else ns; alwd=[v for v in ["list","get","create","update","delete"] if can(res,v,c_ns,grp)]
            meta=""
            if "list" in alwd:
                p=f"/api/v1/{res}" if not grp else f"/apis/{grp}/{ver}/{res}"
                if not clus: p=f"/api/v1/namespaces/{ns}/{res}" if not grp else f"/apis/{grp}/{ver}/namespaces/{ns}/{res}"
                d=curl(p)
                if d and "items" in d:
                    nms=[i["metadata"]["name"] for i in d["items"]]
                    if nms: 
                        extra=f" | img: {d['items'][0]['spec']['containers'][0]['image']}" if res=="pods" else ""
                        meta=f" {Col.Y}({len(nms)}: {', '.join(nms[:2])}...{extra}){Col.NC}"
            l=f"[C] {res}" if clus else res
            if alwd:
                cl=Col.R if res in ["secrets","rolebindings","clusterrolebindings"] else Col.G
                print(f"  {l:<20} -> {cl}{','.join(alwd)}{Col.NC}{meta}")
            else: print(f"  {l:<20} -> {Col.R}DENIED{Col.NC}")
    print(f"\n{Col.BOLD}{Col.C}--- ESCALATION ---{Col.NC}")
    for s in [("exec","create"),("log","get"),("portforward","create"),("attach","create")]:
        st=f"{Col.G}ALLOW" if can("pods",s[1],MNS,"",s[0]) else f"{Col.R}DENY"
        print(f"  pods/{s[0]:<10} -> {st}{Col.NC}")
if __name__ == "__main__": probe()
EOF
