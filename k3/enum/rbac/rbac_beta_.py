#!/usr/bin/env python3
"""
rbac_audit.py — Secure, typed RBAC enumerator and analyzer (Python 3.9+) ..(testing)..

Performs safe, read-only enumeration of Kubernetes RBAC objects and heuristic analysis.

Features:
  • Fetch clusterroles & clusterrolebindings
  • Enumerate namespaces (roles, rolebindings)
  • Run SelfSubjectRulesReview (effective token scope)
  • Generate JSON artifacts + findings.csv

Security:
  • Never writes tokens to disk.
  • No network calls beyond Kubernetes API.
  • Handles all 4xx/5xx responses gracefully.
"""

from __future__ import annotations
import argparse, csv, json, os, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Optional

# -------------------------- HTTP layer --------------------------
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("requests library is required (pip install requests)")

@dataclass
class KubeClient:
    apiserver: str
    token: str
    verify_ssl: bool = False
    timeout: int = 20

    def __post_init__(self):
        self.apiserver = self.apiserver.rstrip("/")
        self.session = requests.Session()
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    def get(self, path: str) -> tuple[int, dict[str, Any] | None]:
        url = f"{self.apiserver}{path}"
        try:
            r = self.session.get(url, headers=self.headers, verify=self.verify_ssl, timeout=self.timeout)
            return r.status_code, (r.json() if r.ok else None)
        except requests.RequestException:
            return 0, None

    def post(self, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
        url = f"{self.apiserver}{path}"
        try:
            r = self.session.post(url, headers=self.headers, json=body, verify=self.verify_ssl, timeout=self.timeout)
            return r.status_code, (r.json() if r.ok else None)
        except requests.RequestException:
            return 0, None

# -------------------------- Utilities --------------------------

def log(msg: str) -> None:
    print(f"[+] {msg}", flush=True)

def warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)

def read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None

def safe_write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

# -------------------------- Analyzer --------------------------

@dataclass
class Analyzer:
    outdir: str
    findings: list[dict[str, Any]] = None
    _id_lock: threading.Lock = threading.Lock()
    _id: int = 1

    def __post_init__(self):
        self.findings = []

    def _add(self, **kw) -> None:
        with self._id_lock:
            kw["id"] = self._id
            self._id += 1
        self.findings.append(kw)

    def analyze(self) -> None:
        crb = self._load("clusterrolebindings.json")
        cr = self._load("clusterroles.json")
        if crb: self._analyze_crb(crb)
        if cr: self._analyze_cr(cr)

        ns_path = os.path.join(self.outdir, "namespaces")
        for ns in os.listdir(ns_path):
            ns_dir = os.path.join(ns_path, ns)
            rb = self._load(os.path.join(ns_dir, "rolebindings.json"))
            ssr = self._load(os.path.join(ns_dir, "selfsubjectrules.json"))
            if rb: self._analyze_rb(ns, rb)
            if ssr: self._analyze_ssr(ns, ssr)

    def export_csv(self) -> str:
        path = os.path.join(self.outdir, "findings.csv")
        fields = ["id","principal","subject_kind","namespace","capability","impact","remediation"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader(); w.writerows(self.findings)
        return path

    # ---- Rules ----
    def _analyze_crb(self, data: dict[str, Any]) -> None:
        for i in data.get("items", []):
            if i.get("roleRef", {}).get("name") == "cluster-admin":
                for s in i.get("subjects", []):
                    self._add(
                        principal=f"{s.get('kind')}:{s.get('name')}",
                        subject_kind=s.get("kind","?"),
                        namespace=s.get("namespace","cluster"),
                        capability="cluster-admin binding",
                        impact="High",
                        remediation="Remove cluster-admin binding; apply least privilege."
                    )

    def _analyze_cr(self, data: dict[str, Any]) -> None:
        for i in data.get("items", []):
            name=i.get("metadata",{}).get("name","?")
            for r in i.get("rules",[]):
                if "*" in r.get("verbs",[]) or "*" in r.get("resources",[]):
                    self._add(
                        principal=f"ClusterRole:{name}",
                        subject_kind="ClusterRole",
                        namespace="cluster",
                        capability="wildcard verbs/resources",
                        impact="High",
                        remediation="Replace wildcards with explicit verbs/resources."
                    ); break

    def _analyze_rb(self, ns: str, data: dict[str, Any]) -> None:
        for i in data.get("items", []):
            for s in i.get("subjects", []):
                if s.get("kind") == "ServiceAccount":
                    self._add(
                        principal=f"ServiceAccount:{s.get('name')}@{ns}",
                        subject_kind="ServiceAccount",
                        namespace=ns,
                        capability=f"rolebinding:{i.get('metadata',{}).get('name','?')}",
                        impact="Medium",
                        remediation="Limit SA to namespace; apply least privilege."
                    )

    def _analyze_ssr(self, ns: str, data: dict[str, Any]) -> None:
        for r in data.get("rules", []):
            verbs=set(r.get("verbs",[])); res=set(r.get("resources",[]))
            if verbs & {"create","patch","update"} and res & {"rolebindings","clusterrolebindings","secrets"}:
                self._add(
                    principal="current-token",
                    subject_kind="Token",
                    namespace=ns,
                    capability="sensitive verbs on sensitive resources",
                    impact="High",
                    remediation="Restrict token verbs or rolebinding privileges."
                )

    def _load(self, path: str) -> dict[str, Any] | None:
        try:
            with open(os.path.join(self.outdir, path),"r",encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

# -------------------------- Main --------------------------

def main() -> None:
    p = argparse.ArgumentParser(description="Secure RBAC auditor (Python)")
    p.add_argument("--token-file", default=None)
    p.add_argument("--token", default=None)
    p.add_argument("--apiserver", default="https://kubernetes.default.svc")
    p.add_argument("--outdir", default="./rbac-out")
    p.add_argument("--all-namespaces", action="store_true")
    p.add_argument("--namespaces", default=None)
    p.add_argument("--threads", type=int, default=6)
    p.add_argument("--no-analyze", action="store_true")
    a = p.parse_args()

    token = a.token or read_file(a.token_file or "/var/run/secrets/kubernetes.io/serviceaccount/token")
    if not token: sys.exit("No token provided or readable.")
    outdir=os.path.abspath(a.outdir); os.makedirs(outdir,exist_ok=True)

    c = KubeClient(a.apiserver, token)
    log("Fetching clusterroles / clusterrolebindings")
    for name in ["clusterroles","clusterrolebindings"]:
        code,obj=c.get(f"/apis/rbac.authorization.k8s.io/v1/{name}")
        if code>=200 and obj: safe_write_json(f"{outdir}/{name}.json",obj)
        else: warn(f"failed to fetch {name} ({code})")

    # Namespace discovery
    if a.all_namespaces:
        code,nsobj=c.get("/api/v1/namespaces")
        nss=[i["metadata"]["name"] for i in nsobj.get("items",[])] if code>=200 and nsobj else ["default"]
    elif a.namespaces:
        nss=[n.strip() for n in a.namespaces.split(",") if n.strip()]
    else:
        nsf=read_file("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        nss=[nsf or "default"]
    log(f"Namespaces: {nss}")

    nsdir=f"{outdir}/namespaces"; os.makedirs(nsdir,exist_ok=True)

    def fetch_ns(ns:str)->None:
        npath=f"{nsdir}/{ns}"; os.makedirs(npath,exist_ok=True)
        for rsrc in ["roles","rolebindings"]:
            code,obj=c.get(f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/{rsrc}")
            if code>=200 and obj: safe_write_json(f"{npath}/{rsrc}.json",obj)
        body={"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":ns}}
        code,obj=c.post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",body)
        if code>=200 and obj: safe_write_json(f"{npath}/selfsubjectrules.json",obj)

    with ThreadPoolExecutor(max_workers=max(2,min(a.threads,16))) as ex:
        list(as_completed([ex.submit(fetch_ns,ns) for ns in nss]))

    if not a.no_analyze:
        log("Analyzing RBAC outputs")
        analyzer=Analyzer(outdir); analyzer.analyze()
        csv_path=analyzer.export_csv()
        log(f"Findings written → {csv_path} ({len(analyzer.findings)} entries)")
    else:
        log("Analysis skipped (--no-analyze)")

    log(f"Artifacts under {outdir}")

if __name__=="__main__":
    main()
