#!/usr/bin/env python3
"""
rbac_audit.py — read-only RBAC dumper and conservative analyzer (Python 3)

Intended to be run inside-cluster (recommended) or from a bastion with a token.
The script will:

  - Fetch clusterroles & clusterrolebindings
  - Optionally enumerate namespaces and fetch roles/rolebindings per-namespace
  - Run SelfSubjectRulesReview per-namespace (to see effective permissions of current token)
  - Save JSON artifacts under --outdir
  - Run conservative heuristics and emit findings.csv

Security notes:
  - The script never writes the token to disk.
  - If you supply a token via --token (not recommended), it will be kept in memory only.
  - Do not commit the output directory into VCS if it contains sensitive data.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

# Prefer requests but provide a fallback to urllib if requests is not installed.
try:
    import requests

    requests.packages.urllib3.disable_warnings()  # silence insecure warnings when verify=False
    http_request = None
    def http_get(url, headers, timeout=30, verify=False, stream=False):
        return requests.get(url, headers=headers, timeout=timeout, verify=verify, stream=stream)
    def http_post(url, headers, json_body, timeout=30, verify=False):
        return requests.post(url, headers=headers, json=json_body, timeout=timeout, verify=verify)
except Exception:
    requests = None
    import urllib.request as _urllib
    import urllib.error as _urlerr

    def http_get(url, headers, timeout=30, verify=False, stream=False):
        req = _urllib.Request(url, headers=headers, method="GET")
        with _urllib.urlopen(req, timeout=timeout) as resp:
            return type("R", (), {"status_code": resp.getcode(), "text": resp.read().decode("utf-8")})

    def http_post(url, headers, json_body, timeout=30, verify=False):
        data = json.dumps(json_body).encode("utf-8")
        hdrs = dict(headers)
        hdrs["Content-Type"] = "application/json"
        req = _urllib.Request(url, data=data, headers=hdrs, method="POST")
        try:
            with _urllib.urlopen(req, timeout=timeout) as resp:
                return type("R", (), {"status_code": resp.getcode(), "text": resp.read().decode("utf-8")})
        except _urlerr.HTTPError as e:
            return type("R", (), {"status_code": e.code, "text": e.read().decode("utf-8")})


# ---- Utility functions ----

def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_json_file(path: str, obj) -> None:
    # Write atomically
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    os.replace(tmp, path)


def read_incluster_namespace() -> Optional[str]:
    ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    try:
        with open(ns_path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return None


def read_token_from_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return None


def pretty(s: str) -> str:
    # short helper to trim long jsons in logs
    return s if len(s) < 1024 else s[:1024] + " ... (truncated)"


# ---- Core client ----

class KubeClient:
    def __init__(self, apiserver: str, token: str, verify_ssl: bool = False, timeout: int = 30):
        self.apiserver = apiserver.rstrip("/")
        self.token = token
        self.verify = verify_ssl
        self.timeout = timeout
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    def get(self, path: str) -> Tuple[int, Optional[dict]]:
        url = f"{self.apiserver}{path}"
        resp = http_get(url, headers=self.headers, timeout=self.timeout, verify=self.verify)
        code = getattr(resp, "status_code", None)
        text = getattr(resp, "text", "")
        if code and code >= 200 and code < 300:
            try:
                return code, json.loads(text)
            except Exception:
                return code, None
        return code or 0, _try_parse_json_safe(text)

    def post(self, path: str, body: dict) -> Tuple[int, Optional[dict]]:
        url = f"{self.apiserver}{path}"
        resp = http_post(url, headers=self.headers, json_body=body, timeout=self.timeout, verify=self.verify)
        code = getattr(resp, "status_code", None)
        text = getattr(resp, "text", "")
        if code and code >= 200 and code < 300:
            try:
                return code, json.loads(text)
            except Exception:
                return code, None
        return code or 0, _try_parse_json_safe(text)


def _try_parse_json_safe(s: str) -> Optional[dict]:
    try:
        return json.loads(s)
    except Exception:
        return None


# ---- Analyzer heuristics ----

class Analyzer:
    """
    Conservative heuristics engine to create findings from dumped JSON artifacts.
    """

    def __init__(self, outdir: str):
        self.outdir = outdir
        self.findings = []  # list of dict
        self._id = 1

    def _append(self, principal, subject_kind, namespace, capability, evidence_file, impact, remediation):
        entry = {
            "id": self._id,
            "principal": principal,
            "subject_kind": subject_kind,
            "namespace": namespace,
            "capability": capability,
            "evidence_file": evidence_file,
            "impact": impact,
            "remediation": remediation,
        }
        self.findings.append(entry)
        self._id += 1

    def analyze_clusterrolebindings(self, path_clusterrolebindings: str):
        obj = _load_json(path_clusterrolebindings)
        if not obj:
            return
        items = obj.get("items", [])
        for item in items:
            roleRef = item.get("roleRef", {}).get("name")
            name = item.get("metadata", {}).get("name")
            if roleRef == "cluster-admin":
                subjects = item.get("subjects") or []
                for subj in subjects:
                    kind = subj.get("kind")
                    s_name = subj.get("name")
                    s_ns = subj.get("namespace") or "cluster"
                    principal = f"{kind}:{s_name}"
                    evidence = path_clusterrolebindings
                    impact = "High"
                    remediation = f"Remove cluster-admin binding '{name}' from {principal}; replace with least-privilege ClusterRole/Role."
                    self._append(principal, kind, s_ns, f"cluster-admin binding ({name})", evidence, impact, remediation)

    def analyze_clusterroles(self, path_clusterroles: str):
        obj = _load_json(path_clusterroles)
        if not obj:
            return
        for cr in obj.get("items", []):
            crname = cr.get("metadata", {}).get("name")
            rules = cr.get("rules", []) or []
            for r in rules:
                verbs = r.get("verbs", []) or []
                resources = r.get("resources", []) or []
                if "*" in verbs or "*" in resources:
                    principal = f"ClusterRole:{crname}"
                    evidence = path_clusterroles
                    impact = "High"
                    remediation = f"Review ClusterRole '{crname}' and replace wildcard verbs/resources with explicit least-privilege rules."
                    self._append(principal, "ClusterRole", "cluster", "wildcard verbs/resources", evidence, impact, remediation)
                    break

    def analyze_rolebindings_per_namespace(self, ns: str, path_rolebindings: str):
        obj = _load_json(path_rolebindings)
        if not obj:
            return
        items = obj.get("items", [])
        for rb in items:
            rbname = rb.get("metadata", {}).get("name")
            subjects = rb.get("subjects") or []
            for subj in subjects:
                kind = subj.get("kind")
                name = subj.get("name")
                if kind == "ServiceAccount":
                    principal = f"ServiceAccount:{name}@{ns}"
                    evidence = path_rolebindings
                    impact = "Medium"
                    remediation = f"Limit ServiceAccount '{name}' to fewer namespaces; create dedicated SA per-app with least privilege."
                    self._append(principal, kind, ns, f"rolebinding:{rbname}", evidence, impact, remediation)

    def analyze_selfsubjectrules(self, ns: str, ssr_path: str):
        obj = _load_json(ssr_path)
        if not obj:
            return
        rules = obj.get("rules") or []
        for r in rules:
            verbs = r.get("verbs", []) or []
            resources = r.get("resources", []) or []
            # If we can create/patch/update rolebindings/clusterrolebindings or secrets -> high
            verbs_set = set(verbs)
            res_set = set(resources)
            if verbs_set & {"create", "patch", "update"} and res_set & {"rolebindings", "clusterrolebindings", "secrets"}:
                principal = "current-token"
                evidence = ssr_path
                impact = "High"
                remediation = (f"Token has permissions to create/modify high-impact objects in namespace {ns}. "
                              "Investigate token scope and remove unnecessary verbs.")
                self._append(principal, "Token", ns, "sensitive verbs on sensitive resources", evidence, impact, remediation)

    def export_findings_csv(self, outpath: str):
        fieldnames = ["id", "principal", "subject_kind", "namespace", "capability", "evidence_file", "impact", "remediation"]
        with open(outpath, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for f in self.findings:
                writer.writerow(f)


# ---- Helpers for loading JSON files produced earlier ----

def _load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


# ---- Main workflow ----

def main():
    parser = argparse.ArgumentParser(description="Read-only RBAC dumper + conservative analyzer (Python3)")
    parser.add_argument("--token-file", help="Token file path (default: in-cluster serviceaccount token)", default=None)
    parser.add_argument("--token", help="Raw token (not recommended)", default=None)
    parser.add_argument("--apiserver", help="API server URL (default: https://kubernetes.default.svc)", default="https://kubernetes.default.svc")
    parser.add_argument("--outdir", help="Output directory", default="./k8s-level2-rbac-output")
    parser.add_argument("--all-namespaces", help="Enumerate all namespaces", action="store_true")
    parser.add_argument("--namespaces", help="Comma-separated namespaces to enumerate (overrides in-cluster default)", default=None)
    parser.add_argument("--no-analyze", help="Dump JSON only (skip heuristics analysis)", action="store_true")
    parser.add_argument("--threads", help="Concurrent namespace threads", type=int, default=6)
    args = parser.parse_args()

    outdir = os.path.abspath(args.outdir)
    safe_mkdir(outdir)

    # token resolution (do not write token to disk)
    token = None
    if args.token:
        token = args.token.strip()
    elif args.token_file:
        token = read_token_from_file(args.token_file)
    else:
        token = read_token_from_file("/var/run/secrets/kubernetes.io/serviceaccount/token")

    if not token:
        print("ERROR: no token supplied or readable. Provide --token-file or run in-cluster.", file=sys.stderr)
        sys.exit(2)

    client = KubeClient(args.apiserver, token, verify_ssl=False, timeout=30)

    # fetch cluster-wide RBAC objects
    print("[+] Fetching cluster-level RBAC objects")
    code, clusterroles = client.get("/apis/rbac.authorization.k8s.io/v1/clusterroles")
    if code >= 200 and clusterroles is not None:
        write_json_file(os.path.join(outdir, "clusterroles.json"), clusterroles)
    else:
        print(f"[!] Failed to fetch clusterroles (HTTP {code})")

    code, clusterrolebindings = client.get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
    if code >= 200 and clusterrolebindings is not None:
        write_json_file(os.path.join(outdir, "clusterrolebindings.json"), clusterrolebindings)
    else:
        print(f"[!] Failed to fetch clusterrolebindings (HTTP {code})")

    # decide namespaces to enumerate
    namespaces_list: List[str] = []
    if args.all_namespaces:
        c, nsobj = client.get("/api/v1/namespaces")
        if c >= 200 and nsobj:
            for it in nsobj.get("items", []):
                name = it.get("metadata", {}).get("name")
                if name:
                    namespaces_list.append(name)
        else:
            print(f"[!] Failed to fetch namespaces list (HTTP {c}); defaulting to current namespace")
    if not namespaces_list:
        if args.namespaces:
            namespaces_list = [n.strip() for n in args.namespaces.split(",") if n.strip()]
        else:
            in_ns = read_incluster_namespace()
            namespaces_list = [in_ns] if in_ns else ["default"]

    print(f"[+] Namespaces to enumerate: {namespaces_list}")

    # per-namespace fetch: roles, rolebindings, selfsubjectrulesreviews
    ns_outdir = os.path.join(outdir, "namespaces")
    safe_mkdir(ns_outdir)

    def fetch_ns(ns: str):
        result = {}
        ns_dir = os.path.join(ns_outdir, ns)
        safe_mkdir(ns_dir)
        pr = client.get(f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles")
        if pr[0] >= 200 and pr[1] is not None:
            write_json_file(os.path.join(ns_dir, "roles.json"), pr[1])
            result["roles"] = os.path.join(ns_dir, "roles.json")
        else:
            result["roles"] = None

        pr = client.get(f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings")
        if pr[0] >= 200 and pr[1] is not None:
            write_json_file(os.path.join(ns_dir, "rolebindings.json"), pr[1])
            result["rolebindings"] = os.path.join(ns_dir, "rolebindings.json")
        else:
            result["rolebindings"] = None

        # SelfSubjectRulesReview: conservative read-only POST to see what this token can do in ns
        ssr_body = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": ns}}
        pr = client.post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", ssr_body)
        if pr[0] >= 200 and pr[1] is not None:
            write_json_file(os.path.join(ns_dir, "selfsubjectrules.json"), pr[1])
            result["selfsubjectrules"] = os.path.join(ns_dir, "selfsubjectrules.json")
        else:
            result["selfsubjectrules"] = None

        return ns, result

    # concurrency
    with ThreadPoolExecutor(max_workers=max(2, min(args.threads, 16))) as ex:
        futures = {ex.submit(fetch_ns, ns): ns for ns in namespaces_list}
        ns_map: Dict[str, Dict[str, Optional[str]]] = {}
        for fut in as_completed(futures):
            ns = futures[fut]
            try:
                nsn, res = fut.result()
                ns_map[nsn] = res
            except Exception as e:
                print(f"[!] Namespace fetch error for {ns}: {e}", file=sys.stderr)

    # save api groups for context (optional)
    c, api_groups = client.get("/apis")
    if c >= 200 and api_groups is not None:
        write_json_file(os.path.join(outdir, "api-groups.json"), api_groups)

    # ANALYSIS
    if not args.no_analyze:
        print("[+] Running conservative heuristics analysis")
        analyzer = Analyzer(outdir)
        analyzer.analyze_clusterrolebindings(os.path.join(outdir, "clusterrolebindings.json"))
        analyzer.analyze_clusterroles(os.path.join(outdir, "clusterroles.json"))
        for ns, paths in ns_map.items():
            rbpath = paths.get("rolebindings")
            if rbpath:
                analyzer.analyze_rolebindings_per_namespace(ns, rbpath)
            ssrpath = paths.get("selfsubjectrules")
            if ssrpath:
                analyzer.analyze_selfsubjectrules(ns, ssrpath)

        findings_csv = os.path.join(outdir, "findings.csv")
        analyzer.export_findings_csv(findings_csv)
        print(f"[+] Findings written to: {findings_csv} (count={len(analyzer.findings)})")
    else:
        print("[+] Analysis skipped (--no-analyze)")

    # final summary
    print(f"[+] All artifacts saved under: {outdir}")
    print("[+] Key files: clusterroles.json, clusterrolebindings.json, namespaces/*/rolebindings.json, namespaces/*/selfsubjectrules.json, findings.csv")

if __name__ == "__main__":
    main()
