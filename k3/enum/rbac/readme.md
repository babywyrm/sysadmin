# k8s-level2/rbac — Intermediate RBAC README

* `README.md` — this document (same content) explaining concepts, checks, detection, remediation, and guidance for Level-2 RBAC assessment.
* `rbac-audit.sh` — a practical, robust shell script that dumps RBAC-related resources, performs a conservative local analysis, and emits a `findings.csv` along with JSON artifacts. The script is intentionally **read-only**.

> **Important:** Run only in environments you own or where you have explicit written authorization. The script performs only GET/POST calls that are non-destructive and does not create, modify or delete cluster resources.

---

## Goals

1. Produce a reproducible JSON snapshot of cluster RBAC state:

   * `clusterroles.json`
   * `clusterrolebindings.json`
   * `roles-<ns>.json` (per namespace)
   * `rolebindings-<ns>.json` (per namespace)
   * `selfsubjectrules-<ns>.json` (per-namespace for the running principal)
2. Produce a compact `findings.csv` with prioritized issues.
3. Provide deterministic outputs for defenders to triage and remediate.

---

## Quick design summary of `rbac-audit.sh`

* Inputs:

  * `--token-file` (default `/var/run/secrets/kubernetes.io/serviceaccount/token`) OR `--token` (inline)
  * `--apiserver` (default `https://kubernetes.default.svc`)
  * `--outdir` (default `./k8s-level2-rbac-output`)
  * `--namespaces` (comma-separated list or `--all-namespaces`)
  * `--no-analyze` (dump-only)
* Dependencies: `curl`, `jq`, `base64`, `sed`, `grep`, `awk` (standard Linux/macOS tools).
* Behavior: Dumps RBAC objects then performs conservative analysis for:

  * `ClusterRoleBindings` to `cluster-admin`.
  * `ClusterRoles` or `Roles` that use wildcard verbs or resources (`"*"`).
  * `RoleBindings` / `ClusterRoleBindings` whose subjects include `ServiceAccount` subjects.
  * Repeated bindings of the same subject across multiple namespaces.
  * SelfSubjectRulesReview output per-namespace for the running principal.

---

## Safety & Operational Notes

* The script never writes to the cluster or attempts to `exec` into pods.
* It avoids creating ServiceAccounts / RoleBindings / Secrets.
* For offline analysis, you can run the script in a bastion or jump host with the appropriate token exported.
* Avoid committing any tokens or JSON artifacts that contain secrets into source control.

---

## Typical invocation examples

```bash
# Run inside cluster (service account token auto-detected)
bash rbac-audit.sh --outdir ./audit.out

# Run from a host with a token file
bash rbac-audit.sh --token-file ./my-token --apiserver https://api.mycluster.example.com --outdir ./audit.out

# Dump-only (no analysis)
bash rbac-audit.sh --no-analyze --outdir ./audit.out
```

After a successful run the `outdir` will contain JSON dumps and `findings.csv`.

---

## Findings.csv columns (explained)

* `id` — unique id for the finding
* `principal` — the subject (e.g., `system:serviceaccount:namespace:name` or `User:foo`)
* `subject_kind` — ServiceAccount / User / Group
* `namespace` — namespace where the binding exists (or `cluster` for cluster-scope)
* `capability` — short human-readable capability or rule matched (e.g., `cluster-admin`, `wildcard-verbs`, `can-bind-roles`)
* `evidence_file` — path to the JSON artifact in `outdir` that supports the finding
* `impact` — High / Medium / Low
* `remediation` — short remediation guidance

---

## What `rbac-audit.sh` does (detailed)

1. Validates inputs and dependencies.
2. Reads token from `--token-file` or environment.
3. Fetches cluster-wide objects: `ClusterRoles`, `ClusterRoleBindings`, `API groups`.
4. Optionally enumerates namespaces (all or a provided list) and fetches `Roles` and `RoleBindings` per-namespace.
5. Runs a `SelfSubjectRulesReview` per-namespace for the active token (if readable) to understand the effective permissions of the running principal.
6. Runs analysis heuristics locally and writes `findings.csv`.
7. Prints a short summary and where the outputs are saved.

---

## Heuristics used by the analyzer (conservative, explainable)

* **Cluster-admin bindings**: Any `ClusterRoleBinding` whose `roleRef.name` equals `cluster-admin` is High impact. Evidence: `clusterrolebindings.json`.
* **Wildcard rules**: Any `ClusterRole` or `Role` with a `.rules[]` entry that contains `verbs: ["*"]` or `resources: ["*"]` is High impact.
* **Pods/exec / Secrets access**: Roles that include `pods/exec` or `secrets` `get/list` in sensitive namespaces are Medium/High depending on namespace.
* **Role-binding proliferation**: Subjects (SAs/users) that appear bound across many namespaces get a proportional score (3+ namespaces → Medium).

These heuristics are intended to be conservative; they prefer false positives over false negatives to ensure defenders get a clear triage starting point.

---

## Detection & Remediation Guidance (copyable)

* **Detection**: Enable kube-apiserver audit with a policy that captures `create`, `patch`, `exec`, `create rolebinding`, `create clusterrolebinding`, `token` operations. Forward audit logs to a central SIEM.
* **Remediation**:

  * Remove `cluster-admin` bindings for non-admin principals.
  * Replace `verbs: ["*"]` with explicit verbs.
  * Restrict RoleBinding creation permissions to a small, audited admin cohort.
  * Rotate and shorten ServiceAccount token TTLs; prefer projected tokens with short TTLs.

---

## Next steps / integration

* Add a small `rbac-analyze.py` (optional) that loads the JSON dumps and produces richer graphs (Graphviz) of principals → namespaces → capabilities.
* Add automated CI that runs `rbac-audit.sh` nightly against a read-only audit account producing alerts for new High-impact findings.

---

## rbac-audit.sh  (beta)


```bash
#!/usr/bin/env bash
# rbac-audit.sh — read-only RBAC dumper and conservative analyzer
# Usage: bash rbac-audit.sh [--token-file <file>] [--token <token>] [--apiserver <url>] [--outdir <path>] [--all-namespaces] [--namespaces ns1,ns2] [--no-analyze]

set -euo pipefail
IFS=$'\n\t'

PROGNAME=$(basename "$0")

### Defaults
APISERVER_DEFAULT="https://kubernetes.default.svc"
TOKEN_FILE_DEFAULT="/var/run/secrets/kubernetes.io/serviceaccount/token"
OUTDIR_DEFAULT="./k8s-level2-rbac-output"

APISERVER="$APISERVER_DEFAULT"
TOKEN_FILE=""
TOKEN=""
OUTDIR="$OUTDIR_DEFAULT"
NAMESPACES=""
ALL_NAMESPACES=false
ANALYZE=true

usage() {
  cat <<EOF
Usage: $PROGNAME [--token-file <file>] [--token <token>] [--apiserver <url>] [--outdir <path>] [--all-namespaces] [--namespaces ns1,ns2] [--no-analyze]

Options:
  --token-file FILE    Read token from FILE (default: $TOKEN_FILE_DEFAULT when running in-cluster)
  --token TOKEN        Provide token inline (dangerous to keep in history)
  --apiserver URL      Kubernetes API server URL (default: $APISERVER_DEFAULT)
  --outdir DIR         Output directory (default: $OUTDIR_DEFAULT)
  --all-namespaces     Enumerate all namespaces
  --namespaces N1,N2   Comma-separated list of namespaces to enumerate
  --no-analyze         Dump JSON only, skip heuristics analysis
  -h, --help           Show this help
EOF
}

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token-file)
      TOKEN_FILE="$2"; shift 2;;
    --token)
      TOKEN="$2"; shift 2;;
    --apiserver)
      APISERVER="$2"; shift 2;;
    --outdir)
      OUTDIR="$2"; shift 2;;
    --all-namespaces)
      ALL_NAMESPACES=true; shift 1;;
    --namespaces)
      NAMESPACES="$2"; shift 2;;
    --no-analyze)
      ANALYZE=false; shift 1;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

mkdir -p "$OUTDIR"

# load token
if [[ -n "$TOKEN" ]]; then
  : # token already set
elif [[ -n "$TOKEN_FILE" ]]; then
  if [[ -r "$TOKEN_FILE" ]]; then
    TOKEN=$(sed -n '1p' "$TOKEN_FILE")
  else
    # try default in-cluster path
    if [[ -r "$TOKEN_FILE_DEFAULT" ]]; then
      TOKEN=$(sed -n '1p' "$TOKEN_FILE_DEFAULT")
    fi
  fi
fi

if [[ -z "${TOKEN:-}" ]]; then
  echo "ERROR: no token provided or readable at $TOKEN_FILE_DEFAULT. Provide --token-file or --token." >&2
  exit 3
fi

CURL_OPTS=( -sS --insecure -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" )

info() { printf "[+] %s\n" "$*"; }
warn() { printf "[!] %s\n" "$*"; }
err() { printf "[ERR] %s\n" "$*"; }

# helper to fetch and save a URL
fetch() {
  local url="$1" path="$2"
  info "Fetching: $url -> $path"
  if ! curl "${CURL_OPTS[@]}" -o "$path" "$url"; then
    warn "Failed to fetch $url"
    return 1
  fi
  return 0
}

# 1) cluster-wide dumps
fetch "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles" "$OUTDIR/clusterroles.json" || true
fetch "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" "$OUTDIR/clusterrolebindings.json" || true

# discover namespaces if requested
if [[ "$ALL_NAMESPACES" == true ]]; then
  fetch "$APISERVER/api/v1/namespaces" "$OUTDIR/namespaces.json" || true
  NAMESPACES=$(jq -r '.items[].metadata.name' "$OUTDIR/namespaces.json" | paste -sd , -)
fi

# if explicit namespaces not provided, default to current namespace if available; else just 'default'
if [[ -z "$NAMESPACES" ]]; then
  if [[ -r "/var/run/secrets/kubernetes.io/serviceaccount/namespace" ]]; then
    NAMESPACES=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
  else
    NAMESPACES="default"
  fi
fi

# split namespaces into array
IFS=',' read -r -a NS_ARR <<< "$NAMESPACES"

for ns in "${NS_ARR[@]}"; do
  ns_trimmed=$(echo "$ns" | xargs)
  if [[ -z "$ns_trimmed" ]]; then continue; fi
  mkdir -p "$OUTDIR/namespaces/$ns_trimmed"
  fetch "
```
