#!/usr/bin/env bash
set -euo pipefail

##
## K3s diagnostic collector
## inspired by https://gist.github.com/superseb/aaee8d3c6e5b95ee3a09e40966f55ecb
##

TMPDIR=$(mktemp -d "${MKTEMP_BASEDIR:-/tmp}/k3s-diag.XXXXXX")
SYSTEMNAMESPACES=("kube-system" "kube-public" "kube-node-lease")

echo "[*] Collecting K3s diagnostics into: $TMPDIR"

if command -v k3s >/dev/null 2>&1; then
    # Prepare directories
    mkdir -p "$TMPDIR"/k3s/{crictl,logs,podlogs,kubectl}

    # Basic checks
    k3s check-config >"$TMPDIR/k3s/check-config" 2>&1 || true

    # Cluster info
    k3s kubectl get nodes -o json >"$TMPDIR/k3s/kubectl/nodes" 2>&1 || true
    k3s kubectl version -o yaml >"$TMPDIR/k3s/kubectl/version" 2>&1 || true
    k3s kubectl get pods -A -o wide >"$TMPDIR/k3s/kubectl/pods" 2>&1 || true

    # Journal logs
    if grep -q "k3s.service" "$TMPDIR/systeminfo/systemd-units" 2>/dev/null; then
        journalctl -u k3s >"$TMPDIR/k3s/logs/journalctl-k3s" 2>&1 || true
    fi

    # Pod logs for system namespaces
    for ns in "${SYSTEMNAMESPACES[@]}"; do
        for pod in $(k3s kubectl -n "$ns" get pods -o name --no-headers 2>/dev/null | cut -d/ -f2); do
            k3s kubectl -n "$ns" logs "$pod" >"$TMPDIR/k3s/podlogs/${ns}-${pod}.log" 2>&1 || true
        done
    done

    # Container runtime info
    for cmd in ps -a pods info stats version images imagefsinfo; do
        k3s crictl $cmd >"$TMPDIR/k3s/crictl/$cmd" 2>&1 || true
    done

    echo "[*] Collection complete. Data saved under $TMPDIR"
else
    echo "[!] k3s not found on PATH"
    exit 1
fi
