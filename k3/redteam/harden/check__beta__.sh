#!/usr/bin/env bash
# Kubernetes Hardening Audit Script
# Mi Familia Defensive Stack – v1.0
# Non-destructive, safe read-only compliance assessment.

set -euo pipefail

OUT="k8s_hardening_report_$(hostname)_$(date +%Y%m%dT%H%M%S).txt"

log() {
    echo -e "[*] $1" | tee -a "$OUT"
}

section() {
    echo -e "\n\n===== $1 =====" | tee -a "$OUT"
}

header() {
    echo "KUBERNETES HARDENING AUDIT REPORT" > "$OUT"
    echo "Host: $(hostname)" >> "$OUT"
    echo "Date: $(date)" >> "$OUT"
    echo "======================================" >> "$OUT"
}

header

###############################################
# SECTION 1 — NODE HARDENING CHECKS
###############################################
section "1. Node Hardening"

log "Checking OS details…"
uname -a | tee -a "$OUT"

log "Checking SELinux status…"
sestatus 2>/dev/null | tee -a "$OUT" || echo "SELinux not installed" | tee -a "$OUT"

log "Checking AppArmor profiles…"
aa-status 2>/dev/null | tee -a "$OUT" || echo "AppArmor not installed" | tee -a "$OUT"

log "Checking if root filesystem is read-only…"
mount | grep ' / ' | tee -a "$OUT"

log "Checking running container runtime…"
ps aux | grep -E 'containerd|dockerd|crio' | grep -v grep | tee -a "$OUT"

log "Checking for containerd socket permissions…"
/bin/ls -l /run/containerd/containerd.sock 2>/dev/null | tee -a "$OUT" || echo "containerd sock not found" | tee -a "$OUT"

log "Checking for kernel hardening (sysctl)…"
sysctl kernel.kptr_restrict net.ipv4.ip_forward kernel.yama.ptrace_scope | tee -a "$OUT"


###############################################
# SECTION 2 — KUBELET SECURITY CHECKS
###############################################
section "2. Kubelet Security"

KUBELET_CONF="/var/lib/kubelet/config.yaml"
log "Looking for kubelet config at $KUBELET_CONF…"

if [[ -f "$KUBELET_CONF" ]]; then
    grep -E "anonymousAuth|readOnlyPort|tlsCertFile|tlsPrivateKeyFile" "$KUBELET_CONF" | tee -a "$OUT"
else
    echo "kubelet config not found" | tee -a "$OUT"
fi

log "Checking kubelet anonymous auth…"
grep -R "anonymous-auth" /etc/systemd/system/kubelet.service* /etc/systemd/* 2>/dev/null | tee -a "$OUT"

log "Checking kubelet read-only port exposure…"
netstat -tulnp | grep 10255 | tee -a "$OUT" || echo "Read-only port not exposed (good)" | tee -a "$OUT"


###############################################
# SECTION 3 — POD SECURITY CHECKS
###############################################
section "3. Pod & Runtime Security"

log "Checking for privileged pods…"
kubectl get pods -A -o json 2>/dev/null | jq '.items[] | select(.spec.containers[]?.securityContext.privileged==true) | .metadata.name' | tee -a "$OUT" \
    || echo "No privileged pods found" | tee -a "$OUT"

log "Checking for hostPath mounts…"
kubectl get pods -A -o json 2>/dev/null | jq '.items[] | select(.spec.volumes[]?.hostPath) | .metadata.name' | tee -a "$OUT" \
    || echo "No hostPath usage found" | tee -a "$OUT"

log "Checking for lack of seccomp…"
kubectl get pods -A -o json 2>/dev/null | jq '.items[] | select(.metadata.annotations."seccomp.security.alpha.kubernetes.io/pod" == null) | .metadata.name' | tee -a "$OUT"


###############################################
# SECTION 4 — NETWORK SECURITY CHECKS
###############################################
section "4. Network Zero Trust"

log "Checking for NetworkPolicy existence…"
kubectl get networkpolicies -A 2>/dev/null | tee -a "$OUT"

log "Checking for default-deny policies per namespace…"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    DENY=$(kubectl get netpol -n "$ns" -o json 2>/dev/null | jq '.items[] | select(.spec.podSelector=={} and .spec.policyTypes[]=="Ingress")')
    if [[ -z "$DENY" ]]; then
        echo "Namespace $ns has NO default-deny (high risk)" | tee -a "$OUT"
    else
        echo "Namespace $ns has a default-deny policy" | tee -a "$OUT"
    fi
done


###############################################
# SECTION 5 — CONTROL PLANE SECURITY
###############################################
section "5. Control Plane Security"

log "Testing API server endpoint exposure…"
curl -sk https://kubernetes.default.svc/healthz | tee -a "$OUT"

log "Checking for anonymous API access…"
curl -sk https://kubernetes.default.svc/api  | head -n 5 | tee -a "$OUT"

log "Checking if audit logging is enabled..."
ps aux | grep kube-apiserver | grep audit | tee -a "$OUT" || echo "Audit logging not found!" | tee -a "$OUT"


###############################################
# SECTION 6 — RBAC / IDENTITY SECURITY
###############################################
section "6. RBAC Hardening"

log "Checking for cluster-admin bindings…"
kubectl get clusterrolebindings -o json 2>/dev/null | jq '.items[] | select(.roleRef.name=="cluster-admin")' | tee -a "$OUT"

log "Checking for wildcard RBAC permissions…"
kubectl get clusterroles -o json 2>/dev/null | jq '.items[] | select(.rules[]?.resources[]?=="*" or .rules[]?.verbs[]?=="*")' | tee -a "$OUT"


###############################################
# SECTION 7 — CLOUD METADATA PROTECTION
###############################################
section "7. Cloud Metadata Hardening"

log "Checking access to cloud metadata service…"
curl -s --connect-timeout 1 http://169.254.169.254/latest/meta-data/ 2>&1 | tee -a "$OUT" \
    && echo "WARNING: Metadata service accessible! High-risk!" | tee -a "$OUT" \
    || echo "Metadata service not accessible (good)" | tee -a "$OUT"


###############################################
# SECTION 8 — SUPPLY CHAIN SECURITY
###############################################
section "8. Supply Chain Hardening"

log "Checking image registries used in cluster…"
kubectl get pods -A -o json 2>/dev/null | jq -r '.items[].spec.containers[].image' | sort -u | tee -a "$OUT"

log "Checking for unsigned / untrusted registries (manual review recommended)…"


###############################################
# SECTION 9 — POD SECRETS & SENSITIVE CONFIG
###############################################
section "9. Secret & ConfigMap Hardening"

log "Checking Opaque secrets for plaintext risks…"
kubectl get secrets -A -o json 2>/dev/null | jq '.items[] | select(.type=="Opaque") | .metadata.name' | tee -a "$OUT"

log "Checking ConfigMaps for sensitive keywords…"
kubectl get configmaps -A -o json 2>/dev/null | jq '.items[] | select(.data|to_entries[]?.value|test("password|secret|aws|key|token";"i"))' | tee -a "$OUT"


###############################################
# DONE
###############################################
section "Audit Complete"
log "Full report written to: $OUT"
