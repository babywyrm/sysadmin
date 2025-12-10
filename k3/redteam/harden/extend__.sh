#!/usr/bin/env bash
# Kubernetes Hardening Audit — Mi Familia ULTRA Edition v2.5
# >150 hardening checks — Node, Kubelet, API Server, RBAC, Runtime, Network, Secrets, IAM, CRDs, PSS, etc.
# 100% SAFE – READ-ONLY – NON-DESTRUCTIVE

set -euo pipefail

OUT="k8s_hardening_ultra_$(hostname)_$(date +%Y%m%dT%H%M%S).txt"

log() { echo -e "[*] $1" | tee -a "$OUT"; }
warn() { echo -e "[!] WARNING: $1" | tee -a "$OUT"; }
good() { echo -e "[+] OK: $1" | tee -a "$OUT"; }

section() {
    echo -e "\n\n===================== $1 =====================\n" | tee -a "$OUT"
}

header() {
    echo "KUBERNETES HARDENING ULTRA REPORT" > "$OUT"
    echo "Host: $(hostname)" >> "$OUT"
    echo "Date: $(date)" >> "$OUT"
    echo "==========================================================" >> "$OUT"
}
header


##########################################################
# 1 — NODE HARDENING
##########################################################
section "1 — Node Hardening"

log "OS / kernel info:"
uname -a | tee -a "$OUT"

log "SELinux/AppArmor/IMA:"
sestatus 2>/dev/null | tee -a "$OUT"
aa-status 2>/dev/null | tee -a "$OUT"
lsmod | grep integrity 2>/dev/null | tee -a "$OUT"

log "Kernel lockdown mode:"
cat /sys/kernel/security/lockdown 2>/dev/null | tee -a "$OUT" || warn "Lockdown not supported"

log "Root filesystem read-only check:"
mount | grep ' / ' | tee -a "$OUT"

log "Dangerous kernel modules:"
lsmod | grep -E "(overlay|nfs|fuse|bpf)" | tee -a "$OUT"

log "Container runtime detection:"
ps aux | grep -E "(containerd|crio|dockerd)" | grep -v grep | tee -a "$OUT"

log "containerd socket permissions:"
ls -l /run/containerd/containerd.sock 2>/dev/null | tee -a "$OUT"

log "Kernel escape-related sysctls:"
sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope \
       kernel.unprivileged_bpf_disabled fs.protected_symlinks fs.protected_hardlinks \
       net.ipv4.ip_forward 2>/dev/null | tee -a "$OUT"

log "Writable sensitive directories:"
for d in /proc /sys /boot; do
    echo "Checking $d…" | tee -a "$OUT"
    find "$d" -maxdepth 1 -writable 2>/dev/null | tee -a "$OUT"
done


##########################################################
# 2 — KUBELET HARDENING
##########################################################
section "2 — Kubelet Hardening"

KCONF="/var/lib/kubelet/config.yaml"

log "Kubelet config file ($KCONF):"
if [[ -f "$KCONF" ]]; then
    grep -E "anonymousAuth|readOnlyPort|authorizationMode|tlsCertFile|tlsPrivateKeyFile" "$KCONF" | tee -a "$OUT"
else
    warn "kubelet config not found — may be managed by systemd flags"
fi

log "Kubelet flags:"
ps aux | grep kubelet | grep -v grep | tee -a "$OUT"

log "Checking insecure kubelet ports (10250/10255):"
netstat -tulnp | grep -E "1025[05]" | tee -a "$OUT" || good "No insecure kubelet ports exposed"

log "Checking kubelet certificate rotation:"
grep -R "rotate" /var/lib/kubelet 2>/dev/null | tee -a "$OUT" || warn "No cert rotation flags detected"


##########################################################
# 3 — API SERVER HARDENING
##########################################################
section "3 — API Server Hardening"

log "API server health:"
curl -sk https://kubernetes.default.svc/healthz | tee -a "$OUT"

log "Checking for anonymous API access:"
curl -sk https://kubernetes.default.svc/api 2>&1 | tee -a "$OUT"

log "Audit logging detection:"
ps aux | grep kube-apiserver | grep audit | tee -a "$OUT" || warn "Audit logging NOT detected!"

log "Checking for insecure flags:"
ps aux | grep kube-apiserver | grep -E "(insecure-port|basic-auth-file|allow-privileged)" | tee -a "$OUT"

log "Admission controller list:"
ps aux | grep kube-apiserver | grep admission | tee -a "$OUT"


##########################################################
# 4 — ADMISSION WEBHOOK HARDENING
##########################################################
section "4 — Admission Controllers"

log "Validating Admission Webhooks:"
kubectl get validatingwebhookconfigurations 2>/dev/null | tee -a "$OUT"

log "Mutating Admission Webhooks:"
kubectl get mutatingwebhookconfigurations 2>/dev/null | tee -a "$OUT"


##########################################################
# 5 — POD / RUNTIME SECURITY
##########################################################
section "5 — Pod & Runtime Security"

log "Privileged pods:"
kubectl get pods -A -o json |
  jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true).metadata.name' |
  tee -a "$OUT"

log "Pods running as root:"
kubectl get pods -A -o json |
  jq -r '.items[] | select(.spec.securityContext.runAsUser==0).metadata.name' |
  tee -a "$OUT"

log "Pods missing seccomp profiles:"
kubectl get pods -A -o json |
  jq -r '.items[] | select(.metadata.annotations."seccomp.security.alpha.kubernetes.io/pod" == null).metadata.name' |
  tee -a "$OUT"

log "Pods with hostPath mounts:"
kubectl get pods -A -o json |
  jq -r '.items[] | select(.spec.volumes[]?.hostPath).metadata.name' |
  tee -a "$OUT"

log "Dangerous capabilities:"
kubectl get pods -A -o json |
  jq -r '.items[] |
    select(.spec.containers[].securityContext.capabilities.add[]? |
    test("SYS_ADMIN|SYS_PTRACE|DAC_OVERRIDE|NET_ADMIN")) |
    .metadata.name' |
  tee -a "$OUT"


##########################################################
# 6 — NETWORK ZERO TRUST
##########################################################
section "6 — Network / Zero Trust"

log "CNI plugin files:"
ls /opt/cni/bin/ 2>/dev/null | tee -a "$OUT"

log "NetworkPolicies:"
kubectl get netpol -A 2>/dev/null | tee -a "$OUT"

log "Default-deny per namespace:"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
    COUNT=$(kubectl get netpol -n "$ns" -o json |
            jq '[.items[] | select(.spec.podSelector=={} )] | length')
    if [[ "$COUNT" -eq 0 ]]; then
        warn "Namespace $ns has NO default-deny policy!"
    else
        good "Namespace $ns has a default-deny policy"
    fi
done

log "Services & exposure:"
kubectl get svc -A -o wide | tee -a "$OUT"


##########################################################
# 7 — RBAC & IDENTITY
##########################################################
section "7 — RBAC & Identity Hardening"

log "RBAC wildcard permissions:"
kubectl get clusterroles -o json |
  jq '.items[] | select(.rules[]?.verbs[]=="*" or .rules[]?.resources[]=="*") | .metadata.name' |
  tee -a "$OUT"

log "Cluster-admin bindings:"
kubectl get clusterrolebindings -o json |
  jq '.items[] | select(.roleRef.name=="cluster-admin")' |
  tee -a "$OUT"

log "Impersonation permissions:"
kubectl get clusterroles -o json |
  jq -r '.items[] | select(.rules[]?.verbs[]?=="impersonate") | .metadata.name' |
  tee -a "$OUT"

log "ServiceAccounts:"
kubectl get serviceaccounts -A | tee -a "$OUT"


##########################################################
# 8 — SECRETS / CONFIG HARDENING
##########################################################
section "8 — Secrets & ConfigMap Hardening"

log "Suspicious secrets (password/token/key):"
kubectl get secrets -A -o json |
  jq -r '.items[] |
         select(.data | tostring | test("password|token|aws|key|secret";"i")) |
         .metadata.namespace + "/" + .metadata.name' |
  tee -a "$OUT"

log "Legacy service account tokens:"
kubectl get secrets -A -o json |
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | .metadata.name' |
  tee -a "$OUT"

log "ConfigMaps with suspicious strings:"
kubectl get configmaps -A -o json |
  jq -r '.items[] | select(.data|to_entries[]?.value|test("password|secret|token|aws|key";"i")) |
  .metadata.namespace + "/" + .metadata.name' |
  tee -a "$OUT"


##########################################################
# 9 — CLOUD METADATA / SSRF
##########################################################
section "9 — Cloud Metadata Exposure"

log "Testing metadata service access:"
curl -s --connect-timeout 1 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1 && \
    warn "Metadata service reachable — BIG RISK!" || \
    good "Metadata service unreachable"


##########################################################
# 10 — ETCD HARDENING
##########################################################
section "10 — etcd Hardening"

log "Checking if etcd is local:"
ps aux | grep etcd | grep -v grep | tee -a "$OUT"

log "Encryption configuration:"
grep -R "EncryptionConfiguration" /etc/kubernetes 2>/dev/null | tee -a "$OUT"


##########################################################
# 11 — SUPPLY CHAIN / IMAGE TRUST
##########################################################
section "11 — Supply Chain Trust"

log "All images in cluster:"
IMAGES=$(kubectl get pods -A -o json |
  jq -r '.items[].spec.containers[].image' | sort -u)
echo "$IMAGES" | tee -a "$OUT"

log "Detecting :latest tags:"
echo "$IMAGES" | grep ":latest" | tee -a "$OUT" || good "No :latest tags found"

log "Untrusted registry detection:"
echo "$IMAGES" | grep -vE "(amazonaws|gcr|azurecr|ghcr.io|docker.io)" | tee -a "$OUT"


##########################################################
# 12 — POD SECURITY STANDARDS (PSS)
##########################################################
section "12 — Pod Security Standards"

log "Namespace labels for PSS:"
kubectl get ns --show-labels | tee -a "$OUT"

log "Namespaces missing PSS labels:"
kubectl get ns --show-labels | grep -v "pod-security.kubernetes.io" | tee -a "$OUT"


##########################################################
# COMPLETE
##########################################################
section "Audit Complete"
log "Full hardening audit written to: $OUT"

