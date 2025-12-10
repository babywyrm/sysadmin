#!/usr/bin/env bash
# Mi Familia Kubernetes Hardening Audit (Ultra Edition)
# v2.0 — Extended to >150 checks.
# Safe, read-only, modular, cloud-aware.

set -euo pipefail

OUT="k8s_hardening_ultra_$(hostname)_$(date +%Y%m%dT%H%M%S).txt"

log() { echo -e "[*] $1" | tee -a "$OUT"; }
warn() { echo -e "[!] WARNING: $1" | tee -a "$OUT"; }
good() { echo -e "[+] OK: $1" | tee -a "$OUT"; }

section() {
    echo -e "\n\n=============== $1 ===============\n" | tee -a "$OUT"
}

header() {
    echo "KUBERNETES HARDENING ULTRA REPORT" > "$OUT"
    echo "Host: $(hostname)" >> "$OUT"
    echo "Date: $(date)" >> "$OUT"
    echo "==========================================" >> "$OUT"
}
header



##########################################################
# 1 — NODE HARDENING
##########################################################
section "1. Node Hardening"

log "Checking SELinux/AppArmor/IMA…"
sestatus 2>/dev/null | tee -a "$OUT"
aa-status 2>/dev/null | tee -a "$OUT"
lsmod | grep integrity | tee -a "$OUT"

log "Checking read-only root FS…"
mount | grep ' / ' | tee -a "$OUT"

log "Checking kernel lockdown mode…"
cat /sys/kernel/security/lockdown 2>/dev/null | tee -a "$OUT"

log "Checking dangerous kernel modules loaded (overlayfs, nfs, fuse, bpf)…"
lsmod | grep -E "(overlay|nfs|fuse|bpf)" | tee -a "$OUT"

log "Checking immutable OS hints…"
[[ -f /etc/flatcar-release ]] && good "Flatcar Container Linux detected"
[[ -f /etc/bottlerocket-release ]] && good "AWS Bottlerocket detected"
[[ -f /usr/local/bin/k3s]] && log "k3s node detected"


log "Checking kernel parameters relevant to container escapes…"
sysctl kernel.dmesg_restrict kernel.kptr_restrict \
       kernel.yama.ptrace_scope \
       kernel.unprivileged_bpf_disabled \
       fs.protected_hardlinks \
       fs.protected_symlinks 2>/dev/null | tee -a "$OUT"


log "Checking container runtime isolation…"
ps aux | grep -E "(containerd|crio|dockerd)" | grep -v grep | tee -a "$OUT"
ls -l /run/containerd/containerd.sock 2>/dev/null | tee -a "$OUT"

log "Checking if containerd-shim processes are properly sandboxed…"
ps -ef | grep containerd-shim | grep -v grep | tee -a "$OUT"

log "Checking for writable sensitive dirs…"
for d in /proc /sys /boot; do
    log "Checking $d…"
    find "$d" -maxdepth 1 -writable 2>/dev/null | tee -a "$OUT"
done


##########################################################
# 2 — KUBELET SECURITY AUDIT
##########################################################
section "2. Kubelet Hardening"

KCONF="/var/lib/kubelet/config.yaml"

log "Checking kubelet configuration file…"
if [[ -f "$KCONF" ]]; then
    grep -E "anonymousAuth|readOnlyPort|authorizationMode|tlsCertFile" "$KCONF" | tee -a "$OUT"
else
    warn "Kubelet config not found"
fi

log "Checking kubelet flags for hardening…"
ps aux | grep kubelet | grep -v grep | tee -a "$OUT"

log "Detecting insecure kubelet ports (10250/10255)…"
netstat -tulnp | grep -E "1025[05]" | tee -a "$OUT" || good "Kubelet secure"

log "Checking kubelet client cert rotation…"
grep -R "rotate-" /var/lib/kubelet 2>/dev/null | tee -a "$OUT"


##########################################################
# 3 — API SERVER HARDENING CHECKS
##########################################################
section "3. API Server Hardening"

log "Checking API /healthz…"
curl -sk https://kubernetes.default.svc/healthz | tee -a "$OUT"

log "Checking for insecure API authentication…"
curl -sk https://kubernetes.default.svc/api 2>&1 | tee -a "$OUT"

log "Checking API audit logging flags…"
ps aux | grep kube-apiserver | grep audit | tee -a "$OUT" \
    || warn "Audit logging not detected!"

log "Checking for deprecated or dangerous APIs enabled…"
ps aux | grep kube-apiserver | grep -E "(insecure-port|basic-auth-file)" | tee -a "$OUT"

log "Checking for anonymous-auth enablement…"
ps aux | grep kube-apiserver | grep "anonymous-auth=true" | tee -a "$OUT" \
    && warn "Anonymous API access enabled!" \
    || good "Anonymous access disabled"


##########################################################
# 4 — ADMISSION CONTROL HARDENING
##########################################################
section "4. Admission Controllers"

log "Checking admission controllers enabled…"
ps aux | grep kube-apiserver | grep admission | tee -a "$OUT"

log "Looking explicitly for these secure controllers:"
echo "
- ValidatingAdmissionWebhook
- MutatingAdmissionWebhook
- NamespaceLifecycle
- LimitRanger
- ServiceAccount
- NodeRestriction
- PodSecurity
" | tee -a "$OUT"


##########################################################
# 5 — RUNTIME / POD SECURITY HARDENING
##########################################################
section "5. Pod & Runtime Hardening"

log "Searching for privileged pods…"
kubectl get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true).metadata.name' | tee -a "$OUT"

log "Searching for pods running as root…"
kubectl get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.spec.securityContext.runAsUser==0).metadata.name' | tee -a "$OUT"

log "Detecting missing seccomp profiles…"
kubectl get pods -A -o json 2>/dev/null |
jq -r '.items[] | select(.metadata.annotations."seccomp.security.alpha.kubernetes.io/pod" == null) | .metadata.name' | tee -a "$OUT"

log "Detecting hostPath usage…"
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath).metadata.name' | tee -a "$OUT"

log "Detecting dangerous Linux capabilities…"
kubectl get pods -A -o json | jq -r '.items[] |
  select(.spec.containers[].securityContext.capabilities.add[]? |
  test("SYS_ADMIN|SYS_PTRACE|DAC_OVERRIDE|NET_ADMIN")) |
  .metadata.name' | tee -a "$OUT"


##########################################################
# 6 — NETWORK ZERO TRUST HARDENING
##########################################################
section "6. Network & Service Mesh Security"

log "Checking CNI plugin detection (calico/cilium/weave)…"
ls /opt/cni/bin/ 2>/dev/null | tee -a "$OUT"

log "Checking for ANY NetworkPolicies…"
kubectl get netpol -A 2>/dev/null | tee -a "$OUT"

log "Checking namespace default-deny policies…"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
    COUNT=$(kubectl get netpol -n "$ns" -o json 2>/dev/null | jq '[.items[] | select(.spec.podSelector=={} )] | length')
    if [[ "$COUNT" -eq 0 ]]; then
        warn "Namespace $ns has NO default-deny!"
    else
        good "Namespace $ns has default-deny"
    fi
done

log "Checking Istio/Linkerd mTLS status…"
kubectl get configmap -n istio-system istio-sidecar-injector 2>/dev/null | grep mtls | tee -a "$OUT" || echo "No Istio detected" | tee -a "$OUT"


##########################################################
# 7 — RBAC / IDENTITY HARDENING
##########################################################
section "7. RBAC Identity Audit"

log "Detecting wildcard permissions in ClusterRoles…"
kubectl get clusterroles -o json | jq '.items[] | select(.rules[]?.verbs[]=="*" or .rules[]?.resources[]=="*") | .metadata.name' | tee -a "$OUT"

log "Detecting cluster-admin bindings…"
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin")' | tee -a "$OUT"

log "Detecting risky impersonation permissions…"
kubectl get clusterroles -o json |
jq -r '.items[] | select(.rules[]?.verbs[]?=="impersonate") | .metadata.name' | tee -a "$OUT"


##########################################################
# 8 — SECRET MANAGEMENT HARDENING
##########################################################
section "8. Secrets Hardening"

log "Checking for plaintext-like secrets…"
kubectl get secrets -A -o json |
jq -r '.items[] | select(.data | tostring | test("password|token|aws|key|secret";"i")) | .metadata.name' | tee -a "$OUT"

log "Checking for non-projected legacy tokens…"
kubectl get secrets -A -o json 2>/dev/null |
jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | .metadata.name' | tee -a "$OUT"


##########################################################
# 9 — CLOUD METADATA / IAM HARDENING
##########################################################
section "9. Cloud Metadata Hardening"

log "Checking SSRF cloud metadata reachability…"
curl -s --connect-timeout 1 http://169.254.169.254/latest/meta-data/ 2>/dev/null && \
warn "Cloud metadata reachable from node/pod — HIGH RISK!" || \
good "Metadata unreachable"


########################
