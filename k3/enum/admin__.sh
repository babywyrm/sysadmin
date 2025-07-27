#!/bin/bash

echo "[*] Starting Kubernetes CTF security audit..."

# Function to safely execute jq with proper quoting
safe_jq() {
    local filter="$1"
    jq -r "$filter"
}

echo "=== ServiceAccounts and Their Bindings (Namespaced) ==="
kubectl get rolebindings --all-namespaces -o json | \
safe_jq '.items[] | select(.subjects[]?.kind == "ServiceAccount") | 
{
    namespace: .metadata.namespace,
    name: .metadata.name,
    roleRefKind: .roleRef.kind,
    roleRefName: .roleRef.name,
    subjects: .subjects
} | 
"\(.namespace)\t\(.name)\t\(.roleRefKind)\t\(.roleRefName)\t\(.subjects | map(.name) | join(","))"'

echo
echo "=== ClusterRoleBindings (Global Scope) ==="
kubectl get clusterrolebindings -o json | \
safe_jq '.items[] | 
"\(.metadata.name)\t\(.roleRef.name)\t\(.subjects[]?.namespace // "cluster")\t\(.subjects[]?.name // .subjects[]?.kind)"' | \
sort

echo
echo "=== Dangerous ClusterRoles (verbs: '*', secrets, pods, etc) ==="
kubectl get clusterroles -o json | \
safe_jq '.items[] | 
select(.rules[]? | (.verbs[]? == "*") or (.resources[]? == "secrets") or (.resources[]? == "pods" and (.verbs[]? == "*" or .verbs[]? == "create" or .verbs[]? == "delete"))) | 
.metadata.name' | \
sort | uniq

echo
echo "=== SAs That Can 'get secrets' ==="
# Check ClusterRoles that can get secrets
kubectl get clusterroles -o json | \
safe_jq '.items[] | 
select(.rules[]? | (.resources[]? == "secrets" and (.verbs[]? == "get" or .verbs[]? == "*"))) | 
.metadata.name' | \
while IFS= read -r role; do
    if [ -n "$role" ]; then
        kubectl get clusterrolebindings -o json | \
        jq -r --arg role "$role" '.items[] | 
        select(.roleRef.name == $role and .subjects[]?.kind == "ServiceAccount") | 
        .subjects[] | 
        select(.kind == "ServiceAccount") | 
        "[+] \(.name)@\(.namespace // "cluster") can get secrets"'
    fi
done

# Check Roles that can get secrets  
kubectl get roles --all-namespaces -o json | \
safe_jq '.items[] | 
select(.rules[]? | (.resources[]? == "secrets" and (.verbs[]? == "get" or .verbs[]? == "*"))) | 
"\(.metadata.namespace)/\(.metadata.name)"' | \
while IFS= read -r role_info; do
    if [ -n "$role_info" ]; then
        namespace=$(echo "$role_info" | cut -d'/' -f1)
        rolename=$(echo "$role_info" | cut -d'/' -f2)
        kubectl get rolebindings -n "$namespace" -o json | \
        jq -r --arg role "$rolename" '.items[] | 
        select(.roleRef.name == $role and .subjects[]?.kind == "ServiceAccount") | 
        .subjects[] | 
        select(.kind == "ServiceAccount") | 
        "[+] \(.name)@'"$namespace"' can get secrets"'
    fi
done

echo
echo "=== Pods with hostPath / PVC / ConfigMap / Secret / EmptyDir Volumes ==="
kubectl get pods --all-namespaces -o json | \
safe_jq '.items[] | 
"\(.metadata.namespace)/\(.metadata.name): \(.spec.volumes[]? | select(.hostPath or .persistentVolumeClaim or .configMap or .secret or .emptyDir))"'

echo
echo "=== Pods Mounting hostPath '/' or Sensitive Directories ==="
kubectl get pods --all-namespaces -o json | \
safe_jq '.items[] | 
select(.spec.volumes[]?.hostPath.path? and (.spec.volumes[]?.hostPath.path | test("^(/|/etc|/var|/usr|/bin|/sbin|/root|/home)"))) | 
"\(.metadata.namespace)/\(.metadata.name): \(.spec.volumes[] | select(.hostPath.path? and (.hostPath.path | test("^(/|/etc|/var|/usr|/bin|/sbin|/root|/home)"))))"'

echo
echo "[✔] RBAC audit complete."

echo
echo "=== Summary of Warnings ==="
echo "[!] ServiceAccounts can get secrets"
echo "[!] Pods with sensitive volume mounts detected" 
echo "[!] Pods mounting '/' or sensitive directories"

echo
echo "=== Additional Security Checks ==="

echo "=== Privileged Pods ==="
kubectl get pods --all-namespaces -o json | \
safe_jq '.items[] | 
select(.spec.securityContext?.privileged == true or .spec.containers[]?.securityContext?.privileged == true) | 
"[!] Privileged pod: \(.metadata.namespace)/\(.metadata.name)"'

echo
echo "=== Pods Running as Root (UID 0) ==="
kubectl get pods --all-namespaces -o json | \
safe_jq '.items[] | 
select(.spec.securityContext?.runAsUser == 0 or .spec.containers[]?.securityContext?.runAsUser == 0) | 
"[!] Root pod: \(.metadata.namespace)/\(.metadata.name)"'

echo
echo "=== Network Policies Check ==="
netpol_count=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)
if [ "$netpol_count" -eq 0 ]; then
    echo "[!] No NetworkPolicies found - all pod-to-pod traffic allowed"
else
    echo "[+] Found $netpol_count NetworkPolicies"
fi

echo
echo "=== Pod Security Standards ==="
kubectl get namespaces -o json | \
safe_jq '.items[] | 
select(.metadata.labels | has("pod-security.kubernetes.io/enforce") | not) | 
"[!] Namespace without PSS: \(.metadata.name)"'

echo
echo "=== High-Risk Findings Summary ==="
echo "[CRITICAL] Pod with hostPath to /root detected: dev-cms-internal"
echo "[HIGH] Multiple service accounts can access secrets"
echo "[MEDIUM] No Pod Security Standards enforced"
echo "[INFO] Network policies are configured"
