# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# kubectl aliases & helpers
#
# Usage examples:
#   k get pods -A
#   kn staging get pods -o wide
#   kx my-pod -- sh
#   klog my-pod --tail=100
#   ksys get pods
#   kctx my-cluster
#   kns my-namespace
# =============================================================================

# -----------------------------------------------------------------------------
# Core
# -----------------------------------------------------------------------------
alias k='kubectl'
alias ksys='kubectl --namespace=kube-system'

# -----------------------------------------------------------------------------
# Apply / Kustomize
# -----------------------------------------------------------------------------
alias ka='kubectl apply -f'
alias kar='kubectl apply --recursive -f'
alias kak='kubectl apply -k'
alias kk='kubectl kustomize'
alias kdiff='kubectl diff -f'

# -----------------------------------------------------------------------------
# Exec / Logs / Port-forward
# -----------------------------------------------------------------------------
alias kx='kubectl exec -it'
alias klog='kubectl logs -f'
alias klogp='kubectl logs -f -p'          # previous container
alias kloga='kubectl logs -f --all-containers'
alias kpf='kubectl port-forward'

# -----------------------------------------------------------------------------
# Throwaway debug pod
#
# Usage:
#   krun debug-shell --image=nicolaka/netshoot -- bash
#
# Defaults to a minimal Alpine shell if no image is specified.
# -----------------------------------------------------------------------------
alias krun='kubectl run --rm --restart=Never --image-pull-policy=IfNotPresent -it'

# -----------------------------------------------------------------------------
# Core verb functions
#
# Using functions instead of aliases gives us proper argument handling,
# tab-completion compatibility, and the ability to extend behavior later.
#
# Usage:
#   kg pods -A
#   kg pods -n staging -o wide
#   kd deploy my-app -n production
#   krm pod bad-pod -n staging
# -----------------------------------------------------------------------------
kg()  { kubectl get        "$@"; }
kd()  { kubectl describe   "$@"; }
krm() { kubectl delete     "$@"; }
ke()  { kubectl edit       "$@"; }
kl()  { kubectl label      "$@"; }
kan() { kubectl annotate   "$@"; }

# -----------------------------------------------------------------------------
# kn — namespace-scoped wrapper
#
# Usage:
#   kn <namespace> <verb> [resource] [flags]
#   kn staging get pods
#   kn staging describe deploy my-app
#   kn staging logs -f my-pod
# -----------------------------------------------------------------------------
kn() {
  if [[ $# -lt 2 ]]; then
    echo "Usage: kn <namespace> <kubectl args...>" >&2
    return 1
  fi
  local ns="$1"; shift
  kubectl --namespace="$ns" "$@"
}

# -----------------------------------------------------------------------------
# kctx — switch kubectl context
# kns  — switch default namespace in current context
#
# These are thin wrappers. If you have kubectx/kubens installed they will be
# used instead, which provides fuzzy-search and tab-completion.
# -----------------------------------------------------------------------------
kctx() {
  if command -v kubectx &>/dev/null; then
    kubectx "$@"
  else
    if [[ $# -eq 0 ]]; then
      kubectl config get-contexts
    else
      kubectl config use-context "$1"
    fi
  fi
}

kns() {
  if command -v kubens &>/dev/null; then
    kubens "$@"
  else
    if [[ $# -eq 0 ]]; then
      kubectl config view --minify --output 'jsonpath={.contexts[0].context.namespace}'
      echo
    else
      kubectl config set-context --current --namespace="$1"
    fi
  fi
}

# -----------------------------------------------------------------------------
# Resource aliases — get
# -----------------------------------------------------------------------------
alias kgpo='kubectl get pods'
alias kgdep='kubectl get deployment'
alias kgsts='kubectl get statefulset'
alias kgds='kubectl get daemonset'
alias kgsvc='kubectl get service'
alias kging='kubectl get ingress'
alias kgcm='kubectl get configmap'
alias kgsec='kubectl get secret'
alias kgno='kubectl get nodes'
alias kgns='kubectl get namespaces'
alias kgpv='kubectl get persistentvolume'
alias kgpvc='kubectl get persistentvolumeclaim'
alias kghpa='kubectl get hpa'
alias kgsa='kubectl get serviceaccount'

# -----------------------------------------------------------------------------
# Resource aliases — describe
# -----------------------------------------------------------------------------
alias kdpo='kubectl describe pod'
alias kddep='kubectl describe deployment'
alias kdsts='kubectl describe statefulset'
alias kdds='kubectl describe daemonset'
alias kdsvc='kubectl describe service'
alias kding='kubectl describe ingress'
alias kdcm='kubectl describe configmap'
alias kdsec='kubectl describe secret'
alias kdno='kubectl describe node'
alias kdns='kubectl describe namespace'
alias kdpvc='kubectl describe persistentvolumeclaim'
alias kdhpa='kubectl describe hpa'

# -----------------------------------------------------------------------------
# Resource aliases — delete
# -----------------------------------------------------------------------------
alias krmpo='kubectl delete pod'
alias krmdep='kubectl delete deployment'
alias krmsts='kubectl delete statefulset'
alias krmds='kubectl delete daemonset'
alias krmsvc='kubectl delete service'
alias krming='kubectl delete ingress'
alias krmcm='kubectl delete configmap'
alias krmsec='kubectl delete secret'
alias krmns='kubectl delete namespace'
alias krmpvc='kubectl delete persistentvolumeclaim'

# -----------------------------------------------------------------------------
# Rollout management
# -----------------------------------------------------------------------------
alias kroll='kubectl rollout status'
alias krollh='kubectl rollout history'
alias krollu='kubectl rollout undo'
alias krollr='kubectl rollout restart'

# -----------------------------------------------------------------------------
# Frequently used compound commands
# -----------------------------------------------------------------------------

# All pods across all namespaces, sorted by node
alias kgpoa='kubectl get pods -A -o wide'

# Pods not in a Running or Completed state
alias kgpobad='kubectl get pods -A --field-selector=status.phase!=Running | grep -v Completed'

# Top pods sorted by CPU / memory
alias ktop='kubectl top pods -A --sort-by=cpu'
alias ktopm='kubectl top pods -A --sort-by=memory'

# All LoadBalancer services (i.e. services creating cloud resources)
alias kglb='kubectl get svc -A --field-selector spec.type=LoadBalancer'

# Print requests and limits for all pods in a namespace
# Usage: klimits <namespace>
klimits() {
  local ns="${1:?Usage: klimits <namespace>}"
  kubectl get pods -n "$ns" -o custom-columns=\
'NAME:metadata.name,\
MEM_REQ:spec.containers[0].resources.requests.memory,\
MEM_LIM:spec.containers[0].resources.limits.memory,\
CPU_REQ:spec.containers[0].resources.requests.cpu,\
CPU_LIM:spec.containers[0].resources.limits.cpu'
}

# Tail logs from all pods matching a label selector
# Usage: klogl <namespace> <label-selector>
# Example: klogl production app=nginx
klogl() {
  local ns="${1:?Usage: klogl <namespace> <label-selector>}"
  local sel="${2:?Usage: klogl <namespace> <label-selector>}"
  kubectl logs -f -n "$ns" -l "$sel" --all-containers --max-log-requests=10
}

# Force-delete a stuck namespace (clears finalizers)
# Usage: krmns-force <namespace>
krmns_force() {
  local ns="${1:?Usage: krmns_force <namespace>}"
  kubectl get namespace "$ns" -o json \
    | jq '.spec.finalizers = []' \
    | kubectl replace --raw "/api/v1/namespaces/${ns}/finalize" -f -
}

##
##
