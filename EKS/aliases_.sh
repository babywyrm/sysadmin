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

# ---------------------------------------------------------------------------
# kubectl — sane alias set
# Usage examples:
#   k get pods
#   kn my-namespace get pods -o wide
#   kx my-pod -- bash
#   klog my-pod
#   ksys get pods
# ---------------------------------------------------------------------------

# Core shorthand
alias k='kubectl'
alias ksys='kubectl --namespace=kube-system'

# Apply / kustomize
alias ka='kubectl apply --recursive -f'
alias kak='kubectl apply -k'
alias kk='kubectl kustomize'

# Exec / logs / proxy / port-forward
alias kx='kubectl exec -it'
alias klog='kubectl logs -f'
alias klogp='kubectl logs -f -p'
alias kpf='kubectl port-forward'
alias kp='kubectl proxy'

# Quick-run a throwaway pod
alias krun='kubectl run --rm --restart=Never --image-pull-policy=IfNotPresent -it'

# ---------------------------------------------------------------------------
# kg  — smart getter
#
# Usage: kg [resource] [flags]
#   kg po                        → kubectl get pods
#   kg po -n kube-system         → kubectl get pods -n kube-system
#   kg po -A -o wide             → kubectl get pods -A -o wide
#   kg svc --show-labels         → kubectl get service --show-labels
#   kg deploy -w -o yaml         → kubectl get deployment --watch -o yaml
# ---------------------------------------------------------------------------
kg()  { kubectl get "$@"; }
kd()  { kubectl describe "$@"; }
krm() { kubectl delete "$@"; }

# ---------------------------------------------------------------------------
# kn  — namespace-scoped wrapper  (first arg = namespace)
#
# Usage: kn <namespace> <verb> [resource] [flags]
#   kn staging get pods
#   kn staging describe deploy my-app
#   kn staging delete pod bad-pod
# ---------------------------------------------------------------------------
kn() {
  local ns="$1"; shift
  kubectl --namespace="$ns" "$@"
}

# ---------------------------------------------------------------------------
# kx  — exec shorthand with optional namespace
#
# Usage:
#   kx <pod> [-- command]
#   kx -n <ns> <pod> [-- command]
# ---------------------------------------------------------------------------
kx() { kubectl exec -it "$@"; }

# ---------------------------------------------------------------------------
# Common resource aliases — just the ones people actually type daily
# ---------------------------------------------------------------------------
alias kgpo='kubectl get pods'
alias kgdep='kubectl get deployment'
alias kgsts='kubectl get statefulset'
alias kgsvc='kubectl get service'
alias kging='kubectl get ingress'
alias kgcm='kubectl get configmap'
alias kgsec='kubectl get secret'
alias kgno='kubectl get nodes'
alias kgns='kubectl get namespaces'

alias kdpo='kubectl describe pods'
alias kddep='kubectl describe deployment'
alias kdsts='kubectl describe statefulset'
alias kdsvc='kubectl describe service'
alias kding='kubectl describe ingress'
alias kdcm='kubectl describe configmap'
alias kdsec='kubectl describe secret'
alias kdno='kubectl describe nodes'
alias kdns='kubectl describe namespaces'

alias krmpo='kubectl delete pods'
alias krmdep='kubectl delete deployment'
alias krmsts='kubectl delete statefulset'
alias krmsvc='kubectl delete service'
alias krming='kubectl delete ingress'
alias krmcm='kubectl delete configmap'
alias krmsec='kubectl delete secret'
alias krmns='kubectl delete namespaces'
