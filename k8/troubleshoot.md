Kubernetes kubectl cheat sheet
Dijeesh Padinharethil on Apr 17
 Jun 8 1 min
Few kubectl commands that will be helpful in troubleshooting K8S environments

Cheat Sheet
Sort events by timestamp

kubectl get events --sort-by='.metadata.creationTimestamp'
Get list of resources stuck in a namespace

kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get --show-kind --ignore-not-found -n <namespace>
Delete namespace stuck in Terminating Status

kubectl get namespace NAMESPACE -o json > NAMESPACE.json
Remove kubernetes from finalizers array which is under spec
kubectl replace --raw "/api/v1/namespaces/NAMESPACE/finalize" -f ./NAMESPACE.json
Get list of pods sorted by node name

kubectl get pods --all-namespaces -o wide --sort-by="{.spec.nodeName}"
Get list of images running on your cluster

kubectl get pods --all-namespaces -o jsonpath="{..image}" | tr -s '[[:space:]]' '\n' | sort | uniq -c
Get list of PODs in not running state

kubectl get pods --field-selector=status.phase!=Running --all-namespaces
