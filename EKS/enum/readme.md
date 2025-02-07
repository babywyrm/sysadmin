# Kubernetes Enumeration Worksheet  
This worksheet provides a comprehensive list of `kubectl` commands to help you explore and enumerate various components in your Kubernetes cluster. 

It covers listing namespaces, pods, container images, metadata, and more.

**Listing Namespaces:**  
`kubectl get namespaces`  
Lists every namespace defined in your Kubernetes cluster.

**Listing Pods (All Namespaces):**  
`kubectl get pods --all-namespaces`  
Lists all pods across every namespace. For a specific namespace, use:  
`kubectl get pods -n <namespace>`

**Viewing Pod Details in JSON Format:**  
`kubectl get pods -o json`  
Outputs detailed pod information in JSON format for advanced querying or scripting.

**Extracting Container Images:**  
`kubectl get pods --all-namespaces -o jsonpath="{range .items[*]}{range .spec.containers[*]}{.image}{'\n'}{end}{end}"`  
Extracts and prints the container images used by the pods, one image per line.

**Listing Unique Container Images:**  
`kubectl get pods --all-namespaces -o jsonpath="{range .items[*]}{range .spec.containers[*]}{.image}{'\n'}{end}{end}" | sort -u`  
Sorts the images and removes duplicates so each container image is listed only once.

**Retrieving Pod Metadata (Labels & Annotations):**  
`kubectl get pods --all-namespaces -o jsonpath="{range .items[*]}{.metadata.name}{'\t'}{.metadata.labels}{'\t'}{.metadata.annotations}{'\n'}{end}"`  
Prints each pod’s name along with its labels and annotations, separated by tabs.

**Additional Enumeration Commands:**  
- **Deployments:** `kubectl get deployments --all-namespaces`  
- **Services:** `kubectl get services --all-namespaces`  
- **Nodes:** `kubectl get nodes`  

**Viewing Pod Logs:**  
`kubectl logs <pod-name> -n <namespace>`  
Replace `<pod-name>` and `<namespace>` with the appropriate values to view logs for a specific pod.

For further information, refer to the [Kubernetes Official Documentation](https://kubernetes.io/docs/) and the [JSONPath Reference for kubectl](https://kubernetes.io/docs/reference/kubectl/jsonpath/).


##
##
##

# Kubectl tips and tricks

## Auth

Can the service account `test-sa` in namespace `test` create pods in the namespace `test`?
```
kubectl auth can-i create pods --namespace test --as system:serviceaccount:test:test-sa
```
What can the service account `test` in namespace `test` do in namespace `test`?
```
kubectl auth can-i -n test --as system:serviceaccount:test:test-sa --list
```
Can `test` use the privileged pod security policy in namespace `test`?
```
kubectl auth can-i use podsecuritypolicies.policy/privileged -n test --as system:serviceaccount:test:test-sa
```

## Resource usage and utilization

Check current usage:
```
kubectl top pods --all-namespaces
```
Check requests:
```
kubectl get pods -o custom-columns=NAME:.metadata.name,"CPU(cores)":.spec.containers[*].resources.requests.cpu,"MEMORY(bytes)":.spec.containers[*].resources.requests.memory --all-namespaces
```

## Delete evicted pods

```shell
# Check what you are doing
kubectl get pods --all-namespaces --field-selector "status.phase==Failed" --field-selector "status.reason==Evicted"
# Delete the pods
kubectl delete pods --all-namespaces --field-selector "status.phase==Failed" --field-selector "status.reason==Evicted"
```

## Check container images used

```shell
kubectl get pods -A -o jsonpath="{range .items[*].spec.containers[*]}{.image}{'\n'}{end}" | sort | uniq
```

## Check certificate status (cert-manager)

```shell
kubectl get certificate --all-namespaces --sort-by status.notAfter \
    --output=custom-columns=NAMESPACE:metadata.namespace,NAME:metadata.name,NOT_AFTER:status.notAfter,RENEWAL_TIME:status.renewalTime,MESSAGE:status.conditions[0].message
```

## Alias and completion

See `kubectl completion --help` for how to get auto completion for kubectl.
If you use an alias (e.g. `k`) instead of `kubectl`, the completion won't work without an extra step:

```shell
# use k instead of kubectl
alias k=kubectl
# enable autocompletion for the k alias
complete -o default -F __start_kubectl k
```

## Clean up cloud provider resources

WARNING! This will delete things from your cluster!

Delete persistent volumes:
```bash
volume_namespaces="$(kubectl get pv -o jsonpath="{.items[*].spec.claimRef.namespace}" |
    tr " " "\n" | sort -u | tr "\n" " ")"

echo "Namespaces with volumes: ${volume_namespaces}"

kubectl delete ns ${volume_namespaces}
kubectl delete pv --all --wait

volumes_left="$(kubectl get pv -o json |
    jq ".items[] | {
        pv_name: .metadata.name,
        pvc_namespace: .spec.claimRef.namespace,
        pvc_name: .spec.claimRef.name
    }")"

if [ "${volumes_left}" != "" ]; then
    echo "WARNING: There seems to be volumes left in the"
    echo "         cluster, this will result in volumes that"
    echo "         needs to be cleaned up manually."
    echo "Volumes left:"
    echo "${volumes_left}"
else
    echo "All volumes where successfully cleaned up!"
fi
```
