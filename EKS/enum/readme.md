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

##
##


# Kubernetes & EKS Deployment Enumeration Worksheet

This document provides a one-stop reference for enumerating the major deployment types in Kubernetes—as well as related AWS resources—in an Amazon EKS cluster. Below, you'll find commands using `kubectl` (and one using the AWS CLI) to list and inspect Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs, Nodes, and AWS Auto Scaling Groups (ASGs). Each section also includes a brief description of what the resource type is and why it might be used.

---

**Deployments:**  
- **What they are:**  
  A Deployment provides declarative updates for Pods and ReplicaSets. It allows you to define the desired state of your application, and Kubernetes will ensure that the current state matches that specification over time.  
- **Command:**
  ```
  kubectl get deployments --all-namespaces


StatefulSets:

What they are:
A StatefulSet is used for managing stateful applications. It assigns unique, persistent identities to pods and guarantees ordered deployment, scaling, and updates.
Command:

```
kubectl get statefulsets --all-namespaces
```

DaemonSets:

What they are:
A DaemonSet ensures that a copy of a pod runs on all (or selected) nodes in the cluster. This is typically used for cluster-wide services such as log collectors, monitoring agents, or networking daemons.
Command:

```
kubectl get daemonsets --all-namespaces
```


ReplicaSets:

What they are:
A ReplicaSet ensures that a specified number of pod replicas are running at any given time. Although Deployments usually manage ReplicaSets, you might enumerate them separately for troubleshooting.
Command:

```
kubectl get replicasets --all-namespaces
```


Jobs & CronJobs:

Jobs:
What they are:
A Job creates one or more pods and ensures that a specified number of them terminate successfully.
Command:

```
kubectl get jobs --all-namespaces
```

CronJobs:
What they are:
A CronJob schedules Jobs to run at specified time intervals (similar to cron in Unix/Linux).
Command:

```
kubectl get cronjobs --all-namespaces
```

Nodes:

What they are:
Nodes are the worker machines in your Kubernetes cluster. They run your application workloads and are managed by the control plane.
Command:

```
kubectl get nodes
```

AWS Auto Scaling Groups (ASGs):

What they are:
In an EKS cluster, the underlying nodes are typically managed by AWS Auto Scaling Groups (ASGs). 
ASGs automatically adjust the number of EC2 instances (nodes) based on demand, ensuring your cluster scales appropriately.
Command (using AWS CLI):
Replace YOUR_CLUSTER_NAME with your actual EKS cluster name.


```
aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[?contains(Tags[?Key=='eks:cluster-name'].Value, 'YOUR_CLUSTER_NAME')]" --output table
```
