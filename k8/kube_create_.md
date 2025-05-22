# Modern Kubernetes (kubectl) Cheat Sheet

## Kubernetes Objects Comparison Table

| Object | Purpose | Scaling | Pod Management | Use Cases | Lifecycle | kubectl Management Commands |
|--------|---------|---------|----------------|-----------|-----------|----------------------------|
| **Pod** | Basic execution unit | N/A - single instance | Direct container management | Testing, one-off jobs | Terminated when process completes | `kubectl run nginx --image=nginx`<br>`kubectl get pods`<br>`kubectl logs <pod-name>`<br>`kubectl exec -it <pod-name> -- sh` |
| **ReplicaSet** | Maintains pod replicas | Manual or auto | Ensures specified number of replicas | Rarely used directly | Tied to controller | `kubectl get rs`<br>`kubectl scale rs <name> --replicas=3`<br>`kubectl describe rs <name>` |
| **Deployment** | Declarative updates | Manual or auto | Rolling updates, rollbacks | Stateless applications | Managed lifecycle with history | `kubectl create deployment nginx --image=nginx`<br>`kubectl rollout status deployment/<name>`<br>`kubectl rollout undo deployment/<name>`<br>`kubectl scale deployment/<name> --replicas=5` |
| **StatefulSet** | Ordered pod management | Ordered scaling | Stable network IDs, persistent storage | Databases, stateful apps | Ordered creation/deletion | `kubectl get statefulset`<br>`kubectl scale statefulset <name> --replicas=3`<br>`kubectl rollout status sts/<name>` |
| **DaemonSet** | Runs on all/selected nodes | One per node | Node-level operations | Monitoring, logging agents | Tied to node lifecycle | `kubectl get daemonset`<br>`kubectl rollout status ds/<name>`<br>`kubectl rollout history ds/<name>`<br>`kubectl apply -f daemonset.yaml` |
| **Job** | Run-to-completion | Parallelism parameter | Tracks successful completions | Batch processing | Terminates after completion | `kubectl create job <name> --image=busybox -- <command>`<br>`kubectl get jobs`<br>`kubectl describe job <name>` |
| **CronJob** | Scheduled jobs | Based on schedule | Creates Jobs on schedule | Backups, reporting | Recurring based on cron schedule | `kubectl create cronjob <name> --image=busybox --schedule="*/5 * * * *" -- <command>`<br>`kubectl get cronjobs`<br>`kubectl delete cronjob <name>` |
| **Service** | Network abstraction | N/A | Load balancing, service discovery | API access, app exposure | Persists until deleted | `kubectl expose deployment <name> --port=80 --type=ClusterIP`<br>`kubectl get svc`<br>`kubectl describe svc <name>` |
| **Ingress** | HTTP/S routing | N/A | External access to Services | URL-based routing | Persists until deleted | `kubectl get ingress`<br>`kubectl describe ingress <name>`<br>`kubectl apply -f ingress.yaml` |
| **ConfigMap** | Configuration data | N/A | Config injection to pods | App configuration | Persists until deleted | `kubectl create configmap <name> --from-file=config.txt`<br>`kubectl get configmaps`<br>`kubectl describe configmap <name>` |
| **Secret** | Sensitive data | N/A | Secure data injection | Credentials, tokens | Persists until deleted | `kubectl create secret generic <name> --from-literal=key=value`<br>`kubectl get secrets`<br>`kubectl describe secret <name>` |

## Creating Objects

```bash
# Create resources from files
kubectl apply -f ./file.yml                   # Create or update resource(s)
kubectl apply -f ./file1.yml -f ./file2.yaml  # Create or update from multiple files
kubectl apply -f ./dir                        # Create or update from all manifests in directory
kubectl apply -k ./kustomization-dir          # Apply resources with kustomize

# Create from URL
kubectl apply -f https://raw.githubusercontent.com/kubernetes/examples/master/application/wordpress/mysql-deployment.yaml

# Create objects with generators
kubectl create deployment nginx --image=nginx:latest
kubectl create job test-job --image=busybox -- echo "Hello World"
kubectl create cronjob test-cron --image=busybox --schedule="*/1 * * * *" -- echo "Hello World"

# Create multiple YAML objects from stdin
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: busybox-sleep
spec:
  containers:
  - name: busybox
    image: busybox
    args:
    - sleep
    - "1000000"
---
apiVersion: v1
kind: Pod
metadata:
  name: busybox-sleep-less
spec:
  containers:
  - name: busybox
    image: busybox
    args:
    - sleep
    - "1000"
EOF

# Create a secret with several keys
kubectl create secret generic mysecret \
  --from-literal=username=jane \
  --from-literal=password=s33msi4

# Explain resource with examples
kubectl explain deployment --recursive
kubectl explain deployment.spec.strategy
```

## Viewing and Finding Resources

```bash
# Basic resource viewing
kubectl get pods                               # List all pods in current namespace
kubectl get pods -A                            # List all pods in all namespaces
kubectl get pods -o wide                       # List pods with additional details
kubectl get deployment,services                # List multiple resource types
kubectl get all                                # List all resources in current namespace

# Output formatting
kubectl get pods -o yaml                       # YAML output
kubectl get pods -o json                       # JSON output
kubectl get pods -o jsonpath='{.items[*].metadata.name}'  # Extract specific fields
kubectl get pods -o custom-columns=NAME:.metadata.name,STATUS:.status.phase  # Custom columns

# Sorting and filtering
kubectl get services --sort-by=.metadata.name
kubectl get pods --sort-by=.status.containerStatuses[0].restartCount
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --selector=app=nginx,tier=frontend

# Verbose output and inspection
kubectl describe pod <pod-name>
kubectl describe node <node-name>
kubectl events                                 # Show events in current namespace
kubectl logs <pod-name>                        # Show pod logs
kubectl logs -f <pod-name>                     # Stream pod logs
kubectl logs <pod-name> -c <container-name>    # Show specific container logs

# Advanced queries
# Get pods with resource usage
kubectl top pods

# Get ExternalIPs of all nodes
kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="ExternalIP")].address}'

# Check which nodes are ready
kubectl get nodes -o jsonpath='{range .items[*]}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}'| tr ';' "\n" | grep "Ready=True"
```

## Modifying and Deleting Resources

```bash
# Editing resources
kubectl edit deployment <deployment-name>      # Edit a resource in default editor
kubectl patch deployment <name> --patch '{"spec": {"replicas": 2}}'  # Patch a resource

# Labels and annotations
kubectl label pods <pod-name> environment=dev  # Add or update labels
kubectl label pods <pod-name> environment-     # Remove a label
kubectl annotate pods <pod-name> description="My description"  # Add annotation

# Scaling resources
kubectl scale deployment <name> --replicas=3   # Scale a deployment
kubectl autoscale deployment <name> --min=2 --max=5 --cpu-percent=80  # Autoscale

# Updating resources
kubectl rollout restart deployment <name>      # Restart deployment (triggers rolling update)
kubectl set image deployment/<name> container-name=new-image:tag  # Update container image
kubectl rollout status deployment/<name>       # Check rollout status
kubectl rollout history deployment/<name>      # View rollout history
kubectl rollout undo deployment/<name>         # Rollback to previous version
kubectl rollout undo deployment/<name> --to-revision=2  # Rollback to specific revision

# Deleting resources
kubectl delete pod <pod-name>                  # Delete a pod
kubectl delete -f ./file.yaml                  # Delete resources in file
kubectl delete deployment <name> --cascade=foreground  # Delete with dependencies
kubectl delete pods --all                      # Delete all pods
kubectl delete all --all                       # Delete all resources in namespace
kubectl delete namespace <name>                # Delete an entire namespace
```

## Interacting with Running Pods

```bash
# Executing commands
kubectl exec <pod-name> -- ls /                # Run command in existing pod (1 container)
kubectl exec <pod-name> -c <container-name> -- ls /  # Run command in specific container
kubectl exec -it <pod-name> -- /bin/bash       # Start interactive shell

# Port forwarding
kubectl port-forward pod/<pod-name> 8080:80    # Forward pod port to local machine
kubectl port-forward svc/<service-name> 8080:80  # Forward service port
kubectl port-forward deploy/<name> 8080:8080   # Forward port to deployment

# Copy files
kubectl cp <pod-name>:/path/to/file /local/path  # Copy from pod to local
kubectl cp /local/path <pod-name>:/path/in/pod   # Copy from local to pod

# Temporary pod for debugging
kubectl run debug --rm -it --image=alpine -- sh  # Start temporary pod and shell

# API proxy for accessing Kubernetes API
kubectl proxy --port=8080                      # Start local proxy to API server
```

## Context and Configuration

```bash
# Manage contexts
kubectl config get-contexts                    # List all contexts
kubectl config current-context                 # Show current context
kubectl config use-context <context-name>      # Switch context
kubectl config set-context --current --namespace=<namespace>  # Change default namespace

# Manage kubeconfig
kubectl config view                           # Show merged kubeconfig
kubectl config view --raw                     # Show raw kubeconfig
```

## Advanced Operations

```bash
# Node management
kubectl cordon <node-name>                    # Mark node as unschedulable
kubectl drain <node-name>                     # Drain node for maintenance
kubectl uncordon <node-name>                  # Mark node as schedulable

# Cluster information
kubectl cluster-info                          # Display cluster info
kubectl api-resources                         # List all API resources
kubectl api-versions                          # List all API versions
kubectl version                               # Show client and server version
```

