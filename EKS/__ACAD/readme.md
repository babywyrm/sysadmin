```
kubectl get services                # List all services 
kubectl get pods                    # List all pods
kubectl get nodes -w                # Watch nodes continuously
kubectl version                     # Get version information
kubectl cluster-info                # Get cluster information
kubectl config view                 # Get the configuration
kubectl describe node <node>        # Output information about a node
kubectl get pods                         # List the current pods
kubectl describe pod <name>              # Describe pod <name>
kubectl get rc                           # List the replication controllers
kubectl get rc --namespace="<namespace>" # List the replication controllers in <namespace>
kubectl describe rc <name>               # Describe replication controller <name>
kubectl get svc                          # List the services
kubectl describe svc <name>              # Describe service <name>

kubectl run <name> --image=<image-name>                             # Launch a pod called <name> 
                                                                    # using image <image-name> 
kubectl create -f <manifest.yaml>                                   # Create a service described 
                                                                    # in <manifest.yaml>
kubectl scale --replicas=<count> rc <name>                          # Scale replication controller 
                                                                    # <name> to <count> instances
kubectl expose rc <name> --port=<external> --target-port=<internal> # Map port <external> to 
                                                                    # port <internal> on replication 
                                                                    # controller <name>
kubectl delete pod <name>                                         # Delete pod <name>
kubectl delete rc <name>                                          # Delete replication controller <name>
kubectl delete svc <name>                                         # Delete service <name>
kubectl drain <n> --delete-local-data --force --ignore-daemonsets # Stop all pods on <n>
kubectl delete node <name>                                        # Remove <node> from the cluster
kubectl exec <service> <command> [-c <$container>] # execute <command> on <service>, optionally 
                                                   # selecting container <$container>
kubectl logs -f <name> [-c <$container>]           # Get logs from service <name>, optionally
                                                   # selecting container <$container>
watch -n 2 cat /var/log/kublet.log                 # Watch the Kublet logs
kubectl top node                                   # Show metrics for nodes
kubectl top pod                                    # Show metrics for pods
kubeadm init                                              # Initialize your master node
kubeadm join --token <token> <master-ip>:<master-port>    # Join a node to your Kubernetes cluster
kubectl create namespace <namespace>                      # Create namespace <name>
kubectl taint nodes --all node-role.kubernetes.io/master- # Allow Kubernetes master nodes to run pods
kubeadm reset                                             # Reset current state
kubectl get secrets                                       # List all secrets

```
##
##

## Add a kubectl context

```bash
# copy cluster's certificate to a file
vi cluster-certificate.txt

# Set cluster
kubectl config set-cluster <CLUSTER_NAME> --server=https://37.187.1.138:6443 --certificate-authority=cluster-certificate.txt --embed-certs=true

# Set credentials
kubectl config set-credentials <USER_NAME> --token=<TOKEN>

# Set context
kubectl config set-context <KUBECTL_CONTEXT_NAME> --cluster=<CLUSTER_NAME> --user=<USER_NAME> --namespace=<NAMESPACE>

# Use context
kubectl config use-context <KUBECTL_CONTEXT_NAME>
```

## Clean up a namespace

```bash
# Delete a config map
kubectl get configmaps | awk '{print $1}' | grep -v 'NAME' | xargs kubectl delete configmap

# Real "get all"
kubectl get -n <NAMESPACE> configmaps,daemonsets,deployments,endpoints,ingresses,jobs,persistentvolumeclaims,pods,podtemplates,replicasets,services,statefulsets

# Delete ALL
kubectl get -n <NAMESPACE> configmaps,daemonsets,deployments,endpoints,ingresses,jobs,persistentvolumeclaims,pods,podtemplates,replicasets,services,statefulsets,secrets | awk '{print $1}' | grep -v "NAME" | grep -v "secret/default-token" | xargs kubectl delete

```

## Stop/Start a deployment

```
kubectl get deployment

# Stop
kubectl scale deployment.apps/<DEPLOYMENT_NAME> --replicas 0

# Start
kubectl scale deployment.apps/<DEPLOYMENT_NAME> --replicas 1
```

Sometime you just want to restart a container into a pod.

This will send a `SIGTERM` signal to process 1, which is the main process running in the container. All other processes will be children of process 1, and will be terminated after process 1 exits.

Note: It will not solve your problem. This is only a quick fix.

```
kubectl exec -it <POD_NAME> -c <CONTAINER_NAME> -- /bin/sh -c "kill 1"
```

## Fix rewrite problems with PHPMyAdmin

I don't know why but sometimes, `helm upgrade` doesn't upgrade these annotations so I have to do it manualy. 

```
kubectl annotate --overwrite ingress <INGRESS_NAME> "nginx.ingress.kubernetes.io/rewrite-target"-
kubectl annotate --overwrite ingress <INGRESS_NAME> "ingress.kubernetes.io/rewrite-target"-
```

## Other cheat sheets

- [Official cheat sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [dennyzhang/cheatsheet-kubernetes-A4](https://github.com/dennyzhang/cheatsheet-kubernetes-A4)

## Tools

- [kubectx and kubens](https://github.com/ahmetb/kubectx) to "switch faster between clusters and namespaces in kubectl".
- [jonmosco/kube-ps1](https://github.com/jonmosco/kube-ps1)to add the current Kubernetes context and namespace to your prompt.
- [Kubernetes client kubectl container](https://github.com/lachie83/k8s-kubectl)
- [Kubectl-debug](https://github.com/aylei/kubectl-debug)
- [jordanwilson230/kubectl-plugins](https://github.com/jordanwilson230/kubectl-plugins)

##
##
