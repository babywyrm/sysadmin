```
#!/bin/bash
# ============================================================================
# EKS & Kubernetes Command Reference - Enhanced
# ============================================================================

# ============================================================================
# 1. CLUSTER INFORMATION & MANAGEMENT
# ============================================================================

# Check latest EKS Kubernetes versions
curl -s https://docs.aws.amazon.com/eks/latest/userguide/doc-history.rss | grep "<title>Kubernetes version"

# Get current EKS cluster version
aws eks describe-cluster --name <cluster-name> --query 'cluster.version' --output text

# List all EKS clusters in region
aws eks list-clusters --region us-east-1

# Get cluster details with add-ons
aws eks describe-cluster --name <cluster-name> --region us-east-1 | jq -r '.cluster | {version, platformVersion, status, endpoint}'

# List cluster add-ons
aws eks list-addons --cluster-name <cluster-name>

# Describe specific add-on
aws eks describe-addon --cluster-name <cluster-name> --addon-name vpc-cni

# ============================================================================
# 2. CLUSTER CREATION (Updated for modern versions)
# ============================================================================

# Basic cluster with managed node group (recommended)
eksctl create cluster \
  --name my-cluster \
  --version 1.29 \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 2 \
  --nodes-min 1 \
  --nodes-max 4 \
  --managed

# Cluster with private networking
eksctl create cluster \
  --name private-cluster \
  --version 1.29 \
  --region us-east-1 \
  --vpc-private-subnets=subnet-xxx,subnet-yyy \
  --vpc-public-subnets=subnet-aaa,subnet-bbb \
  --nodegroup-name private-ng \
  --node-type t3.medium \
  --nodes 2 \
  --node-private-networking \
  --managed

# Control plane only (no nodes)
eksctl create cluster \
  --without-nodegroup \
  --name control-plane-only \
  --version 1.29 \
  --region us-east-1

# Create from config file (recommended for production)
eksctl create cluster -f cluster-config.yaml

# ============================================================================
# 3. NODE GROUP MANAGEMENT
# ============================================================================

# List node groups
eksctl get nodegroup --cluster <cluster-name>

# Scale node group
eksctl scale nodegroup \
  --cluster <cluster-name> \
  --name <nodegroup-name> \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 5

# Create additional node group
eksctl create nodegroup \
  --cluster <cluster-name> \
  --name new-nodegroup \
  --node-type t3.large \
  --nodes 2 \
  --managed

# Delete node group
eksctl delete nodegroup \
  --cluster <cluster-name> \
  --name <nodegroup-name> \
  --drain=true

# Upgrade node group
eksctl upgrade nodegroup \
  --cluster <cluster-name> \
  --name <nodegroup-name>

# ============================================================================
# 4. NODE INFORMATION & QUERIES
# ============================================================================

# Get all worker nodes with detailed info
cluster_name="my-cluster"
region="us-east-1"

aws ec2 describe-instances --region ${region} \
  --filters "Name=tag:kubernetes.io/cluster/${cluster_name},Values=owned" \
  --query "Reservations[*].Instances[*].{
    Instance:InstanceId,
    Type:InstanceType,
    PublicIP:PublicIpAddress,
    PrivateIP:PrivateIpAddress,
    State:State.Name,
    AZ:Placement.AvailabilityZone,
    Subnet:SubnetId,
    LaunchTime:LaunchTime,
    NodeGroup:Tags[?Key=='eks:nodegroup-name']|[0].Value
  }" --output table

# Get instance by pod IP
aws ec2 describe-instances \
  --filters "Name=network-interface.addresses.private-ip-address,Values=<pod-ip>" \
  --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Get ENIs of specific instance
aws ec2 describe-network-interfaces \
  --filters "Name=attachment.instance-id,Values=<instance-id>" \
  --query 'NetworkInterfaces[*].{ENI:NetworkInterfaceId,IP:PrivateIpAddress,Type:InterfaceType}' \
  --output table

# Check node resource allocation
kubectl describe nodes | grep -A 5 "Allocated resources"

# ============================================================================
# 5. KUBECTL NODE OPERATIONS
# ============================================================================

# Get external IPs of all nodes
kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="ExternalIP")].address}'

# Get internal IPs
kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}'

# Check node readiness
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}:{range .status.conditions[*]}{.type}={.status};{end}{"\n"}{end}' | grep "Ready=True"

# Get node with most pods
kubectl get pods --all-namespaces -o json | jq -r '.items[] | .spec.nodeName' | sort | uniq -c | sort -rn | head -1

# Get nodes with capacity info
kubectl get nodes -o custom-columns=NAME:.metadata.name,CPU:.status.capacity.cpu,MEMORY:.status.capacity.memory,PODS:.status.capacity.pods

# Cordon node (prevent new pods)
kubectl cordon <node-name>

# Drain node safely
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data

# Uncordon node
kubectl uncordon <node-name>

# ============================================================================
# 6. POD OPERATIONS & QUERIES
# ============================================================================

# Get pods on specific node
kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName=<node-name>

# Get running pods only
kubectl get pods -A --field-selector status.phase=Running

# Find pod by IP
kubectl get pods --all-namespaces -o wide | grep <ip-address>

# Get pods with high restart count
kubectl get pods -A -o json | jq -r '.items[] | select(.status.containerStatuses[]?.restartCount > 5) | "\(.metadata.namespace)/\(.metadata.name): \(.status.containerStatuses[].restartCount)"'

# Get pods not in Running state
kubectl get pods -A --field-selector=status.phase!=Running

# Copy file from pod
kubectl cp <namespace>/<pod-name>:<remote-path> <local-path>

# Copy file to pod
kubectl cp <local-path> <namespace>/<pod-name>:<remote-path>

# Execute command in pod
kubectl exec -it <pod-name> -n <namespace> -- /bin/bash

# Port forward to pod
kubectl port-forward <pod-name> <local-port>:<pod-port> -n <namespace>

# ============================================================================
# 7. RESOURCE MONITORING & METRICS
# ============================================================================

# Total memory usage across all pods
kubectl top pods -A --no-headers | awk '{sum += $4} END {print "Total Memory: " sum "Mi"}'

# Total CPU usage across all pods
kubectl top pods -A --no-headers | awk '{sum += $3} END {print "Total CPU: " sum "m"}'

# Memory usage by namespace
kubectl top pods -A --no-headers | awk '{ns[$1] += $4} END {for (n in ns) print n ": " ns[n] "Mi"}' | sort -t: -k2 -rn

# Top 10 pods by memory
kubectl top pods -A --no-headers | sort -k4 -rn | head -10

# Top 10 pods by CPU
kubectl top pods -A --no-headers | sort -k3 -rn | head -10

# Node resource usage
kubectl top nodes

# Pod usage on specific node
kubectl get pods -A --field-selector spec.nodeName=<node-name>,status.phase==Running -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name --no-headers | \
while read ns pod; do
  kubectl top pod $pod -n $ns --no-headers
done

# Get resource requests vs limits
kubectl get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,CPU_REQ:.spec.containers[*].resources.requests.cpu,MEM_REQ:.spec.containers[*].resources.requests.memory,CPU_LIM:.spec.containers[*].resources.limits.cpu,MEM_LIM:.spec.containers[*].resources.limits.memory

# ============================================================================
# 8. EKS-SPECIFIC COMPONENTS
# ============================================================================

# VPC CNI Configuration
# ---------------------

# Check CNI version
kubectl describe daemonset aws-node -n kube-system | grep Image

# Get current CNI settings
kubectl get daemonset aws-node -n kube-system -o yaml | grep -A 10 env:

# Set WARM_IP_TARGET
kubectl set env daemonset aws-node -n kube-system WARM_IP_TARGET=5

# Set WARM_ENI_TARGET
kubectl set env daemonset aws-node -n kube-system WARM_ENI_TARGET=1

# Enable prefix delegation
kubectl set env daemonset aws-node -n kube-system ENABLE_PREFIX_DELEGATION=true

# Set custom networking
kubectl set env daemonset aws-node -n kube-system AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG=true

# Verify CNI settings
kubectl get ds aws-node -n kube-system -o yaml | grep -E 'WARM_IP_TARGET|WARM_ENI_TARGET|ENABLE_PREFIX_DELEGATION'

# Check CNI metrics
kubectl get --raw /api/v1/namespaces/kube-system/pods/$(kubectl get pods -n kube-system -l k8s-app=aws-node -o jsonpath='{.items[0].metadata.name}'):61678/metrics

# CoreDNS Management
# ------------------

# Check CoreDNS version
kubectl describe deployment coredns -n kube-system | grep Image

# Get CoreDNS pods and locations
kubectl get pods -n kube-system -l eks.amazonaws.com/component=coredns -o wide

# Get CoreDNS configmap
kubectl get configmap coredns -n kube-system -o yaml

# Edit CoreDNS configuration
kubectl edit configmap coredns -n kube-system

# Scale CoreDNS replicas
kubectl scale deployment coredns -n kube-system --replicas=3

# Get CoreDNS metrics
COREDNS_POD=$(kubectl get pod -n kube-system -l eks.amazonaws.com/component=coredns -o jsonpath='{.items[0].metadata.name}')
kubectl get --raw /api/v1/namespaces/kube-system/pods/$COREDNS_POD:9153/proxy/metrics | grep -E 'coredns_dns_request|coredns_dns_response'

# Kube-proxy
# ----------

# Check kube-proxy version
kubectl describe daemonset kube-proxy -n kube-system | grep Image

# Get kube-proxy config
kubectl get configmap kube-proxy-config -n kube-system -o yaml

# Check kube-proxy mode (iptables vs ipvs)
kubectl logs -n kube-system -l k8s-app=kube-proxy | grep "Using"

# ============================================================================
# 9. COMPREHENSIVE LOG COLLECTION
# ============================================================================

# All CoreDNS logs
kubectl logs -n kube-system -l eks.amazonaws.com/component=coredns --all-containers=true --tail=100

# Save all CoreDNS logs to file
for pod in $(kubectl get pods -n kube-system -l k8s-app=kube-dns -o name); do
  echo "=== $pod ===" | tee -a coredns-logs.txt
  kubectl logs -n kube-system $pod -c coredns >> coredns-logs.txt
done

# All aws-node logs
for pod in $(kubectl get pods -n kube-system -l k8s-app=aws-node -o name); do
  echo "=== $pod ==="
  kubectl logs -n kube-system $pod --tail=50
done

# Save aws-node logs to file
kubectl logs -n kube-system -l k8s-app=aws-node --all-containers=true --tail=200 > aws-node-logs.txt

# Get logs from crashed pods
kubectl get pods -A --field-selector status.phase=Failed -o json | \
jq -r '.items[] | "\(.metadata.namespace) \(.metadata.name)"' | \
while read ns pod; do
  echo "=== $ns/$pod ==="
  kubectl logs -n $ns $pod --previous
done

# Get events sorted by time
kubectl get events -A --sort-by='.lastTimestamp' | tail -50

# Watch events in real-time
kubectl get events -A --watch

# ============================================================================
# 10. TROUBLESHOOTING COMMANDS
# ============================================================================

# Check cluster health
kubectl get componentstatuses
kubectl get --raw='/readyz?verbose'
kubectl cluster-info

# DNS troubleshooting pod
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- /bin/bash

# Test DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup kubernetes.default

# Check service endpoints
kubectl get endpoints -A

# Verify pod network connectivity
kubectl run tmp-shell --rm -i --tty --image nicolaka/netshoot -- /bin/bash
# Then inside: ping <pod-ip>

# Check RBAC permissions
kubectl auth can-i list pods --as=system:serviceaccount:<namespace>:<serviceaccount>

# Verify service account tokens
kubectl get serviceaccount <sa-name> -o yaml
kubectl get secret <sa-secret> -o jsonpath='{.data.token}' | base64 -d

# Check node conditions
kubectl get nodes -o json | jq '.items[] | {name: .metadata.name, conditions: .status.conditions}'

# Check for pod evictions
kubectl get events -A | grep Evicted

# Check for OOM kills
kubectl get pods -A -o json | jq -r '.items[] | select(.status.containerStatuses[]?.lastState.terminated.reason == "OOMKilled") | "\(.metadata.namespace)/\(.metadata.name)"'

# ============================================================================
# 11. SECURITY & IRSA (IAM Roles for Service Accounts)
# ============================================================================

# Create OIDC provider (required for IRSA)
eksctl utils associate-iam-oidc-provider --cluster <cluster-name> --approve

# Create IAM service account
eksctl create iamserviceaccount \
  --name my-service-account \
  --namespace default \
  --cluster <cluster-name> \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \
  --approve

# List IAM service accounts
eksctl get iamserviceaccount --cluster <cluster-name>

# Check service account annotations (should have eks.amazonaws.com/role-arn)
kubectl get sa <sa-name> -o yaml

# Verify pod identity
kubectl run test-irsa --image=amazon/aws-cli --command -- sleep 3600
kubectl exec test-irsa -- aws sts get-caller-identity

# ============================================================================
# 12. MAINTENANCE & UPGRADES
# ============================================================================

# Upgrade EKS control plane
eksctl upgrade cluster --name <cluster-name> --version 1.29 --approve

# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name <cluster-name>

# Update add-ons
aws eks update-addon --cluster-name <cluster-name> --addon-name vpc-cni --resolve-conflicts OVERWRITE

# Check if add-on needs update
aws eks describe-addon-versions --addon-name vpc-cni --kubernetes-version 1.29

# ============================================================================
# 13. CLEANUP COMMANDS
# ============================================================================

# Delete specific node group
eksctl delete nodegroup --cluster <cluster-name> --name <nodegroup-name> --drain=true

# Delete cluster (careful!)
eksctl delete cluster --name <cluster-name> --region us-east-1

# Force delete stuck namespace
kubectl delete namespace <namespace> --force --grace-period=0

# Clean up completed pods
kubectl delete pods --field-selector status.phase=Succeeded -A

# Clean up failed pods
kubectl delete pods --field-selector status.phase=Failed -A

# Remove evicted pods
kubectl get pods -A -o json | jq -r '.items[] | select(.status.reason == "Evicted") | "\(.metadata.namespace) \(.metadata.name)"' | xargs -n 2 kubectl delete pod -n

# ============================================================================
# 14. USEFUL ALIASES (Add to .bashrc or .zshrc)
# ============================================================================

# alias k='kubectl'
# alias kgp='kubectl get pods'
# alias kgpa='kubectl get pods -A'
# alias kgn='kubectl get nodes'
# alias kdp='kubectl describe pod'
# alias kdn='kubectl describe node'
# alias kl='kubectl logs'
# alias klf='kubectl logs -f'
# alias kex='kubectl exec -it'
# alias kctx='kubectl config current-context'
# alias kns='kubectl config set-context --current --namespace'

# ============================================================================
# 15. MONITORING & OBSERVABILITY
# ============================================================================

# Install metrics-server if not present
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Check if metrics-server is running
kubectl get deployment metrics-server -n kube-system

# Get pod logs with labels
kubectl logs -l app=myapp --tail=100 -n <namespace>

# Stream logs from multiple pods
kubectl logs -l app=myapp -f --all-containers=true -n <namespace>

# Get resource quotas
kubectl get resourcequota -A

# Get limit ranges
kubectl get limitrange -A

# Check PVC status
kubectl get pvc -A

# Check storage classes
kubectl get storageclass

# ============================================================================
# 16. NETWORK POLICIES & INGRESS
# ============================================================================

# Get all network policies
kubectl get networkpolicies -A

# Get all ingresses
kubectl get ingress -A

# Describe ingress
kubectl describe ingress <ingress-name> -n <namespace>

# Get services
kubectl get svc -A -o wide

# Check load balancer services
kubectl get svc -A -o wide | grep LoadBalancer

# ============================================================================
# END OF REFERENCE
# ============================================================================

```
##

### *_check EKS release_*
`curl -s https://docs.aws.amazon.com/eks/latest/userguide/doc-history.rss | grep "<title>Kubernetes version"`

### *_Create EKS Cluster_*
`eksctl create cluster --version=1.14 --name suhas-eks-test --region us-east-1 --zones us-east-1a,us-east-1b --node-type t2.medium --nodes 2 --ssh-access=true --ssh-public-key basarkod-test`

### *_Without any nodeGroup - Public_*
`eksctl create cluster --without-nodegroup --version=1.14 --name delete-me --vpc-public-subnets=subnet-123,subnet-456`

### *_Without any nodeGroup - PRIVATE_*
`eksctl create cluster --without-nodegroup --version=1.14 --name delete-me --vpc-public-subnets=subnet-abc,subnet-xyz`

### *_Scale the nodes to 2_*
`eksctl scale nodegroup --cluster delete-me --name ng-fe0ad48b --nodes 2 --region us-east-1`

### *_2 public Subnets_*
`eksctl create cluster --version=1.14 --name suhas-eks-test  --vpc-public-subnets=subnet-123,subnet-456 --node-type t2.medium --nodes 2 --ssh-access=true --ssh-public-key test-key`

### *_To create a cluster using 2x private and 2x public subnets_*
`eksctl create cluster --vpc-private-subnets=subnet-xxx,subnet-xxx --vpc-public-subnets=subnet-xxx,subnet-xxx --node-type t2.medium --nodes 2 --ssh-access=true --ssh-public-key basarkod-test`

### *_Get list of workerNodes belonging to a specific EKS Cluster created by eksctl (modify the tags for clusters launched via CFN)_*
`cluster_name="suhas-eks" && region="us-east-1"`

`aws ec2 describe-instances --region ${region} --query "Reservations[*].Instances[*].{PublicDnsName:PublicDnsName,PrivateDnsName:PrivateDnsName,PublicIP:PublicIpAddress,Instance:InstanceId,Subnet:SubnetId,ASGName:Tags[?Key=='aws:autoscaling:groupName']|[0].Value,NodeGroupName:Tags[?Key=='alpha.eksctl.io/nodegroup-name']|[0].Value,CFNStack:Tags[?Key=='aws:cloudformation:stack-id']|[0].Value}" --filters "Name=tag:kubernetes.io/cluster/${cluster_name},Values=owned"`

### *_Get ENI's of a specific instance_*
`aws ec2 describe-instances --instance-ids i-0c34061da1f8bf9ec --query "Reservations[*].Instances[*].NetworkInterfaces[*].{ENI:NetworkInterfaceId}"`

### *_Get InstanceID using pod's ip_*
`aws ec2 describe-instances --filters  Name=network-interface.addresses.private-ip-address,Values=<pod_ip>`

### *_Get ExternalIPs of all nodes_*
`kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="ExternalIP")].address}' `

### *_Check which nodes are ready_*
`JSONPATH='{range .items[*]}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}' && kubectl get nodes -o jsonpath="$JSONPATH" | grep "Ready=True"`

### *_Get Pods on a specific node_*
`kubectl get po -A -o wide --field-selector spec.nodeName=`

### *_Copy file from Pod to the workstation_*
`kubectl cp <namespace>/<pod name>:<file_path>`
EG: `kubectl cp default/test:/var/log/messages`

### *_Total memory usage of all the Pods_*
`kubectl top po -A | awk '{print $4}' | sed 1d | tr -d 'Mi' | awk 'BEGIN {total=0;}{total+=$1;}END {print "Total Memory Usage of all the Pods:",total, "Mi"}'`

### *_Total CPU usage of all the Pods_*
`kubectl top po -A | awk '{print $3}' | sed 1d | tr -d 'm' | awk 'BEGIN {total=0;}{total+=$1;}END {print "Total CPU Usage of all the Pods: ",total, "m"}'`

### *_Total memory usage of all the Pods on a specific node_*
`kubectl get po -A --field-selector spec.nodeName=<node_name>,status.phase==Running -o wide | sed 1d | awk '{print $1" "$2}' | while read namespace pod; do kubectl top pods --no-headers --namespace $namespace $pod; done | awk '{print $3}' | tr -d 'Mi' | awk 'BEGIN {total=0;}{total+=$1;}END {print "Total Memory Usage of all the Pods on this Node:",total, "Mi"}'`

### *_Total CPU usage of all the Pods on a specific node_*
`kubectl get po -A --field-selector spec.nodeName=<node_name>,status.phase==Running -o wide | sed 1d | awk '{print $1" "$2}' | while read namespace pod; do kubectl top pods --no-headers --namespace $namespace $pod; done | awk '{print $2}' | tr -d 'm' | awk 'BEGIN {total=0;}{total+=$1;}END {print "Total CPU Usage of all the Pods on this Node: ",total, "m"}'`

### *_Gets scheduler; controller-manager and etcd status_*
`kubectl get componentstatus`

### *_Set WARM_IP_TARGET_*
`kubectl set env daemonset aws-node -n kube-system WARM_IP_TARGET=10`

### *_Verify:_*
`kubectl get ds aws-node -n kube-system -o yaml | grep WARM_IP_TARGET`
`kubectl get ds aws-node -n kube-system -o yaml | grep -A1 WARM_IP_TARGET`

### *_Troubleshooting and information gathering:_*

1. List coredns pods and find which workers coredns is running on
`kubectl get pod -n kube-system -o wide -l eks.amazonaws.com/component=coredns`

2. Fetch the coredns pod name
`COREDNS_POD=$(kubectl get pod -n kube-system -l eks.amazonaws.com/component=coredns -o jsonpath='{.items[0].metadata.name}')`

3. Query the pod for metrics
`kubectl get --raw /api/v1/namespaces/kube-system/pods/$COREDNS_POD:9153/proxy/metrics | grep 'coredns_dns_request_count_total'`

4. Get coredns configmap file
`kubectl get cm coredns -o yaml -n kube-system `

5. Coredns logs
`for p in $(kubectl get pods --namespace=kube-system -l k8s-app=kube-dns -o name); do kubectl logs --namespace=kube-system $p; done`

6. Coredns deployment 
`kubectl -n kube-system get deploy coredns -o yaml`

### *_coreDNS version_*
`kubectl describe deployment coredns --namespace kube-system | grep Image | cut -d "/" -f 3`

### *_CNI version _*
`kubectl describe daemonset aws-node --namespace kube-system | grep Image | cut -d "/" -f 2`

### *_kube-proxy version_*
`kubectl describe daemonset kube-proxy --namespace kube-system | grep Image | cut -d "/" -f 3`

### *_CoreDns pods_*
`kubectl get po -n kube-system -l k8s-app=kube-dns -o wide`

### *_Extract logs from all the coreDNS pods into a file named corednslogs.txt_*
`for i in $(kubectl get pods --namespace=kube-system -l k8s-app=kube-dns -o name); do echo $i;kubectl logs -n kube-system $i -c coredns >> corednslogs.txt; done;`

### *_Pod logs for 'aws-node'_*
`for i in $(kubectl get pods -n kube-system -o wide -l k8s-app=aws-node | egrep "aws-node" | grep Running | awk '{print $1}'); do echo $i ; kubectl logs $i -n kube-system; echo; done`
