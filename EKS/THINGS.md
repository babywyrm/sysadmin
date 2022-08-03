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
