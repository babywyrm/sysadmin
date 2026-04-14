# Exposing Kubernetes Services on Amazon EKS
## A Security-Focused Guide (2026 Edition)

---

## Table of Contents

1. Architecture Overview
2. Prerequisites & Cluster Hardening Baseline
3. Deploying the Target Application
4. Level 1 — ClusterIP (Internal Only)
5. Level 2 — NodePort (Restricted Debug Access)
6. Level 3 — LoadBalancer with AWS Load Balancer Controller
7. Production Pattern — Ingress + ACM TLS
8. Live Service Patching
9. Reference Summary

---

## 1. Architecture Overview

Understanding the threat model of each service type before deploying is not optional — it determines your attack surface.

**ClusterIP**
Assigns a stable virtual IP routable only within the cluster network. Nothing outside the cluster can reach it directly. This is the correct default for all internal service communication.

**NodePort**
Opens a port in the range `30000–32767` on the network interface of every worker node in the cluster. This increases your attack surface proportionally to your node count. It should never be used in production and must be treated as a temporary debugging mechanism only.

**LoadBalancer**
Provisions an AWS load balancer (NLB or CLB) and wires it to your pods. Without additional hardening, the provisioned load balancer is publicly reachable from `0.0.0.0/0`. Source range restrictions and TLS termination are mandatory for any production workload.

**Key principle:** Always start with the least-permissive type (ClusterIP) and escalate only when you have a justified, documented reason.

---

## 2. Prerequisites & Cluster Hardening Baseline

### Required tooling

| Tool | Minimum Version | Purpose |
| :--- | :--- | :--- |
| `kubectl` | 1.29+ | Cluster interaction |
| `eksctl` or Terraform | Current | Cluster provisioning |
| AWS Load Balancer Controller | 2.7+ | NLB/ALB provisioning via annotations |
| AWS CLI | 2.x | IAM and resource inspection |

### AWS Load Balancer Controller

The in-tree cloud provider LoadBalancer support (Classic ELB) is deprecated. The AWS Load Balancer Controller is now the correct path for all EKS load balancer provisioning. Install it before proceeding with Section 6.

```bash
# Verify the controller is installed and healthy
kubectl get deployment -n kube-system aws-load-balancer-controller

# Expected output
NAME                           READY   UP-TO-DATE   AVAILABLE
aws-load-balancer-controller   2/2     2            2
```

Install instructions: [https://kubernetes-sigs.github.io/aws-load-balancer-controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller)

### Node Security Group baseline

Before any service exposure, confirm your worker node security groups follow least-privilege:

```bash
# Identify the security group attached to your managed node group
aws eks describe-nodegroup \
  --cluster-name my-cluster \
  --nodegroup-name my-nodegroup \
  --query 'nodegroup.resources.remoteAccessSecurityGroup' \
  --output text

# Audit inbound rules on that security group
aws ec2 describe-security-groups \
  --group-ids sg-xxxxxxxxxxxxxxxxx \
  --query 'SecurityGroups[*].IpPermissions'
```

Close any inbound rules that are not explicitly required before proceeding.

---

## 3. Deploying the Target Application

We use a pinned, non-root Nginx image throughout this guide. Using `nginx:latest` or `nginx:1.14.2` (end of life) in any environment is a security risk.

### 3.1 — Namespace isolation

Always deploy workloads into a dedicated namespace rather than `default`.

```bash
kubectl create namespace web-apps
```

### 3.2 — Deployment manifest

Create `nginx-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: web-apps
  labels:
    app: nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      # Run as a non-root user
      securityContext:
        runAsNonRoot: true
        runAsUser: 101        # nginx default non-root UID
        runAsGroup: 101
        fsGroup: 101

      # Do not mount service account tokens unless required
      automountServiceAccountToken: false

      containers:
        - name: nginx
          image: nginx:1.27-alpine   # pinned, minimal, actively maintained
          ports:
            - containerPort: 8080    # non-privileged port; requires nginx config adjustment
          resources:
            requests:
              cpu: "100m"
              memory: "64Mi"
            limits:
              cpu: "250m"
              memory: "128Mi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          # Required when readOnlyRootFilesystem is true
          volumeMounts:
            - name: nginx-cache
              mountPath: /var/cache/nginx
            - name: nginx-run
              mountPath: /var/run

      volumes:
        - name: nginx-cache
          emptyDir: {}
        - name: nginx-run
          emptyDir: {}
```

### 3.3 — Apply and verify

```bash
kubectl apply -f nginx-deployment.yaml

# Confirm pods are running with their assigned IPs
kubectl get pods -n web-apps -l app=nginx -o wide

# Confirm no pod is running as root
kubectl get pods -n web-apps -o json | \
  jq '.items[].spec.securityContext'
```

---

## 4. Level 1 — ClusterIP (Internal Only)

**Appropriate for:** Database connections, internal APIs, inter-service communication, anything that must never be reachable from outside the cluster.

### 4.1 — Manifest

Create `clusterip.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-clusterip
  namespace: web-apps
spec:
  type: ClusterIP
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
```

### 4.2 — Apply

```bash
kubectl apply -f clusterip.yaml

kubectl get service nginx-service-clusterip -n web-apps
```

```text
NAME                      TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
nginx-service-clusterip   ClusterIP   10.100.24.5    <none>        80/TCP    12s
```

### 4.3 — Verify internal reachability

```bash
# Launch a temporary debug pod in the same namespace
kubectl run curl-test \
  --image=curlimages/curl:8.7.1 \
  --rm -it \
  --restart=Never \
  -n web-apps \
  -- curl -s http://nginx-service-clusterip
```

Attempting to reach the ClusterIP from outside the cluster must fail. Confirm this from your workstation:

```bash
# This must time out - if it does not, your network policy is misconfigured
curl --connect-timeout 5 http://10.100.24.5
```

### 4.4 — Network Policy (required hardening)

Without a NetworkPolicy, any pod in the cluster can reach this service. Restrict it:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-nginx-ingress
  namespace: web-apps
spec:
  podSelector:
    matchLabels:
      app: nginx
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: frontend    # Only allow pods with this label
      ports:
        - protocol: TCP
          port: 8080
```

```bash
kubectl apply -f networkpolicy.yaml
```

### 4.5 — Cleanup

```bash
kubectl delete service nginx-service-clusterip -n web-apps
```

---

## 5. Level 2 — NodePort (Restricted Debug Access)

**Appropriate for:** Short-lived debugging sessions only. Not for production. Must be cleaned up immediately after use.

### 5.1 — Threat model

Opening a NodePort means:
- Every worker node in the cluster has a port open on its network interface
- If any worker node has a public IP or sits in a public subnet, that port is exposed to the internet unless the EC2 Security Group blocks it
- The EC2 Security Group is your only boundary — it is not managed by Kubernetes

### 5.2 — Manifest

Create `nodeport.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-nodeport
  namespace: web-apps
  annotations:
    # Document why this exists and who approved it
    ops.company.com/reason: "Temporary debug - ticket #1234"
    ops.company.com/expires: "2026-04-21"
spec:
  type: NodePort
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
      # Pin to a specific port for predictable Security Group rules.
      # If left unset, Kubernetes assigns a random port in 30000-32767.
      nodePort: 30080
```

### 5.3 — Apply and retrieve node addresses

```bash
kubectl apply -f nodeport.yaml

kubectl get service nginx-service-nodeport -n web-apps
```

Get the appropriate node IP based on your subnet type:

```bash
# Public subnet nodes
kubectl get nodes -o wide | awk 'NR>1 {print $1, $7}' | column -t

# Private subnet nodes (requires VPN or bastion)
kubectl get nodes -o wide | awk 'NR>1 {print $1, $6}' | column -t
```

### 5.4 — Security Group update (mandatory before access)

```bash
# Allow your specific IP only — never open to 0.0.0.0/0
MY_IP=$(curl -s https://checkip.amazonaws.com)

aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxxxxxxxxxx \
  --protocol tcp \
  --port 30080 \
  --cidr "${MY_IP}/32" \
  --tag-specifications \
    'ResourceType=security-group-rule,Tags=[{Key=reason,Value=debug-ticket-1234}]'
```

### 5.5 — Cleanup (do not skip)

Remove both the Kubernetes service and the Security Group rule:

```bash
kubectl delete service nginx-service-nodeport -n web-apps

# Retrieve and revoke the security group rule
aws ec2 describe-security-group-rules \
  --filters Name=group-id,Values=sg-xxxxxxxxxxxxxxxxx \
  --query 'SecurityGroupRules[?FromPort==`30080`].SecurityGroupRuleId' \
  --output text | xargs -I{} aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxxxxxxxxxxxxx \
  --security-group-rule-ids {}
```

---

## 6. Level 3 — LoadBalancer with AWS Load Balancer Controller

**Appropriate for:** Production traffic. Requires the AWS Load Balancer Controller (Section 2).

The in-tree annotation `service.beta.kubernetes.io/aws-load-balancer-type: nlb` is deprecated. Use the external controller annotation set below.

### 6.1 — Manifest

Create `loadbalancer.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-nlb
  namespace: web-apps
  annotations:
    # Use the AWS Load Balancer Controller (not the deprecated in-tree provider)
    service.beta.kubernetes.io/aws-load-balancer-type: "external"
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: "ip"
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internet-facing"

    # Enable cross-zone load balancing
    service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"

    # Tag the NLB for cost allocation and audit trails
    service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags: >-
      Environment=production,
      Team=platform,
      ManagedBy=kubernetes
spec:
  type: LoadBalancer

  # Restrict source IPs at the NLB level.
  # Replace with your actual CIDR ranges. Never leave this as 0.0.0.0/0
  # unless you have WAF or Ingress handling access control upstream.
  loadBalancerSourceRanges:
    - "203.0.113.0/24"    # Example: corporate egress range

  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
```

### 6.2 — Apply and monitor provisioning

```bash
kubectl apply -f loadbalancer.yaml

# Watch until EXTERNAL-IP is populated (takes 2-5 minutes)
kubectl get service nginx-service-nlb -n web-apps -w
```

### 6.3 — Verify

```bash
export LB_HOST=$(kubectl get svc nginx-service-nlb \
  -n web-apps \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

echo "Load balancer hostname: ${LB_HOST}"

curl -s "http://${LB_HOST}" | grep -i title
```

### 6.4 — Verify source range enforcement

From a machine outside the allowed CIDR, the connection should be refused or time out:

```bash
# Should fail if run from outside loadBalancerSourceRanges
curl --connect-timeout 5 "http://${LB_HOST}"
```

### 6.5 — Cleanup

```bash
kubectl delete service nginx-service-nlb -n web-apps
```

Confirm the NLB was deprovisioned in AWS — do not assume Kubernetes cleanup is sufficient:

```bash
aws elbv2 describe-load-balancers \
  --query 'LoadBalancers[?contains(LoadBalancerName, `nginx`)].[LoadBalancerArn,State.Code]' \
  --output table
```

---

## 7. Production Pattern — Ingress + ACM TLS

For production HTTP/HTTPS workloads, a bare `LoadBalancer` service is not the recommended pattern. Use an AWS Application Load Balancer (ALB) Ingress with TLS termination at the load balancer using an ACM certificate.

### 7.1 — Manifest

Create `ingress-tls.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx-ingress
  namespace: web-apps
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip

    # ACM certificate ARN — terminate TLS at the ALB
    alb.ingress.kubernetes.io/certificate-arn: >-
      arn:aws:acm:us-east-1:123456789012:certificate/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

    # Redirect HTTP to HTTPS
    alb.ingress.kubernetes.io/ssl-redirect: "443"

    # Enforce TLS 1.2 minimum
    alb.ingress.kubernetes.io/ssl-policy: ELBSecurityPolicy-TLS13-1-2-2021-06

    # Restrict inbound CIDRs at the ALB level
    alb.ingress.kubernetes.io/inbound-cidrs: "203.0.113.0/24"

    # Enable WAF integration if available
    # alb.ingress.kubernetes.io/wafv2-acl-arn: arn:aws:wafv2:...

spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: nginx-service-clusterip
                port:
                  number: 80
```

```bash
kubectl apply -f ingress-tls.yaml

kubectl get ingress nginx-ingress -n web-apps -w
```

---

## 8. Live Service Patching

Patching a service type in place is possible but carries risk — particularly when patching from ClusterIP to LoadBalancer on a production service, as it immediately provisions a public AWS resource.

```bash
# Review the current state before patching
kubectl get svc my-nginx -n web-apps -o yaml

# Patch the service type
kubectl patch svc my-nginx \
  -n web-apps \
  -p '{"spec": {"type": "LoadBalancer"}}'

# Apply source ranges immediately after — do not leave this step for later
kubectl patch svc my-nginx \
  -n web-apps \
  -p '{"spec": {"loadBalancerSourceRanges": ["203.0.113.0/24"]}}'

# Monitor the transition
kubectl get svc my-nginx -n web-apps -w
```

**Note:** If you need to patch both the type and source ranges together, combine them into a single patch to avoid a window where the load balancer is public with no source restrictions:

```bash
kubectl patch svc my-nginx -n web-apps -p '{
  "spec": {
    "type": "LoadBalancer",
    "loadBalancerSourceRanges": ["203.0.113.0/24"]
  }
}'
```

---

## 9. Reference Summary

### Service type comparison

| Attribute | ClusterIP | NodePort | LoadBalancer (NLB) | Ingress (ALB) |
| :--- | :--- | :--- | :--- | :--- |
| Externally reachable | No | Yes (via node IP) | Yes (via AWS DNS) | Yes (via AWS DNS) |
| AWS resource created | None | None | NLB | ALB |
| Hourly AWS cost | None | None | Yes | Yes |
| TLS termination | No | No | Passthrough only | Yes (ACM) |
| Source IP restriction | NetworkPolicy | Security Group (manual) | `loadBalancerSourceRanges` | `inbound-cidrs` annotation |
| Appropriate for production | Yes (internal) | No | Limited | Yes |
| Attack surface | Minimal | High | Medium | Medium (with WAF: Low) |

### Security checklist before exposing any service

```text
[ ] Workload runs as non-root with a read-only filesystem
[ ] Resource limits are defined on all containers
[ ] NetworkPolicy restricts pod-to-pod traffic
[ ] Service type is the minimum required for the use case
[ ] LoadBalancer source ranges are defined (not 0.0.0.0/0)
[ ] NodePort Security Group rules are scoped to specific CIDRs
[ ] TLS is terminated at the load balancer with a valid ACM certificate
[ ] AWS Load Balancer Controller is used (not the deprecated in-tree provider)
[ ] NLB/ALB resources are tagged for cost allocation and audit
[ ] Cleanup of temporary services and Security Group rules is confirmed
```

### Quick reference commands

```bash
# List all services and their types across all namespaces
kubectl get svc -A -o custom-columns=\
'NAMESPACE:metadata.namespace,NAME:metadata.name,TYPE:spec.type,CLUSTER-IP:spec.clusterIP,EXTERNAL-IP:status.loadBalancer.ingress[0].hostname,PORT:spec.ports[0].port'

# Find all LoadBalancer services (i.e., services creating AWS resources)
kubectl get svc -A --field-selector spec.type=LoadBalancer

# Find services with no source range restriction
kubectl get svc -A -o json | \
  jq -r '.items[] |
    select(.spec.type == "LoadBalancer") |
    select(.spec.loadBalancerSourceRanges == null or
           (.spec.loadBalancerSourceRanges | length == 0)) |
    [.metadata.namespace, .metadata.name] | @tsv'

# Audit all NodePort services
kubectl get svc -A --field-selector spec.type=NodePort

# Get the external hostname of a LoadBalancer service
kubectl get svc my-service -n my-namespace \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

##
##

# 🌐 Exposing Kubernetes Services on Amazon EKS: The Definitive Guide

This document provides a step-by-step walkthrough for exposing applications running on Amazon EKS. Unlike standard documentation, this guide emphasizes **Security Posture** and **Real-world Context** for every configuration.

---

## 📑 Table of Contents
1.  **Concept Overview:** Understanding the three Service Types.
2.  **Preparation:** Deploying the Target Application.
3.  **Level 1: Internal Access (ClusterIP)** - *Secure, private communication.*
4.  **Level 2: Host Access (NodePort)** - *Direct debugging access.*
5.  **Level 3: Public Access (LoadBalancer)** - *Production traffic management.*
6.  **Advanced: Live Patching** - *Changing types on the fly.*
7.  **Executive Summary & Recap** - *The "Cheat Sheet" takeaway.*

---

## 1. 🧠 Concept Overview

Before running commands, it is critical to understand the architecture:

*   **ClusterIP (Default):** Assigns a stable, internal Virtual IP.
    *   *Analogy:* Calling an extension on an office phone system. You must be in the building to dial it.
*   **NodePort:** Opens a specific TCP port (e.g., 30005) on the physical network interface of *every* server in the cluster.
    *   *Analogy:* Drilling a hole through the wall of every room in the building. Anyone standing outside can shout through it.
*   **LoadBalancer:** Automates the creation of an AWS Elastic Load Balancer (ELB/NLB) to route internet traffic to your pods.
    *   *Analogy:* Hiring a receptionist to greet visitors at the front door and guide them to the right room.

---

## 2. 🏗️ Preparation: Deploying the Target

We require a running application to expose. We will use Nginx.

**Step 2.1: Define the Deployment**
Create a file named `nginx-deployment.yaml`. This tells Kubernetes to run two copies (replicas) of Nginx.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
```

**Step 2.2: Launch and Verify**
```bash
# Apply the configuration
kubectl apply -f nginx-deployment.yaml

# Confirm the pods have started and have internal IPs
kubectl get pods -l 'app=nginx' -o wide
```
*Result:* You should see two pods listed as `Running`.

---

## 3. 🔒 Level 1: Internal Access (ClusterIP)
*Best for: Database connections, backend APIs, internal microservice traffic.*

**Step 3.1: The Configuration**
Create `clusterip.yaml`. This abstract service will load balance traffic between your two Nginx pods.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-cluster-ip
spec:
  type: ClusterIP      # <--- The default type if unspecified
  selector:
    app: nginx         # <--- Must match the label in your Deployment
  ports:
    - protocol: TCP
      port: 80         # Port the Service listens on
      targetPort: 80   # Port the Container listens on
```

**Step 3.2: Execution**
```bash
kubectl apply -f clusterip.yaml
kubectl get service nginx-service-cluster-ip
```

**Step 3.3: Verification**
You will see a `CLUSTER-IP` (e.g., `10.100.24.5`).
*   **Observation:** If you try to `curl` this IP from your laptop, it will fail. This works as designed.
*   **Testing:** You must be inside a pod in the cluster to access this IP.

**🛡️ Security Check:** This is the most secure Service type. It exposes zero surface area to the public internet.

**Cleanup:**
```bash
kubectl delete service nginx-service-cluster-ip
```

---

## 4. ⚠️ Level 2: Host Access (NodePort)
*Best for: Temporary debugging, monitoring agents, or custom ingress controllers.*

**Step 4.1: The Configuration**
Create `nodeport.yaml`.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-nodeport
spec:
  type: NodePort       # <--- Exposes on the physical node IP
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
      # nodePort: 30000  <--- Optional: You can request a specific port
```

**Step 4.2: Execution**
```bash
kubectl apply -f nodeport.yaml
kubectl get service nginx-service-nodeport
```
*Look for output like:* `80:31542/TCP`. The number `31542` is your "Node Port."

**Step 4.3: Accessing the Application**
To use this, you need the IP address of the AWS EC2 instance (the Node).

```bash
# For Public Subnets:
kubectl get nodes -o wide | awk {'print $1" " $7'} 

# For Private Subnets (VPN Access required):
kubectl get nodes -o wide | awk {'print $1" " $6'}
```

**🛡️ Security Critical Warning:**
In EKS, AWS Security Groups usually block ports 30000-32767 by default.
*   **Action:** You must edit the EC2 Security Group for your worker nodes to allow Inbound TCP traffic on the specific port shown above.
*   **Risk:** Do not leave these ports open permanently.

**Cleanup:**
```bash
kubectl delete service nginx-service-nodeport
```

---

## 5. ☁️ Level 3: Public Access (LoadBalancer)
*Best for: Production HTTP/HTTPS traffic.*

**Step 5.1: The Configuration (With Security Best Practices)**
Create `loadbalancer.yaml`. Unlike standard examples, we will use the newer Network Load Balancer (NLB) and restrict access.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-loadbalancer
  annotations:
    # Optimizes performance on AWS
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
spec:
  type: LoadBalancer
  
  # SECURITY: Limit who can access this Load Balancer.
  # If omitted, the entire internet (0.0.0.0/0) can access it.
  # Example: Only allow your corporate VPN IP.
  loadBalancerSourceRanges:
    - "203.0.113.50/32" 
    
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
```

**Step 5.2: Execution**
```bash
kubectl apply -f loadbalancer.yaml

# Watch the creation process
kubectl get service nginx-service-loadbalancer -w
```

**Step 5.3: Verification**
It takes AWS 2-5 minutes to provision the hardware. Eventually, `EXTERNAL-IP` will change from `<pending>` to a long URL ending in `.elb.amazonaws.com`.

```bash
export LB_HOST=$(kubectl get svc nginx-service-loadbalancer -o jsonpath='{.status.loadBalancer.ingress[*].hostname}')
curl -s "http://${LB_HOST}" | grep title
```

**Cleanup:**
```bash
kubectl delete service nginx-service-loadbalancer
```

---

## 6. 🔄 Advanced: Live Patching
Did you accidentally create a `ClusterIP` service but now need to expose it publicly? You do not need to delete and recreate it.

```bash
# 1. Check current status
kubectl get svc my-nginx

# 2. Patch the spec live
kubectl patch svc my-nginx -p '{"spec": {"type": "LoadBalancer"}}'

# 3. Watch the transformation
kubectl get svc my-nginx -w
```

---

## 7. 📝 Executive Summary & Recap

| Feature | ClusterIP | NodePort | LoadBalancer |
| :--- | :--- | :--- | :--- |
| **Visibility** | **Private** (Cluster Only) | **Semi-Public** (Node IP) | **Public** (Internet) |
| **AWS Resource** | None (Virtual iptables) | None (Opens Host Port) | Creates AWS ELB/NLB |
| **Cost** | Free | Free | **$$$** (Hourly AWS Cost) |
| **Security Risk** | 🟢 Low | 🔴 High (Requires SG management) | 🟡 Medium (Manage SourceRanges) |
| **Use Case** | DBs, Backend APIs | Debugging, Ops Tools | Frontend Web Apps |

### ✅ Top 3 Takeaways
1.  **Default to ClusterIP:** Always start with ClusterIP unless you explicitly need external access.
2.  **Use Source Ranges:** When using `LoadBalancer`, always use `loadBalancerSourceRanges` to prevent the entire internet from scanning your app.
3.  **Prefer NLB:** On EKS, use the annotation `service.beta.kubernetes.io/aws-load-balancer-type: nlb` for better performance and modern features compared to the "Classic" ELB.

##
##

https://aws.amazon.com/premiumsupport/knowledge-center/eks-kubernetes-services-cluster/

##
#

 How do I expose the Kubernetes services running on my Amazon EKS cluster?

Last updated: 2022-08-17

I want to expose the Kubernetes services running on my Amazon Elastic Kubernetes Service (Amazon EKS) cluster.
Short description

To expose the Kubernetes services running on your cluster, create a sample application. Then, apply the ClusterIP, NodePort, and LoadBalancer Kubernetes ServiceTypes to your sample application.

Keep in mind the following:

    ClusterIP exposes the service on a cluster's internal IP address.
    NodePort exposes the service on each node’s IP address at a static port.
    LoadBalancer exposes the service externally using a load balancer.

Note: Amazon EKS supports the Network Load Balancer and the Classic Load Balancer for pods running on Amazon Elastic Compute Cloud (Amazon EC2) instance worker nodes. Amazon EKS provides this support by using the LoadBalancer. You can load balance network traffic to a Network Load Balancer (instance or IP targets) or a Classic Load Balancer (instance target only).
Resolution
Create a sample application

1.    Define and apply a deployment file. The following example creates a ReplicaSet that spins up two nginx pods, and then creates filed called nginx-deployment.yaml.

cat <<EOF > nginx-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
EOF

2.    Create the deployment:

kubectl apply -f nginx-deployment.yaml

3.    Verify that your pods are running and have their own internal IP addresses:

kubectl get pods -l 'app=nginx' -o wide | awk {'print $1" " $3 " " $6'} | column -t

Output:

NAME                               STATUS   IP
nginx-deployment-574b87c764-hcxdg  Running  192.168.20.8
nginx-deployment-574b87c764-xsn9s  Running  192.168.53.240

Create a ClusterIP service

1.    Create a file called clusterip.yaml, and then set type to ClusterIP. For example:

cat <<EOF > clusterip.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-cluster-ip
spec:
  type: ClusterIP
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
EOF

2.    Create the ClusterIP object in Kubernetes using either a declarative or imperative command.

To create the object and apply the clusterip.yaml file, run the following declarative command:

kubectl create -f clusterip.yaml

Output:

service/nginx-service-cluster-ip created

-or-

To expose a deployment of ClusterIP type, run the following imperative command:

kubectl expose deployment nginx-deployment  --type=ClusterIP  --name=nginx-service-cluster-ip

Output:

service "nginx-service-cluster-ip" exposed

Note: The expose command creates a service without creating a YAML file. However, kubectl translates your imperative command into a declarative Kubernetes Deployment object.

3.    Access the application and get the ClusterIP number:

kubectl get service nginx-service-cluster-ip

Output:

NAME                       TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
nginx-service-cluster-ip   ClusterIP   10.100.12.153   <none>        80/TCP    23s

4.    Delete the ClusterIP service:

kubectl delete service nginx-service-cluster-ip

Output:

service "nginx-service-cluster-ip" deleted

Create a NodePort service

1.    To create a NodePort service, create a file called nodeport.yaml, and then set type to NodePort. For example:

cat <<EOF > nodeport.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-nodeport
spec:
  type: NodePort
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
EOF

2.    Create the NodePort object in Kubernetes using either a declarative or imperative command.

To create the object and apply the nodeport.yaml file, run the following declarative command:

kubectl create -f nodeport.yaml

-or-

To expose a deployment of NodePort type, run the following imperative command:

kubectl expose deployment nginx-deployment  --type=NodePort  --name=nginx-service-nodeport

Output:

service/nginx-service-nodeport exposed

3.    Get information about nginx-service:

kubectl get service/nginx-service-nodeport

Output:

NAME                     TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
nginx-service-nodeport   NodePort   10.100.106.151   <none>        80:30994/TCP   27s

Important: The ServiceType is a NodePort and ClusterIP that are created automatically for the service. The output from the preceding command shows that the NodePort service is exposed externally on the port (30994) of the available worker node's EC2 instance. Before you access NodeIP:NodePort from outside the cluster, you must set the security group of the nodes to allow incoming traffic. You can allow incoming traffic through the port (30994) that's listed in the output of the preceding kubectl get service command.

4.    If the node is in a public subnet and is reachable from the internet, check the node’s public IP address:

kubectl get nodes -o wide |  awk {'print $1" " $2 " " $7'} | column -t

Output:

NAME                                      STATUS  EXTERNAL-IP
ip-10-0-3-226.eu-west-1.compute.internal  Ready   1.1.1.1
ip-10-1-3-107.eu-west-1.compute.internal  Ready   2.2.2.2

-or-

If the node is in a private subnet and is reachable only inside or through a VPC, then check the node’s private IP address:

kubectl get nodes -o wide |  awk {'print $1" " $2 " " $6'} | column -t

Output:

NAME                                      STATUS  INTERNAL-IP
ip-10-0-3-226.eu-west-1.compute.internal  Ready   10.0.3.226
ip-10-1-3-107.eu-west-1.compute.internal  Ready   10.1.3.107

5.     Delete the NodePort service:

kubectl delete service nginx-service-nodeport

Output:

service "nginx-service-nodeport" deleted

Create a LoadBalancer service

1.    To create a LoadBalancer service, create a file called loadbalancer.yaml, and then set type to LoadBalancer. For example:

cat <<EOF > loadbalancer.yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-loadbalancer
spec:
  type: LoadBalancer
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
EOF

2.    Apply the loadbalancer.yaml file:

kubectl create -f loadbalancer.yaml

Output:

service/nginx-service-loadbalancer created

-or-

Expose a deployment of LoadBalancer type:

kubectl expose deployment nginx-deployment  --type=LoadBalancer  --name=nginx-service-loadbalancer

Output:

service "nginx-service-loadbalancer" exposed

3.    Get information about nginx-service:

kubectl get service/nginx-service-loadbalancer |  awk {'print $1" " $2 " " $4 " " $5'} | column -t

Output:

NAME                        TYPE          EXTERNAL-IP                        PORT(S)
nginx-service-loadbalancer  LoadBalancer  *****.eu-west-1.elb.amazonaws.com  80:30039/TCP

4.    Verify that you can access the load balancer externally:

curl -silent *****.eu-west-1.elb.amazonaws.com:80 | grep title

You should receive the following output between HTML title tags: "Welcome to nginx!"

5.    Delete the LoadBalancer service:

kubectl delete service nginx-service-loadbalancer

Output:

service "nginx-service-loadbalancer" deleted

Note: By default, the preceding LoadBalancer service creates a Classic Load Balancer.

6.    To create a Network Load Balancer with an instance type target, add the following annotation to the service manifest:

service.beta.kubernetes.io/aws-load-balancer-type: nlb

 
 ##################
#############################
 ##################
 
 #
 # 
 
 Exposing the Service

For some parts of your applications you may want to expose a Service onto an external IP address. Kubernetes supports two ways of doing this: NodePort and LoadBalancer.

kubectl -n my-nginx get svc my-nginx

Output


NAME       TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)   AGE
my-nginx   ClusterIP   10.100.225.196   <none>        80/TCP    33m

Currently the Service does not have an External IP, so let’s now patch the Service to use a cloud load balancer, by updating the type of the my-nginx Service from ClusterIP to LoadBalancer:

kubectl -n my-nginx patch svc my-nginx -p '{"spec": {"type": "LoadBalancer"}}'

We can check for the changes:

kubectl -n my-nginx get svc my-nginx

Output


NAME       TYPE           CLUSTER-IP       EXTERNAL-IP                                                             PORT(S)        AGE
my-nginx   LoadBalancer   10.100.225.196   aca434079a4cb0a9961170c1-23367063.us-west-2.elb.amazonaws.com           80:30470/TCP   39m

The Load Balancer can take a couple of minutes in being available on the DNS.

Now, let’s try if it’s accessible.

export loadbalancer=$(kubectl -n my-nginx get svc my-nginx -o jsonpath='{.status.loadBalancer.ingress[*].hostname}')

curl -k -s http://${loadbalancer} | grep title

Output


<title>Welcome to nginx!</title>

If the Load Balancer name is too long to fit in the standard kubectl get svc output, you’ll need to do kubectl describe service my-nginx to see it. You’ll see something like this:

kubectl -n my-nginx describe service my-nginx | grep Ingress

Output


LoadBalancer Ingress:   a320587ffd19711e5a37606cf4a74574-1142138393.us-east-1.elb.amazonaws.com

