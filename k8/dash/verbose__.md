# The Complete Kubernetes Command-Line Observatory: Enhanced Edition

## Table of Contents
1. [Quick Health Checks (30-Second Scan)](#1-quick-health-checks)
2. [Resource Consumption Analysis](#2-resource-consumption-analysis)
3. [Pod Health & Lifecycle Diagnostics](#3-pod-health--lifecycle-diagnostics)
4. [Node-Level Infrastructure Analysis](#4-node-level-infrastructure-analysis)
5. [Event Stream Analysis](#5-event-stream-analysis)
6. [Network & Service Mesh Diagnostics](#6-network--service-mesh-diagnostics)
7. [Storage & PersistentVolume Analysis](#7-storage--persistentvolume-analysis)
8. [Security & RBAC Auditing](#8-security--rbac-auditing)
9. [Advanced JSONPath Queries](#9-advanced-jsonpath-queries)
10. [Production-Ready Dashboard Scripts](#10-production-ready-dashboard-scripts)

---

## 1. Quick Health Checks (30-Second Scan)

| **Purpose** | **Command** | **What It Shows** |
|------------|-------------|-------------------|
| Cluster-wide pod status | `kubectl get pods -A` | All pods across all namespaces |
| Find broken pods instantly | `kubectl get pods -A --field-selector=status.phase!=Running` | Only non-Running pods (Pending, Failed, CrashLoop) |
| Node health summary | `kubectl get nodes` | Node status (Ready/NotReady) |
| API server responsiveness | `kubectl cluster-info` | Control plane endpoints and health |
| Component health | `kubectl get componentstatuses` | etcd, scheduler, controller-manager status |

### The "First Responder" One-Liner
```bash
kubectl get pods -A -o wide | grep -vE 'Running|Completed'
```
*This shows every pod that isn't healthy, with its Node assignment.*

---

## 2. Resource Consumption Analysis

### A. Real-Time Resource Usage

| **Metric** | **Command** | **Use Case** |
|-----------|-------------|--------------|
| Top CPU consumers | `kubectl top pods -A --sort-by=cpu` | Find runaway processes |
| Top Memory consumers | `kubectl top pods -A --sort-by=memory` | Identify memory leaks |
| Per-node resource usage | `kubectl top nodes` | Find overloaded nodes |
| Container-level metrics | `kubectl top pod <pod-name> --containers -n <namespace>` | Multi-container pod breakdown |

### B. Resource Allocation vs. Usage

**Show Requested vs. Actual Usage:**
```bash
kubectl get pods -A -o custom-columns=\
"NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
CPU_REQ:.spec.containers[*].resources.requests.cpu,\
CPU_LIM:.spec.containers[*].resources.limits.cpu,\
MEM_REQ:.spec.containers[*].resources.requests.memory,\
MEM_LIM:.spec.containers[*].resources.limits.memory"
```

**Find Pods Without Resource Limits (Dangerous in Production):**
```bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].resources.limits == null) | "\(.metadata.namespace)/\(.metadata.name)"'
```
*Requires `jq` but shows pods that can OOMKill the entire node.*

### C. Node Capacity Analysis

**Show Total Allocatable Resources per Node:**
```bash
kubectl describe nodes | grep -A 5 "Allocated resources"
```

**Calculate Node Pressure (Advanced):**
```bash
kubectl get nodes -o custom-columns=\
"NODE:.metadata.name,\
CPU_CAPACITY:.status.capacity.cpu,\
MEM_CAPACITY:.status.capacity.memory,\
CPU_ALLOC:.status.allocatable.cpu,\
MEM_ALLOC:.status.allocatable.memory"
```

---

## 3. Pod Health & Lifecycle Diagnostics

### A. Restart & Crash Analysis

| **Scenario** | **Command** | **What to Look For** |
|-------------|-------------|---------------------|
| Find crashlooping pods | `kubectl get pods -A --sort-by='.status.containerStatuses[0].restartCount'` | Restart count > 5 |
| Show restart reasons | `kubectl describe pod <pod> -n <ns> \| grep "Last State"` | "OOMKilled", "Error", "Completed" |
| Get exit codes | `kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[0].lastState.terminated.exitCode}{"\n"}{end}'` | Exit code 137 = OOMKilled, 1 = General error |

**The "Autopsy" Command (Why Did It Die?):**
```bash
kubectl describe pod <pod-name> -n <namespace> | grep -A 10 "Last State"
```

### B. Pod Age & Uptime Analysis

**Find Oldest Running Pods:**
```bash
kubectl get pods -A --sort-by=.metadata.creationTimestamp
```

**Find Recently Created Pods (Deployment Rollout Tracking):**
```bash
kubectl get pods -A --sort-by=.metadata.creationTimestamp | tail -n 10
```

### C. Container Image Analysis

**List All Images Running in Cluster:**
```bash
kubectl get pods -A -o jsonpath="{.items[*].spec.containers[*].image}" | tr -s '[[:space:]]' '\n' | sort | uniq -c
```

**Find Pods Using "latest" Tag (Anti-Pattern):**
```bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].image | contains(":latest")) | "\(.metadata.namespace)/\(.metadata.name)"'
```

---

## 4. Node-Level Infrastructure Analysis

### A. Node Resource Pressure

| **Condition** | **Command** | **Meaning** |
|--------------|-------------|-------------|
| Memory Pressure | `kubectl describe nodes \| grep -i "MemoryPressure"` | Node is running out of RAM |
| Disk Pressure | `kubectl describe nodes \| grep -i "DiskPressure"` | Node disk is >85% full |
| PID Pressure | `kubectl describe nodes \| grep -i "PIDPressure"` | Too many processes running |

**Find Nodes Under Pressure:**
```bash
kubectl get nodes -o json | jq -r '.items[] | select(.status.conditions[] | select(.type=="MemoryPressure" and .status=="True")) | .metadata.name'
```

### B. Node Taints & Tolerations

**Show All Node Taints:**
```bash
kubectl get nodes -o custom-columns="NAME:.metadata.name,TAINTS:.spec.taints[*].key"
```

**Find Pods Scheduled on Tainted Nodes:**
```bash
kubectl get pods -A -o wide | grep <node-name>
```

### C. Node Kubelet Logs

**Check Node System Health (Requires Node SSH):**
```bash
# On the node itself:
journalctl -u kubelet -n 100 --no-pager
```

---

## 5. Event Stream Analysis

### A. Real-Time Event Monitoring

**Watch Events Live (Like `tail -f`):**
```bash
kubectl get events -A --watch
```

**Show Last 20 Events by Timestamp:**
```bash
kubectl get events -A --sort-by='.lastTimestamp' | tail -n 20
```

### B. Filtered Event Queries

| **Filter** | **Command** | **Purpose** |
|-----------|-------------|-------------|
| Errors only | `kubectl get events -A \| grep -i error` | Find failures |
| Warnings only | `kubectl get events -A \| grep -i warning` | Pre-failure indicators |
| OOM events | `kubectl get events -A \| grep -i "OOMKilled"` | Memory exhaustion |
| Failed scheduling | `kubectl get events -A \| grep -i "FailedScheduling"` | Resource constraints |
| Image pull failures | `kubectl get events -A \| grep -i "ImagePullBackOff"` | Registry issues |

**Count Event Types (Statistical View):**
```bash
kubectl get events -A -o json | jq -r '.items[].reason' | sort | uniq -c | sort -rn
```

### C. Per-Object Event Tracking

**Events for a Specific Pod:**
```bash
kubectl describe pod <pod-name> -n <namespace> | grep -A 20 "Events:"
```

**Events for a Deployment:**
```bash
kubectl describe deployment <deployment-name> -n <namespace> | grep -A 20 "Events:"
```

---

## 6. Network & Service Mesh Diagnostics

### A. Service & Endpoint Health

| **Check** | **Command** | **What It Reveals** |
|----------|-------------|---------------------|
| All services | `kubectl get svc -A` | ClusterIP, LoadBalancer status |
| Service endpoints | `kubectl get endpoints -A` | Backend pods for each service |
| Services without endpoints | `kubectl get svc -A -o json \| jq -r '.items[] \| select(.spec.selector != null) \| select(.metadata.name as $svc \| (.metadata.namespace + "/" + $svc) as $key \| $key)' \| while read svc; do kubectl get endpoints ${svc##*/} -n ${svc%%/*} -o json \| jq -e '.subsets == null' > /dev/null && echo $svc; done` | Broken service selectors |

**Find Services with No Healthy Backends:**
```bash
kubectl get endpoints -A -o json | jq -r '.items[] | select(.subsets == null or .subsets == []) | "\(.metadata.namespace)/\(.metadata.name)"'
```

### B. Ingress & Load Balancer Analysis

**Show All Ingress Rules:**
```bash
kubectl get ingress -A -o wide
```

**Find Ingress Without Backends:**
```bash
kubectl describe ingress -A | grep -B 5 "Default backend"
```

### C. DNS Troubleshooting

**Test CoreDNS Health:**
```bash
kubectl get pods -n kube-system -l k8s-app=kube-dns
```

**DNS Resolution Test from Inside Cluster:**
```bash
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup kubernetes.default
```

---

## 7. Storage & PersistentVolume Analysis

### A. Volume Health Checks

| **Resource** | **Command** | **Purpose** |
|-------------|-------------|-------------|
| PersistentVolumes | `kubectl get pv` | Show all cluster storage |
| PersistentVolumeClaims | `kubectl get pvc -A` | Show storage requests |
| Unbound PVCs | `kubectl get pvc -A \| grep Pending` | Storage provisioning failures |

**Find PVCs Using the Most Space:**
```bash
kubectl get pvc -A -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,CAPACITY:.spec.resources.requests.storage" --sort-by=.spec.resources.requests.storage
```

### B. StorageClass Analysis

**Show Available Storage Classes:**
```bash
kubectl get storageclass
```

**Find Pods Using Specific StorageClass:**
```bash
kubectl get pvc -A -o json | jq -r '.items[] | select(.spec.storageClassName=="<storage-class>") | "\(.metadata.namespace)/\(.metadata.name)"'
```

---

## 8. Security & RBAC Auditing

### A. Role & Permission Analysis

**List All ServiceAccounts:**
```bash
kubectl get serviceaccounts -A
```

**Find Pods Running as Root:**
```bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.securityContext.runAsUser == 0 or .spec.containers[].securityContext.runAsUser == 0) | "\(.metadata.namespace)/\(.metadata.name)"'
```

**Check RBAC for a ServiceAccount:**
```bash
kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<sa-name>
```

### B. Secret & ConfigMap Auditing

**Find Secrets Not Mounted Anywhere (Orphaned):**
```bash
comm -23 <(kubectl get secrets -A -o json | jq -r '.items[].metadata.name' | sort) <(kubectl get pods -A -o json | jq -r '.items[].spec.volumes[]?.secret.secretName' | sort | uniq)
```

---

## 9. Advanced JSONPath Queries

### A. Custom Output Formats

**Get Pod IPs with Names:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.podIP}{"\n"}{end}'
```

**Extract Container Environment Variables:**
```bash
kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].env[*].name}'
```

**Get All Container Ports:**
```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].ports[*].containerPort}{"\n"}{end}'
```

### B. Conditional Filtering

**Find Pods with High Memory Requests (>1Gi):**
```bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].resources.requests.memory | select(. != null) | tonumber > 1073741824) | "\(.metadata.namespace)/\(.metadata.name)"'
```

---

## 10. Production-Ready Dashboard Scripts

### The "War Room" Dashboard
Save this as `k-war-room.sh`:

```bash
#!/bin/bash

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         KUBERNETES CLUSTER HEALTH DASHBOARD                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"

echo -e "\n[1/8] NODE HEALTH"
kubectl get nodes -o custom-columns="NAME:.metadata.name,STATUS:.status.conditions[?(@.type=='Ready')].status,CPU:.status.capacity.cpu,MEMORY:.status.capacity.memory"

echo -e "\n[2/8] TOP 5 CPU CONSUMERS"
kubectl top pods -A --sort-by=cpu | head -n 6

echo -e "\n[3/8] TOP 5 MEMORY CONSUMERS"
kubectl top pods -A --sort-by=memory | head -n 6

echo -e "\n[4/8] UNHEALTHY PODS"
kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded

echo -e "\n[5/8] PODS WITH HIGH RESTART COUNTS (>3)"
kubectl get pods -A -o json | jq -r '.items[] | select(.status.containerStatuses[]?.restartCount > 3) | "\(.metadata.namespace)\t\(.metadata.name)\t\(.status.containerStatuses[0].restartCount)"' | column -t

echo -e "\n[6/8] RECENT ERRORS (Last 10)"
kubectl get events -A --sort-by='.lastTimestamp' | grep -iE 'error|fail|kill' | tail -n 10

echo -e "\n[7/8] SERVICES WITHOUT ENDPOINTS"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl get endpoints -n $ns -o json | jq -r --arg ns "$ns" '.items[] | select(.subsets == null or .subsets == []) | "\($ns)/\(.metadata.name)"'
done

echo -e "\n[8/8] NODE RESOURCE ALLOCATION"
kubectl describe nodes | grep -A 5 "Allocated resources" | grep -E "Resource|cpu|memory"

echo -e "\n╔════════════════════════════════════════════════════════════════╗"
echo "║                    SCAN COMPLETE                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
```

**Run it:**
```bash
chmod +x k-war-room.sh
./k-war-room.sh
```

### The "Live Ops" Monitor
For continuous monitoring:

```bash
#!/bin/bash
while true; do
  clear
  echo "=== LIVE CLUSTER MONITOR (Refreshing every 5s) ==="
  echo "Time: $(date)"
  echo ""
  echo "--- NODES ---"
  kubectl top nodes
  echo ""
  echo "--- TOP PODS ---"
  kubectl top pods -A --sort-by=cpu | head -n 10
  echo ""
  echo "--- RECENT EVENTS ---"
  kubectl get events -A --sort-by='.lastTimestamp' | tail -n 5
  sleep 5
done
```

### The Forensic Deep-Dive Script
When something is broken and you need EVERYTHING:

```bash
#!/bin/bash
POD=$1
NAMESPACE=$2

if [ -z "$POD" ] || [ -z "$NAMESPACE" ]; then
  echo "Usage: $0 <pod-name> <namespace>"
  exit 1
fi

echo "=== FORENSIC ANALYSIS: $NAMESPACE/$POD ==="
echo ""
echo "[1] POD DEFINITION"
kubectl get pod $POD -n $NAMESPACE -o yaml

echo -e "\n[2] POD EVENTS"
kubectl describe pod $POD -n $NAMESPACE | grep -A 50 "Events:"

echo -e "\n[3] CONTAINER LOGS (Last 100 Lines)"
kubectl logs $POD -n $NAMESPACE --tail=100

echo -e "\n[4] PREVIOUS CONTAINER LOGS (If Crashed)"
kubectl logs $POD -n $NAMESPACE --previous 2>/dev/null || echo "No previous logs (pod never crashed)"

echo -e "\n[5] RESOURCE USAGE"
kubectl top pod $POD -n $NAMESPACE --containers

echo -e "\n[6] NODE ASSIGNMENT"
NODE=$(kubectl get pod $POD -n $NAMESPACE -o jsonpath='{.spec.nodeName}')
echo "Running on node: $NODE"
kubectl describe node $NODE | grep -A 10 "Allocated resources"

echo -e "\n[7] SECURITY CONTEXT"
kubectl get pod $POD -n $NAMESPACE -o jsonpath='{.spec.securityContext}'

echo -e "\n[8] ENVIRONMENT VARIABLES"
kubectl get pod $POD -n $NAMESPACE -o jsonpath='{.spec.containers[*].env[*]}'
```

---

## Alias Collection for `.bashrc` / `.zshrc`

Add these to your shell profile for instant access:

```bash
# Quick health checks
alias k-health='kubectl get pods -A | grep -vE "Running|Completed"'
alias k-nodes='kubectl top nodes'
alias k-top='kubectl top pods -A --sort-by=cpu'
alias k-events='kubectl get events -A --sort-by=.lastTimestamp | tail -n 20'

# Deep dives
alias k-restarts='kubectl get pods -A --sort-by=".status.containerStatuses[0].restartCount"'
alias k-oom='kubectl get events -A | grep -i oomkilled'
alias k-pending='kubectl get pods -A --field-selector=status.phase=Pending'

# Resource analysis
alias k-no-limits='kubectl get pods -A -o json | jq -r ".items[] | select(.spec.containers[].resources.limits == null) | \"\(.metadata.namespace)/\(.metadata.name)\""'
alias k-images='kubectl get pods -A -o jsonpath="{.items[*].spec.containers[*].image}" | tr -s "[[:space:]]" "\n" | sort | uniq -c'

# Network debugging
alias k-svc-broken='kubectl get endpoints -A -o json | jq -r ".items[] | select(.subsets == null or .subsets == []) | \"\(.metadata.namespace)/\(.metadata.name)\""'
```

---

## Troubleshooting Decision Tree

```
Is the pod Running?
├─ NO → Check: kubectl describe pod <name> | grep Events
│        ├─ "ImagePullBackOff" → Check image name/registry auth
│        ├─ "CrashLoopBackOff" → Check logs: kubectl logs <pod> --previous
│        ├─ "Pending" → Check: kubectl describe pod <name> | grep -i "insufficient"
│        └─ "OOMKilled" → Increase memory limits in deployment YAML
│
└─ YES → Is it using high resources?
          ├─ YES → Check: kubectl top pod <name> --containers
          │        └─ If Memory > Limit → OOMKill imminent
          │        └─ If CPU > Limit → Throttling occurring
          │
          └─ NO → Check application logs: kubectl logs <pod> --tail=100
```

---

## Performance Notes

- `kubectl top` requires **metrics-server** to be installed
- Event retention is typically 1 hour by default (configurable via API server flags)
- For clusters >100 nodes, use `--chunk-size` flag: `kubectl get pods -A --chunk-size=500`
- JSONPath queries are client-side filtered (slower on large datasets)

---

## Emergency Runbook Commands

| **Emergency** | **Command** | **Notes** |
|--------------|-------------|-----------|
| Cluster is unresponsive | `kubectl get --raw /healthz` | Tests API server directly |
| Need to drain node for maintenance | `kubectl drain <node> --ignore-daemonsets --delete-emptydir-data` | Safely evicts pods |
| Force delete stuck pod | `kubectl delete pod <pod> -n <ns> --grace-period=0 --force` | Last resort only |
| Get cluster version | `kubectl version --short` | Client and server versions |
| Export all resources | `kubectl get all -A -o yaml > cluster-backup.yaml` | Backup before major changes |

---

##
##
