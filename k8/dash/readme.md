This guide provides a universal "Standard Operating Procedure" for building a command-line dashboard using only native `kubectl` functionality. 
  These patterns work on any Kubernetes distribution (EKS, GKE, AKS, K3s, Minikube, or Bare Metal).

---

# Guide: Native Kubectl Command-Line Dashboards

To monitor a cluster effectively without external tools, you need to combine three views: **Real-time Resource Consumption**, **Object Health**, and **System Events**.

## 1. The "Live" Resource Monitor
To create a real-time dashboard similar to `top` or `htop`, use the Linux `watch` command. This is the best way to see spikes in CPU or Memory as they happen.

**Top Pods by CPU (Live):**
```bash
watch -n 2 "kubectl top pods -A --sort-by=cpu"
```

**Top Pods by Memory (Live):**
```bash
watch -n 2 "kubectl top pods -A --sort-by=memory"
```

**Node Infrastructure Health:**
```bash
watch -n 2 "kubectl top nodes"
```

## 2. The Troubleshooting Dashboard (Identifying Issues)
Resource usage doesn't tell the whole story. A pod using `0m` CPU might be crashed. Use these custom views to find the "Why."

### A. The "Restart Hunter"
Pods with high restart counts usually indicate **OOMKilled** (Out of Memory) errors or application panics.
```bash
kubectl get pods -A --sort-by='.status.containerStatuses[0].restartCount' \
  -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount,STATUS:.status.phase"
```

### B. The "Non-Running" Filter
On large clusters, hide the "healthy" pods to focus on what is broken (Pending, Error, CrashLoop, ImagePullBackOff).
```bash
kubectl get pods -A --field-selector=status.phase!=Running
```

### C. The Pressure View (Limits vs. Requests)
This shows you which pods are "scheduled" to use the most resources, which helps find pods that haven't crashed yet but are over-provisioned.
```bash
kubectl get pods -A -o custom-columns="NAME:.metadata.name,CPU_REQ:.spec.containers[*].resources.requests.cpu,MEM_REQ:.spec.containers[*].resources.requests.memory,CPU_LIM:.spec.containers[*].resources.limits.cpu,MEM_LIM:.spec.containers[*].resources.limits.memory"
```

## 3. The "Event Stream" (The Cluster's Pulse)
Events explain the "verbs" of the cluster (e.g., *Scheduled, Pulled, Failed, Killed*). Viewing these in chronological order is the fastest way to debug.

**Show last 10 cluster events:**
```bash
kubectl get events -A --sort-by='.lastTimestamp' | tail -n 10
```

## 4. The "One-Page" Master Dashboard Script
You can combine these into a single command that provides a full cluster overview. Save this as an alias in your `.bashrc` or `.zshrc`:

```bash
alias k-dash='echo "--- NODES ---"; kubectl top nodes; \
              echo -e "\n--- TOP 5 CPU PODS ---"; kubectl top pods -A --sort-by=cpu | head -n 6; \
              echo -e "\n--- UNHEALTHY PODS ---"; kubectl get pods -A --field-selector=status.phase!=Running; \
              echo -e "\n--- RECENT ERRORS ---"; kubectl get events -A --sort-by=".lastTimestamp" | grep -iE "error|fail|warn" | tail -n 5'
```

---

## Summary Diagnostic Workflow
When you see a pod behaving badly in your dashboard:

1.  **Check for Memory/CPU pressure:** `kubectl top pod <name>`
2.  **Check the Lifecycle:** `kubectl describe pod <name>` 
    *   *Look for "Reason: OOMKilled" or "Taints".*
3.  **Check the Logs:** `kubectl logs <name> --tail=100`
4.  **Check the Node:** If many pods on one node are failing, run `kubectl describe node <node-name>` to check for `DiskPressure` or `MemoryPressure`.
