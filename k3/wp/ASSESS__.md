

# 🛡️ Kubernetes CTF Monitoring & Testing Workbook ..beta..

This workbook contains essential `kubectl`, `watch`, `curl`, and `tail` commands to **monitor**, **test**, and **debug** your CTF Kubernetes clusters.

---

## 1. General Pod/Service Health

```bash
# Get pods across all namespaces
watch -n 2 'kubectl get pods -A'

# Get events sorted by time (cluster activity log)
kubectl get events -A --sort-by=.metadata.creationTimestamp | tail -40

# Describe a pod in detail (replace NAME + NAMESPACE)
kubectl describe pod <pod-name> -n <namespace>

# Show logs of a pod
kubectl logs <pod-name> -n <namespace>

# Show logs of a pod's *previous* crashed container
kubectl logs <pod-name> -n <namespace> --previous
````

---

## 2. Watch + Curl Tests

```bash
# Curl every 2s for 200s to test availability (from the host)
for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080; sleep 2; done

# Watch curl inside cluster
watch -n 2 'kubectl exec -it <pod-name> -n <namespace> -- curl -s -I http://localhost:8080 | head -n 1'

# Curl a service (ClusterIP)
kubectl exec -it <pod-name> -n <namespace> -- curl -s http://legacy-intranet-service.default.svc.cluster.local:5000
```

---

## 3. Logs & Tail

```bash
# Tail logs from all pods with label (example: legacy-intranet-cms)
kubectl logs -l app=legacy-intranet-cms -n default -f

# Tail only the last 50 lines
kubectl logs <pod-name> -n <namespace> --tail=50 -f
```

---

## 4. Crash / Restart Debugging

```bash
# See why pod restarted (look for OOMKilled, CrashLoopBackOff, etc.)
kubectl describe pod <pod-name> -n <namespace> | grep -A5 "Last State"

# Check node messages for OOM
dmesg | grep -i "killed process"

# Monitor restart counts live
watch -n 2 'kubectl get pods -A -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,RESTARTS:.status.containerStatuses[*].restartCount,STATUS:.status.phase"'
```

---

## 5. Resource & Node Monitoring

```bash
# Get nodes and resources
kubectl get nodes -o wide
kubectl top nodes
kubectl top pods -A

# Describe node for capacity / resource pressure
kubectl describe node <node-name>
```

---

## 6. Cron & System Checks (CTF Host)

```bash
# Show cron service logs
journalctl -u cron.service --since "today"

# Show root’s crontab
crontab -l -u root

# Watch free disk + memory
watch -n 2 'df -h; free -m'
```

---

## 7. Resilience Testing

```bash
# Scale down to 0 replicas, then back up
kubectl scale deployment legacy-intranet-cms -n default --replicas=0
kubectl scale deployment legacy-intranet-cms -n default --replicas=5

# Delete a pod to force restart
kubectl delete pod <pod-name> -n <namespace>
```

---

## 8. Quick Aliases (Optional)

Add to `.bashrc` for speed:

```bash
alias kga='kubectl get pods -A'
alias kevents='kubectl get events -A --sort-by=.metadata.creationTimestamp | tail -20'
alias klogs='kubectl logs -f'
alias kdesc='kubectl describe pod'
```

##
##
