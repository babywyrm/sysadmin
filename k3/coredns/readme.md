

# 🧰 CoreDNS Debugging Runbook ..beta..

This guide explains how to safely enable verbose CoreDNS logging, isolate it from production, and capture/query logs in real-time with **stern**.

---

## 1. Why we do this

* CoreDNS is critical — it handles all DNS inside the cluster.
* When it OOMs or drops queries, workloads fail cluster-wide.
* Sometimes we need **deep visibility** (query-level logging) to find noisy workloads, misconfigured services, or DNS floods.
* Logging everything is noisy and expensive, so we isolate it onto **debug pods/nodes**.

---

## 2. Prepare a “logging” node group

Create a dedicated EKS node group for CoreDNS debug:

```bash
# Label nodes
kubectl label node <node-name> role=coredns-logging

# Optionally taint them
kubectl taint nodes <node-name> coredns-logging=true:NoSchedule
```

This ensures only debug CoreDNS pods land on those nodes.

---

## 3. Deploy “logging” CoreDNS pods

Patch or clone the CoreDNS deployment:

```yaml
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
      - matchExpressions:
        - key: role
          operator: In
          values:
          - coredns-logging

tolerations:
- key: "coredns-logging"
  operator: "Equal"
  value: "true"
  effect: "NoSchedule"
```

Enable query logging in their Corefile:

```hcl
.:53 {
    errors
    health
    ready
    log       # 👈 add this
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
    }
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance
}
```

Add this annotation so Fluent Bit doesn’t ship the firehose to your central log pipeline:

```yaml
metadata:
  annotations:
    fluentbit.io/exclude: "true"
```

---

## 4. Use stern to tail logs

### Realtime streaming (fresh logs only)

```bash
stern -n kube-system -l role=coredns-logging \
  --timestamps \
  --tail=0 \
  --since=1s
```

### With pod name prefixes

```bash
stern -n kube-system -l role=coredns-logging \
  --timestamps --tail=0 --since=1s -o json \
  | jq -r '.pod + " " + .message'
```

### Filtering (NXDOMAIN, PTR lookups, etc.)

```bash
stern -n kube-system -l role=coredns-logging \
  -i NXDOMAIN --timestamps
```

---

## 5. Guardrails

* **Only run 1–2 logging pods**. Never enable `log` across the whole CoreDNS deployment in prod.
* **Exclude from Fluent Bit** so you don’t swamp Elasticsearch or S3.
* **Use staging first** — debug configs should always be tested in non-prod clusters.
* **Tear down logging pods** when done (disable `log` or scale down the debug deployment).

---

## 6. Common patterns to look for

* **PTR lookups (`.in-addr.arpa`, `.ip6.arpa`)** → often noisy apps or agents.
* **NXDOMAIN spam** → pods querying decommissioned services.
* **Repeated external lookups (AWS APIs, SaaS domains)** → good candidate for longer external cache (`cache 300`).

---

## 7. Scaling guidance

If CoreDNS pods hit OOMs:

* Bump resources:

  ```yaml
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
  ```
* Scale replicas: 4–6 is common for busy clusters.
* Deploy NodeLocal DNSCache for real relief (caches failed queries and cuts load).

---

## 8. Rollback

When finished debugging:

```bash
# Remove the `log` directive from Corefile
kubectl -n kube-system edit configmap coredns

# Restart CoreDNS
kubectl -n kube-system rollout restart deployment coredns
```

---

## 9. Quick commands cheat sheet

```bash
# Label node for logging
kubectl label node <node> role=coredns-logging

# Patch CoreDNS deployment to enable log
kubectl -n kube-system edit configmap coredns

# Restart CoreDNS pods
kubectl -n kube-system rollout restart deployment coredns

# Tail only debug pods
stern -n kube-system -l role=coredns-logging --since=1s --tail=0
```


