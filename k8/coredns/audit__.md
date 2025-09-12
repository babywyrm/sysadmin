
# 🛡️ CoreDNS Audit & Troubleshooting Runbook ..beta..

---

## 📌 TL;DR

* **Symptoms:** Pods experience DNS delays or failures; CoreDNS logs show timeouts like

  ```
  plugin/errors: 2 205.17.97.202.in-addr.arpa. PTR: dial tcp 10.49.0.2:53: i/o timeout
  ```
* **Cause:** CoreDNS is forwarding queries (especially PTR lookups) to an upstream resolver that is slow, unreachable, or misconfigured.
* **Impact:** Stuck PTR lookups consume CoreDNS worker threads and degrade DNS service for the entire cluster.
* **Fix:** Audit DNS paths, identify noisy pods, and tune CoreDNS with fallback resolvers, query logging, or suppression of unnecessary lookups.

---

## 🔍 Investigation Steps

### 1. Check CoreDNS Pod Health

```bash
kubectl -n kube-system get pods -l k8s-app=kube-dns -o wide
kubectl -n kube-system logs -l k8s-app=kube-dns --tail=50
```

Look for repeated `i/o timeout` errors or pods in CrashLoopBackOff.

---

### 2. Tail CoreDNS Logs in Real-Time

```bash
stern -n kube-system coredns --timestamps --since=1m | grep ERROR
```

This shows failing lookups, including PTR queries that might be flooding.

---

### 3. Deploy an Audit Pod

Create a pod with DNS tools:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: dns-audit
  namespace: kube-system
spec:
  containers:
  - name: dnsutils
    image: infoblox/dnstools
    command: ["sleep", "3600"]
  restartPolicy: Never
```

Exec into it:

```bash
kubectl exec -it -n kube-system dns-audit -- bash
```

---

### 4. Run DNS Audit Script

```bash
#!/bin/bash
# dns-audit.sh – Audit CoreDNS resolution in cluster

COREDNS=$(getent hosts kube-dns.kube-system.svc.cluster.local | awk '{print $1}')

echo "[*] Using CoreDNS at $COREDNS"
echo "[*] Timestamp: $(date)"
echo

DOMAINS=("kubernetes.default.svc.cluster.local" "google.com" "cisco.com")
IPS=("8.8.8.8" "1.1.1.1" "205.17.97.202")

echo "== Forward Lookups =="
for d in "${DOMAINS[@]}"; do
  echo -n "$d -> "
  dig +time=2 +tries=1 @$COREDNS $d | grep "ANSWER SECTION" -A2 || echo "FAILED"
done

echo
echo "== Reverse Lookups =="
for ip in "${IPS[@]}"; do
  echo -n "$ip -> "
  dig +time=2 +tries=1 @$COREDNS -x $ip | grep "ANSWER SECTION" -A2 || echo "FAILED"
done
```

Copy and run inside the audit pod:

```bash
kubectl cp dns-audit.sh kube-system/dns-audit:/tmp/
kubectl exec -it -n kube-system dns-audit -- bash /tmp/dns-audit.sh
```

---

### 5. Enable Query Logging in CoreDNS

Edit the CoreDNS ConfigMap:

```bash
kubectl -n kube-system edit configmap coredns
```

Add `log` under the root server block:

```coredns
.:53 {
    log
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    forward . 10.49.0.2
}
```

Now logs show **source IPs** for each query:

```
[INFO] 10.49.200.127:49284 - PTR IN 205.17.97.202.in-addr.arpa. udp 54 false 512
```

---

### 6. Map Source IPs Back to Pods

```bash
kubectl get pods -A -o wide | grep 10.49.200.127
```

This identifies the workload generating the PTR traffic.

---

## 🛠️ Remediation Options

### Option 1: Fix Upstream Resolver

* Validate `10.49.0.2` can answer PTR queries:

  ```bash
  dig -x 205.17.97.202 @10.49.0.2
  ```
* If it fails, repair or replace the upstream DNS service.

---

### Option 2: Add Fallback Upstreams

In `coredns` ConfigMap:

```coredns
forward . 10.49.0.2 8.8.8.8 1.1.1.1
```

This prevents CoreDNS from stalling if the primary upstream is down.

---

### Option 3: Suppress Useless PTR Lookups

If reverse lookups aren’t required, short-circuit them:

```coredns
rewrite stop {
  name regex (.*)\.in-addr\.arpa\.$ NXDOMAIN
}
```

Or handle specific zones with static `hosts`.

---

### Option 4: NodeLocal DNSCache

Deploy NodeLocal DNSCache to reduce pressure on CoreDNS:

```bash
kubectl apply -f https://k8s.io/examples/admin/dns/nodelocaldns.yaml
```

---

## 📊 Continuous Auditing

### Deploy a CronJob

Runs every 5 minutes and prints logs:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: dns-audit-job
  namespace: kube-system
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: dns-audit
            image: infoblox/dnstools
            command: ["/bin/sh", "-c"]
            args:
              - |
                COREDNS=$(getent hosts kube-dns.kube-system.svc.cluster.local | awk '{print $1}')
                echo "[*] DNS Audit $(date)"
                dig +time=2 +tries=1 @$COREDNS kubernetes.default.svc.cluster.local
                dig +time=2 +tries=1 @$COREDNS -x 8.8.8.8
          restartPolicy: Never
```

Check results:

```bash
kubectl logs -n kube-system job/dns-audit-job-<timestamp>
```

---

## 🚀 Future Improvements

* Scrape CoreDNS `/metrics` (Prometheus):

  * `coredns_dns_request_count_total`
  * `coredns_dns_request_duration_seconds`
* Add alerts for spikes in PTR traffic.
* Deploy Falco or Cilium Hubble to trace DNS queries by pod automatically.
* Maintain an allowlist/denylist for PTR lookups to avoid wasting cycles.

---

##
##
