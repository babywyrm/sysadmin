
# 🛡️ CoreDNS Audit Runbook ..beta..

## 1. Deploy an Audit Pod

Start with a pod that has DNS tools:

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

Apply it:

```bash
kubectl apply -f dns-audit.yaml
```

This gives you a shell inside the cluster with `dig`, `nslookup`, `drill`.

---

## 2. CoreDNS Health Audit Script

Here’s a Bash script you can run inside the `dns-audit` pod. It will test **forward lookups**, **reverse lookups**, and **timings**.

```bash
#!/bin/bash
# dns-audit.sh – Audit CoreDNS resolution in cluster

COREDNS=$(getent hosts kube-dns.kube-system.svc.cluster.local | awk '{print $1}')

echo "[*] Using CoreDNS at $COREDNS"
echo "[*] Timestamp: $(date)"
echo

DOMAINS=(
  "kubernetes.default.svc.cluster.local"
  "google.com"
  "cisco.com"
  "thousandeyes.com"
)

IPS=(
  "8.8.8.8"
  "1.1.1.1"
  "205.17.97.202"
  "172.217.164.142"
)

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
echo

echo "== Latency Tests =="
for d in "${DOMAINS[@]}"; do
  echo -n "$d -> "
  dig +stats @$COREDNS $d | grep "Query time"
done
```

Copy it into the pod and run:

```bash
kubectl cp dns-audit.sh kube-system/dns-audit:/tmp/
kubectl exec -it -n kube-system dns-audit -- bash /tmp/dns-audit.sh
```

---

## 3. Automate With a CronJob

Here’s a Kubernetes CronJob that runs the script every 5 minutes and prints logs you can collect:

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

Get results with:

```bash
kubectl logs -n kube-system job/dns-audit-job-<timestamp>
```

---

## 4. Find Which Pod is Hammering CoreDNS

If you see floods of PTR lookups in CoreDNS logs:

1. **Enable CoreDNS query logging** (ConfigMap):

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

2. **Find source IPs in logs:**

```bash
stern -n kube-system coredns | grep PTR
```

Example:

```
[INFO] 10.49.200.127:49284 - PTR 205.17.97.202.in-addr.arpa.
```

3. **Map IP back to a pod:**

```bash
kubectl get pods -A -o wide | grep 10.49.200.127
```

---

## 5. Extras

* **Prometheus metrics:** CoreDNS exposes `/metrics`. You can scrape `coredns_dns_request_duration_seconds` and `coredns_dns_request_count_total`.
* **eBPF tracing:** Use `kubectl sniff` or Cilium Hubble to watch DNS packets at the node level.
* **Failover testing:** Modify CoreDNS ConfigMap to add backup resolvers (e.g. `8.8.8.8`, `1.1.1.1`) and rerun audit script.

---

##
##
