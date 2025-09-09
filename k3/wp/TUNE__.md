

# 🛡 WordPress CTF Defense Configuration

This document explains the two hardened reverse proxy / web server configurations we’ve built to defend WordPress in a CTF environment:

1. **Nginx Deployment + Service (Kubernetes manifest)**
2. **Apache Helm values (Bitnami-style override)**

---

## 1. Nginx Reverse Proxy (Kubernetes)

This proxy sits in front of WordPress and enforces per-client rate limits, connection caps, and short-lived caching.

### Key Features

* **Logging to stdout/stderr**:
  All logs go to `kubectl logs`, no local disk writes.

* **Real client IP preservation**:
  Uses `externalTrafficPolicy: Local` and `real_ip_header X-Forwarded-For`.

* **Per-client DoS defense**:

  ```nginx
  limit_req_zone $binary_remote_addr zone=perip:20m rate=10r/s;
  limit_conn_zone $binary_remote_addr zone=connlimit:20m;
  ```

* **Limits applied at request time**:

  ```nginx
  limit_req zone=perip burst=20 delay=10;
  limit_req_status 429;
  limit_conn connlimit 20;
  limit_conn_status 429;
  ```

  → Attackers get **429 Too Many Requests**, not global 503s.

* **Caching**:

  * 200 responses cached for 10s (reduces backend load during floods).
  * Static assets cached for 1h.

* **Performance tuning**:

  * `worker_connections 16384`
  * Keepalives to WordPress backend
  * Proxy buffer tuning to prevent slowloris

### Rollout Instructions

```bash
kubectl apply -f patched.yaml
kubectl rollout restart deployment/wp-nginx -n default
kubectl rollout status deployment/wp-nginx -n default
```

Monitor logs:

```bash
kubectl logs -n default deploy/wp-nginx -f
```

---

## 2. Apache Helm Values (`values.yaml` override)

When running WordPress behind Apache (Bitnami style), the configuration below enforces request limits and blocks common fuzzing tools.

### Key Features

* **Core modules loaded**:
  Includes `mod_reqtimeout`, `mod_ratelimit`, `mod_rewrite`.

* **Logging to stdout/stderr**:
  Works seamlessly with Kubernetes pods.

* **Slowloris & body floods defended**:

  ```apache
  <IfModule reqtimeout_module>
    RequestReadTimeout header=5-10,MinRate=1500 body=10,MinRate=1500
  </IfModule>
  ```

* **Block fuzzers/scanners**:

  ```apache
  RewriteCond %{HTTP_USER_AGENT} (ffuf|gobuster|sqlmap|nmap|wpscan) [NC]
  RewriteRule .* - [F,L]
  ```

* **WordPress-specific hardening**:

  * Block `/wp-login.php` brute force via rate limit
  * Disable `/xmlrpc.php` entirely
  * Block `/wp-content/plugins/` and `/wp-content/themes/` enumeration
  * Deny access to readmes, changelogs, backups, and installer files
  * Disable feeds and cron for fingerprinting

* **Anti-ffuf global throttle**:
  Applies `mod_ratelimit` to slow down high-speed fuzzing across `/`.

---

## 🧪 Monitoring

### From outside (user experience)

```bash
watch -n 1 'curl -o /dev/null -s -w "Status:%{http_code} Time:%{time_total}s\n" http://<nginx-service-ip>/'
```

### From inside cluster (proxy logs)

```bash
kubectl logs -n default deploy/wp-nginx -f
```

---

## ✅ TL;DR

* **Nginx proxy** → Shields WordPress with per-IP rate limiting, connection caps, caching, and tuned buffering.
* **Apache config** → Adds another layer of WordPress-specific defenses against fuzzers and enumeration.
* Both write logs to stdout/stderr, making them **Kubernetes-native**.

---

