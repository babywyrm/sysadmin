
# 🧵 cURL Cheat Sheet — Command-Line Power Reference (2025 Edition)

> A practical, opinionated collection of **battle-tested one-liners** for APIs, debugging HTTP issues, automation, security testing, and **incident response**.

---

## 📑 Table of Contents

1. [Basic Usage](#-1-basic-usage)
2. [Authentication](#-2-authentication)
3. [Sending Data](#-3-sending-data)
4. [Headers & Cookies](#-4-headers--cookies)
5. [Debugging & Timing](#-5-debugging--timing)
6. [Timeouts & Reliability](#-6-timeouts--reliability)
7. [TLS / Certificates](#-7-tls--certificates)
8. [DNS, Host Overrides & Proxies](#-8-dns-host-overrides--proxies)
9. [APIs & JSON](#-9-apis--json)
10. [HTTP Methods](#-10-http-methods)
11. [CORS & Preflight (Security)](#-11-cors--preflight-security)
12. [HTTP/2 & Modern Protocols](#-12-http2--modern-protocols)
13. [Uploads & Downloads](#-13-uploads--downloads)
14. [Automation Patterns](#-14-automation-patterns)
15. [High-Value One-Liners](#-15-high-value-one-liners)
16. [System / Network Companion Commands](#-16-system--network-companion-commands)
17. [Security & CTF Helpers](#-17-security--ctf-helpers)
18. [Git / DevOps](#-18-git--devops)
19. [Quality-of-Life Tools](#-19-quality-of-life-tools)
20. 🚨 [Incident Response Playbook](#-20-incident-response-playbook)
21. [References](#-21-references)

---

## 🧠 1. Basic Usage

```bash
curl https://example.com
curl -I https://example.com
curl -v https://example.com
curl -s https://example.com
curl -L https://short.url
curl -o file.txt https://example.com
curl -D headers.txt -o body.json https://example.com
```

---

## 🔐 2. Authentication

### Basic Auth

```bash
curl -u user:password https://api.example.com
```

```bash
BASE64=$(echo -n "user:password" | base64)
curl -H "Authorization: Basic ${BASE64}" https://api.example.com
```

### Bearer Token

```bash
TOKEN="your-access-token"
curl -H "Authorization: Bearer ${TOKEN}" https://api.example.com/v1/data
```

### OAuth2 Password Grant (legacy / internal)

```bash
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=${USER}&password=${PASS}" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}"
```

---

## 📤 3. Sending Data

### JSON

```bash
curl -X POST https://api.example.com/resource \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}'
```

```bash
curl -X POST -H "Content-Type: application/json" \
  -d @data.json https://api.example.com
```

### Form / File Upload

```bash
curl -F "file=@payload.zip" -F "user=bob" https://example.com/upload
```

### URL-Encoded

```bash
curl -X POST -d "username=bob&password=1234" https://example.com/login
```

---

## 🧾 4. Headers & Cookies

```bash
curl -H "X-API-Key: ${API_KEY}" \
     -H "Accept: application/json" \
     https://example.com
```

```bash
curl -c cookies.txt -b cookies.txt https://example.com
```

```bash
curl -H "Accept-Encoding: gzip" --compressed https://example.com
```

---

## 🔍 5. Debugging & Timing

```bash
curl -i https://example.com
curl -v -D - https://example.com -o /dev/null
```

### Latency Breakdown

```bash
curl -w "@curl-format.txt" -o /dev/null -s https://example.com
```

`curl-format.txt`

```text
dns: %{time_namelookup}s
connect: %{time_connect}s
ttfb: %{time_starttransfer}s
total: %{time_total}s
```

---

## ⏱️ 6. Timeouts & Reliability

```bash
curl --connect-timeout 5 https://example.com
curl --max-time 10 https://example.com
curl --retry 3 --retry-connrefused https://example.com
curl --limit-rate 500K https://example.com/file
```

---

## 🔒 7. TLS / Certificates

```bash
curl -k https://self-signed.local
```

```bash
curl --cert client.pem --key client.key https://secure.example.com
```

```bash
curl --cert-type P12 --cert client.p12:password https://secure.example.com
```

---

## 🌐 8. DNS, Host Overrides & Proxies

```bash
curl --resolve api.example.com:443:127.0.0.1 https://api.example.com
```

```bash
curl -H "Host: prod.example.com" http://127.0.0.1
```

```bash
curl -x http://proxy:8080 https://example.com
```

---

## 📦 9. APIs & JSON

```bash
curl -s https://api.github.com/users/octocat | jq
```

```bash
curl -X PATCH \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}' \
  https://api.example.com/toggles/1
```

---

## 🧰 10. HTTP Methods

| Method | Example                                             |
| ------ | --------------------------------------------------- |
| GET    | `curl https://example.com/items`                    |
| POST   | `curl -X POST -d '{}' https://example.com/items`    |
| PUT    | `curl -X PUT -d '{}' https://example.com/items/1`   |
| PATCH  | `curl -X PATCH -d '{}' https://example.com/items/1` |
| DELETE | `curl -X DELETE https://example.com/items/1`        |

---

## 🧩 11. CORS & Preflight (Security)

```bash
curl -X OPTIONS https://api.example.com \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST"
```

```bash
curl -i https://api.example.com/secret \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=abc"
```

---

## ⚙️ 12. HTTP/2 & Modern Protocols

```bash
curl --http2 -I https://example.com
curl --http2-prior-knowledge https://example.com
```

---

## 📥 13. Uploads & Downloads

```bash
curl -O https://example.com/file.zip
curl -o renamed.zip https://example.com/file.zip
curl -T local.zip ftp://user:pass@ftp.site/
```

---

## 🧬 14. Automation Patterns

```bash
CURL_ARGS=( -s -H "Authorization: Bearer ${TOKEN}" )
curl "${CURL_ARGS[@]}" https://api.example.com/me
```

```bash
for id in {1..5}; do
  curl -s https://api.example.com/item/$id | jq '.id'
done
```

---

## 🪄 15. High-Value One-Liners

```bash
curl -o /dev/null -s -w "%{http_code}\n" https://example.com
curl -IL https://short.url
curl -s -w '%{size_download}\n' -o /dev/null https://example.com
curl -A "Mozilla/5.0" https://example.com
```

---

## 🧠 16. System / Network Companion Commands

```bash
ss -tuna
sudo ss -tuna | grep 443
nc -zv host 443
nmap -p- --min-rate 1000 target
```

```bash
df -h
sudo du -h -d1 /var | sort -h
journalctl --disk-usage
journalctl --vacuum-time=7d
```

```bash
docker inspect container | jq
docker system prune -af
crictl ps
nerdctl ps
```

---

## 🔐 17. Security & CTF Helpers

```bash
strings file.bin
file payload
xxd payload
echo -n "command" | base64 -w0
python3 -m http.server 8000
nc -lvnp 4444
```

```bash
for p in {1..1024}; do
  (echo >/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo "open $p"
done
```

---

## 🧬 18. Git / DevOps

```bash
git restore . && git clean -fd
git log --oneline --graph --decorate
```

```bash
curl -v -H "Authorization: Bearer $CI_TOKEN" $API
```

---

## 🧰 19. Quality-of-Life Tools

```bash
batcat file.txt
fd pattern
rg string
tldr curl
sudo apt autoremove --purge -y
```

---

## 🚨 20. Incident Response Playbook

### 20.1 Why curl in IR

| Scenario        | Why                        |
| --------------- | -------------------------- |
| API outage      | Removes client/LB noise    |
| Auth failures   | Precise token testing      |
| TLS issues      | Full handshake visibility  |
| Security events | Reproduce attacker traffic |
| CI breakage     | Deterministic replay       |

---

### 20.2 Is It Down?

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://api.example.com/health
```

```bash
curl -v --connect-timeout 3 https://api.example.com
```

**Interpretation**

* `000` → DNS / TCP / TLS failure
* `5xx` → backend issue
* `401/403` → auth or policy regression
* High TTFB → upstream dependency

---

### 20.3 TLS / Cert Incidents

```bash
curl -vI https://example.com
curl --tlsv1.2 https://example.com
```

Look for:

* Expired certs
* CN/SAN mismatch
* TLS downgrade
* SNI errors

---

### 20.4 Auth / Token Outages

```bash
curl -v -H "Authorization: Bearer $TOKEN" https://api.example.com/me
```

```bash
curl -i -H "Authorization: Bearer $TOKEN" https://api.example.com/admin
```

Compare **pre-deploy vs post-deploy** behavior.

---

### 20.5 CORS / Frontend Incidents

```bash
curl -i https://api.example.com \
  -H "Origin: https://frontend.example"
```

```bash
curl -i https://api.example.com \
  -H "Origin: https://evil.com"
```

Used to confirm:

* Misconfig vs frontend regression
* Cache poisoning
* Origin reflection

---

### 20.6 Suspected Abuse / Attack Traffic

Replay suspicious request:

```bash
curl -v -X POST https://api.example.com/endpoint \
  -H "Authorization: Bearer stolen?" \
  -d '{"payload":"test"}'
```

Used for:

* Impact validation
* Logging verification
* WAF bypass confirmation

---

### 20.7 Before / After Diff

```bash
curl -s -D - https://api.example.com | sha256sum
```

Run before + after deploy to detect header or behavior drift.

---

## 📚 21. References

* `man curl`
* *Everything curl*
* `jq`
* OWASP API Security Top 10

##
##
