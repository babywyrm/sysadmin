
# 🧵 cURL Cheat Sheet — Command-Line Power Reference (2025 Edition)

> A practical, opinionated collection of **battle-tested one-liners** for APIs, debugging HTTP, security testing, automation, and incident response.

---

## 🧠 1. Basic Usage

```bash
curl https://example.com
```

Simple GET request (stdout response)

```bash
curl -I https://example.com
```

HEAD request — headers only

```bash
curl -v https://example.com
```

Verbose — shows DNS, TLS, request + response headers

```bash
curl -s https://example.com
```

Silent (no progress meter)

```bash
curl -L https://short.url
```

Follow redirects (useful for OAuth / login flows)

```bash
curl -o file.txt https://example.com
```

Save response to file

```bash
curl -D headers.txt -o body.json https://example.com
```

Split headers and body (excellent for debugging APIs)

---

## 🔐 2. Authentication

### Basic Auth

```bash
curl -u user:password https://api.example.com
```

Manual header construction:

```bash
BASE64=$(echo -n "user:password" | base64)
curl -H "Authorization: Basic ${BASE64}" https://api.example.com
```

---

### Bearer Token (API / OAuth)

```bash
TOKEN="your-access-token"
curl -H "Authorization: Bearer ${TOKEN}" https://api.example.com/v1/data
```

Debug token scopes:

```bash
curl -v -H "Authorization: Bearer ${TOKEN}" https://api.example.com/me
```

---

### OAuth2 Password Grant (Legacy / Internal)

```bash
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=${USER}&password=${PASS}" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}"
```

⚠️ Avoid in modern public systems — included for legacy/internal APIs.

---

## 📤 3. Sending Data

### JSON Payload

```bash
curl -X POST https://api.example.com/resource \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}'
```

From file:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d @data.json https://api.example.com
```

---

### Form Data / File Upload

```bash
curl -F "file=@payload.zip" -F "user=bob" https://example.com/upload
```

---

### URL-Encoded Forms (Login)

```bash
curl -X POST \
  -d "username=bob&password=1234" \
  https://example.com/login
```

---

## 🧾 4. Headers & Cookies

```bash
curl -H "X-API-Key: ${API_KEY}" \
     -H "Accept: application/json" \
     https://example.com
```

Persist cookies:

```bash
curl -c cookies.txt -b cookies.txt https://example.com
```

Compressed responses:

```bash
curl -H "Accept-Encoding: gzip" --compressed https://example.com
```

---

## 🔍 5. Debugging & Timing

### Show Headers Only

```bash
curl -i https://example.com | grep Server
```

### Full Request/Response Dump

```bash
curl -v -D - https://example.com -o /dev/null
```

---

### Measure Latency & Performance

```bash
curl -w "@curl-format.txt" -o /dev/null -s https://example.com
```

`curl-format.txt`:

```text
dns: %{time_namelookup}s
connect: %{time_connect}s
ttfb: %{time_starttransfer}s
total: %{time_total}s
```

Excellent for SLOs and incident triage.

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

Ignore TLS validation (testing only):

```bash
curl -k https://self-signed.local
```

Client cert (PEM):

```bash
curl --cert client.pem --key client.key https://secure.example.com
```

P12 / PFX:

```bash
curl --cert-type P12 --cert client.p12:password https://secure.example.com
```

---

## 🌐 8. DNS, Host Overrides & Proxies

Override DNS:

```bash
curl --resolve api.example.com:443:127.0.0.1 https://api.example.com
```

Override Host header:

```bash
curl -H "Host: prod.example.com" http://127.0.0.1
```

Proxy:

```bash
curl -x http://proxy:8080 https://example.com
```

---

## 📦 9. APIs & JSON

```bash
curl -s https://api.github.com/users/octocat | jq
```

PATCH:

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

Credential abuse test:

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

Reusable args:

```bash
CURL_ARGS=( -s -H "Authorization: Bearer ${TOKEN}" )
curl "${CURL_ARGS[@]}" https://api.example.com/me
```

Loop:

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
```

Simulate browser:

```bash
curl -A "Mozilla/5.0" https://example.com
```

---

## 🧠 16. System / Network Companion Commands

### Networking

```bash
ss -tuna
sudo ss -tuna | grep 443
nc -zv host 443
nmap -p- --min-rate 1000 target
```

### Disk & Logs

```bash
df -h
sudo du -h -d1 /var | sort -h
journalctl --disk-usage
journalctl --vacuum-time=7d
```

### Containers

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
base64 <<< "command"
python3 -m http.server 8000
nc -lvnp 4444
```

Port scan via bash:

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

CI debug pattern:

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

## 📚 20. References

* `man curl`
* *Everything curl*
* `jq`
* OWASP API Security Top 10

---

### 🧠 Final Notes

* `curl` proves **server behavior**
* Browsers prove **exploitability**
* Combine with `jq`, `grep`, `ss`, `nc` for real power

---
