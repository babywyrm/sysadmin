
# **cURL Cheat Sheet — Command‑Line Power Reference (2025 Edition)**

Collection of practical one‑liners and examples for testing APIs, debugging HTTP issues, and automating network tasks.

---

## 🧠 Basic Usage
```bash
curl https://example.com                 # Simple GET request
curl -I https://example.com              # Show headers only (HEAD)
curl -v https://example.com              # Verbose: show request/response headers
curl -s https://example.com              # Silent mode (no progress)
curl -L https://short.url                # Follow redirects
curl -o file.txt https://example.com     # Save output to file
```

---

## 🔐 Authentication

### Basic Auth
```bash
curl -u "user:password" https://api.example.com
BASE64=$(echo -n "user:password" | base64)
curl -H "Authorization: Basic ${BASE64}" https://api.example.com
```

### Bearer Token
```bash
TOKEN="your-access-token"
curl -H "Authorization: Bearer ${TOKEN}" https://api.example.com/v1/data
```

### OAuth2 Password Grant
```bash
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=${USER}&password=${PASS}" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}"
```

---

## 📤 Sending Data

### JSON Payload
```bash
curl -X POST https://api.example.com/resource \
  -H "Content-Type: application/json" \
  -d '{"key1":"value1","key2":"value2"}'
```

### Send Data from File
```bash
curl -X POST -H "Content-Type: application/json" -d @data.json https://api.example.com
```

### Form Upload
```bash
curl -F "file=@/path/to/file.zip" -F "user=bob" https://example.com/upload
```

### URL‑Encoded Form Data
```bash
curl -X POST -d "username=bob&password=1234" https://example.com/login
```

---

## 🧾 Headers & Cookies
```bash
curl -H "X-API-Key: ${API_KEY}" -H "Accept: application/json" https://example.com
curl -c cookies.txt -b cookies.txt https://example.com   # Save and reuse cookies
curl -H "Accept-Encoding: gzip" --compressed https://example.com
```

---

## 🔍 Debugging & Verbose Output

### Show Response Headers
```bash
curl -i https://example.com | grep Server
```

### Detailed Verbose Output
```bash
curl -v -H "Accept: application/json" https://example.com
```

### Measure Connection Timings
```bash
curl -w "@curl-format.txt" -o /dev/null -s https://example.com
```
`curl-format.txt` example:
```
time_namelookup: %{time_namelookup}s
time_connect: %{time_connect}s
time_starttransfer: %{time_starttransfer}s
time_total: %{time_total}s
```

### Show Request + Response Headers
```bash
curl -v -D - https://example.com -o /dev/null
```

---

## ⏱️ Connection & Performance Options
```bash
curl --connect-timeout 5 https://example.com     # Connection timeout
curl --max-time 10 https://example.com            # Total timeout
curl --limit-rate 500K https://example.com/file   # Limit download speed
curl --keepalive-time 20 https://example.com      # Adjust keepalive
```

---

## 🔒 Certificates & Security

### Ignore SSL Verification (for Testing)
```bash
curl -k https://self-signed.local
```

### Client Certificate (PEM)
```bash
curl --cert client.pem --key client.key https://secure.example.com
```

### P12 / PFX Certificate
```bash
curl --cert-type P12 --cert client.p12:password https://secure.example.com
```

---

## 🌐 DNS, Host Overrides & Proxies

### Custom DNS Resolve
```bash
curl -v --resolve 'api.example.com:443:127.0.0.1' https://api.example.com
```

### Override Host Header
```bash
curl -v -H "Host: www.example.com" http://127.0.0.1
```

### Use a Proxy
```bash
curl -x http://proxy.example.com:8080 https://example.com
```

---

## 📦 JSON & APIs
```bash
curl -s https://api.github.com/users/octocat | jq '.login'
curl -s -H "Authorization: Bearer ${TOKEN}" https://api.example.com/data | jq
curl -s -X PATCH -H 'Content-Type: application/json' -d '{"enabled":true}' https://api.example.com/toggles/1
```

---

## 🧰 HTTP Methods

| Method  | Example |
|----------|----------|
| GET      | `curl https://example.com/items` |
| POST     | `curl -X POST -d '{"foo":"bar"}' https://example.com/items` |
| PUT      | `curl -X PUT -d '{"foo":"new"}' https://example.com/items/1` |
| PATCH    | `curl -X PATCH -d '{"foo":"patched"}' https://example.com/items/1` |
| DELETE   | `curl -X DELETE https://example.com/items/1` |

---

## 🧩 CORS & Preflight
```bash
curl -v -X OPTIONS https://api.example.com \
  -H "Origin: https://example.org" \
  -H "Access-Control-Request-Method: POST"
```

---

## ⚙️ HTTP/2 & Modern Testing
```bash
curl --http2 -I https://example.com
curl -v --http2-prior-knowledge https://example.com
```

---

## 📥 Uploads & Downloads
```bash
curl -O https://example.com/file.zip                  # Preserve filename
curl -o newname.zip https://example.com/file.zip
curl -T localfile.zip ftp://user:pass@ftp.site/
```

---

## 🧬 Automation Patterns

### Parameter Arrays
```bash
CURL_ARGS=( -s -H "Accept: application/json" -H "Authorization: Bearer ${TOKEN}" )
curl "${CURL_ARGS[@]}" "https://api.example.com/v1/users"
```

### Loop Through Endpoints
```bash
for id in {1..5}; do
  curl -s "https://api.example.com/item/$id" | jq '.id'
done
```

---

## 🪄 Useful One‑Liners
```bash
curl -o /dev/null -s -w "%{http_code}\n" https://example.com    # Status only
curl -IL https://short.url                                      # Full redirect chain
curl -D headers.txt -o body.json https://example.com/api         # Separate headers/body
curl -s -w '%{size_download}\n' -o /dev/null https://example.com # Download size
```

---

## ✅ Tips
- Combine with `jq` for pretty JSON output.
- Use `--trace-ascii debug.txt` for total session debugging.
- Use `--retry 3 --retry-connrefused` for unstable endpoints.
- To simulate browsers:  
  ```bash
  curl -A "Mozilla/5.0 (X11; Linux x86_64)" https://example.com
  ```

---

### 📚 Reference
- [curl official man page](https://curl.se/docs/manpage.html)
- [Everything curl book](https://curl.se/book.html)
- JSON processor: [jq](https://stedolan.github.io/jq/)

---

##
##

### 1. System and Process Basics
- Disk, memory, CPU usage with `df`, `du`, `free`, `top`, and `ps`.
- Modern replacements: `lsblk`, `btop`, `btm`, and `htop`.

### 2. Network Checks
- Keep all the `ss`, `lsof`, and `netstat` entries.
- Add `sudo ss -tuna | grep <port>` shortcut.
- Add `nmap -p- --min-rate 1000 <target>` for fast scanning.
- Add `nc -zv host port` simple port check.

### 3. Disk Usage and Cleanup
- Keep existing `du` one-liners.
- Add:
  ```bash
  sudo du -h -d1 /var | sort -h  # quickly find big dirs
  sudo journalctl --disk-usage    # check systemd log space
  sudo journalctl --vacuum-time=7d  # clean logs older than 7 days
  ```
- Add basic container cleanup:
  ```bash
  sudo k3s crictl image prune
  sudo docker system prune -af
  ```

### 4. Containers (Docker / K3s / Podman)
- Keep Docker section.
- Add `crictl`, `nerdctl`, and `podman` equivalents.
- Add modern "cleanup" one-liners:
  ```bash
  sudo docker container prune -f
  sudo docker image prune -af
  sudo docker volume prune -f
  ```
- Add a quick container inspection:
  ```bash
  docker inspect <container> | jq
  ```

### 5. Security & CTF Additions
- `strings`, `file`, `exiftool`, `binwalk`, `xxd`, `nc`, `curl`, `jq`
- Common scanning and enumeration one-liners:
  ```bash
  for port in {1..1024}; do (echo >/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1 && echo "Port $port open"; done
  ```
- Add payload helpers like:
  ```bash
  echo -n "command" | base64 -w0
  python3 -m http.server 8000  # quick file share
  nc -lvnp 4444                # start a reverse listener
  ```

### 6. Git / DevOps
- Keep your git section but add:
  ```bash
  git restore . && git clean -fd
  git log --oneline --graph --decorate
  ```
- Add CI/CD debugging (curl + token workflow already there).

### 7. Networking / Curl Rework
- Keep your Bearer/Basic Auth + JSON workflows.
- Add:
  ```bash
  curl -w "@curl-format.txt" -o /dev/null -s https://example.com
  ```
  (for measuring latency, speed, etc.)
- Add curl with colors / pretty JSON:
  ```bash
  curl -s https://api.github.com | jq
  ```

### 8. Quality of Life Tools
- Add:
  ```bash
  batcat file.txt    # better cat
  fd pattern         # faster find
  rg string          # faster grep
  tldr command       # quick manpages
  ```
- Add:
  ```bash
  sudo apt autoremove --purge -y
  ```

---


