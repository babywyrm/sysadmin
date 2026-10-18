
# 🧩 XSS Decode Server v2.0
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Security Level](https://img.shields.io/badge/security-configurable-orange)]()

> A secure, extensible **decode server** for handling URL/Base64 encoded exfiltration payloads, XSS captures, or encoded responses — built for testers and analysts.

---

## 🚀 Overview

`XSS Decode Server` listens for **GET** or **POST** payloads, decodes nested layers of URL/Base64 data, identifies HTML content, and safely logs and stores results.  
Originally designed for XSS proof‑of‑concept captures, it also works as a general decoding backend.

✅ Out‑of‑the‑box support for:
- Recursive URL/Base64 decoding  
- File‑safe storage and JSON logging  
- Threat pattern detection  
- Rate limiting per IP  
- API key authentication  
- `/stats` monitoring endpoint  
- Threaded handling with SSL/TLS, webhooks, and plugins

---

## 🧰 Features

| Category | Description |
|-----------|-------------|
| **Decoding** | Recursive URL/Base64 decoding with optional plugin processing |
| **Logging** | JSON log and console output with full/short preview modes |
| **Security** | IP allowlist, API key auth, content validation, permissions hardening |
| **Network Controls** | Rate limiting per IP, API‑key enforcement |
| **Reporting** | `/stats` endpoint with live metrics |
| **Integrations** | Webhook notifications (Slack, Discord, etc.) |
| **Transport** | SSL/TLS support with hardened ciphers |

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/xss-decode-server.git
cd xss-decode-server
python3 -m venv venv
source venv/bin/activate
pip install requests
```

> Requirements: Python 3.9+

---

## ⚡ Quick Start

Start the decode listener on port 8080:

```bash
python decode_server.py --port 8080
```

Send test data:

```bash
curl "http://localhost:8080/?data=SGVsbG8sIFdvcmxkIQ=="
```

Then open `decoded_html/` to see results saved as:
```
raw_YYYYMMDDTHHMMSSZ.txt
decoded_YYYYMMDDTHHMMSSZ.html
```

---

## 🖥️ Command‑Line Options

| Option | Description |
|---------|-------------|
| `--port, -p` | Port to listen on (default: 80) |
| `--show` | Print decoded **HTML** content to console |
| `--show-all` | Print **all decoded content**, HTML and non‑HTML |
| `--show-full-preview` | Disable truncation in log previews |
| `--json-log` | Write full logs to `decoded_html/log.jsonl` |
| `--allow-ip <IP1> <IP2>` | Restrict access to specific IPs |
| `--api-key <KEY>` | Require `X-API-Key` header |
| `--rate-limit <N>` | Limit requests per IP (default `100`) |
| `--rate-window <S>` | Time window for rate limit (default `60s`) |
| `--webhook-url <URL>` | Send event JSON to a webhook endpoint |
| `--ssl-cert, --ssl-key` | Provide cert pair for HTTPS |
| `--security-level` | `low`, `medium` (default), or `high` |
| `--max-content <B>` | Max upload size (default `10MB`) |
| `--save-dir <DIR>` | Directory to write decoded files |
| `--no-stats` | Disable `/stats` endpoint |
| `--log-level` | Set verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## 🧑🔬 Examples

**Minimal:**
```bash
python decode_server.py --port 8080
```

**Show everything (good for testing):**
```bash
python decode_server.py --port 8080 --show-all --show-full-preview --log-level DEBUG
```

**Secure HTTPS instance:**
```bash
python decode_server.py \
  --port 443 \
  --ssl-cert server.crt --ssl-key server.key \
  --security-level high \
  --api-key SECRET123 \
  --allow-ip 192.168.1.10 10.0.0.2
```

**Webhook integration:**
```bash
python decode_server.py --webhook-url https://hooks.slack.com/services/... --json-log
```

---

## 🧾 Example Output

```text
[2025-11-05 20:15:12,272] [INFO] __main__.Handler: Raw (data) from 192.168.1.253: eyJvdXRwdXQi...
[2025-11-05 20:15:12,272] [INFO] __main__.Handler:     Layer 1 (b64): {"output":"PING localhost(localhost (::1))...
[2025-11-05 20:15:12,272] [INFO] __main__.Handler: Final length: 963 chars
[2025-11-05 20:15:12,272] [INFO] __main__.Handler: Final preview: '{"output":"PING loca'
[2025-11-05 20:15:12,274] [INFO] __main__.FileManager: Saved HTML: ./decoded_html/decoded_20251106T041512Z.html

--- BEGIN DECODED CONTENT ---
{"output":"PING localhost(localhost (::1)) 56 data bytes...
<!DOCTYPE HTML><html lang="en"><head>...</head></html>
--- END DECODED CONTENT ---
```

> Use `--show-all --show-full-preview` to display the entire decoded result in console and logs.

---

## 📊 Stats Endpoint

When enabled (default), view live statistics at:

```
http://localhost:8080/stats
```

**Example Response:**
```json
{
  "total_requests": 24,
  "html_files_saved": 6,
  "blocked_requests": 1,
  "unique_ips": 3,
  "uptime_seconds": 315.14,
  "rate_limiter": {
    "active_ips": 2,
    "total_recent_requests": 10
  },
  "security_level": "medium"
}
```

---

## 🛡️ Security Notes

- Run only in trusted or controlled environments (lab, container, internal net).
- Do **not** expose this service publicly.
- Prefer TLS (`--ssl-cert` / `--ssl-key`) when network‑accessible.
- Set `--api-key` for authenticated use.
- In `--security-level high` mode:
  - Private and loopback IPs are blocked.
  - Suspicious HTML/JS patterns are denied.
  - All writes are sandboxed under restrictive permissions.

---

## 🗄️ Directory Layout

```
decoded_html/
├── raw_<timestamp>.txt
├── decoded_<timestamp>.html
└── log.jsonl
```

---

## 🧩 Architecture Summary

1. **DecodeHandler**
   Handles HTTP GET/POST requests, permission checks, and dispatches decoding logic.

2. **RecursiveDecoder**
   Recursively decodes URL/Base64 data; supports plugin injection.

3. **FileManager**
   Writes sanitized output under strict permissions.

4. **RateLimiter**
   Maintains request counters per IP.

5. **SecurityValidator**
   Applies pattern analysis, IP validation, and behavior restrictions.

6. **WebhookNotifier**
   Dispatches analyzed data to remote systems.

---

## ⚙️ Roadmap

- Plugin discovery and hot‑reloading.  
- SQLite or file‑indexed archival system.  
- Container image for instant deployment.  
- REST API for artifact retrieval.

---

## 🧑💻 Contributing

Pull requests and suggestions are welcome.  
Focus areas: plugin ecosystem, performance enhancements, and new decode strategies.

---

## 📜 License

```
MIT License © 2025
Use responsibly and within lawful, authorized security testing contexts.
```

##
##
