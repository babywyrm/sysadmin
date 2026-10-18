

# **Advanced CSRF Simulation — Internal Training Runbook**

**Purpose:**  
This simulation demonstrates how poorly implemented CSRF defenses and loose CORS or cookie configurations could be abused.  
It exists solely to train internal **red** (offensive simulation) and **blue** (defensive detection/response) teams in recognizing and mitigating such conditions.

---

## **1. Scenario Overview**

**Objective:** Validate whether a web application correctly enforces CSRF protection mechanisms across authenticated endpoints.

**Key Focus Areas:**
- Token generation and binding (per‑session vs per‑request).
- CORS and credential handling (Origin, Referer, SameSite).
- Content‑Type and preflight enforcement.
- Logging and alerting of anomalous cross‑origin activity.

---

## **2. Simulation Architecture**

The lab consists of:
- `victim-app.local` — a mock vulnerable application.
- `attacker-sim.local` — a safe simulator script running in a sandboxed environment.
- Monitoring tools for HTTP traces and audit logs.

All requests in this exercise are **local simulations** — no real internet communication occurs.

---

## **3. Conceptual Flow**

Each exercise step represents what an attacker *would try*, but the environment only **simulates** responses.

```text
Step 1. Fetch the protected resource (e.g., /account/settings)
         → Verify how the app sends CSRF tokens (meta tag, hidden form, JS variable)

Step 2. Attempt to reuse or replay these tokens across an unintended endpoint (/api/transfer)
         → The simulator logs server behavior (accepted, rejected, error)

Step 3. Blue Team verifies:
         - Were invalid requests blocked?
         - Did the response omit sensitive data?
         - Are tokens unique per session?
         - Did logs capture the origin mismatch?
```

---

## **4. Example Simulator Stub (Safe Code)**

```js
/**
 * CSRF Training Simulator (for internal labs only)
 * This does NOT execute real cross‑domain network requests.
 * It models CSRF token extraction and validation scenarios.
 */

class CSRFTrainingSimulator {
  constructor() {
    this.mockHTML = `
      <meta name="csrf-token" content="SIMULATED_TOKEN_123">
      <input type="hidden" name="csrfmiddlewaretoken" value="SIMULATED_TOKEN_456">
    `;
    this.log = [];
  }

  extractTokens() {
    const tokens = [];
    if (this.mockHTML.includes('csrf-token')) tokens.push('meta');
    if (this.mockHTML.includes('csrfmiddlewaretoken')) tokens.push('form');
    this.log.push(`Extracted token types: ${tokens.join(', ')}`);
    return tokens;
  }

  simulateAction(tokensUsed) {
    // Simulate a defense check
    const success = tokensUsed.includes('meta') && tokensUsed.includes('form');
    this.log.push(success ? 'Defense succeeded (CSRF rejected)' : 'Defense failed (token missing)');
    return success;
  }

  run() {
    const tokens = this.extractTokens();
    this.simulateAction(tokens);
    return this.log;
  }
}

// Demo (safe local testing)
const simulator = new CSRFTrainingSimulator();
console.log(simulator.run());
```

This stub lets trainees observe how different token combinations affect pass/fail results — but no live network calls are made.

---

## **5. Blue Team Validation Checklist**

| Area | Validation Goal | Tools / Evidence |
|------|-----------------|------------------|
| CSRF tokens | Each action requires a valid, session‑bound token | HTTP inspector, network logs |
| Cookies | SameSite set to `Lax` or `Strict` | Browser dev tools |
| CORS | No wildcard `Access-Control-Allow-Origin` with credentials enabled | Burp/ZAP |
| Header integrity | Origin and Referer validated | WAF or application logs |
| Error handling | Failed CSRF attempts are logged clearly | Server log review |
| Alerting | SIEM detects multiple cross‑origin attempts | Security monitoring |

---

## **6. Variants and Learning Scenarios**

- **Misconfigured Tokens:**  
  Test what happens if tokens are accepted across users or reused between sessions.
- **CORS Exposure:**  
  Simulate endpoints where `Access-Control-Allow-Origin: *` with `credentials: true` exists.
- **2FA/Chained Auth:**  
  Evaluate if secondary checks prevent transaction-level CSRF.

---

## **7. Defensive Takeaways**

- Regenerate CSRF tokens on each sensitive action.  
- Use `SameSite=Strict` for cookies unless cross‑domain interaction is required.  
- Enforce strict `Origin` and `Referer` validation.  
- Disable credentialed CORS unless absolutely necessary.  
- Log and alert on anomalies in cross‑origin requests.

---

## **8. Lab Debrief Template**

| Role | Question | Notes |
|------|-----------|-------|
| Red Team | Which protection failed or was missing? | |
| Blue Team | How did detection systems respond? | |
| Developers | What code/config changes mitigate this? | |
| Management | Were internal alerts or tickets generated? | |

---

##
##
