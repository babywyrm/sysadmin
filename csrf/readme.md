

# CSRF vs XSS: Enhanced Technical Guide with Visual Diagrams

## Attack Flow Diagrams

### CSRF Attack Flow
```
┌─────────────┐    1. Visit malicious site    ┌─────────────┐
│   Victim    │ ──────────────────────────────▶│  Attacker   │
│   Browser   │                                │    Site     │
└─────────────┘                                └─────────────┘
       │                                              │
       │ 2. Malicious site serves                     │
       │    forged request                            │
       ▼                                              │
┌─────────────┐                                       │
│   Victim    │                                       │
│   Browser   │                                       │
│ ┌─────────┐ │ 3. Browser auto-includes               │
│ │ Cookies │ │    auth cookies                       │
│ │ Session │ │                                       │
│ └─────────┘ │                                       │
└─────────────┘                                       │
       │                                              │
       │ 4. Authenticated request                     │
       │    (victim unaware)                          │
       ▼                                              │
┌─────────────┐                                       │
│   Target    │ 5. Executes action                    │
│   Website   │    (transfer money, etc.)             │
│             │                                       │
└─────────────┘                                       │
       │                                              │
       │ 6. Success response                          │
       └──────────────────────────────────────────────┘
```

### XSS Attack Flow
```
┌─────────────┐    1. Inject malicious script    ┌─────────────┐
│  Attacker   │ ─────────────────────────────────▶│   Target    │
│             │                                   │   Website   │
└─────────────┘                                   └─────────────┘
                                                         │
                                                         │ 2. Store/Reflect
                                                         │    malicious script
                                                         ▼
┌─────────────┐    3. Visit infected page        ┌─────────────┐
│   Victim    │ ──────────────────────────────────│   Target    │
│   Browser   │                                   │   Website   │
└─────────────┘                                   └─────────────┘
       ▲                                                 │
       │                                                 │ 4. Serve page with
       │                                                 │    malicious script
       │                                                 ▼
       │                                          ┌─────────────┐
       │ 6. Script executes in                    │   Victim    │
       │    target's context                      │   Browser   │
       │                                          │ ┌─────────┐ │
       │                                          │ │ Cookies │ │
       │                                          │ │ Session │ │
       │                                          │ └─────────┘ │
       │                                          └─────────────┘
       │                                                 │
       │                                                 │ 5. Malicious script
       │                                                 │    accesses data
       │                                                 ▼
       │                                          ┌─────────────┐
       └──────────────────────────────────────────│  Attacker   │
                 7. Steal data/credentials        │   Server    │
                                                  └─────────────┘
```

## Comprehensive Comparison Table

| Category | CSRF | XSS |
|----------|------|-----|
| **Attack Vector** | Forged cross-site requests | Malicious script injection |
| **Execution Context** | Victim's browser → Target site | Target site → Victim's browser |
| **Trust Exploitation** | Site trusts authenticated user | User trusts legitimate site |
| **User Awareness** | Often completely unaware | May notice unusual behavior |
| **Persistence** | Per-request basis | Can be persistent (Stored XSS) |
| **Authentication Required** | Yes (victim must be logged in) | No (but more powerful if authenticated) |
| **Same-Origin Limitation** | Bypasses (cross-site nature) | Executes within origin |
| **Primary Impact** | Unauthorized actions | Data theft, session hijacking |
| **Detection Difficulty** | Moderate (network analysis) | High (content analysis required) |

## Attack Scenarios Matrix

### CSRF Scenarios
```
┌─────────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐
│   Attack Type       │   Delivery Method   │   Target Action     │   Stealth Level     │
├─────────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Form Auto-Submit    │ Malicious Website   │ State Change        │ High                │
│ Image Tag Exploit   │ Email/Website       │ GET-based Action    │ Very High           │
│ AJAX Request        │ Malicious Website   │ API Calls           │ Medium              │
│ File Upload         │ Malicious Website   │ File System Access  │ Medium              │
│ WebSocket Hijack    │ Malicious Website   │ Real-time Actions   │ High                │
└─────────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘
```

### XSS Scenarios
```
┌─────────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐
│   XSS Type          │   Injection Point   │   Payload Delivery  │   Persistence       │
├─────────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Reflected           │ URL Parameters      │ Malicious Link      │ Temporary           │
│ Stored              │ Database            │ User Input Forms    │ Permanent           │
│ DOM-based           │ Client-side JS      │ URL Fragments       │ Temporary           │
│ Mutation-based      │ DOM Manipulation    │ Dynamic Content     │ Temporary           │
│ Server-side         │ Template Engine     │ Server Processing   │ Permanent           │
└─────────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘
```

## Technical Implementation Comparison

### CSRF Attack Implementations

#### Simple Form-Based CSRF
```ascii
Attacker Site Structure:
┌─────────────────────────────────────────┐
│ <html>                                  │
│   <body onload="document.forms[0].      │
│                 submit()">              │
│     <form action="https://bank.com/     │
│           transfer" method="POST">      │
│       <input name="to" value="evil">   │
│       <input name="amount" value="1000">│
│     </form>                             │
│   </body>                              │
│ </html>                                 │
└─────────────────────────────────────────┘
```

#### JSON API CSRF
```ascii
Modern API Attack:
┌─────────────────────────────────────────┐
│ fetch('https://api.target.com/users',   │
│   {                                     │
│     method: 'DELETE',                   │
│     credentials: 'include',             │
│     headers: {                          │
│       'Content-Type': 'application/json'│
│     },                                  │
│     body: JSON.stringify({id: 'victim'})│
│   }                                     │
│ );                                      │
└─────────────────────────────────────────┘
```

### XSS Attack Implementations

#### Reflected XSS Flow
```ascii
Request Flow:
┌─────────────┐    GET /search?q=<script>  ┌─────────────┐
│   Victim    │ ─────────alert('XSS')──────▶│   Target    │
│   Browser   │                             │   Server    │
└─────────────┘                             └─────────────┘
       ▲                                           │
       │                                           │
       │ HTTP/1.1 200 OK                          │
       │ <h1>Results for: <script>                │
       │ alert('XSS')</script></h1>               │
       └───────────────────────────────────────────┘
```

#### Stored XSS Database Flow
```ascii
Database Injection:
┌─────────────┐    POST /comment           ┌─────────────┐
│  Attacker   │ ──────────────────────────▶│   Web       │
│             │  payload: <script>evil()   │   Server    │
└─────────────┘                             └─────────────┘
                                                   │
                                                   ▼
                                            ┌─────────────┐
                                            │  Database   │
                                            │ ┌─────────┐ │
                                            │ │ comments│ │
                                            │ │ <script>│ │
                                            │ │ evil()  │ │
                                            │ └─────────┘ │
                                            └─────────────┘
                                                   │
┌─────────────┐    GET /comments           ┌─────────────┐
│   Victim    │ ◄──────────────────────────│   Web       │
│   Browser   │  <script>evil()</script>   │   Server    │
└─────────────┘                             └─────────────┘
```

## Defense Mechanisms Comparison

### CSRF Defense Architecture
```ascii
Defense Layers:
┌─────────────────────────────────────────────────────────────┐
│                    CSRF Defense Stack                       │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: SameSite Cookies                                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Set-Cookie: session=abc123; SameSite=Strict; Secure    │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: CSRF Tokens                                        │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ <input type="hidden" name="csrf" value="random_token">  │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Origin/Referer Validation                          │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ if (origin !== 'https://trusted-site.com') reject()    │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Custom Headers                                     │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ X-Requested-With: XMLHttpRequest                        │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### XSS Defense Architecture
```ascii
Defense Layers:
┌─────────────────────────────────────────────────────────────┐
│                     XSS Defense Stack                       │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Input Validation & Sanitization                    │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Input → Validate → Sanitize → Encode → Store/Display   │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Content Security Policy (CSP)                      │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Content-Security-Policy: script-src 'self' 'nonce-xyz' │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Output Encoding                                    │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ <script> → &lt;script&gt;                               │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: HTTPOnly Cookies                                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Set-Cookie: session=abc123; HttpOnly; Secure           │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Combined Attack Scenario

### XSS-Enhanced CSRF Attack Flow
```ascii
Advanced Combined Attack:
                    ┌─────────────┐
                    │  Attacker   │
                    │   Server    │
                    └─────────────┘
                           │
                           │ 1. Inject XSS payload
                           ▼
    ┌─────────────┐ ──────────────────── ┌─────────────┐
    │   Victim    │ 2. Visit target site │   Target    │
    │   Browser   │ ◄─────────────────── │   Website   │
    └─────────────┘                      └─────────────┘
           │                                     │
           │ 3. XSS payload executes            │
           ▼                                     │
    ┌─────────────┐                             │
    │   Malicious │ 4. Extract CSRF token       │
    │   Script    │ ◄───────────────────────────┘
    │   Execution │
    └─────────────┘
           │
           │ 5. Forge authenticated request
           │    with valid CSRF token
           ▼
    ┌─────────────┐
    │   Target    │ 6. Execute privileged action
    │   Website   │    (appears legitimate)
    │   API       │
    └─────────────┘
```

## 2025 Threat Landscape

### Emerging Attack Vectors
```ascii
Modern Web Attack Surface:
┌─────────────────────────────────────────────────────────────┐
│                    Browser Environment                       │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│ │   Main      │ │   Service   │ │   Web       │ │  WASM   │ │
│ │   Thread    │ │   Worker    │ │  Worker     │ │ Module  │ │
│ │   ┌─────┐   │ │   ┌─────┐   │ │   ┌─────┐   │ │ ┌─────┐ │ │
│ │   │ XSS │   │ │   │ XSS │   │ │   │ XSS │   │ │ │ XSS │ │ │
│ │   └─────┘   │ │   └─────┘   │ │   └─────┘   │ │ └─────┘ │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐ │
│ │   Browser   │ │   PWA       │ │   Extension │ │  iframe │ │
│ │   Extension │ │   Context   │ │   Content   │ │ Context │ │
│ │   ┌─────┐   │ │   ┌─────┐   │ │   ┌─────┐   │ │ ┌─────┐ │ │
│ │   │CSRF │   │ │   │CSRF │   │ │   │CSRF │   │ │ │CSRF │ │ │
│ │   └─────┘   │ │   └─────┘   │ │   └─────┘   │ │ └─────┘ │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘ │
└─────────────────────────────────────────────────────────────┘
```




## 📃 CSRF Defense Cheat Sheet (2025 Edition)

### 🔐 Common CSRF Defenses

#### 1. CSRF Tokens

* Use **cryptographically secure random values**
* Must be **tied to the authenticated session**
* Best practice: **double-submit cookie** pattern with `SameSite` attribute
* Should not be guessable, predictable, or reused
* Implement with **per-form or per-request token freshness**
* Example (with JavaScript fetch):

```javascript
fetch('/transfer', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': getCSRFTokenFromCookie(),
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify({ amount: 100 })
})
```

---

#### 2. HTTP Headers

| Header    | Purpose                             |
| --------- | ----------------------------------- |
| `Origin`  | Indicates the origin of the request |
| `Referer` | Shows full URL path of the page     |

* Validate both `Origin` and `Referer` headers on **state-changing requests**
* Reject requests with missing, empty, or cross-origin headers
* Consider `strict-origin-when-cross-origin` referrer policy for granularity

---

#### 3. SameSite Cookie Attribute

| Mode     | Behavior                                                          |
| -------- | ----------------------------------------------------------------- |
| `None`   | Cookies sent on all requests (requires `Secure` flag)             |
| `Lax`    | Sent on top-level GET navigations, **default** in modern browsers |
| `Strict` | Only sent in same-site requests, **most secure**                  |

```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict
```

---

## 🌐 Cross-Origin Resource Sharing (CORS)

### 🔹 Important CORS Headers

| Header                             | Description                                                    |
| ---------------------------------- | -------------------------------------------------------------- |
| `Access-Control-Allow-Origin`      | Specifies allowed origin(s)                                    |
| `Access-Control-Allow-Methods`     | Specifies allowed HTTP methods (e.g. `POST, PUT`)              |
| `Access-Control-Allow-Headers`     | Specifies allowed headers (e.g. `Authorization, X-CSRF-Token`) |
| `Access-Control-Allow-Credentials` | Allows credentials (cookies, headers) in requests              |
| `Access-Control-Expose-Headers`    | Indicates which headers are visible to the browser             |
| `Access-Control-Max-Age`           | Defines how long preflight responses can be cached             |

### 🤔 Simple vs Preflighted Requests

**Simple requests**:

* `GET`, `HEAD`, `POST` with **no custom headers**
* `Content-Type` must be: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`

**Preflighted requests**:

* All other requests
* Browser sends an `OPTIONS` request **before the actual request**
* Server must handle and allow based on origin/method/headers

---

### ❌ Common CORS Misconfigurations

* `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`
* Reflecting arbitrary `Origin` headers (e.g., `echo back Origin`)
* Including `null` as a trusted origin (e.g., via file:// schemes)
* Omitting preflight handling or headers in `OPTIONS` responses

Example of an **insecure misconfig**:

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

---

## 🔒 Content-Security Policy (CSP)

### 🔹 Core CSP Directives

| Directive                   | Use Case                                               |
| --------------------------- | ------------------------------------------------------ |
| `default-src`               | Fallback for all resource types not explicitly defined |
| `script-src`                | Controls JS sources                                    |
| `style-src`                 | Controls CSS sources                                   |
| `img-src`                   | Controls image sources                                 |
| `connect-src`               | Defines origins for XMLHttpRequest / fetch             |
| `frame-ancestors`           | Prevents Clickjacking (like `X-Frame-Options`)         |
| `form-action`               | Limits where forms can be submitted                    |
| `base-uri`                  | Restricts the base tag to avoid path manipulation      |
| `upgrade-insecure-requests` | Forces HTTPS for all resource fetches                  |

### Example CSP Header

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
```

---

## 🛡️ XSS Filter Bypass Techniques (Advanced Reference)

### 🔹 Encodings and Payload Variants

| Technique    | Example                                            |
| ------------ | -------------------------------------------------- |
| Unicode      | `alert(1)`                                         |
| Octal        | `\141\154\145\162\164\50\61\51`                    |
| Hex          | `\x61\x6c\x65\x72\x74\x28\x31\x29`                 |
| Base64       | `atob("YWxlcnQoMSk=")`                             |
| fromCharCode | `String.fromCharCode(97,108,101,114,116,40,49,41)` |
| No-Space     | `<svg/onload=alert(1)>`                            |
| URI Decoding | `decodeURI(/alert("xss")/.source)`                 |

### 🔹 Dangerous Execution Sinks

* `eval()`
* `setTimeout()` / `setInterval()` with string args
* `Function("code")()`
* `new Function("code")`
* `[].constructor.constructor("alert(1)")()`

### 🔹 Bypass Patterns

```html
<ScRiPt>alert(1);</ScRiPt>
<object data="JaVaScRiPt:alert(1)">
<img src=x OnErRoR=alert(1)>
<svg/onload=alert(1)>
<script src="data:text/javascript,alert(1)"></script>
```

### 🔹 CSP-Aware Bypasses

* Exploit `script-src-elem` vs `script-src`
* Use allowed inline event handlers if `'unsafe-inline'` is present
* Abuse open redirect + data URLs if `connect-src` allows `data:`

---

Continue using this reference alongside a hardened CSP, secure session cookies (`SameSite=Strict; Secure; HttpOnly`), and token-based anti-CSRF mechanisms (double-submit pattern or server-bound tokens).

For advanced defense-in-depth, combine:

* CSP (restricts resource loading)
* Origin/Referer validation
* SameSite cookies
* Per-request CSRF tokens
* JWT audience + CSRF token coupling

---

## 📑 Additional Resources

* [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
* [Mozilla CORS Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
* [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
* [PortSwigger XSS Bypass List](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
* [WebAppSec SameSite Cookies](https://web.dev/samesite-cookies-explained/)
* [CSRF Prevention in SPAs](https://github.com/spotify/backstage/issues/3660#issuecomment-726127604)
* 
