
# CORS (Cross-Origin Resource Sharing) — 2025 primer

**Short definition:**
CORS is an HTTP mechanism that lets servers declare which origins (scheme + host + port) are allowed to access their resources from cross-origin web pages. Browsers enforce these rules to protect users from unsafe cross-origin reads.

## Same-Origin Policy (SOP) — the basics

A *same origin* requires three things to match between the page doing the request and the requested resource:

1. **Scheme** (protocol) — `http` vs `https`
2. **Host** (domain) — `example.com` vs `api.example.com`
3. **Port** — `:80`, `:443`, or a custom port

If any of the three differ, the request is “cross-origin.” Browsers block cross-origin reads unless the server explicitly permits them via CORS response headers.

### Example

Originating page: `http://normal-website.com/example/example.html`

| URL requested                             | Allowed to read response? | Why                         |
| ----------------------------------------- | ------------------------: | --------------------------- |
| `http://normal-website.com/example/`      |                       Yes | same scheme, host, and port |
| `http://normal-website.com:8080/example/` |                        No | different port              |
| `https://normal-website.com/example/`     |                        No | different scheme            |
| `http://en.normal-website.com/example/`   |                        No | different host/subdomain    |

> Note: older or niche browser implementations historically differed; always test target browser matrix when protecting legacy clients.

---

## Key CORS response headers (what servers return)

* **`Access-Control-Allow-Origin: <origin> | *`**

  * Allows that origin to read the response. `*` means any origin — but `*` **cannot** be used if credentials are allowed.
* **`Access-Control-Allow-Credentials: true|false`**

  * When `true`, browsers will include credentials (cookies, Authorization header, TLS client cert) on cross-origin requests and permit JavaScript to read the response. **Never use `*` for `Allow-Origin` with credentials.**
* **`Access-Control-Allow-Methods: <method-list>`**

  * Methods (GET, POST, PUT, DELETE, OPTIONS, etc.) permitted for cross-origin requests.
* **`Access-Control-Allow-Headers: <header-list>`**

  * Lists non-simple request headers the server accepts (e.g., `X-Custom-Header, Authorization`).
* **`Access-Control-Expose-Headers: <header-list>`**

  * Response headers that JS is allowed to read (beyond simple response headers).
* **`Access-Control-Max-Age: <seconds>`**

  * How long (seconds) the preflight response can be cached.
* **`Vary: Origin`**

  * Important when returning different `Access-Control-Allow-Origin` values per request — prevents caching servers (and browsers) from delivering the wrong CORS response to other origins.

---

## What triggers a *preflight* (OPTIONS) request?

Browsers send a preflight (an `OPTIONS` request) when a cross-origin request **is not a "simple request."** A request is **simple** if **all** of these are true:

1. Method is one of: `GET`, `HEAD`, `POST`.
2. Allowed request headers are only the CORS-safelisted headers (examples: `Accept`, `Accept-Language`, `Content-Language`, and `Content-Type` if it’s a safe value).
3. If `Content-Type` is present, it must be one of `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`.
4. No `XMLHttpRequest`/`fetch` `withCredentials` is required to read the response unless the server explicitly allows credentials.

If any of the above are violated (e.g., method `PUT`, a custom header like `X-Api-Version`, `Content-Type: application/json`), the browser will do an OPTIONS preflight to ask the server which methods and headers are allowed.

### Example preflight request

```
OPTIONS /data HTTP/1.1
Host: api.example.com
Origin: https://normal-website.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Special-Header, Content-Type
```

### Example preflight response

```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: X-Special-Header, Content-Type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Vary: Origin
```

> Important: even if a preflight is not required, the *response* still must include the appropriate CORS headers for the browser to let JS read it.

---

## Correct client usage examples

**Fetch with credentials (cookies):**

```js
fetch('https://api.example.com/user', {
  method: 'GET',
  credentials: 'include' // 'same-origin' or 'include' when cookies/credentials are needed
})
.then(r => r.json())
.then(data => console.log(data));
```

**XHR with credentials:**

```js
const xhr = new XMLHttpRequest();
xhr.open('GET', 'https://api.example.com/user', true);
xhr.withCredentials = true;
xhr.onreadystatechange = () => {
  if (xhr.readyState === 4 && xhr.status === 200) {
    console.log(xhr.responseText);
  }
};
xhr.send();
```

---

## Common exploitable misconfigurations (and why they matter)

1. **`Access-Control-Allow-Origin` reflects the incoming `Origin` header without validation**

   * If the server simply echoes `Origin`, an attacker-controlled site can read sensitive responses.

2. **Using `Access-Control-Allow-Origin: *` plus `Access-Control-Allow-Credentials: true`**

   * Browsers forbid this combination, but app logic that attempts to do both or adds credentials server-side can lead to subtle mistakes.

3. **Allowing `null` origin indiscriminately**

   * Some apps whitelist `null` (used by data URLs, `file://`, sandboxed iframes). Whitelisting `null` broadly can create surprises for local dev vs production.

4. **Overly broad wildcard patterns or naive regexes**

   * Bad regexes like `if origin contains 'victim.com'` can be abused using `victim.com.attacker.com` or Unicode confusable hostnames.

5. **Server-side cache poisoning and missing `Vary: Origin`**

   * Caching a CORS response that contains `Access-Control-Allow-Origin: <origin>` without `Vary: Origin` can leak cached responses to other origins.

6. **Subdomain XSS enabling CORS bypass**

   * If any subdomain trusted by the server is vulnerable to XSS, attackers can exfiltrate via the browser using XHR + credentials.

7. **DNS rebinding + internal-auth reliance**

   * If access control depends on client IP (internal ranges), an attacker can use DNS rebinding to make a victim’s browser talk to internal hosts and proxy responses back to the attacker.

8. **Exposed sensitive response headers (no `Access-Control-Expose-Headers` control)**

   * Servers may unknowingly allow sensitive header reads if they provide permissive CORS responses.

---

## Practical mitigations — what to do on the server

* **Only allow exact origins you trust.** Keep a server-side allowlist; never echo `Origin` without strict validation.
* **Use `Vary: Origin`** when returning dynamic `Access-Control-Allow-Origin`. Prevents bad caching.
* **Avoid credentials unless necessary.** Prefer token-based APIs (Authorization bearer tokens) with strict CORS rules and `SameSite` cookie settings where cookies are used.
* **Set `Access-Control-Allow-Credentials` only when strictly needed.**
* **Limit allowed methods and headers** to the minimum necessary.
* **Validate `Origin` server-side** against canonicalized hostnames; be careful with punycode/unicode confusables.
* **Protect subdomains**: treat each subdomain as a distinct origin and harden them (CSP, input sanitization, XSS mitigations).
* **Use authentication & authorization server-side** — don’t rely on CORS as an auth control.
* **Enable modern browser protections**:

  * Use `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, and `Cross-Origin-Resource-Policy` where appropriate.
  * Implement Private Network Access (PNA) policies for access to internal IPs (per WICG specs).
* **Monitor and test** with automated fuzzer tools (see tools list).

---

## Tools & fuzzers (updated)

* **CORScanner** — CORS fuzzing and misconfiguration scans (GitHub).
* **Corsy** — interactive CORS scanner / exploit helper.
* **CorsMe / CorsBuster** — various community tools for testing policies.
* **PayloadsAllTheThings (CORS section)** — practical payloads and patterns.
* **Burp Suite** — manual testing and automation for CORS-related header injection & caching tests.

(Names above — search GitHub or your favorite package index for the latest repos and forks.)

---

## Attack techniques to be aware of (summary)

* **Reflective `Origin` exploitation** — attacker site tricks server to reflect origin and allows reading the response.
* **`null` origin abuse via sandboxed iframes** — `srcdoc` or `data:` frames can cause `Origin: null`.
* **Client/server cache poisoning** — missing `Vary: Origin` or vulnerable caching layers.
* **DNS rebinding to access private services** — use TLS + Host validation + PNA to reduce risk.
* **XSSI / JSONP** — old JSONP endpoints and unsanitized script injection can leak data.

---

## References (recommended reading)

* MDN — *CORS* and the *HTTP headers* reference (developer.mozilla.org).
* PortSwigger — deep articles and research on CORS exploitation.
* OWASP — Cross-origin resource sharing guides and attack categories.
* WICG / Private Network Access — proposals for better private network protections.
* PayloadsAllTheThings — CORS misconfiguration payloads and examples.

---

## Quick checklist for auditors (tl;dr)

* Do you have a server-side origin allowlist (not a naive `Origin` echo)? ✅
* Is `Vary: Origin` set when `Allow-Origin` is dynamic? ✅
* Is `Access-Control-Allow-Credentials` used only where needed? ✅
* Are allowed methods and headers the minimal required? ✅
* Are subdomains hardened and treated separately? ✅
* Are caches/CDNs configured to honor Vary and not leak CORS responses? ✅

---

##
##


# Support HackTricks — 2025 edition ..updated..

* Work at a security company and want your brand shown on HackTricks? Check our sponsorship/subscription plans.
* Subscribers get early access to the latest PEASS builds, downloadable PDFs, and subscriber-only bundles.
* Official PEASS & HackTricks swag, limited drops and community NFTs (optional).
* Join the community: Discord, Telegram and X (formerly Twitter) — follow @carlospolopm for updates.
* Contribute: send pull requests to the HackTricks GitHub repo — share techniques, writeups and checks.
* Want an offline copy? Subscribers can download the up-to-date PDF editions.

---

##
##
