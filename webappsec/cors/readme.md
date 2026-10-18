

# CORS — A Developer's Field Guide

CORS (Cross-Origin Resource Sharing) is a browser security mechanism that controls how web applications interact with resources from different origins. Understanding it deeply saves you from hours of debugging cryptic network errors and helps you build secure APIs.

---

## The Problem CORS Solves

Browsers enforce the **Same-Origin Policy (SOP)** — a security rule that prevents scripts on one origin from reading responses from another. An "origin" is the combination of protocol + host + port:

```text
https://app.example.com:443
│       │               │
protocol host            port
```

These are all different origins:
```text
http://example.com       # different protocol
https://api.example.com  # different subdomain
https://example.com:8080 # different port
```

Without SOP, a malicious site could silently make authenticated requests to your bank, read the response, and exfiltrate data. With SOP, the browser blocks the response. CORS is the controlled, opt-in mechanism to relax that restriction when you actually need cross-origin communication.

---

## How CORS Works

CORS is entirely header-driven. The server declares what it allows; the browser enforces it. The client cannot override this — it's implemented in the browser, not in your JavaScript.

### The Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `Access-Control-Allow-Origin` | Response | Which origin(s) may access the resource |
| `Access-Control-Allow-Methods` | Response (preflight) | Which HTTP methods are permitted |
| `Access-Control-Allow-Headers` | Response (preflight) | Which request headers are permitted |
| `Access-Control-Expose-Headers` | Response | Which response headers JS can read |
| `Access-Control-Allow-Credentials` | Response | Whether cookies/auth headers are allowed |
| `Access-Control-Max-Age` | Response (preflight) | How long to cache the preflight result (seconds) |
| `Origin` | Request | Set automatically by the browser — never by JS |

---

## Request Types

### 1. Simple Requests

A request is "simple" if it meets all of these:
- Method is `GET`, `POST`, or `HEAD`
- Only uses [CORS-safelisted headers](https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_request_header)
- `Content-Type` is one of: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`

Simple requests go straight to the server. The browser checks the response headers and decides whether to expose the response to JS.

```text
Browser                          Server
   │                                │
   │── GET /api/data ──────────────▶│
   │   Origin: https://app.com      │
   │                                │
   │◀─ 200 OK ─────────────────────│
   │   Access-Control-Allow-Origin: https://app.com
   │                                │
   │  ✅ Browser exposes response to JS
```

### 2. Preflighted Requests

Any request that doesn't qualify as "simple" triggers a **preflight** — an automatic `OPTIONS` request the browser sends first to ask the server what it allows.

Common triggers:
- Methods: `PUT`, `DELETE`, `PATCH`
- Custom headers: `Authorization`, `X-Custom-Header`, etc.
- `Content-Type: application/json`

```text
Browser                          Server
   │                                │
   │── OPTIONS /api/data ──────────▶│  (preflight)
   │   Origin: https://app.com      │
   │   Access-Control-Request-Method: DELETE
   │   Access-Control-Request-Headers: Authorization
   │                                │
   │◀─ 204 No Content ─────────────│
   │   Access-Control-Allow-Origin: https://app.com
   │   Access-Control-Allow-Methods: GET, POST, DELETE
   │   Access-Control-Allow-Headers: Authorization
   │   Access-Control-Max-Age: 1800
   │                                │
   │── DELETE /api/data ───────────▶│  (actual request)
   │   Origin: https://app.com      │
   │   Authorization: Bearer ...    │
   │                                │
   │◀─ 200 OK ─────────────────────│
   │                                │
   │  ✅ Browser exposes response to JS
```

### 3. Credentialed Requests

By default, cross-origin requests don't include cookies or `Authorization` headers. To include them:

```js
// fetch
fetch('https://api.example.com/data', {
  credentials: 'include'
})

// XMLHttpRequest
const xhr = new XMLHttpRequest()
xhr.withCredentials = true
```

For the browser to expose the response, the server **must**:
1. Set `Access-Control-Allow-Credentials: true`
2. Set `Access-Control-Allow-Origin` to a **specific origin** — `*` is not allowed here

```text
❌  Access-Control-Allow-Origin: *
    Access-Control-Allow-Credentials: true

✅  Access-Control-Allow-Origin: https://app.example.com
    Access-Control-Allow-Credentials: true
```

---

## Server Configuration Examples

### Node.js / Express

```js
import cors from 'cors'
import express from 'express'

const app = express()

// Permissive — fine for public APIs
app.use(cors())

// Locked down — for production
app.use(cors({
  origin: 'https://app.example.com',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 1800 // 30 minutes
}))

// Dynamic origin whitelisting
const allowedOrigins = new Set([
  'https://app.example.com',
  'https://admin.example.com'
])

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.has(origin)) {
      cb(null, true)
    } else {
      cb(new Error(`Origin ${origin} not allowed`))
    }
  }
}))
```

### Nginx

```nginx
location /api/ {
    if ($request_method = 'OPTIONS') {
        add_header 'Access-Control-Allow-Origin' 'https://app.example.com';
        add_header 'Access-Control-Allow-Methods' 'GET, POST, DELETE, OPTIONS';
        add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type';
        add_header 'Access-Control-Max-Age' 1800;
        return 204;
    }

    add_header 'Access-Control-Allow-Origin' 'https://app.example.com';
    add_header 'Access-Control-Allow-Credentials' 'true';
}
```

### Go

```go
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
        w.Header().Set("Access-Control-Allow-Credentials", "true")

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

---

## Bypassing CORS (and When That's Legitimate)

Sometimes you need to work around CORS — for scraping, local development, or proxying to third-party APIs you don't control. Here are the real approaches:

### Server-Side Proxy (The Right Way)

Your backend makes the request — CORS is a browser restriction, servers aren't subject to it.

```js
// Express proxy endpoint
app.get('/proxy', async (req, res) => {
  const { url } = req.query
  const response = await fetch(url)
  const data = await response.text()
  res.send(data)
})
```

```js
// Client calls your proxy instead of the external domain
const res = await fetch(`/proxy?url=${encodeURIComponent('https://external-api.com/data')}`)
```

> ⚠️ Never build an open proxy in production. Validate and whitelist the URLs your proxy will accept.

### HTML Scraping via Proxy (`bypasscors`)

If you need to scrape external pages and parse them as DOM:

```bash
npm install bypasscors express
```

```js
// server.js
app.get('/geturl', (req, res) => {
  require('bypasscors')(req.query.url, (html) => res.send(html))
})
```

```js
// client — parse the returned HTML as DOM
const res = await fetch(`/geturl?url=${encodeURIComponent('https://example.com')}`)
const html = await res.text()
const doc = new DOMParser().parseFromString(html, 'text/html')
doc.querySelectorAll('div') // etc.
```

> **Limitation:** This returns static HTML only. JavaScript-rendered content (React, Vue, etc.) won't be present. For that, you need a headless browser.

### Full JS Execution via iframe

For JS-rendered pages, load the proxied URL into a hidden iframe on the same origin:

```js
const iframe = document.createElement('iframe')
iframe.style.cssText = 'width:0;height:0;border:none;'
document.body.appendChild(iframe)

iframe.src = `/proxy?url=${encodeURIComponent(targetUrl)}`

iframe.addEventListener('load', () => {
  // Same-origin now — browser allows DOM access
  const content = iframe.contentWindow.document.body.innerHTML
})
```

For server-side JS execution, use [Playwright](https://playwright.dev) or [Puppeteer](https://pptr.dev) instead of the deprecated PhantomJS.

### `cors-bypass` (postMessage Approach)

For situations like **offline PWAs needing HTTP APIs from an HTTPS context**, [`cors-bypass`](https://github.com/nicktindall/cyclon.p2p-rtc-io) uses `postMessage` and `BroadcastChannel` across tabs to proxy requests through a page on the permissive origin.

```js
import * as BypassCors from 'cors-bypass'

const client = new BypassCors.Client()

await client.openServerInNewTab({
  serverUrl: 'http://http-domain.com/server.html',   // the permissive origin
  adapterUrl: 'https://your-app.com/adapter.html'    // your app's relay page
})

// WebSocket proxied through the server tab, but usable here
const ws = new BypassCors.WebSocket('ws://echo.websocket.org')
ws.onopen = () => ws.send('hello')
ws.onmessage = ({ data }) => console.log('received:', data)
```

Architecture:
```text
your-app.com (HTTPS)          http-domain.com (HTTP)
┌──────────────────┐          ┌──────────────────┐
│  Client          │          │  Server          │
│  + Adapter       │◀────────▶│  (makes actual   │
│  (BroadcastChan) │postMsg   │   HTTP requests) │
└──────────────────┘          └──────────────────┘
```

---

## Security Considerations

### Do
- **Whitelist specific origins** — avoid `*` on any endpoint that touches user data
- **Validate the `Origin` header server-side** against your allowlist — don't just reflect it back blindly
- **Keep preflight cache short** — Google recommends `< 1800s` (30 min); long caches can mask header changes
- **Audit `Access-Control-Expose-Headers`** — only expose headers that are safe to read from JS

### Don't
- **Don't treat CORS as authentication** — it's a browser hint, not a security boundary. A `curl` request ignores it entirely
- **Don't use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`** — browsers reject this, but it signals a misconfiguration
- **Don't reflect the `Origin` header without validation:**

```js
// ❌ Dangerous — allows any origin
res.setHeader('Access-Control-Allow-Origin', req.headers.origin)

// ✅ Safe — validate first
const origin = req.headers.origin
if (allowedOrigins.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin)
}
```

---

## Debugging CORS Errors

Most CORS errors are opaque by design — the browser won't tell your JS *why* the request was blocked, only that it was.

| Symptom | Likely Cause |
|---------|-------------|
| `No 'Access-Control-Allow-Origin' header` | Server not sending CORS headers at all |
| `Origin not allowed` | Origin mismatch or wildcard with credentials |
| Preflight returns `405` | Server doesn't handle `OPTIONS` |
| Cookies not sent | Missing `credentials: 'include'` or `withCredentials` |
| Custom header blocked | Not listed in `Access-Control-Allow-Headers` |

**Check with curl to isolate browser vs server issues:**

```bash
# Simulate a preflight
curl -X OPTIONS https://api.example.com/data \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: Authorization" \
  -v
```

If the response headers look right in `curl` but the browser still blocks — check for `credentials` mismatches or wildcard `*` conflicts.

---

## References

- [MDN — Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [W3C CORS Specification](https://www.w3.org/TR/cors/)
- [OWASP CORS Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Fetch Living Standard — CORS Protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [Google Web Fundamentals — CORS](https://web.dev/cross-origin-resource-sharing/)
