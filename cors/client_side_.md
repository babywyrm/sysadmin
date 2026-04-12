# Handle CORS Client-side — Extended Research

> **Cross-origin resource sharing** (CORS) is a browser security mechanism that restricts web pages from making requests to a different domain than the one that served the page. **CORS is enforced by the browser and configured on the server — there is no legitimate client-side override for production use. However, there are architectural patterns and workarounds worth understanding.**

_Sources_: [MDN - HTTP Access Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS) | [Wiki - CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) | [OWASP CORS](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny) | [Fetch Living Standard](https://fetch.spec.whatwg.org/)

---

## Table of Contents

1. [What is CORS? Deep Dive](#1-what-is-cors-deep-dive)
2. [CORS Headers — Full Reference](#2-cors-headers--full-reference)
3. [Preflight Requests Explained](#3-preflight-requests-explained)
4. [Simple vs. Preflighted vs. Credentialed Requests](#4-simple-vs-preflighted-vs-credentialed-requests)
5. [Server-side CORS Setup (for context)](#5-server-side-cors-setup-for-context)
6. [Bypassing CORS in Production](#6-bypassing-cors-in-production)
7. [Bypassing CORS in Development](#7-bypassing-cors-in-development)
8. [CORS Security Implications](#8-cors-security-implications)
9. [Troubleshooting CORS Errors](#9-troubleshooting-cors-errors)
10. [Modern Alternatives to CORS Workarounds](#10-modern-alternatives-to-cors-workarounds)

---

## 1. What is CORS? Deep Dive

CORS is part of the **Same-Origin Policy (SOP)** — a critical browser security model. Two URLs share the same origin **only if** all three match:

| Component | Example |
|-----------|---------|
| Protocol | `https://` |
| Host | `example.com` |
| Port | `:443` |

So `https://example.com` and `http://example.com` are **different origins** (different protocol). Likewise `https://example.com` and `https://api.example.com` are **different origins** (different subdomain).

### Why does it exist?

Without SOP/CORS, a malicious site could make authenticated requests to your bank, Gmail, or any other site you're logged into — and read the response. CORS is a *protection*, not a bureaucratic annoyance.

### What CORS does NOT restrict

- Form submissions (historically allowed before CORS existed)
- `<script>`, `<img>`, `<link>`, `<iframe>` tag loads (which is what JSONP exploits)
- Requests from non-browser clients (Postman, curl, servers) — **CORS is browser-only**

---

## 2. CORS Headers — Full Reference

### Request Headers (sent by the browser)

```http
Origin: https://yourdomain.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization
```

### Response Headers (sent by the server)

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: https://yourdomain.com

Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS

Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With

Access-Control-Allow-Credentials: true

Access-Control-Max-Age: 86400

Access-Control-Expose-Headers: X-Custom-Header, Content-Length
```

#### Header Breakdown

| Header | Purpose | Notes |
|--------|---------|-------|
| `Access-Control-Allow-Origin` | Which origins may access | `*` or specific origin |
| `Access-Control-Allow-Methods` | Which HTTP methods are permitted | Comma-separated |
| `Access-Control-Allow-Headers` | Which request headers are allowed | Must list custom headers |
| `Access-Control-Allow-Credentials` | Allow cookies/auth headers | Cannot use `*` with this |
| `Access-Control-Max-Age` | How long to cache preflight (seconds) | Reduces preflight requests |
| `Access-Control-Expose-Headers` | Which response headers JS can read | Default headers are always accessible |

> **Important:** When `Access-Control-Allow-Credentials: true` is set, `Access-Control-Allow-Origin` **cannot** be a wildcard `*`. It must be an explicit origin.

---

## 3. Preflight Requests Explained

For requests that might have side effects (non-simple requests), the browser first sends an **OPTIONS preflight request** to check permissions before the actual request.

```
Browser                          Server
   |                               |
   |--- OPTIONS /api/data -------->|   (preflight)
   |    Origin: https://app.com   |
   |    Access-Control-Request-   |
   |    Method: POST              |
   |                               |
   |<-- 200 OK -------------------|   (preflight response)
   |    Access-Control-Allow-     |
   |    Origin: https://app.com   |
   |    Access-Control-Allow-     |
   |    Methods: POST             |
   |                               |
   |--- POST /api/data ----------->|   (actual request)
   |<-- 200 OK -------------------|   (actual response)
```

### Visualizing the full flow in code

```js
// This triggers a preflight because of the custom header
const response = await fetch("https://api.example.com/data", {
  method: "POST",
  headers: {
    "Content-Type": "application/json", // triggers preflight
    Authorization: "Bearer token123", // triggers preflight
  },
  body: JSON.stringify({ name: "T3 Chat" }),
});
```

---

## 4. Simple vs. Preflighted vs. Credentialed Requests

### Simple Requests (no preflight)

A request is "simple" and skips preflight if **all** of the following are true:

- Method is `GET`, `POST`, or `HEAD`
- Only uses headers: `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`
- `Content-Type` is one of: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`

```js
// Simple request — no preflight
fetch("https://api.example.com/data");

// Also simple
fetch("https://api.example.com/data", {
  method: "POST",
  body: new FormData(),
});
```

### Preflighted Requests

```js
// NOT simple — triggers preflight (JSON content-type + custom header)
fetch("https://api.example.com/data", {
  method: "DELETE",
  headers: {
    "Content-Type": "application/json",
    "X-Custom-Header": "value",
  },
});
```

### Credentialed Requests (Cookies & Auth)

By default, browsers do **not** send cookies cross-origin. You must opt in:

```js
fetch("https://api.example.com/data", {
  credentials: "include", // sends cookies, TLS certs, HTTP auth
});

// OR with XMLHttpRequest:
const xhr = new XMLHttpRequest();
xhr.withCredentials = true;
```

And the server **must** respond with:

```http
Access-Control-Allow-Origin: https://yourdomain.com
Access-Control-Allow-Credentials: true
```

---

## 5. Server-side CORS Setup (for context)

Since CORS is a server concern, here's how you'd configure it across common platforms:

### Node.js — Express

```js
import cors from "cors";
import express from "express";

const app = express();

// Allow all origins (development only — be careful)
app.use(cors());

// Allow specific origin with credentials
app.use(
  cors({
    origin: "https://yourdomain.com",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    maxAge: 86400, // cache preflight for 24h
  })
);
```

### Node.js — Manual Middleware

```js
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://yourdomain.com");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  // Handle preflight
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});
```

### Python — FastAPI

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Python — Django

```python
# settings.py
INSTALLED_APPS = [
    ...
    "corsheaders",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",  # Must be before CommonMiddleware
    "django.middleware.common.CommonMiddleware",
    ...
]

CORS_ALLOWED_ORIGINS = [
    "https://yourdomain.com",
]

CORS_ALLOW_CREDENTIALS = True
```

### Nginx Config

```nginx
location /api/ {
    add_header 'Access-Control-Allow-Origin' 'https://yourdomain.com' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
    add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type' always;

    if ($request_method = 'OPTIONS') {
        add_header 'Access-Control-Max-Age' 1728000;
        add_header 'Content-Length' 0;
        return 204;
    }

    proxy_pass http://backend;
}
```

---

## 6. Bypassing CORS in Production

### 6.1 Your Own Reverse Proxy (Recommended)

The **best and most reliable production approach**. Route API calls through your own server/proxy so the browser only ever talks to your domain.

```
Browser --> your-domain.com/api --> third-party-api.com
```

#### Example: Next.js API Route as Proxy

```ts
// pages/api/proxy.ts
import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const response = await fetch(
    `https://third-party-api.com/${req.query.path}`,
    {
      method: req.method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.API_SECRET}`,
      },
      body: req.method !== "GET" ? JSON.stringify(req.body) : undefined,
    }
  );

  const data = await response.json();
  res.status(response.status).json(data);
}
```

#### Example: Express Proxy

```js
import express from "express";
import { createProxyMiddleware } from "http-proxy-middleware";

const app = express();

app.use(
  "/api",
  createProxyMiddleware({
    target: "https://third-party-api.com",
    changeOrigin: true,
    pathRewrite: { "^/api": "" },
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.setHeader("Authorization", `Bearer ${process.env.API_SECRET}`);
      },
    },
  })
);
```

#### Example: Vite Dev Server Proxy (dev only but clean)

```ts
// vite.config.ts
import { defineConfig } from "vite";

export default defineConfig({
  server: {
    proxy: {
      "/api": {
        target: "https://third-party-api.com",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
```

---

### 6.2 Public CORS Proxies

> ⚠️ **WARNING:** These are third-party services. If they go down, your app breaks. Avoid in production — your API key/data passes through their servers.

| Service | URL |
|---------|-----|
| cors-anywhere | `https://cors-anywhere.herokuapp.com/` |
| allOrigins | `https://api.allorigins.win/raw?url=` |
| corsproxy.io | `https://corsproxy.io/?` |

```js
const PROXY = "https://corsproxy.io/?";
const API_URL = "https://api.example.com/data";

const response = await fetch(`${PROXY}${encodeURIComponent(API_URL)}`);
const data = await response.json();
```

More proxies: [jimmywarting's CORS proxy gist](https://gist.github.com/jimmywarting/ac1be6ea0297c16c477e17f8fbe51347)

---

### 6.3 JSONP (Legacy)

> ⚠️ **WARNING:** JSONP only supports `GET` requests. It is a security risk if the API is untrusted (XSS vector). Avoid unless the API explicitly supports it and you have no better option.

JSONP exploits the fact that `<script>` tags are not subject to CORS. Instead of JSON, the server returns JavaScript that calls a function you define:

```js
// Server returns: myCallback({"name": "T3 Chat"})
// You define the callback globally:

function myCallback(data) {
  console.log(data);
}

const script = document.createElement("script");
script.src = "https://api.example.com/data?callback=myCallback";
document.body.appendChild(script);
```

#### jQuery JSONP

```js
$.ajax({
  method: "GET",
  url: "https://api.example.com/data",
  dataType: "jsonp",
  success: (res) => {
    console.log(res);
  },
  error: (err) => {
    console.error("JSONP failed", err);
  },
});
```

#### fetch-jsonp (modern fetch-style API)

```bash
npm install fetch-jsonp
```

```js
import fetchJsonp from "fetch-jsonp";

fetchJsonp("https://api.example.com/data", {
  jsonpCallbackFunction: "myCallback",
  timeout: 5000,
})
  .then((res) => res.json())
  .then((json) => console.log(json))
  .catch((err) => console.error(err));
```

#### Vanilla JS JSONP utility

```js
function jsonp(url, callbackName = "callback") {
  return new Promise((resolve, reject) => {
    const fnName = `jsonp_${Date.now()}_${Math.random().toString(36).slice(2)}`;

    window[fnName] = (data) => {
      resolve(data);
      delete window[fnName];
      document.body.removeChild(script);
    };

    const script = document.createElement("script");
    script.src = `${url}${url.includes("?") ? "&" : "?"}${callbackName}=${fnName}`;
    script.onerror = () => {
      reject(new Error("JSONP request failed"));
      delete window[fnName];
      document.body.removeChild(script);
    };

    document.body.appendChild(script);
  });
}

// Usage
jsonp("https://api.example.com/data")
  .then((data) => console.log(data))
  .catch(console.error);
```

---

### 6.4 PostMessage + iframe (Niche Use Case)

For scenarios where you control both pages but they're on different origins:

```js
// Parent page (https://app.com)
const iframe = document.getElementById("api-frame");

iframe.contentWindow.postMessage(
  { type: "FETCH_DATA", url: "/api/endpoint" },
  "https://api-domain.com"
);

window.addEventListener("message", (event) => {
  if (event.origin !== "https://api-domain.com") return;
  console.log("Received:", event.data);
});
```

```js
// Inside iframe (https://api-domain.com)
window.addEventListener("message", async (event) => {
  if (event.origin !== "https://app.com") return;

  const response = await fetch(event.data.url);
  const data = await response.json();

  event.source.postMessage(data, event.origin);
});
```

---

## 7. Bypassing CORS in Development

### 7.1 Browser Extensions

> ⚠️ **For development/testing only.** Disable when not testing — known to break GitHub and other sites.

| Extension | Browser |
|-----------|---------|
| [CORS Unblock](https://chrome.google.com/webstore/detail/cors-unblock/lfhmikememgdcahcdlaciloancbhjino) | Chrome |
| [Allow CORS](https://addons.mozilla.org/en-US/firefox/addon/access-control-allow-origin/) | Firefox |
| [CORS Everywhere](https://addons.mozilla.org/en-US/firefox/addon/cors-everywhere/) | Firefox |

---

### 7.2 Disable Browser Security (Temporary Local Testing Only)

> ⚠️ **NEVER browse the internet with these flags active.** Use a separate browser profile.

```bash
# macOS
open -n -a "Google Chrome" --args \
  --user-data-dir="/tmp/cors_dev" \
  --disable-web-security

# Windows
"C:\Program Files\Google\Chrome\Application\chrome.exe" \
  --disable-web-security \
  --user-data-dir="%TEMP%\cors_dev"

# Linux
google-chrome \
  --disable-web-security \
  --user-data-dir="/tmp/cors_dev"
```

---

### 7.3 Local Proxy Tools

#### mitmproxy

```bash
pip install mitmproxy

# Intercept and add CORS headers to all responses
mitmdump --mode regular \
  --modify-headers "/~s/Access-Control-Allow-Origin/*"
```

#### local-cors-proxy (npm)

```bash
npx local-cors-proxy \
  --proxyUrl https://api.example.com \
  --port 8010 \
  --origin http://localhost:3000
```

Then in your app:

```js
// Instead of https://api.example.com/endpoint
fetch("http://localhost:8010/proxy/endpoint");
```

---

### 7.4 Framework Dev Server Proxies

#### Create React App

```json
// package.json
{
  "proxy": "https://api.example.com"
}
```

Or more advanced in `src/setupProxy.js`:

```js
const { createProxyMiddleware } = require("http-proxy-middleware");

module.exports = function (app) {
  app.use(
    "/api",
    createProxyMiddleware({
      target: "https://api.example.com",
      changeOrigin: true,
    })
  );
};
```

#### Vite

```ts
// vite.config.ts
export default {
  server: {
    proxy: {
      "/api": {
        target: "https://api.example.com",
        changeOrigin: true,
        secure: false,
      },
    },
  },
};
```

#### Webpack DevServer

```js
// webpack.config.js
module.exports = {
  devServer: {
    proxy: {
      "/api": {
        target: "https://api.example.com",
        changeOrigin: true,
        pathRewrite: { "^/api": "" },
      },
    },
  },
};
```

---

## 8. CORS Security Implications

### Common Misconfiguration: Reflecting the Origin

```js
// DANGEROUS — blindly reflects whatever Origin is sent
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin); // ❌ Never do this
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});
```

This effectively disables CORS protections and allows any site to make credentialed requests to your API.

### Safe Dynamic Origin Allowlisting

```js
const ALLOWED_ORIGINS = new Set([
  "https://app.example.com",
  "https://admin.example.com",
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (ALLOWED_ORIGINS.has(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Vary", "Origin"); // Important for CDN caching correctness
    res.header("Access-Control-Allow-Credentials", "true");
  }

  next();
});
```

### Common Vulnerabilities

| Vulnerability | Risk | Fix |
|---------------|------|-----|
| `*` with credentials | High | Never combine — browsers block it |
| Reflecting `Origin` blindly | Critical | Use an allowlist |
| Trusting `null` origin | High | Never allow `null` as an origin |
| Subdomain wildcard (`*.example.com`) | Medium | Browsers don't support this — must handle server-side |
| Missing `Vary: Origin` header | Medium | Add `Vary: Origin` when dynamically setting the header |

---

## 9. Troubleshooting CORS Errors

### Common Error Messages

```text
Access to fetch at 'https://api.example.com' from origin 'https://app.com'
has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header
is present on the targeted resource.
```

**→ The server isn't sending CORS headers. Fix it server-side.**

```text
The value of the 'Access-Control-Allow-Origin' header in the response must
not be the wildcard '*' when the request's credentials mode is 'include'.
```

**→ Server uses `*` but you're using `credentials: 'include'`. Use explicit origin on server.**

```text
Request header field Authorization is not allowed by
Access-Control-Allow-Headers in preflight response.
```

**→ Server needs to add `Authorization` to `Access-Control-Allow-Headers`.**

### Debugging Checklist

```text
☐ Open DevTools > Network tab
☐ Find the failing request
☐ Check if an OPTIONS preflight was sent (look for OPTIONS method)
☐ Inspect the preflight response headers
☐ Verify Access-Control-Allow-Origin matches your origin exactly
☐ Check for typos (https vs http, trailing slashes)
☐ Confirm the server handles OPTIONS method (returns 200/204)
☐ Check Access-Control-Allow-Headers includes your custom headers
☐ If using credentials, confirm the origin is not wildcard *
☐ Check server logs to ensure the request actually reaches the server
```

### Quick Test with curl

```bash
# Test preflight
curl -X OPTIONS https://api.example.com/endpoint \
  -H "Origin: https://yourdomain.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -v 2>&1 | grep -i "access-control"

# Test actual request
curl -X GET https://api.example.com/endpoint \
  -H "Origin: https://yourdomain.com" \
  -v 2>&1 | grep -i "access-control"
```

---

## 10. Modern Alternatives to CORS Workarounds

### Server-Sent Events (SSE)

SSE is a one-way server-to-client stream. Subject to CORS like any fetch:

```js
const es = new EventSource("https://api.example.com/stream", {
  withCredentials: true,
});

es.onmessage = (event) => console.log(event.data);
```

### WebSockets

WebSockets use a different handshake — browsers send `Origin` but the server is responsible for validating it (not the browser):

```js
const ws = new WebSocket("wss://api.example.com/ws");
ws.onmessage = (event) => console.log(event.data);
```

> Note: Browsers don't enforce CORS on WebSockets, but servers **should** validate the `Origin` header manually.

### Service Workers as a Proxy

A service worker can intercept requests and modify/proxy them:

```js
// service-worker.js
self.addEventListener("fetch", (event) => {
  if (event.request.url.includes("api.example.com")) {
    event.respondWith(
      fetch(event.request.url, {
        headers: {
          ...Object.fromEntries(event.request.headers),
          "X-Custom-Header": "value",
        },
      })
    );
  }
});
```

---

## Summary Table

| Approach | Environment | Reliability | Security | Complexity |
|----------|-------------|-------------|----------|------------|
| Fix server CORS config | Production | ✅ Best | ✅ Safe | Low |
| Your own reverse proxy | Production | ✅ Best | ✅ Safe | Medium |
| Public CORS proxy | Production | ⚠️ Risky | ⚠️ Risky | Low |
| JSONP | Production | ⚠️ GET only | ⚠️ XSS risk | Medium |
| Framework dev proxy | Development | ✅ Great | ✅ Safe | Low |
| Browser extension | Development | ⚠️ Dev only | ⚠️ Dev only | Low |
| Disable browser security | Testing only | ⚠️ Dangerous | ❌ Unsafe | Low |
| PostMessage + iframe | Niche | ✅ OK | ✅ If validated | High |
