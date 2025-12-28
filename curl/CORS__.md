

# 🔐 CORS Testing with curl — 2025 Hardened Guide

> **Audience:** AppSec, Platform, API owners, Pentesters
> **Goal:** Accurately validate CORS behavior *as browsers enforce it*, and detect real-world misconfigurations.

---

## 0. Ground Rules (Important)

* **curl does not enforce CORS** — it only simulates browser requests.
* **Missing CORS headers ≠ server vulnerability** by itself.
* **Danger = browser allows a malicious origin to read responses**
* Always test **with and without credentials**
* Treat **reflection + credentials** as 🔥 CRITICAL

---

## 1. Baseline Preflight Tests

### 1.1 Canonical Preflight (OPTIONS)

```bash
curl -i -X OPTIONS https://example.com/api/resource \
  -H "Origin: https://test-origin.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Content-Type, Authorization"
```

#### ✅ Secure Expected Response

```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://test-origin.com
Access-Control-Allow-Methods: GET
Access-Control-Allow-Headers: Content-Type, Authorization
Vary: Origin
```

#### 🚨 Red Flags

* `Access-Control-Allow-Origin: *`
* Missing `Vary: Origin`
* Allowing `Authorization` broadly without origin validation

---

## 2. Simple Requests (No Preflight)

### 2.1 Simple GET

```bash
curl -i https://example.com/api/resource \
  -H "Origin: https://test-origin.com"
```

#### Expected

```
Access-Control-Allow-Origin: https://test-origin.com
```

> ❗ If this header is missing, **browser blocks response access**, but server still processed it.

---

## 3. Non-Simple Requests (Realistic Browser Traffic)

### 3.1 JSON POST (Triggers Preflight)

```bash
curl -i -X POST https://example.com/api/resource \
  -H "Origin: https://test-origin.com" \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}'
```

#### Expected

```
Access-Control-Allow-Origin: https://test-origin.com
```

---

## 4. Custom Header Abuse Testing

### 4.1 Arbitrary Header Injection

```bash
curl -i -X POST https://example.com/api/resource \
  -H "Origin: https://evil.com" \
  -H "X-Evil-Header: pwned" \
  -H "Content-Type: application/json" \
  -d '{}'
```

#### Secure Behavior

* Preflight **rejects**
* No ACAO header

#### 🚨 Vulnerability

```
Access-Control-Allow-Headers: *
```

---

## 5. Method Escalation Testing

```bash
curl -i -X DELETE https://example.com/api/resource \
  -H "Origin: https://test-origin.com"
```

#### Secure

```
405 Method Not Allowed
(no ACAO header)
```

#### 🚨 Risk

* Method allowed via CORS but blocked server-side → confusion bugs
* Method allowed both sides → escalation

---

## 6. Origin Reflection (Critical)

### 6.1 Reflection Detection

```bash
curl -i https://example.com/api/resource \
  -H "Origin: https://attacker.com"
```

#### 🚨 CRITICAL IF:

```
Access-Control-Allow-Origin: https://attacker.com
```

> Especially dangerous if combined with credentials (see below)

---

## 7. Wildcard Handling (Modern Interpretation)

### 7.1 Wildcard Test

```bash
curl -i https://example.com/api/resource \
  -H "Origin: https://random.com"
```

#### Acceptable ONLY IF

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: (absent)
```

#### 🚨 INVALID BY SPEC

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

(Browsers reject this, but many APIs still misconfigure it.)

---

## 8. Credentialed Requests (🔥 Highest Risk)

### 8.1 Cookies + Authorization

```bash
curl -i https://example.com/api/resource \
  -H "Origin: https://trusted.com" \
  -H "Authorization: Bearer testtoken" \
  -H "Cookie: session=abc123"
```

#### Secure Expected

```
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Credentials: true
Vary: Origin
```

#### 🚨 CRITICAL

* Wildcard origin
* Origin reflection
* Missing `Vary: Origin`

---

## 9. Fetch Metadata Defense (2025 Best Practice)

### 9.1 Sec-Fetch Validation

```bash
curl -i https://example.com/api/resource \
  -H "Origin: https://evil.com" \
  -H "Sec-Fetch-Site: cross-site" \
  -H "Sec-Fetch-Mode: cors"
```

#### Recommended Server Behavior

* Reject or restrict cross-site requests
* Use alongside CORS, **not instead**

---

## 10. Malformed & Abuse Scenarios

### 10.1 Invalid Origin Format

```bash
curl -i -X OPTIONS https://example.com/api/resource \
  -H "Origin: null"
```

```bash
curl -i -X OPTIONS https://example.com/api/resource \
  -H "Origin: file://"
```

#### Secure

* Reject or no ACAO header

---

## 11. Automation-Friendly Checks

### 11.1 Quick Reflection Detection

```bash
curl -s -D - https://example.com/api/resource \
  -H "Origin: https://evil.com" | grep -i access-control-allow-origin
```

### 11.2 Credential + Wildcard Detection

```bash
curl -s -D - https://example.com/api/resource \
  -H "Origin: https://evil.com" \
  -H "Cookie: test=1" | grep -Ei "allow-origin|allow-credentials"
```

---

## 12. Common Real-World Misconfigs (Seen in Prod)

| Misconfiguration                   | Severity    |
| ---------------------------------- | ----------- |
| Reflects Origin + Credentials      | 🔥 Critical |
| `*` + Credentials                  | 🔥 Critical |
| Missing `Vary: Origin`             | High        |
| Broad header allowlist             | High        |
| Authorization allowed cross-origin | High        |
| CORS differs by endpoint           | Medium      |
| OPTIONS allowed everywhere         | Medium      |

---

## 13. Final Security Guidance

### ✅ Best Practices (2025)

* Explicit origin allowlist
* No reflection
* No wildcard with credentials
* Always `Vary: Origin`
* Pair with **AuthZ**, not replace it
* Validate **fetch metadata**
* Log rejected preflights

### ❌ Never Do

* `Access-Control-Allow-Origin: *` on authenticated APIs
* Trust `Origin` blindly
* Assume curl success == browser success

---



##
#
https://reqbin.com/req/c-taimahsa/curl-cors-request
#
https://stackoverflow.com/questions/12173990/how-can-you-debug-a-cors-request-with-curl
#
https://www.zufallsheld.de/2024/09/28/til-how-to-test-CORS-on-the-command-line-with-curl/
@
##



1. Basic Tests
1.1 Preflight Check
CORS uses an OPTIONS request to check permissions before the actual request.

```
curl -X OPTIONS http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -i
```
Expected Response:

Status Code: 204 No Content or 200 OK.
Headers:

```
Access-Control-Allow-Origin: http://test-origin.com
Access-Control-Allow-Methods: GET
Access-Control-Allow-Headers: Content-Type
```

1.2 Simple Request
Perform a basic GET request with an Origin header.

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -i
```

Expected Response:

The response should include:
```
Access-Control-Allow-Origin: http://test-origin.com
```

2. Intermediate Tests
2.1 Custom Headers
Send a request with custom headers.

```
curl -X POST http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -H "X-Custom-Header: custom-value" \
  -H "Content-Type: application/json" \
  -d '{"key":"value"}' \
  -i
```

Expected Response:
```
If Access-Control-Allow-Headers is properly configured:

Access-Control-Allow-Headers: Content-Type, X-Custom-Header
```

2.2 Methods Not Allowed
Test with HTTP methods not permitted by CORS policy.

```
curl -X DELETE http://example.com/api/resource \
  -H "Origin: http://test-origin.com" \
  -i
```
Expected Response:

Status Code: 405 Method Not Allowed.
No Access-Control-Allow-Origin header should be present.


3. Advanced Tests
3.1 Origin Reflection
Test if the server reflects the Origin header.

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://untrusted-origin.com" \
  -i
```


Expected Behavior:

If reflection is disabled: No Access-Control-Allow-Origin header.
If reflection is enabled (potential security risk):


Access-Control-Allow-Origin: http://untrusted-origin.com
3.2 Wildcard Matching
Test with a wildcard (*) in the Access-Control-Allow-Origin header.

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://wildcard-test.com" \
  -i
```

Expected Behavior:

The server should return:
Access-Control-Allow-Origin: *
Note: Wildcards should not be used with credentials.
3.3 Credentials Handling
Test requests with credentials (cookies, Authorization headers).

```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://trusted-origin.com" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Cookie: sessionId=abc123" \
  -i
```

Expected Behavior:

The server should return:

Access-Control-Allow-Origin: http://trusted-origin.com
Access-Control-Allow-Credentials: true


4. Error Scenarios
4.1 Invalid Origins
Send a request from an untrusted origin.
```
curl -X GET http://example.com/api/resource \
  -H "Origin: http://untrusted-origin.com" \
  -i
```

Expected Response:

No Access-Control-Allow-Origin header.
The request should fail.
4.2 Malformed Preflight Requests
Send a malformed preflight request.
```
curl -X OPTIONS http://example.com/api/resource \
  -H "Origin: malformed" \
  -H "Access-Control-Request-Method: PUT" \
  -i
```
Expected Behavior:

Status Code: 400 Bad Request or similar error.
5. Summary
This document demonstrates a comprehensive suite of curl commands to test various CORS configurations and edge cases.
Adjust the http://example.com URL to match your API endpoint and replace headers or methods as needed.

Notes:
Check for Misconfigurations: Misconfigured CORS can lead to vulnerabilities like unauthorized access or data leakage.
Avoid Reflective Policies: Always validate the Origin header against a trusted whitelist.
Be Careful with Wildcards: Avoid * in Access-Control-Allow-Origin for sensitive endpoints.



