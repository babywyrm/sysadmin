

##
#
https://www.neuralegion.com/blog/dom-based-xss/
#
https://blog.sessionstack.com/how-javascript-works-5-types-of-xss-attacks-tips-on-preventing-them-e6e28327748a
#
https://www.acunetix.com/blog/articles/dom-xss-explained/
#
https://blog.mozilla.org/attack-and-defense/2021/11/03/finding-and-fixing-dom-based-xss-with-static-analysis/
##

# Cross-Site Scripting (XSS) Attack Types: Modern Guide

## Overview

Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web applications. There are three primary types of XSS attacks, each with distinct characteristics and mitigation strategies.

## Types of XSS Attacks

### 1. Reflected XSS
**Definition**: User input is immediately echoed back in the HTTP response without proper sanitization, escaping, or encoding.

**Characteristics**:
- Payload is sent to the server and reflected back in the response
- Requires social engineering (malicious links)
- Non-persistent (temporary)
- Server-side vulnerability

**Example**:
```
GET /search?q=<script>alert('XSS')</script>
```
The server includes the search parameter directly in the HTML response.

### 2. Stored XSS (Persistent)
**Definition**: Malicious data is stored on the server and later served to other users.

**Characteristics**:
- Payload is stored in database/file system
- Affects multiple users over time
- Most dangerous type due to persistence
- Server-side vulnerability

**Example**:
A comment system that stores user input without sanitization:
```html
<!-- Stored in database -->
<div class="comment">
  <script>steal_cookies()</script>
</div>
```

### 3. DOM-Based XSS
**Definition**: The vulnerability exists in client-side code where JavaScript modifies the DOM using untrusted data.

**Characteristics**:
- Entirely client-side execution
- May never reach the server
- Payload often in URL fragments (`#`)
- Requires client-side mitigation

**Example**:
```javascript
// Vulnerable code
document.getElementById('welcome').innerHTML = 
  'Hello ' + location.hash.substring(1);

// Attack URL: https://example.com/#<script>alert('XSS')</script>
```

## Key Differences

| Aspect | Reflected | Stored | DOM-Based |
|--------|-----------|--------|-----------|
| **Execution Location** | Server-side reflection | Server-side storage | Client-side only |
| **Persistence** | Temporary | Permanent | Temporary |
| **Server Involvement** | Required | Required | Optional |
| **Primary Mitigation** | Server-side filtering | Server-side filtering | Client-side filtering |

## Modern Detection Challenges

### DOM-Based XSS Detection
DOM-based XSS is particularly challenging to detect because:

- **No server-side traces**: Traditional web scanners miss client-only vulnerabilities
- **Dynamic analysis required**: Static analysis tools struggle with complex JavaScript
- **Limited tooling**: Fewer mature detection tools compared to reflected/stored XSS

### Current Detection Tools
- **Static Analysis**: ESLint with security plugins, Semgrep
- **Dynamic Analysis**: Browser-based scanners, OWASP ZAP with DOM XSS plugin
- **Manual Testing**: Browser developer tools, source code review

## Common Misconceptions

### "Can an attack be both DOM-based and Reflected?"
**No.** The attack types are mutually exclusive based on *how* the payload gets executed:

- **Reflected**: Server processes and includes payload in response
- **DOM-based**: Client-side JavaScript processes payload directly

They may use similar payloads, but the execution mechanism differs.

## Modern Prevention Strategies

### Server-Side (Reflected & Stored XSS)
```javascript
// Input validation
const validator = require('validator');
const cleanInput = validator.escape(userInput);

// Content Security Policy
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", 
    "default-src 'self'; script-src 'self'");
  next();
});

// Template engines with auto-escaping
// React, Vue.js automatically escape by default
```

### Client-Side (DOM-Based XSS)
```javascript
// Safe DOM manipulation
function updateContent(userContent) {
  // Use textContent instead of innerHTML
  document.getElementById('content').textContent = userContent;
  
  // Or sanitize HTML
  const cleanHTML = DOMPurify.sanitize(userContent);
  document.getElementById('content').innerHTML = cleanHTML;
}

// Validate URL parameters
function getURLParameter(name) {
  const value = new URLSearchParams(window.location.search).get(name);
  return value ? validator.escape(value) : null;
}
```

## Framework-Specific Protections

### React
```jsx
// Safe by default
function Component({ userInput }) {
  return <div>{userInput}</div>; // Automatically escaped
}

// Dangerous - requires explicit opt-in
function DangerousComponent({ trustedHTML }) {
  return <div dangerouslySetInnerHTML={{__html: trustedHTML}} />;
}
```

### Vue.js
```vue
<template>
  <!-- Safe interpolation -->
  <div>{{ userInput }}</div>
  
  <!-- Dangerous - avoid -->
  <div v-html="trustedHTML"></div>
</template>
```

## Best Practices Summary

1. **Default to safe**: Use frameworks that escape by default
2. **Validate input**: Both client and server-side validation
3. **Use CSP**: Implement strict Content Security Policy
4. **Sanitize HTML**: Use libraries like DOMPurify for trusted HTML
5. **Regular testing**: Include XSS testing in CI/CD pipelines
6. **Security headers**: Implement X-XSS-Protection, X-Content-Type-Options
7. **Code review**: Focus on data flow from user input to output

## Testing Checklist

- [ ] All user inputs are validated and sanitized
- [ ] Output encoding is applied consistently
- [ ] CSP headers are implemented
- [ ] DOM manipulation uses safe methods
- [ ] URL parameters are validated before use
- [ ] Regular security scanning is performed
- [ ] Framework security features are enabled

This modern approach emphasizes prevention through secure coding practices and leveraging framework protections rather than relying solely on detection tools.
