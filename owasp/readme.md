
## 🛡️ OWASP Top 10 Security Analyzer ..(beta)..

**OWASP Top 10 Security Analyzer** is a Python‑based asynchronous scanner that performs lightweight, non‑intrusive checks aligned with the **[OWASP Top 10 (2021)](https://owasp.org/Top10/)** application security risks.

It helps pinpoint common web‑application misconfigurations, insecure headers, and potential exposures — ideal for **DevSecOps pipelines**, **penetration testing**, and **cloud API audits**.

---

### ⚙️ Features

| OWASP ID | Risk Area | Example Detection |
|-----------|------------|------------------|
| **A01** | Broken Access Control | Detects unrestricted `/admin`, `/internal`, or exposed sensitive endpoints |
| **A02** | Cryptographic Failures | Alerts for HTTP use, missing HSTS, weak transport |
| **A03** | Injection | Highlights database/exception traces in output |
| **A05** | Security Misconfiguration | Checks for permissive CORS, insecure response headers |
| **A06** | Outdated Components | Flags known old versions (Apache 2.2, PHP 5, Express 4) |
| **A07** | AuthN/AuthZ Failures | Detects missing auth protection on login/admin URLs |
| **A08** | Integrity Failures | Warns on insecure CDN scripts or HTTP dependencies |
| **A09** | Logging & Monitoring Failures | Notes missing security headers like CSP, X‑Frame‑Options |
| **A10** | SSRF/Deserialization Indicators | Alerts on internal address leaks in responses |

---

### 🧰 Requirements

- Python **3.9+**
- Dependencies:
  ```bash
  pip install aiohttp
  ```

*(Recommended: use a virtual environment or container.)*

---

### 🚀 Usage

```bash
python3 owasp_tester.py "<cookie_string>" <base_url> <namespaces_file> [--json out.json] [--csv out.csv]
```

#### Parameters
| Argument | Description |
|-----------|-------------|
| `<cookie_string>` | Cookies in `"key=value; key2=value2"` format to authenticate (optional). |
| `<base_url>` | Base domain or API URL (e.g. `https://example.com/api`). |
| `<namespaces_file>` | Text file containing API paths/endpoints per line (e.g. `users`, `login`, `admin`). |
| `--json out.json` | (Optional) Save results as structured JSON. |
| `--csv out.csv` | (Optional) Save results as CSV for Excel or PowerBI. |

#### Example

```bash
python3 owasp_tester.py "sessionid=abcd1234; csrftoken=efgh5678" \
  https://example.com/api endpoints.txt \
  --json report.json --csv report.csv
```

#### Example `endpoints.txt`
```
users
login
admin
internal/data
```

---

### 🧾 Output

**Console Example (summarized):**
```
=== OWASP Top 10 Findings Summary ===

A02: 2 findings
  [HIGH] Unencrypted HTTP endpoint detected. → http://example.com/api
  [MEDIUM] Missing HSTS header (Strict-Transport-Security). → https://example.com/api/login

A05: 1 findings
  [HIGH] CORS wildcard origin allows all domains. → https://example.com/api/data
```

**JSON Example:**
```json
[
  {
    "owasp_id": "A02",
    "severity": "HIGH",
    "message": "Unencrypted HTTP endpoint detected.",
    "url": "http://example.com/api"
  },
  {
    "owasp_id": "A05",
    "severity": "HIGH",
    "message": "CORS wildcard origin allows all domains.",
    "url": "https://example.com/api/data"
  }
]
```

---

### 🧩 Integration Examples

#### **CI/CD Security Gate**
Add a stage in GitHub Actions, Jenkins, or GitLab CI that runs:

```bash
python3 owasp_tester.py "$COOKIES" https://$DEPLOY_ENV/api endpoints.txt --json findings.json
```

Then automatically **fail pipeline** if any `HIGH` severity finding appears.

Example snippet:
```bash
jq -e 'map(select(.severity=="HIGH")) | length == 0' findings.json
```

---

### 🧱 Design Principles

- **Non‑Destructive:** Performs read‑only GET/OPTIONS requests; does *not* modify data.
- **Asynchronous:** Uses `aiohttp` for maximum concurrency, minimal latency.
- **Strongly Typed:** Fully PEP‑484 annotated and modular.
- **Auditable Output:** JSON and CSV exports for long‑term tracking.
- **Extensible:** Add new OWASP checks or custom validators easily.

---

### ⚠️ Ethical Use

This tool is for **authorized security testing and audit purposes only**.  
Always obtain **written permission** before scanning non‑owned systems.  
Improper use of scanning tools may violate applicable laws or terms of service.

---

### 🧠 Roadmap ..(projected)..

- [ ] Add colorized CLI output (`rich` or `colorama`)  
- [ ] Add optional concurrency limit flags  
- [ ] Extend detection for A04 / A06 (component inventory and dependency checks)  
- [ ] Support OpenAPI specification parsing for automated endpoint generation  

---

### 🔖 License

MIT License © 2025  
Free to use and modify for responsible cybersecurity research and DevSecOps integration.

