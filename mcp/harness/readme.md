# 🗡️ MCP-SLAYER v3.0 ..beta edition..

### **Overview**
MCP-SLAYER is a specialized Red Team framework designed to audit **Model Context Protocol (MCP)** implementations. 

It maps directly to the **OWASP MCP Top 10**, providing automated validation of identity binding, egress controls, and context isolation.

---

### **Core Components**
1.  **`slayer.py`**: A high-concurrency, type-safe Python 3.11+ harness. 
    *   **Modular Architecture**: Plugin-based modules for Injection, SSRF, Auth, and Supply Chain.
    *   **Defense Validation**: Measures Blue Team detection rates and MTTR.
    *   **Cryptographic Integrity**: Findings are Ed25519-signed to ensure chain-of-custody.
    *   **Safety**: Features a "Safe-Word" kill switch (`REDSTOP`) to abort all active probes instantly.

2.  **`slayer-config.yaml`**: Enterprise-grade configuration.
    *   Defines Gateway and Tool-specific endpoints.
    *   Configures complex Auth Profiles (mTLS, JWT, Basic).
    *   Implements automated PII/Secret redaction for report safety.
    *   Enables SIEM streaming (Splunk/Elastic) for Purple Team exercises.

---

### **Practical Use Cases**

| Scenario | MCP Risk | SLAYER Module |
| :--- | :--- | :--- |
| **Identity Replay** | **MCP02** | Attempts to use a low-privilege Tool-A token to execute actions on an Admin Tool-B. |
| **Cloud Credential Theft**| **MCP05/08** | Injects URL payloads targeting Cloud Instance Metadata (AWS/GCP/Azure) via Agent prompts. |
| **Shadow Tool Detection**| **MCP09** | Scans internal subnets for unauthenticated or default-credentialed MCP servers. |
| **Context Bleed** | **MCP10** | Validates that Tenant-A cannot retrieve "memory" or vector embeddings belonging to Tenant-B. |
| **Prompt Injection** | **MCP06** | Tests if malicious tool-readable files (like a `README.md`) can hijack the Agent's system instructions. |

---

### **Quick Start**
```bash
# 1. Install dependencies
pip install aiohttp pydantic yaml cryptography

# 2. Validate configuration and authorization
python slayer.py --config slayer-config.yaml --authorized --verbose

# 3. Run specific audit modules
python slayer.py --modules confused-deputy,ssrf-metadata --output-formats json,markdown
```

### **Ethical Use**
This tool is for **authorized security testing only**. Use the `safe_word` configuration to ensure tests can be stopped by Ops teams if performance is impacted.
