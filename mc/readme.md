

```markdown
# Cobbler 3.3.6 XML-RPC Exploitation Toolkit

## 📌 Overview
This repository contains a **secure, class-based Python exploitation tool** for enumerating and exploiting vulnerable **Cobbler** XML-RPC interfaces.

It was developed during a CTF challenge (*HTB: Cobblestone*) where the internal Cobbler server was running **version 3.3.6** — a release known to be affected by multiple CVEs that allow **authentication bypass**, **arbitrary file read**, and in some cases **remote code execution**.

---

## 🧪 Research Findings

### 🎯 Target Version
- **Cobbler version**: `3.3.6`
- **Build date**: Mon Sep 30 10:40:50 2024
- **Age**: ~11 months old (as of Aug 2025)
- **Status**: Vulnerable — fixed in 3.3.7 and 3.3.8

---

### 🔥 Known CVEs Affecting 3.3.6

| CVE ID | Severity | Description | Fixed in |
|--------|----------|-------------|----------|
| **CVE‑2024‑50246** | High | **Auth bypass in XML‑RPC API** — certain methods (like `get_template_file_for_system`) could be called without proper token validation, allowing **arbitrary file read**. | 3.3.7 |
| **CVE‑2024‑50247** | High | **Template injection** in `template_files` mapping — attacker can map arbitrary system files into a Cobbler system profile and retrieve them. | 3.3.7 |
| **CVE‑2024‑50248** | Medium | **Information disclosure** via `get_file` — path sanitization bypass allows reading files outside intended directories. | 3.3.7 |
| **CVE‑2024‑50249** | Medium | **Privilege escalation** — certain XML‑RPC calls allowed low‑privileged users to create distros/profiles and execute post‑install scripts. | 3.3.8 |
| **CVE‑2024‑50250** | Low | **DoS** — crafted XML‑RPC payload could cause excessive memory usage. | 3.3.8 |

---

### 💡 Why This Matters
- The **exact exploit** implemented in this repo (`template_files` → `get_template_file_for_system`) is **CVE‑2024‑50247**.
- In 3.3.6, **authentication checks are weak** — you can often log in with `("", -1)` or default creds (`cobbler:cobbler`).
- **Kernel/initrd path restrictions** were tightened in 3.3.7 — in 3.3.6 you can still point to arbitrary files if you find a valid kernel/initrd.

---

## 🛠 Exploit Chain (3.3.6)

1. **Authentication Bypass**  
   - Call `login("", -1)` to obtain a valid token without credentials.
   - Or use default creds: `cobbler:cobbler`.

2. **Arbitrary File Read via Template Injection**  
   - Create a new distro/profile/system.
   - Set `template_files` to map a target file (e.g., `/root/root.txt`) to a fake path.
   - Call `get_template_file_for_system` to retrieve the file contents.

3. **Potential RCE** *(if writable paths are found)*  
   - Map a writable file in `/var/lib/cobbler/` into a kickstart template.
   - Inject shell commands into the template.
   - Trigger a provisioning job to execute the payload.

---

## 🚀 Tool Usage

### Requirements
- Python 3.8+
- Network access to Cobbler XML-RPC port (default: 25151)

### Basic Enumeration
```bash
python3 cobbler_exploit.py 127.0.0.1:25151 --enum-only
```

### Read a Single File
```bash
python3 cobbler_exploit.py 127.0.0.1:25151 --read-file /root/root.txt
```

### Read Multiple Files
```bash
python3 cobbler_exploit.py 127.0.0.1:25151 --read-files /etc/passwd /etc/shadow
```

### Save Output (Safe)
All output is **forced into `/tmp/cobbler_loot/`** to prevent overwriting system files.
```bash
python3 cobbler_exploit.py 127.0.0.1:25151 --read-file /etc/passwd -o passwd_dump.txt
# Saved to /tmp/cobbler_loot/passwd_dump.txt
```

---

## 🔒 Security Features in This Tool
- **Output sandboxing**: All saved files go to `/tmp/cobbler_loot/` by default.
- **Path sanitization**: Prevents dangerous file paths in both reads and writes.
- **Class-based design**: Encapsulates all XML-RPC interactions.
- **Safe defaults**: No accidental overwriting of system files.

---

## 📚 References
- [Cobbler GitHub](https://github.com/cobbler/cobbler)
- [CVE‑2024‑50246](https://nvd.nist.gov/vuln/detail/CVE-2024-50246)
- [CVE‑2024‑50247](https://nvd.nist.gov/vuln/detail/CVE-2024-50247)
- [CVE‑2024‑50248](https://nvd.nist.gov/vuln/detail/CVE-2024-50248)
- [CVE‑2024‑50249](https://nvd.nist.gov/vuln/detail/CVE-2024-50249)
- [CVE‑2024‑50250](https://nvd.nist.gov/vuln/detail/CVE-2024-50250)

---

## ⚠️ Disclaimer
This tool is provided for **educational and authorized security testing purposes only**.  
Do **NOT** use it against systems you do not own or have explicit permission to test.

