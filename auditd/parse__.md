
(..beta..)


# 🧩 parse_fim.py — Advanced Auditd Log Parser for File Integrity Monitoring (FIM)

`parse_fim.py` is a modern Python 3 utility for parsing and analyzing **auditd File Integrity Monitoring (FIM)** events.  
It’s designed for blue teams, SREs, and security engineers who monitor file changes and system integrity on Linux hosts.

---

## 🚀 Overview

This tool reads one or more **auditd** log files — including compressed `.gz` archives — and extracts relevant FIM events based on filters such as:

- **Audit key** (e.g., `fim`)
- **File paths** (via regex)
- **Syscalls** (`open`, `unlink`, `chmod`, etc.)
- **Timestamps** (epoch-based time range filtering)

It supports output in:
- **Plain text**
- **JSON**
- **CSV**

---

## 🧱 Installation

Requires **Python 3.8+**

```bash
git clone https://github.com/<your-org-or-username>/parse_fim.git
cd parse_fim
chmod +x parse_fim.py
pip install -r requirements.txt  # optional if you maintain a requirements file
````

There are no hard dependencies beyond the Python standard library.

---

## ⚙️ Setting Up Auditd Rules

### Ubuntu / Debian

```bash
sudo apt-get install auditd
echo '-w /etc/passwd -p wa -k fim' | sudo tee /etc/audit/rules.d/fim.rules
sudo service auditd restart
```

### RHEL / CentOS

```bash
sudo yum install audit
sudo auditctl -w /etc/passwd -p wa -k fim
sudo systemctl restart auditd
```

The above example will monitor writes and attribute changes to `/etc/passwd` under the key `fim`.

---

## 🧩 Usage Examples

### 1️⃣ Parse the default audit log

```bash
python3 parse_fim.py
```

### 2️⃣ Parse specific logs and filter by key

```bash
python3 parse_fim.py --files "/var/log/audit/audit.log,/var/log/audit/audit.log.1" --filter-key fim
```

### 3️⃣ Match only `/etc` paths and show JSON

```bash
python3 parse_fim.py --filter-path "/etc/" --output-format json
```

### 4️⃣ Filter by syscall and export CSV

```bash
python3 parse_fim.py --filter-syscall unlink --output-format csv --output-file fim_events.csv
```

### 5️⃣ Parse all rotated logs using a glob

```bash
python3 parse_fim.py --files "/var/log/audit/audit.log*"
```

### 6️⃣ Filter by epoch time range (e.g., last 24 hours)

```bash
START=$(date -d "24 hours ago" +%s)
END=$(date +%s)
python3 parse_fim.py --time-start $START --time-end $END
```

---

## 🧠 Features

| Feature                | Description                                                           |
| ---------------------- | --------------------------------------------------------------------- |
| **Multi-file support** | Accepts comma-separated files or globs (`/var/log/audit/audit.log*`). |
| **Gzip support**       | Parses `.gz` audit logs seamlessly.                                   |
| **Threaded parsing**   | Uses `ThreadPoolExecutor` for parallel file processing.               |
| **Flexible filtering** | Filter by audit key, syscall, regex path, or time range.              |
| **Structured output**  | JSON and CSV export supported for SIEM or analytics pipelines.        |
| **Verbose mode**       | Use `--verbose` to see detailed parsing logs.                         |

---

## 🧮 Output Examples

### Plain Text

```
[2025-10-29 11:44:05] PATH (id=122) File: /etc/passwd Syscall: open Key: fim
[2025-10-29 11:44:05] SYSCALL (id=123) Syscall: open Key: fim
```

### JSON

```json
[
  {
    "type": "PATH",
    "timestamp": "1730187845.122",
    "id": "122",
    "name": "/etc/passwd",
    "syscall": "open",
    "key": "fim"
  }
]
```

### CSV

```csv
type,timestamp,id,name,syscall,key
PATH,1730187845.122,122,/etc/passwd,open,fim
```

---

## 📊 Suggested Workflows

* 🔍 **Forensics / Detection Engineering**
  Quickly isolate who changed system-critical files like `/etc/passwd` or `/etc/sudoers`.

* 🧩 **Compliance Auditing**
  Generate CSV exports of all FIM events for PCI-DSS, ISO27001, or FedRAMP documentation.

* 🛡️ **SIEM Enrichment**
  Use JSON output to feed Splunk, ELK, or Grafana Loki pipelines.

---

## 🧰 Command Reference

| Option             | Description                                                                           |
| ------------------ | ------------------------------------------------------------------------------------- |
| `--files`          | Comma-separated list or glob of audit log files (default: `/var/log/audit/audit.log`) |
| `--filter-key`     | Audit key to match (default: `fim`)                                                   |
| `--filter-path`    | Regex filter for file paths                                                           |
| `--filter-syscall` | Syscall name (`open`, `unlink`, `chmod`, etc.)                                        |
| `--time-start`     | Include records with timestamp ≥ this epoch                                           |
| `--time-end`       | Include records with timestamp ≤ this epoch                                           |
| `--output-format`  | One of `plain`, `json`, or `csv`                                                      |
| `--output-file`    | File to write output (optional)                                                       |
| `--verbose`        | Enable verbose logging for debugging                                                  |

---

## 🧠 Example Integration with Systemd Timer

To run every hour and log findings to `/var/log/fim_parsed.json`:

**/etc/systemd/system/parse-fim.service**

```ini
[Unit]
Description=Auditd FIM Parser

[Service]
ExecStart=/usr/bin/python3 /opt/fim/parse_fim.py --output-format json --output-file /var/log/fim_parsed.json
```

**/etc/systemd/system/parse-fim.timer**

```ini
[Unit]
Description=Run FIM parser hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Then enable:

```bash
sudo systemctl enable --now parse-fim.timer
```

---

## 🧑‍💻 Development Notes

### Linting / Type Checking

```bash
ruff check .
mypy parse_fim.py
```

### Unit Testing (Example)

```bash
pytest tests/
```

---

## 📜 License

MIT License © 2025
Maintained by [Your Name or Org]

---

## 🔮 Future Enhancements

* `--summary` flag for aggregated view by syscall or file path frequency
* Support for JSONL streaming for log ingestion pipelines
* Integration with Falco / Wazuh event normalization

---

##
##
