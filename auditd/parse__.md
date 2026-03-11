# parse_fim.py

Advanced auditd log parser for File Integrity Monitoring (FIM).

`parse_fim.py` is a Python 3 utility for parsing and analyzing Linux `auditd`
logs related to file integrity monitoring. It is designed for blue teams, SREs,
and security engineers who need to review file activity, filter relevant audit
events, and export results for investigation or reporting.

## Overview

The tool reads one or more `auditd` log files, including rotated and compressed
`.gz` archives, and extracts records relevant to FIM workflows.

Supported filters include:

- Audit key, such as `fim`
- File path matching via regex
- Syscall filtering
- Epoch-based time range filtering

Supported output formats:

- Plain text
- JSON
- CSV

## Features

- Parse plain-text and gzipped audit logs
- Accept comma-separated file lists or glob patterns
- Filter by audit key, path regex, syscall, or time range
- Process multiple files concurrently
- Export structured results as JSON or CSV
- Optional verbose logging for troubleshooting

## Requirements

- Python 3.8+
- No non-standard library dependencies

## Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/<your-org-or-username>/parse_fim.git
cd parse_fim
chmod +x parse_fim.py
```

Optional, if you maintain a requirements file:

```bash
pip install -r requirements.txt
```

## Configuring auditd for FIM

### Ubuntu / Debian

Install and configure `auditd`:

```bash
sudo apt-get update
sudo apt-get install -y auditd
echo '-w /etc/passwd -p wa -k fim' | sudo tee /etc/audit/rules.d/fim.rules
sudo service auditd restart
```

### RHEL / CentOS

```bash
sudo yum install -y audit
sudo auditctl -w /etc/passwd -p wa -k fim
sudo systemctl restart auditd
```

This example watches `/etc/passwd` for write and attribute changes and tags the
resulting audit records with the key `fim`.

## Usage

### Parse the default audit log

```bash
python3 parse_fim.py
```

### Parse specific logs and filter by key

```bash
python3 parse_fim.py \
  --files "/var/log/audit/audit.log,/var/log/audit/audit.log.1" \
  --filter-key fim
```

### Match only `/etc` paths and return JSON

```bash
python3 parse_fim.py \
  --filter-path "/etc/" \
  --output-format json
```

### Filter by syscall and export CSV

```bash
python3 parse_fim.py \
  --filter-syscall unlink \
  --output-format csv \
  --output-file fim_events.csv
```

### Parse all rotated logs with a glob

```bash
python3 parse_fim.py --files "/var/log/audit/audit.log*"
```

### Filter by epoch time range

Example: last 24 hours

```bash
START=$(date -d "24 hours ago" +%s)
END=$(date +%s)

python3 parse_fim.py \
  --time-start "$START" \
  --time-end "$END"
```

## Command Reference

| Option | Description |
|---|---|
| `--files` | Comma-separated list or glob of audit log files. Default: `/var/log/audit/audit.log` |
| `--filter-key` | Audit key to match. Default: `fim` |
| `--filter-path` | Regex used to match file paths |
| `--filter-syscall` | Syscall name to match, such as `open`, `unlink`, or `chmod` |
| `--time-start` | Include records with timestamp greater than or equal to this epoch |
| `--time-end` | Include records with timestamp less than or equal to this epoch |
| `--output-format` | Output format: `plain`, `json`, or `csv` |
| `--output-file` | Optional file path for writing output |
| `--verbose` | Enable verbose debug logging |

## Output Examples

### Plain text

```text
[2025-10-29 11:44:05] PATH (id=122) File: /etc/passwd Key: fim
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
    "key": "fim"
  }
]
```

### CSV

```text
type,timestamp,id,name,key
PATH,1730187845.122,122,/etc/passwd,fim
```

## Typical Use Cases

### Incident response and forensics

Quickly isolate activity affecting critical files such as:

- `/etc/passwd`
- `/etc/shadow`
- `/etc/sudoers`

### Compliance reporting

Export file monitoring activity to CSV or JSON for control evidence and audit
review in environments aligned with:

- PCI DSS
- ISO 27001
- FedRAMP

### SIEM ingestion

Use JSON output to feed downstream tooling such as:

- Splunk
- Elasticsearch / ELK
- Grafana Loki

## Running on a Schedule with systemd

Example: run hourly and write JSON output to
`/var/log/fim_parsed.json`.

### `/etc/systemd/system/parse-fim.service`

```ini
[Unit]
Description=Auditd FIM Parser

[Service]
ExecStart=/usr/bin/python3 /opt/fim/parse_fim.py --output-format json --output-file /var/log/fim_parsed.json
```

### `/etc/systemd/system/parse-fim.timer`

```ini
[Unit]
Description=Run FIM parser hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now parse-fim.timer
```

## Development

### Linting and type checking

```bash
ruff check .
mypy parse_fim.py
```

### Tests

```bash
pytest tests/
```

## Notes and Limitations

- This parser operates on individual audit log lines unless event correlation is
  added explicitly.
- A single audit event may span multiple record types, such as `SYSCALL`,
  `PATH`, `CWD`, and `PROCTITLE`.
- Depending on your audit configuration, syscall values may appear as numeric
  IDs rather than human-readable names.
- If you need high-fidelity reconstruction of audit events, consider extending
  the parser to group records by audit event ID.

## Roadmap

Potential future enhancements:

- `--summary` output for aggregations by file path, key, or syscall
- JSONL streaming mode for ingestion pipelines
- Event correlation across multi-line audit records
- Normalization for Falco, Wazuh, or SIEM pipelines

##
##
