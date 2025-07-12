
# OWASP Scanner (Beta)

The OWASP Scanner is a lightweight, multi-language static analysis tool that detects common OWASP Top 10 security issues in your source code. 
It supports Go, JavaScript, Python, Java, HTML, and more.  

It can output results in plain text, JSON or Markdown formats, integrate with CI/CD (failing builds on HIGH severity), and even post scan results as comments on GitHub pull requests.

---

## Features

- Multi-language scanning (Go, JS, Python, Java, HTML, …)  
- Comprehensive OWASP Top 10 rule set (injection, crypto failures, insecure configs, etc.)  
- Externalizable rules: load your own `rules.json` via `--rules`  
- Configurable ignore patterns (`--ignore`) and Git diff mode (`--git-diff`)  
- Output formats: text, JSON, Markdown (`--output`)  
- Verbose mode with remediation advice (`--verbose`)  
- Fail CI/CD on HIGH-severity (`--exit-high`)  
- Post Markdown reports to GitHub PRs (`--github-pr`)  

---

## Installation

1. **Clone / Init module**  
   ```bash
   git clone https://github.com/your-org/owasp-scanner.git
   cd owasp-scanner
   go mod init github.com/your-org/owasp-scanner
   ```

2. **Generate `rules.json`**  
   We ship all built-in rules in Go; to export them to JSON:
   ```bash
   go run gen_rule_json.go rules.go > rules.json
   ```
   You can then edit `rules.json` to add/remove rules.

3. **Build the binary**  
   ```bash
   go build -o owasp-scanner .
   ```

---

## Usage

Run `./owasp-scanner --help` for full flag details.  Common flags:

  • `--dir` (string, default `"."`)  
  • `--rules` (string) – path to external `rules.json`; overrides built-in  
  • `--ignore` (string) – comma-separated glob patterns to skip  
  • `--git-diff` – scan only files changed in last commit  
  • `--output` (text/json/markdown)  
  • `--verbose` – include remediation advice  
  • `--exit-high` – exit code 1 if any HIGH severity found  
  • `--github-pr` – post Markdown report as a GitHub PR comment  
  • `--debug` – show internal debug logs  

### Basic Scan

Scan the current directory in plain-text:

```bash
./owasp-scanner --dir . --output text
```

### Use External Rules

Point at your custom rule set:

```bash
./owasp-scanner \
  --rules=rules.json \
  --dir=./src \
  --output=markdown \
  --verbose
```

### Scan Only Changed Files

When running in a Git repo:

```bash
./owasp-scanner \
  --rules=rules.json \
  --git-diff \
  --output=markdown
```

### JSON Report

```bash
./owasp-scanner \
  --rules=rules.json \
  --dir . \
  --output json \
  --verbose > findings.json
```

### CI/CD: Fail on HIGH Severity

```bash
./owasp-scanner \
  --dir . \
  --exit-high
```
A non-zero exit code will fail your pipeline if any HIGH issues are detected.

### GitHub PR Comment

Set these environment vars in your CI:

```bash
export GITHUB_REPOSITORY="your-org/your-repo"
export GITHUB_PR_NUMBER="42"
export GITHUB_TOKEN="ghp_…"
```

Then:

```bash
./owasp-scanner \
  --rules=rules.json \
  --dir . \
  --output markdown \
  --github-pr \
  --verbose
```

This posts a Markdown table of findings as a comment on PR #42.

---

## Examples

#### Go Project, Text Output

```text
[HIGH] main.go:45 – Go FormValue (r.FormValue("username"))
    ▶ Unvalidated form input
    ⚑ Validate & sanitize all form inputs.
[MEDIUM] server.go:102 – TLS SkipVerify (InsecureSkipVerify: true)
    ▶ TLS verification disabled
    ⚑ Enable certificate validation.
```

#### Python Project, JSON Output

```json
[
  {
    "file": "app.py",
    "line": 78,
    "rule_name": "Hardcoded Password",
    "match": "password = \"secret123\"",
    "severity": "HIGH",
    "category": "A02",
    "timestamp": "2025-07-11T20:45:00Z",
    "description": "Credentials in code",
    "remediation": "Use environment variables or vaults."
  }
]
```

#### JavaScript Project, Markdown Output

```markdown
### 🔍 Static Analysis Findings

| File       | Line | Rule               | Match                     | Severity | OWASP |
|------------|------|--------------------|---------------------------|----------|-------|
| server.js  | 102  | Node req.query/body | `req.query.name`          | **HIGH** | A01   |
| app.js     |  88  | Inline JS Handler   | `onClick="doSomething()"` | **MEDIUM** | A07   |
```

