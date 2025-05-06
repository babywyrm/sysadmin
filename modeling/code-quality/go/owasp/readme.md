

# OWASP Scanner (Beta -- Again)

A lightweight security scanner for source code that checks for common OWASP issues.
This tool supports multiple languages (Go, JavaScript, Python, Java, HTML) and produces reports in text, JSON, or Markdown formats.

## Features

- Scan entire directories or only changed files (via Git)
- Multiple output formats: text, JSON, and Markdown
- Option to exit with a non-zero status if HIGH severity issues are detected
- Post scan results as a GitHub PR comment (with proper environment variables set)

## Build Instructions

Make sure you have Go installed. Then, initialize a module and build the binary:

```bash
# In your scanner project directory:
go mod init stuff/things/owasp-scanner
go build -o owasp-scanner .
```

This will produce an executable named `owasp-scanner` in your directory.

## Usage

Run the binary with various options. Below are several examples:

### 1. Basic Scan

Scan the current directory and output results in plain text:

```bash
./owasp-scanner --dir . --output text
```

### 2. Scan Only Changed Files

If you’re using Git, scan only the files changed in the last commit:

```bash
./owasp-scanner --dir . --git-diff --output markdown
```

### 3. Verbose Scan with Remediation Information

Include brief remediation advice in the scan report:

```bash
./owasp-scanner --dir . --verbose --output text
```

### 4. JSON Report

Create a JSON report for automated processing:

```bash
./owasp-scanner --dir . --output json
```

### 5. GitHub Pull Request Comment

Automatically post the Markdown report as a comment on a pull request. Set the following environment variables accordingly:

```bash
export GITHUB_REPOSITORY="your-org/your-repo"
export GITHUB_PR_NUMBER="123"
export GITHUB_TOKEN="your_github_token_here"
./owasp-scanner --dir . --github-pr --output markdown
```

### 6. CI/CD Integration

Exit with a non-zero status code if any HIGH severity issues are found:

```bash
./owasp-scanner --dir . --exit-high
```

## Command-Line Options

- `--dir <path>`: Directory to scan (default: `.`).
- `--output <type>`: Report format. Valid options: `text`, `json`, `markdown` (default: `text`).
- `--debug`: Enable debug output.
- `--git-diff`: Scan only the files changed in the last Git commit.
- `--exit-high`: Exit with code 1 if any HIGH severity findings are detected.
- `--ignore <patterns>`: Comma-separated glob patterns to ignore (default: `vendor,node_modules,dist,public,build`).
- `--github-pr`: Post results as a GitHub PR comment.
- `--verbose`: Include short remediation advice in the output.

## Reporting Examples

### Text Output

```
[HIGH] main.go:45 – Go FormValue (r.FormValue("user"))
▶ Unvalidated form input
⚑ Validate & sanitize all form inputs.

[MEDIUM] main.go:123 – document.write (document.write("Hello"))
...
```

### JSON Output

```json
[
  {
    "file": "main.go",
    "line": 45,
    "rule_name": "Go FormValue",
    "match": "r.FormValue(\"user\")",
    "severity": "HIGH",
    "category": "A01",
    "timestamp": "2025-05-05T19:40:00Z"
  },
  {
    "file": "main.go",
    "line": 123,
    "rule_name": "document.write",
    "match": "document.write(\"Hello\")",
    "severity": "MEDIUM",
    "category": "A07",
    "timestamp": "2025-05-05T19:40:05Z"
  }
]
```

### Markdown Output

A sample Markdown report might look like this:

```markdown
### 🔍 Static Analysis Findings

| File      | Line | Rule            | Match                      | Severity | OWASP |
|-----------|------|-----------------|----------------------------|----------|-------|
| `main.go` | 45   | Go FormValue    | `r.FormValue("user")`      | **HIGH** | A01   |
| `main.go` | 123  | document.write  | `document.write("Hello")`  | **MEDIUM** | A07  |

---

**Severity Summary**

- **HIGH**: 1
- **MEDIUM**: 1

**OWASP Category Summary**

- **A01**: 1
- **A07**: 1
```

## License

This project is licensed under the MIT License.

## Contact

For questions or help, please open an issue on GitHub.
```

---
