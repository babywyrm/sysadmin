
# OWASP Scanner  (( Beta ))

The OWASP Scanner is a lightweight security tool that scans your source code for common OWASP vulnerabilities. It currently supports multiple languages, including Go, JavaScript, Python, Java, and HTML. The tool produces detailed reports in text, JSON, or Markdown formats and integrates easily into CI/CD pipelines.

## Features

- **Multi-language Support:** Scans code in Go, JavaScript, Python, Java, HTML, and more.
- **Comprehensive OWASP Rules:** Detects issues such as unvalidated inputs, insecure cryptography, injection vulnerabilities, and misconfigurations.
- **Customizable Outputs:** Report your findings in plain text, structured JSON, or formatted Markdown.
- **Selective Scanning:** Use Git integration (`--git-diff`) to scan only files that have changed.
- **CI/CD Integration:** Optionally exit with a non-zero code when HIGH severity issues are found (`--exit-high`).
- **GitHub Reporting:** Post scan results as a comment on your GitHub pull requests.

## Build Instructions

Ensure you have Go installed. Initialize a module (if not already done) and build the binary:

```bash
# In your project directory:
go mod init things/stuff/owasp-scanner
go build -o owasp-scanner .
```

This will produce an executable named `owasp-scanner` in your directory.

## Usage

Below are several command-line examples and variations:

### Basic Scan

Scan the entire directory and report in plain text:

```bash
./owasp-scanner --dir . --output text
```

### Scan Only Changed Files

If using Git, scan only recently changed files:

```bash
./owasp-scanner --dir . --git-diff --output markdown
```

### Verbose Scan with Remediation Information

Include remediation advice with your scan report:

```bash
./owasp-scanner --dir . --verbose --output text
```

### JSON Report

Generate a JSON formatted report for further processing:

```bash
./owasp-scanner --dir . --output json
```

### GitHub Pull Request Comment

Automatically post the Markdown report as a comment on a GitHub PR. Make sure to set these environment variables first:

```bash
export GITHUB_REPOSITORY="your-org/your-repo"
export GITHUB_PR_NUMBER="123"
export GITHUB_TOKEN="your_github_token_here"
./owasp-scanner --dir . --github-pr --output markdown
```

### Exit with Non-Zero Code for HIGH Issues

Integrate the scanner into your CI/CD pipeline by exiting with a non-zero status if HIGH severity issues are detected:

```bash
./owasp-scanner --dir . --exit-high
```

### Advanced Configuration Options

- **`--ignore`**: Specify comma-separated patterns to ignore.  
  Example:  
  ```bash
  ./owasp-scanner --dir . --ignore vendor,node_modules,dist
  ```

- **`--debug`**: Enable debug mode to see detailed logs during the scan.  
  Example:  
  ```bash
  ./owasp-scanner --dir . --debug
  ```

## Reporting Examples for Various Languages

### Go Output Example

When scanning Go code, a text output might look like this:

```
[HIGH] main.go:45 – Go FormValue (r.FormValue("username"))
    ▶ Unvalidated form input
    ⚑ Validate & sanitize all form inputs.
```

### Python Output Example

Scanning a Python project, your JSON report might include entries like:

```json
[
  {
    "file": "app.py",
    "line": 78,
    "rule_name": "Hardcoded Password",
    "match": "password = \"secret123\"",
    "severity": "HIGH",
    "category": "A02",
    "timestamp": "2025-05-05T19:45:00Z"
  }
]
```

### JavaScript Output Example

For a JavaScript project, Markdown output could be:

```markdown
### 🔍 Static Analysis Findings

| File         | Line | Rule             | Match                          | Severity | OWASP |
|--------------|------|------------------|--------------------------------|----------|-------|
| `server.js`  | 102  | Node req.query/body | `req.query.name`                | **HIGH** | A01   |
| `app.js`     | 88   | Inline JS Handler   | `onClick="doSomething()"`       | **MEDIUM** | A07  |
```

### Java Output Example

For a Java project, a text report might show:

```
[HIGH] AuthController.java:120 – Java getParameter (request.getParameter("user"))
```

## Integration in CI/CD

To integrate into your CI/CD pipeline and prevent the build when HIGH issues are detected, add a step like:

```bash
./owasp-scanner --dir . --exit-high
```

If any HIGH severity findings are present, the scanner exits with a non-zero exit status, causing your CI build to fail.

## License

This project is licensed under the MIT License.

## Contributing

Contributions and improvements are welcome! Open issues or submit pull requests to help us make this scanner even more robust.

