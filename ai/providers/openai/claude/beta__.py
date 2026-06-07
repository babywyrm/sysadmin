#!/usr/bin/env python3
import os
import sys
import anthropic
from pathlib import Path
import json
import time

API_KEY = "your-api-key-here"
SUPPORTED_EXTENSIONS = {
    '.py': 'python',
    '.go': 'go', 
    '.java': 'java',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.php': 'php',
    '.html': 'html',
    '.htm': 'html',
    '.css': 'css',
    '.sql': 'sql'
}

def get_language_specific_checks(language):
    checks = {
        'python': """
PYTHON-SPECIFIC VULNERABILITIES:
- SQL injection via string formatting, .format(), f-strings in queries
- Command injection via os.system(), subprocess without shell=False
- Pickle deserialization, eval(), exec() with user input
- Flask/Django debug=True, hardcoded secret keys
- Path traversal, YAML.load() instead of safe_load()
- Weak cryptography (md5, sha1)
""",
        'go': """
GO-SPECIFIC VULNERABILITIES:
- SQL injection via fmt.Sprintf() in database queries
- Command injection via exec.Command() with unsanitized input
- Path traversal, race conditions in goroutines
- HTTP server without timeouts or proper TLS
- Hardcoded credentials, weak random number generation
""",
        'java': """
JAVA-SPECIFIC VULNERABILITIES:
- SQL injection via string concatenation
- Command injection via Runtime.exec()
- XXE attacks, insecure deserialization
- Path traversal, LDAP injection
- Weak crypto (DES, MD5), hardcoded passwords
""",
        'javascript': """
JAVASCRIPT-SPECIFIC VULNERABILITIES:
- SQL injection in query strings
- Command injection via child_process.exec()
- XSS via innerHTML, document.write(), eval()
- Prototype pollution, missing CSRF protection
- Hardcoded API keys, insecure cookies
""",
        'php': """
PHP-SPECIFIC VULNERABILITIES:
- SQL injection via string concatenation in queries
- Command injection via exec(), system(), shell_exec()
- File inclusion attacks (include, require with user input)
- Path traversal via $_GET/$_POST parameters
- XSS via echo, print without htmlspecialchars()
- CSRF missing tokens
- Session hijacking (session.cookie_secure=false)
- Weak password hashing (md5, sha1)
- eval() with user input
- Deserialization attacks via unserialize()
- Missing input validation on superglobals
""",
        'html': """
HTML-SPECIFIC VULNERABILITIES:
- Missing CSP headers
- Inline JavaScript and CSS
- Missing input validation attributes
- Insecure form configurations
- Missing CSRF tokens
""",
        'sql': """
SQL-SPECIFIC VULNERABILITIES:
- Direct user input in queries
- Missing parameterization
- Privilege escalation in stored procedures
- Information disclosure in error messages
"""
    }
    return checks.get(language, "")

def get_owasp_prompt(file_path, code_content, language):
    language_checks = get_language_specific_checks(language)
    
    return f"""You are a security expert analyzing {language} code for OWASP Top 10 vulnerabilities.

FILE: {file_path}
LANGUAGE: {language}

{language_checks}

OWASP TOP 10 FOCUS:
A01-BROKEN ACCESS CONTROL: Missing authorization, insecure direct object references
A02-CRYPTOGRAPHIC FAILURES: Hardcoded secrets, weak encryption
A03-INJECTION: SQL, command, LDAP, NoSQL injection
A04-INSECURE DESIGN: Missing security controls, lack of input validation
A05-SECURITY MISCONFIGURATION: Default credentials, missing security headers
A06-VULNERABLE COMPONENTS: Outdated dependencies, insecure libraries
A07-AUTHENTICATION FAILURES: Weak passwords, missing session management
A08-SOFTWARE/DATA INTEGRITY: Insecure deserialization
A09-LOGGING/MONITORING FAILURES: Missing security logging
A10-SSRF: Unvalidated URLs, internal service access

RESPOND WITH VALID JSON ONLY:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "total_issues": 0,
  "language": "{language}",
  "owasp_findings": [
    {{
      "category": "A03",
      "title": "SQL Injection",
      "severity": "HIGH",
      "line_number": 45,
      "vulnerable_code": "query = 'SELECT * FROM users WHERE id = ' + userId",
      "explanation": "String concatenation creates SQL injection risk",
      "fix": "Use parameterized queries or prepared statements",
      "impact": "Database compromise"
    }}
  ],
  "summary": "Brief assessment",
  "next_steps": ["Fix critical issues first"]
}}

CODE:
{code_content}"""

def get_language_from_extension(file_path):
    suffix = file_path.suffix.lower()
    return SUPPORTED_EXTENSIONS.get(suffix, 'unknown')

def analyze_file_with_claude(file_path, api_key):
    client = anthropic.Anthropic(api_key=api_key)
    language = get_language_from_extension(file_path)
    
    if language == 'unknown':
        print(f"   Skipping {file_path} (unsupported file type)")
        return None
        
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        if not content.strip():
            print(f"   Skipping {file_path} (empty file)")
            return None
        if len(content) > 50000:
            print(f"   Skipping {file_path} (file too large: {len(content)} chars)")
            return None
        print(f"   Language: {language}, Size: {len(content)} chars")
        prompt = get_owasp_prompt(file_path, content, language)
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        print(f"   Error: {str(e)}")
        return None

def parse_json_response(response_text):
    try:
        response_text = response_text.strip()
        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        if start >= 0 and end > start:
            json_str = response_text[start:end]
            return json.loads(json_str)
    except Exception as e:
        print(f"   JSON parse error: {str(e)[:100]}")
    return None

def scan_repo_files(repo_path):
    repo = Path(repo_path)
    files = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist', '.pytest_cache', 'target', 'bin', 'obj', '.vscode', '.idea'}
    skip_files = {'package-lock.json', 'yarn.lock', 'go.sum', 'composer.lock'}
    
    for file_path in repo.rglob("*"):
        if (file_path.is_file() and 
            file_path.suffix.lower() in SUPPORTED_EXTENSIONS and 
            not any(skip in file_path.parts for skip in skip_dirs) and
            file_path.name not in skip_files and
            file_path.stat().st_size > 0):
            files.append(file_path)
    return sorted(files)

def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <repo_path>")
        print("Supports: Python, Go, Java, JavaScript, TypeScript, PHP, HTML, CSS, SQL")
        sys.exit(1)
    repo_path = sys.argv[1]
    if not os.path.exists(repo_path):
        print(f"Error: Path '{repo_path}' does not exist")
        sys.exit(1)
    print(f"OWASP Security Scanner")
    print(f"Repository: {repo_path}")
    print(f"Supports: Python, Go, Java, JS/TS, PHP, HTML, CSS, SQL")
    print()
    files = scan_repo_files(repo_path)
    print(f"Found {len(files)} files to scan")
    
    language_counts = {}
    for file_path in files:
        lang = get_language_from_extension(file_path)
        language_counts[lang] = language_counts.get(lang, 0) + 1
    
    print("Files by language:")
    for lang, count in sorted(language_counts.items()):
        print(f"  {lang}: {count}")
    print()
    
    all_findings = []
    critical_count = 0
    high_count = 0
    processed = 0
    
    for i, file_path in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {file_path}")
        analysis = analyze_file_with_claude(file_path, API_KEY)
        if not analysis:
            continue
        processed += 1
        parsed = parse_json_response(analysis)
        if parsed and 'owasp_findings' in parsed:
            findings = parsed['owasp_findings']
            risk = parsed.get('overall_risk', 'UNKNOWN')
            print(f"   Risk: {risk}, Issues: {len(findings)}")
            if risk == 'CRITICAL':
                critical_count += 1
            elif risk == 'HIGH':
                high_count += 1
            for finding in findings:
                category = finding.get('category', 'UNK')
                title = finding.get('title', 'Unknown')
                severity = finding.get('severity', 'UNK')
                line = finding.get('line_number', '?')
                fix = finding.get('fix', 'No fix')
                print(f"     {category}: {title} (L{line}) [{severity}]")
                print(f"     FIX: {fix}")
            all_findings.extend(findings)
        else:
            print(f"   Raw: {analysis[:200]}...")
        print()
        time.sleep(0.5)
    
    print("=" * 50)
    print("RESULTS")
    print("=" * 50)
    print(f"Files processed: {processed}/{len(files)}")
    print(f"Total vulnerabilities: {len(all_findings)}")
    print(f"Critical files: {critical_count}")
    print(f"High risk files: {high_count}")
    
    if all_findings:
        categories = {}
        for finding in all_findings:
            cat = finding.get('category', 'UNK')
            categories[cat] = categories.get(cat, 0) + 1
        print("\nTop vulnerabilities:")
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {cat}: {count}")

if __name__ == "__main__":
    main()
