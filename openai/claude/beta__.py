#!/usr/bin/env python3

import os
import sys
import anthropic
from pathlib import Path
import json
import time

API_KEY = "xxxx"
SUPPORTED_EXTENSIONS = {
    '.py': 'python',
    '.go': 'go', 
    '.java': 'java',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript'
}

def get_language_specific_checks(language):
    checks = {
        'python': """
PYTHON-SPECIFIC VULNERABILITIES:
- SQL injection via string formatting (% operator, .format(), f-strings in queries)
- Command injection via os.system(), subprocess.call() without shell=False
- Pickle deserialization vulnerabilities
- eval() and exec() usage with user input
- Flask/Django security misconfigurations (debug=True, secret keys)
- Hardcoded credentials in config files
- Path traversal via os.path.join() without validation
- YAML.load() instead of safe_load()
- Weak cryptography (hashlib.md5, hashlib.sha1)
""",
        'go': """
GO-SPECIFIC VULNERABILITIES:
- SQL injection via fmt.Sprintf() in database queries
- Command injection via exec.Command() with unsanitized input
- Path traversal via filepath.Join() without validation
- Race conditions in goroutines accessing shared data
- Improper error handling exposing sensitive information
- HTTP server without timeouts or proper TLS configuration
- Hardcoded credentials in source code
- Unsafe reflection usage
- Weak random number generation (math/rand without crypto/rand)
""",
        'java': """
JAVA-SPECIFIC VULNERABILITIES:
- SQL injection via string concatenation in PreparedStatement
- Command injection via Runtime.getRuntime().exec()
- XML External Entity (XXE) attacks in XML parsers
- Insecure deserialization (ObjectInputStream)
- Path traversal via File() constructor
- LDAP injection vulnerabilities
- Weak cryptographic implementations (DES, MD5, SHA1)
- Hardcoded passwords and API keys
- Missing input validation in servlets
- Insecure random number generation (java.util.Random)
""",
        'javascript': """
JAVASCRIPT-SPECIFIC VULNERABILITIES:
- SQL injection in database query strings
- Command injection via child_process.exec()
- Cross-site scripting (XSS) via innerHTML, document.write()
- Prototype pollution attacks
- eval() usage with user input
- Insecure direct object references
- Missing CSRF protection
- Hardcoded API keys and secrets
- Insecure cookie configurations
- Missing input validation and sanitization
""",
        'typescript': """
TYPESCRIPT-SPECIFIC VULNERABILITIES:
- Same as JavaScript plus type-related issues
- Type assertion bypassing security checks
- Any type usage eliminating type safety
- Missing runtime validation despite type definitions
- Insecure type coercion
"""
    }
    return checks.get(language, "")

def get_owasp_prompt(file_path, code_content, language):
    language_checks = get_language_specific_checks(language)
    
    return f"""You are a security expert analyzing {language} code for OWASP Top 10 vulnerabilities.

FILE: {file_path}
LANGUAGE: {language}

{language_checks}

OWASP TOP 10 ANALYSIS CHECKLIST:
A01 - BROKEN ACCESS CONTROL: Missing authorization checks, insecure direct object references, privilege escalation
A02 - CRYPTOGRAPHIC FAILURES: Hardcoded secrets, weak encryption algorithms, insecure random number generation
A03 - INJECTION: SQL injection, command injection, LDAP injection, NoSQL injection
A04 - INSECURE DESIGN: Missing security controls, insecure design patterns, lack of input validation
A05 - SECURITY MISCONFIGURATION: Default credentials, unnecessary features enabled, missing security headers
A06 - VULNERABLE COMPONENTS: Outdated dependencies, insecure libraries, unpatched components
A07 - AUTHENTICATION FAILURES: Weak password requirements, missing session management, insecure password storage
A08 - SOFTWARE/DATA INTEGRITY: Insecure deserialization, unsigned/unverified updates
A09 - LOGGING/MONITORING FAILURES: Missing security logging, insufficient monitoring, log injection
A10 - SERVER-SIDE REQUEST FORGERY: Unvalidated URLs, internal service access, cloud metadata access

PROVIDE ACTIONABLE OUTPUT IN JSON FORMAT:
{{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "total_issues": 0,
  "language": "{language}",
  "owasp_findings": [
    {{
      "category": "A03",
      "title": "SQL Injection Vulnerability",
      "severity": "HIGH", 
      "line_number": 45,
      "vulnerable_code": "query = 'SELECT * FROM users WHERE id = ' + userId",
      "explanation": "Direct string concatenation creates SQL injection risk",
      "fix": "Use parameterized queries or prepared statements",
      "impact": "Attacker can read/modify database"
    }}
  ],
  "summary": "Brief overall assessment",
  "next_steps": ["Priority 1 action", "Priority 2 action"]
}}

CODE TO ANALYZE:
{code_content}

Focus on ACTIONABLE findings with specific fixes for {language}. Be thorough but practical."""

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
            return None
        if len(content) > 100000:
            print(f"   Skipping {file_path} (file too large: {len(content)} chars)")
            return None
        print(f"   Language: {language}, File size: {len(content)} characters")
        prompt = get_owasp_prompt(file_path, content, language)
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        print(f"   Error analyzing {file_path}: {str(e)}")
        return None

def parse_json_response(response_text):
    try:
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        if start >= 0 and end > start:
            json_str = response_text[start:end]
            return json.loads(json_str)
    except Exception as e:
        print(f"   JSON parsing error: {str(e)}")
        pass
    return None

def scan_repo_files(repo_path):
    repo = Path(repo_path)
    files = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist', '.pytest_cache', 'target', 'bin', 'obj'}
    skip_files = {'package-lock.json', 'yarn.lock', 'go.sum', 'go.mod'}
    
    for file_path in repo.rglob("*"):
        if (file_path.is_file() and 
            file_path.suffix.lower() in SUPPORTED_EXTENSIONS and 
            not any(skip in file_path.parts for skip in skip_dirs) and
            file_path.name not in skip_files):
            files.append(file_path)
    return sorted(files)

def main():
    if len(sys.argv) != 2:
        print("Usage: python owasp_security_scanner.py <repo_path>")
        print("Supported languages: Python, Go, Java, JavaScript, TypeScript")
        sys.exit(1)
    repo_path = sys.argv[1]
    if not os.path.exists(repo_path):
        print(f"Error: Repository path '{repo_path}' does not exist")
        sys.exit(1)
    print(f"OWASP Top 10 Security Scanner")
    print(f"Repository: {repo_path}")
    print(f"Engine: Claude 3.5 Sonnet")
    print(f"Supported: Python (.py), Go (.go), Java (.java), JavaScript (.js/.jsx), TypeScript (.ts/.tsx)")
    print()
    files = scan_repo_files(repo_path)
    print(f"Found {len(files)} code files to analyze")
    
    language_counts = {}
    for file_path in files:
        lang = get_language_from_extension(file_path)
        language_counts[lang] = language_counts.get(lang, 0) + 1
    
    print("File breakdown by language:")
    for lang, count in sorted(language_counts.items()):
        print(f"  {lang}: {count} files")
    print()
    
    all_findings = []
    critical_count = 0
    high_count = 0
    language_results = {}
    
    for i, file_path in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {file_path}")
        analysis = analyze_file_with_claude(file_path, API_KEY)
        if not analysis:
            continue
        parsed = parse_json_response(analysis)
        if parsed and 'owasp_findings' in parsed:
            findings = parsed['owasp_findings']
            risk = parsed.get('overall_risk', 'UNKNOWN')
            language = parsed.get('language', 'unknown')
            
            if language not in language_results:
                language_results[language] = {'files': 0, 'issues': 0, 'critical': 0, 'high': 0}
            language_results[language]['files'] += 1
            language_results[language]['issues'] += len(findings)
            
            print(f"   Risk Level: {risk}")
            print(f"   Found {len(findings)} issues")
            if risk == 'CRITICAL':
                critical_count += 1
                language_results[language]['critical'] += 1
            elif risk == 'HIGH':
                high_count += 1
                language_results[language]['high'] += 1
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN')
                category = finding.get('category', 'UNKNOWN')
                title = finding.get('title', 'Unknown Issue')
                line = finding.get('line_number', 'Unknown')
                fix = finding.get('fix', 'No fix provided')
                print(f"     {category}: {title} (Line {line}) - {severity}")
                print(f"     FIX: {fix}")
            all_findings.extend(findings)
        else:
            print("   Raw analysis:")
            print(analysis[:500] + "..." if len(analysis) > 500 else analysis)
        print()
        time.sleep(1)
    
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Total files analyzed: {len(files)}")
    print(f"Total vulnerabilities: {len(all_findings)}")
    print(f"Critical risk files: {critical_count}")
    print(f"High risk files: {high_count}")
    
    if language_results:
        print()
        print("Results by Language:")
        for lang, stats in sorted(language_results.items()):
            print(f"  {lang}: {stats['files']} files, {stats['issues']} issues, {stats['critical']} critical, {stats['high']} high")
    
    if all_findings:
        categories = {}
        for finding in all_findings:
            cat = finding.get('category', 'UNKNOWN')
            categories[cat] = categories.get(cat, 0) + 1
        print()
        print("Top OWASP Categories Found:")
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cat}: {count} issues")

if __name__ == "__main__":
    main()
