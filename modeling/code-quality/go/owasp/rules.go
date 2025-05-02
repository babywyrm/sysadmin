package main

import (
  "regexp"
)

// OWASP category constants
const (
  OWASP_A01 = "A01" // Broken Access Control
  OWASP_A02 = "A02" // Cryptographic Failures
  OWASP_A03 = "A03" // Injection
  OWASP_A05 = "A05" // Security Misconfiguration
  OWASP_A06 = "A06" // Vulnerable & Outdated Components
  OWASP_A07 = "A07" // Cross-Site Scripting (XSS)
  OWASP_A08 = "A08" // Software/Data Integrity Failures
  OWASP_A10 = "A10" // SSRF
)

// Rule defines a scanning rule.
type Rule struct {
  Name        string
  Regex       string
  Pattern     *regexp.Regexp
  Severity    string
  Category    string
  Description string
  Remediation string
}

// Base OWASP-related rules
var rules = []Rule{
  // A01
  {
    Name:        "Go FormValue",
    Regex:       `(?i)r\.FormValue\(`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated form input",
    Remediation: "Validate & sanitize all form inputs.",
  },
  {
    Name:        "Java getParameter",
    Regex:       `(?i)request\.getParameter\(`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated request parameter",
    Remediation: "Use input validation frameworks.",
  },
  {
    Name:        "Node req.query/body",
    Regex:       `(?i)(req\.body|req\.query)\s*[\.\[]`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated Node.js request input",
    Remediation: "Use libraries like joi or express-validator.",
  },
  {
    Name:        "Flask Input",
    Regex:       `(?i)(request\.args|getattr\(request, )`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated Flask input",
    Remediation: "Validate Flask request data explicitly.",
  },

  // A02
  {
    Name:        "Hardcoded Password",
    Regex:       `(?i)password\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "Credentials in code",
    Remediation: "Use environment variables or vaults.",
  },
  {
    Name:        "API Key",
    Regex:       `(?i)(api[_-]?key|secret)\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "API key in code",
    Remediation: "Use secure secret storage.",
  },
  {
    Name:        "JWT Secret",
    Regex:       `(?i)(jwt.*secret|signingkey)\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "JWT secret in code",
    Remediation: "Use env-vars or vaults.",
  },
  {
    Name:        "MD5",
    Regex:       `(?i)md5\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "Weak MD5 hash",
    Remediation: "Use SHA-256 or better.",
  },
  {
    Name:        "SHA1",
    Regex:       `(?i)sha1\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "Weak SHA1 hash",
    Remediation: "Use SHA-256 or better.",
  },

  // A03
  {
    Name:        "Eval Usage",
    Regex:       `(?i)eval\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A03,
    Description: "Use of eval()",
    Remediation: "Avoid eval(); use safe parsing.",
  },
  {
    Name:        "Command Exec",
    Regex:       `(?i)(system|exec)\s*\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "System/exec call",
    Remediation: "Use allow-lists & sanitize args.",
  },

  // A05
  {
    Name:        "TLS SkipVerify",
    Regex:       `(?i)InsecureSkipVerify\s*:\s*true`,
    Severity:    "HIGH",
    Category:    OWASP_A05,
    Description: "TLS Verify disabled",
    Remediation: "Enable certificate validation.",
  },
  {
    Name:        "Flask Debug",
    Regex:       `(?i)app\.run\(.*debug\s*=\s*True`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Debug mode on",
    Remediation: "Disable debug in prod.",
  },

  // A06
  {
    Name:        "Old jQuery",
    Regex:       `jquery-1\.(3|4|5|6|7|8|9)`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Legacy jQuery",
    Remediation: "Upgrade to latest jQuery.",
  },
  {
    Name:        "Known Vuln Lib",
    Regex:       `(?i)(flask==0\.10|lodash@3)`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Vulnerable library version",
    Remediation: "Update dependencies.",
  },

  // A07
  {
    Name:        "Raw Jinja2",
    Regex:       `(?i){{\s*[^}]+\s*}}`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "Unescaped template",
    Remediation: "Use safe filters or escape.",
  },
  {
    Name:        "innerHTML",
    Regex:       `(?i)\.innerHTML\s*=`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "innerHTML assignment",
    Remediation: "Use textContent or sanitize.",
  },
  {
    Name:        "document.write",
    Regex:       `(?i)document\.write\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A07,
    Description: "document.write used",
    Remediation: "Avoid document.write().",
  },
  {
    Name:        "jQuery .html()",
    Regex:       `(?i)\$\(.+\)\.html\(`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "jQuery .html()",
    Remediation: "Use .text() or sanitize.",
  },
  {
    Name:        "Inline JS Handler",
    Regex:       `(?i)on\w+\s*=\s*["'].*["']`,
    Severity:    "MEDIUM",
    Category:    OWASP_A07,
    Description: "Inline JS event",
    Remediation: "Use addEventListener().",
  },

  // A08
  {
    Name:        "Go: exec w/ download",
    Regex:       `(?i)http\.Get.*\|\s*exec\.Command`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "Exec downloaded code",
    Remediation: "Verify & sign before exec.",
  },
  {
    Name:        "Shell curl + sh",
    Regex:       `curl.*\|\s*sh`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "curl | sh",
    Remediation: "Download, verify, then exec.",
  },

  // A10
  {
    Name:        "Python SSRF",
    Regex:       `requests\.get\([^)]+\)`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "Unvalidated requests.get",
    Remediation: "Whitelist URLs/domains.",
  },
  {
    Name:        "Go SSRF",
    Regex:       `http\.Get\([^)]+\)`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "Unvalidated http.Get",
    Remediation: "Whitelist URLs/domains.",
  },
}

// Extended OWASP rules
var extendedRules = []Rule{
  // A01
  {
    Name:        "Java Servlet getHeader",
    Regex:       `(?i)request\.getHeader\(`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Header input unchecked",
    Remediation: "Validate & sanitize headers.",
  },
  {
    Name:        "Spring Security Disabled",
    Regex:       `(?i)http\.csrf\(\)\.disable\(\)`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "CSRF disabled",
    Remediation: "Enable CSRF protection.",
  },

  // A02
  {
    Name:        "Hardcoded RSA Key",
    Regex:       `(?i)privateKey\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "RSA key in code",
    Remediation: "Use secure key mgmt.",
  },
  {
    Name:        "Weak Cipher",
    Regex:       `(?i)Cipher\.getInstance\(["']?(DES|RC4|MD5|SHA1)["']?\)`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "Weak cipher use",
    Remediation: "Use AES-GCM or better.",
  },
  {
    Name:        "Python hashlib md5",
    Regex:       `(?i)hashlib\.md5\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "hashlib.md5",
    Remediation: "Use hashlib.sha256.",
  },
  {
    Name:        "Go crypto/md5",
    Regex:       `(?i)md5\.New\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "crypto/md5",
    Remediation: "Use crypto/sha256.",
  },

  // A03
  {
    Name:        "Java PreparedStatement Concatenation",
    Regex:       `(?i)createStatement\(\)\.executeQuery\(".*"\s*\+\s*.*\)`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "SQL concatenation",
    Remediation: "Use parameterized queries.",
  },
  {
    Name:        "JS eval with template literals",
    Regex:       `(?i)eval\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "eval in JS",
    Remediation: "Avoid eval(); use safe parsing.",
  },
  {
    Name:        "Python os.system",
    Regex:       `(?i)os\.system\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "os.system call",
    Remediation: "Use subprocess with shell=False.",
  },
  {
    Name:        "Go exec.CommandContext",
    Regex:       `(?i)exec\.CommandContext\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "exec.CommandContext",
    Remediation: "Sanitize args; use allow-lists.",
  },

  // A05
  {
    Name:        "Java Debug Enabled",
    Regex:       `(?i)spring\.boot\.devtools\.restart\.enabled\s*=\s*true`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Devtools in prod",
    Remediation: "Disable devtools in prod.",
  },
  {
    Name:        "Node.js Express Error Handler",
    Regex:       `(?i)app\.use\(errorHandler\)`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Default error handler",
    Remediation: "Use custom error handler.",
  },

  // A06
  {
    Name:        "Old AngularJS",
    Regex:       `angular\.module\(`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Legacy AngularJS",
    Remediation: "Migrate to Angular 2+.",
  },
  {
    Name:        "Python Requests Old Version",
    Regex:       `requests==2\.18\.\d+`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Old requests lib",
    Remediation: "Upgrade requests package.",
  },
  {
    Name:        "Go Old Gin Version",
    Regex:       `github\.com/gin-gonic/gin v1\.3\.\d+`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Old Gin framework",
    Remediation: "Upgrade Gin to latest.",
  },

  // A07
  {
    Name:        "JS document.cookie",
    Regex:       `(?i)document\.cookie`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "Cookie access in JS",
    Remediation: "Avoid direct cookie use; use HttpOnly.",
  },
  {
    Name:        "Python Flask Markup Unsafe",
    Regex:       `(?i)Markup\(.*\)`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "Flask Markup()",
    Remediation: "Use safe rendering; escape data.",
  },
  {
    Name:        "Go html/template Unsafe",
    Regex:       `(?i)template\.HTML\(`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "template.HTML use",
    Remediation: "Use auto-escaping templates.",
  },

  // A08
  {
    Name:        "Python pickle load",
    Regex:       `(?i)pickle\.load\(`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "pickle.load()",
    Remediation: "Avoid pickle; use safe formats.",
  },
  {
    Name:        "Go json.Unmarshal unchecked",
    Regex:       `(?i)json\.Unmarshal\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A08,
    Description: "json.Unmarshal",
    Remediation: "Validate JSON before unmarshal.",
  },

  // A10
  {
    Name:        "Java URL openStream",
    Regex:       `(?i)new\s+URL\([^)]*\)\.openStream\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "URL.openStream",
    Remediation: "Whitelist remote endpoints.",
  },
  {
    Name:        "Node.js http.request",
    Regex:       `(?i)http\.request\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "http.request",
    Remediation: "Whitelist URLs/domains.",
  },
  {
    Name:        "Python urllib urlopen",
    Regex:       `(?i)urllib\.request\.urlopen\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "urlopen()",
    Remediation: "Whitelist URLs/domains.",
  },
  {
    Name:        "Go net/http Get",
    Regex:       `(?i)http\.Get\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "http.Get()",
    Remediation: "Whitelist URLs/domains.",
  },
}

// New extraRules for 2025
var extraRules = []Rule{
  {
    Name:        "Java Deserialization",
    Regex:       `(?i)new\s+ObjectInputStream\(`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "Java deserialization",
    Remediation: "Avoid native deserialization; use safe formats.",
  },
  {
    Name:        "Python YAML load",
    Regex:       `(?i)yaml\.load\(`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "Unsafe YAML load",
    Remediation: "Use yaml.safe_load instead.",
  },
  {
    Name:        "SSTI Jinja2 Environment",
    Regex:       `(?i)jinja2\.Environment\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "Potential SSTI",
    Remediation: "Avoid dynamic templates; sanitize inputs.",
  },
  {
    Name:        "Path Traversal",
    Regex:       `(?i)\.\./\.\./`,
    Severity:    "HIGH",
    Category:    OWASP_A05,
    Description: "Path traversal",
    Remediation: "Validate and canonicalize file paths.",
  },
  {
    Name:        "Open Redirect",
    Regex:       `(?i)(sendRedirect|res\.redirect)\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A01,
    Description: "Redirect without validation",
    Remediation: "Whitelist redirect URLs.",
  },
  {
    Name:        "Missing HttpOnly/Secure Cookie",
    Regex:       `(?i)Set-Cookie:`, 
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Insecure cookie flags",
    Remediation: "Set HttpOnly and Secure flags on cookies.",
  },
  {
    Name:        "Rails Mass Assignment",
    Regex:       `(?i)params\.permit\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A01,
    Description: "Potential mass assignment",
    Remediation: "Explicitly whitelist permitted fields.",
  },
}

// InitRules compiles the regex patterns for all rules
func InitRules() map[string]Rule {
  ruleMap := map[string]Rule{}
  
  for i := range rules {
    rules[i].Pattern = regexp.MustCompile(rules[i].Regex)
    ruleMap[rules[i].Name] = rules[i]
  }
  
  for i := range extendedRules {
    extendedRules[i].Pattern = regexp.MustCompile(extendedRules[i].Regex)
    rules = append(rules, extendedRules[i])
    ruleMap[extendedRules[i].Name] = extendedRules[i]
  }
  
  for i := range extraRules {
    extraRules[i].Pattern = regexp.MustCompile(extraRules[i].Regex)
    rules = append(rules, extraRules[i])
    ruleMap[extraRules[i].Name] = extraRules[i]
  }
  
  return ruleMap
}
