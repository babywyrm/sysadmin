package main

import (
  "regexp"
)

// OWASP category constants
const (
  OWASP_A01 = "A01" // Broken Access Control
  OWASP_A02 = "A02" // Cryptographic Failures
  OWASP_A03 = "A03" // Injection
  OWASP_A04 = "A04" // Insecure Design
  OWASP_A05 = "A05" // Security Misconfiguration
  OWASP_A06 = "A06" // Vulnerable & Outdated Components
  OWASP_A07 = "A07" // Identification and Authentication Failures
  OWASP_A08 = "A08" // Software/Data Integrity Failures
  OWASP_A09 = "A09" // Security Logging and Monitoring Failures
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

// --------------------------------------------------------------------------
// Base OWASP-related rules
// --------------------------------------------------------------------------
var rules = []Rule{
  // A01: Broken Access Control
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

  // A02: Cryptographic Failures
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

  // A03: Injection
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

  // A05: Security Misconfiguration
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

  // A06: Vulnerable & Outdated Components
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

  // A07: Identification & Authentication Failures
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

  // A08: Software/Data Integrity Failures
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

  // A10: SSRF
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

// --------------------------------------------------------------------------
// Extended OWASP rules
// --------------------------------------------------------------------------
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

// --------------------------------------------------------------------------
// Extra rules for 2025+ (high-value, low-noise additions)
// --------------------------------------------------------------------------
var extraRules = []Rule{
  // Java deserialization
  {
    Name:        "Java Deserialization",
    Regex:       `(?i)new\s+ObjectInputStream\(`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "Java deserialization vulnerability",
    Remediation: "Avoid native deserialization; use safe formats.",
  },
  // Python YAML load
  {
    Name:        "Python YAML load",
    Regex:       `(?i)yaml\.load\(`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "Unsafe YAML load",
    Remediation: "Use yaml.safe_load instead.",
  },
  // SSTI via Jinja2 Environment
  {
    Name:        "SSTI Jinja2 Environment",
    Regex:       `(?i)jinja2\.Environment\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "Potential SSTI via Jinja2 Environment",
    Remediation: "Avoid dynamic template creation.",
  },
  // Path Traversal
  {
    Name:        "Path Traversal",
    Regex:       `(?i)\.\./\.\./`,
    Severity:    "HIGH",
    Category:    OWASP_A05,
    Description: "Potential path traversal",
    Remediation: "Validate and canonicalize file paths.",
  },
  // Open Redirect
  {
    Name:        "Open Redirect",
    Regex:       `(?i)(sendRedirect|res\.redirect)\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A01,
    Description: "Redirect without validation",
    Remediation: "Whitelist redirect URLs.",
  },
  // Missing HttpOnly/Secure Cookie
  {
    Name:        "Missing HttpOnly/Secure Cookie",
    Regex:       `(?i)Set-Cookie:`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Insecure cookie flags",
    Remediation: "Set HttpOnly and Secure flags on cookies.",
  },
  // Rails Mass Assignment
  {
    Name:        "Rails Mass Assignment",
    Regex:       `(?i)params\.permit\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A01,
    Description: "Potential mass assignment",
    Remediation: "Whitelist permitted fields explicitly.",
  },
  // Go Missing Auth Check
  {
    Name:        "Go Missing Auth Check",
    Regex:       `(?i)http\.HandleFunc\(["'][^"']+["'],\s*func\s*\([^)]+\)\s*{.*return\s*\}`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Endpoint without proper authentication",
    Remediation: "Implement authentication middleware.",
  },
  // Angular Direct DOM Access
  {
    Name:        "Angular Direct DOM Access",
    Regex:       `(?i)(?:bypassSecurityTrust\w+)`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Angular security bypass",
    Remediation: "Avoid sanitization bypass.",
  },
  // JWT No Expiration
  {
    Name:        "JWT No Expiration",
    Regex:       `(?i)(?:jwt\.sign\(|jwt\.create\(|token\.add).*\)`,
    Severity:    "MEDIUM",
    Category:    OWASP_A01,
    Description: "JWT without expiration",
    Remediation: "Always set appropriate token expiration.",
  },
  // Weak Random Generation
  {
    Name:        "Weak Random Generation",
    Regex:       `(?i)(?:Math\.random\(\)|rand\.Intn\(|random\.random\(\))`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "Non-cryptographic random generator",
    Remediation: "Use secure random functions.",
  },
  // Weak Encryption Key Size
  {
    Name:        "Weak Encryption Key Size",
    Regex:       `(?i)(?:key(?:length|size|bits)\s*=\s*(?:512|1024)|RSA\.\w+\(\s*(?:512|1024)\s*\))`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "Insufficient encryption key size",
    Remediation: "Use at least 2048-bit RSA, 256-bit ECC.",
  },
  // Hardcoded IV
  {
    Name:        "Hardcoded IV",
    Regex:       `(?i)(?:iv\s*=\s*["'][0-9a-f]+["']|InitializationVector\s*\(\s*["'][0-9a-f]+["']\))`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "Hardcoded initialization vector",
    Remediation: "Generate fresh IVs for each operation.",
  },
  // GraphQL Injection
  {
    Name:        "GraphQL Injection",
    Regex:       `(?i)gql(?:['"])\s*\$\{(?:[^\}]*?)\}`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "GraphQL injection vulnerability",
    Remediation: "Use GraphQL variables instead of interpolation.",
  },
  // LDAP Injection
  {
    Name:        "LDAP Injection",
    Regex:       `(?i)ldap\.search(?:Request)?\s*\(.+\+.+\)`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "LDAP injection vulnerability",
    Remediation: "Escape LDAP special characters.",
  },
  // Python Vulnerable Templating
  {
    Name:        "Python Vulnerable Templating",
    Regex:       `(?i)(?:Template\s*\(.*request|render_template_string\()`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "Template injection vulnerability",
    Remediation: "Never pass user data directly to templates.",
  },
  // SQL String Concatenation
  {
    Name:        "SQL String Concatenation",
    Regex:       `(?i)(?:query|sql|db\.)(?:Execute|Query)\s*\(\s*(?:[f]?["']SELECT|[f]?["']INSERT|[f]?["']UPDATE|[f]?["']DELETE).*?\+.*?\)`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "SQL injection via concatenation",
    Remediation: "Use parameterized queries.",
  },

  // ------------------------------------------------------------------------
  // New high-value, low-noise additions
  // ------------------------------------------------------------------------

  // Missing Security Headers (A05)
  {
    Name:        "Missing HSTS Header",
    Regex:       `(?i)Strict-Transport-Security:\s*max-age=\d+`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "HSTS header missing",
    Remediation: "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains`.",
  },
  {
    Name:        "Missing CSP Header",
    Regex:       `(?i)Content-Security-Policy:\s*`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "CSP header missing",
    Remediation: "Define a strict CSP to lock down scripts/styles.",
  },
  {
    Name:        "Missing X-Frame-Options",
    Regex:       `(?i)X-Frame-Options:\s*(DENY|SAMEORIGIN)`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "X-Frame-Options header missing",
    Remediation: "Add `X-Frame-Options: DENY` or `SAMEORIGIN`.",
  },
  {
    Name:        "Missing X-Content-Type-Options",
    Regex:       `(?i)X-Content-Type-Options:\s*nosniff`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "X-Content-Type-Options header missing",
    Remediation: "Add `X-Content-Type-Options: nosniff`.",
  },

  // Security Logging & Monitoring (A09)
  {
    Name:        "Exceptions Caught Without Logging",
    Regex:       `(?i)catch\s*\([^)]*\)\s*\{`,
		Severity:    "MEDIUM",
    Category:    OWASP_A09,
    Description: "Exception handler lacks logging",
    Remediation: "Log caught exceptions (e.g. `console.error(err)`).",
  },
  {
    Name:        "Sensitive Data in Logs",
    Regex:       `(?i)(console\.(log|info|error)|logger\.(info|error)).*\b(pass(word)?|token|secret|ssn)\b`,
    Severity:    "HIGH",
    Category:    OWASP_A09,
    Description: "Credentials or PII in logs",
    Remediation: "Mask or remove sensitive data from logs.",
  },

  // Injection & Parsing (A03)
  {
    Name:        "CRLF Injection",
    Regex:       `(?i)(%0d%0a|\\r\\n)`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "CRLF injection risk",
    Remediation: "Strip or encode newline sequences.",
  },
  {
    Name:        "XXE/XML External Entity",
    Regex:       `(?i)<!DOCTYPE\s+[^>]*\s+SYSTEM\s+["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "Possible XXE declaration",
    Remediation: "Disable DTD/ENTITY processing in XML parsers.",
  },

  // Insecure Design (A04)
  {
    Name:        "No Rate Limiting on Auth",
    Regex:       `(?i)(POST|GET)\s*/\S*(login|auth|signin)\b`,
    Severity:    "MEDIUM",
    Category:    OWASP_A04,
    Description: "Auth endpoint lacks rate limiting",
    Remediation: "Apply rate limiting/throttling to auth endpoints.",
  },

  // Cryptographic Failures (A02)
  {
    Name:        "Weak PBKDF2 Iteration Count",
    Regex:       `(?i)pbkdf2.*(?:iterations|count)\s*[<=]\s*10000`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "Low PBKDF2 iteration count",
    Remediation: "Use ≥100k iterations for PBKDF2.",
  },

  // Supply Chain Security (A08)
  {
    Name:        "Dependency Confusion Install Command",
    Regex:       `(?i)(npm\s+install|pip\s+install|go\s+get)\s+http://`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "Installing packages over HTTP",
    Remediation: "Use only HTTPS package registries.",
  },

  // API Security (A05)
  {
    Name:        "Open CORS Policy",
    Regex:       `(?i)Access-Control-Allow-Origin:\s*\*`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "CORS policy allows any origin",
    Remediation: "Restrict CORS to trusted domains.",
  },

  // Zero-Trust & Network Security (A05)
  {
    Name:        "Hardcoded IP Address",
    Regex:       `(?i)\b((?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})\b`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Hardcoded IPv4 address",
    Remediation: "Use DNS names or config management for IPs.",
  },
}

// InitRules compiles all regex patterns and returns a map[name]Rule.
func InitRules() map[string]Rule {
  ruleMap := map[string]Rule{}
  // Compile base rules
  for i := range rules {
    rules[i].Pattern = regexp.MustCompile(rules[i].Regex)
    ruleMap[rules[i].Name] = rules[i]
  }
  // Compile extended rules
  for i := range extendedRules {
    extendedRules[i].Pattern = regexp.MustCompile(extendedRules[i].Regex)
    rules = append(rules, extendedRules[i])
    ruleMap[extendedRules[i].Name] = extendedRules[i]
  }
  // Compile extra rules
  for i := range extraRules {
    extraRules[i].Pattern = regexp.MustCompile(extraRules[i].Regex)
    rules = append(rules, extraRules[i])
    ruleMap[extraRules[i].Name] = extraRules[i]
  }
  return ruleMap
}
