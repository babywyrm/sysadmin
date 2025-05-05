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

// extraRules for 2025 and beyond
var extraRules = []Rule{
	// Previously defined rules
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

	// New Rules - A01: Broken Access Control
	{
		// Modified to remove unsupported negative lookahead
		Name:        "Go Missing Auth Check",
		Regex:       `(?i)http\.HandleFunc\(["'][^"']+["'],\s*func\s*\([^)]+\)\s*{.*return\s*\}`,
		Severity:    "HIGH",
		Category:    OWASP_A01,
		Description: "Endpoint without proper authentication check",
		Remediation: "Implement authentication middleware.",
	},
	{
		Name:        "Angular Direct DOM Access",
		Regex:       `(?i)(?:bypassSecurityTrust\w+)`,
		Severity:    "HIGH",
		Category:    OWASP_A01,
		Description: "Angular security bypass",
		Remediation: "Avoid sanitization bypass.",
	},
	{
		// Updated regex without negative lookahead
		Name:        "JWT No Expiration",
		Regex:       `(?i)(?:jwt\.sign\(|jwt\.create\(|token\.add).*\)`,
		Severity:    "MEDIUM",
		Category:    OWASP_A01,
		Description: "JWT without expiration",
		Remediation: "Always set appropriate token expiration.",
	},

	// New Rules - A02: Cryptographic Failures
	{
		Name:        "Weak Random Generation",
		Regex:       `(?i)(?:Math\.random\(\)|rand\.Intn\(|random\.random\(\))`,
		Severity:    "MEDIUM",
		Category:    OWASP_A02,
		Description: "Non-cryptographic random generator",
		Remediation: "Use cryptographically secure random functions.",
	},
	{
		Name:        "Weak Encryption Key Size",
		Regex:       `(?i)(?:key(?:length|size|bits)\s*=\s*(?:512|1024)|RSA\.\w+\(\s*(?:512|1024)\s*\))`,
		Severity:    "HIGH",
		Category:    OWASP_A02,
		Description: "Insufficient encryption key size",
		Remediation: "Use at least 2048 bits for RSA, 256 bits for ECC.",
	},
	{
		Name:        "Hardcoded IV",
		Regex:       `(?i)(?:iv\s*=\s*["'][0-9a-f]+["']|InitializationVector\s*\(\s*["'][0-9a-f]+["']\))`,
		Severity:    "HIGH",
		Category:    OWASP_A02,
		Description: "Hardcoded initialization vector",
		Remediation: "Generate fresh IVs for each encryption operation.",
	},

	// New Rules - A03: Injection
	{
		Name:        "GraphQL Injection",
		Regex:       `(?i)gql(?:['"])\s*\$\{(?:[^\}]*?)\}`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "GraphQL injection vulnerability",
		Remediation: "Use GraphQL variables instead of string interpolation.",
	},
	{
		Name:        "LDAP Injection",
		Regex:       `(?i)ldap\.search(?:Request)?\s*\(.+\+.+\)`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "LDAP injection vulnerability",
		Remediation: "Use proper LDAP parameter escaping.",
	},
	{
		Name:        "Python Vulnerable Templating",
		Regex:       `(?i)(?:Template\s*\(.*request|render_template_string\()`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "Template injection vulnerability",
		Remediation: "Never pass user-controlled data to template engines.",
	},
	{
		Name:        "SQL String Concatenation",
		Regex:       `(?i)(?:query|sql|db\.)(?:Execute|Query)\s*\(\s*(?:[f]?["']SELECT|[f]?["']INSERT|[f]?["']UPDATE|[f]?["']DELETE).*?\+.*?\)`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "SQL injection vulnerability through string concatenation",
		Remediation: "Use parameterized queries or prepared statements.",
	},

	// New Rules - A04: Insecure Design
	{
		Name:        "Hardcoded Backdoor",
		Regex:       `(?i)(?:backdoor|debug_mode|master_key|master_password|god_mode)\s*=\s*(?:true|["'][^"']+["'])`,
		Severity:    "CRITICAL",
		Category:    OWASP_A04,
		Description: "Hardcoded backdoor",
		Remediation: "Remove backdoors completely.",
	},
	{
		Name:        "Missing Rate Limiting",
		Regex:       `(?i)(?:login|authenticate|auth|sign[_-]?in)\s*=\s*function\s*\((?:(?!rate|limit|throttle).)*\{`,
		Severity:    "MEDIUM",
		Category:    OWASP_A04,
		Description: "Authentication without rate limiting",
		Remediation: "Implement rate limiting on auth endpoints.",
	},

	// New Rules - A05: Security Misconfiguration
	{
		Name:        "Exposed Docker Socket",
		Regex:       `(?i)(?:docker\.sock|/var/run/docker\.sock)`,
		Severity:    "HIGH",
		Category:    OWASP_A05,
		Description: "Exposed Docker socket",
		Remediation: "Never expose the Docker socket to containers.",
	},
	{
		Name:        "Django Debug Enabled",
		Regex:       `(?i)DEBUG\s*=\s*True`,
		Severity:    "MEDIUM",
		Category:    OWASP_A05,
		Description: "Django debug mode enabled",
		Remediation: "Set DEBUG=False in production.",
	},
	{
		Name:        "Kubernetes API Server Insecure",
		Regex:       `(?i)(?:--insecure-port|--disable-admission-plugins|--anonymous-auth=true)`,
		Severity:    "HIGH",
		Category:    OWASP_A05,
		Description: "Insecure Kubernetes API configuration",
		Remediation: "Never disable security features in Kubernetes.",
	},
	{
		Name:        "Docker Root User",
		Regex:       `(?i)FROM\s+(?:(?!scratch).)*(?:(?!USER).)*$`,
		Severity:    "MEDIUM",
		Category:    OWASP_A05,
		Description: "Docker container running as root",
		Remediation: "Use USER instruction to run as non-root.",
	},
	{
		Name:        "Docker Privileged Mode",
		Regex:       `(?i)(?:--privileged|privileged:\s*true)`,
		Severity:    "HIGH",
		Category:    OWASP_A05,
		Description: "Docker container in privileged mode",
		Remediation: "Avoid privileged mode in production.",
	},
	{
		Name:        "Kubernetes RunAsRoot",
		Regex:       `(?i)runAsNonRoot:\s*false`,
		Severity:    "MEDIUM",
		Category:    OWASP_A05,
		Description: "Kubernetes Pod running as root",
		Remediation: "Set runAsNonRoot: true in Pod security context.",
	},
	{
		Name:        "Kubernetes Privileged Container",
		Regex:       `(?i)privileged:\s*true`,
		Severity:    "HIGH",
		Category:    OWASP_A05,
		Description: "Privileged Kubernetes container",
		Remediation: "Avoid privileged containers.",
	},
	{
		Name:        "Kubernetes hostPath",
		Regex:       `(?i)hostPath:\s*\{`,
		Severity:    "MEDIUM",
		Category:    OWASP_A05,
		Description: "Kubernetes hostPath volume mount",
		Remediation: "Avoid hostPath in production; use persistent volumes.",
	},
	{
		Name:        "AWS S3 Public Access",
		Regex:       `(?i)acl\s*=\s*"public-read"`,
		Severity:    "HIGH",
		Category:    OWASP_A05,
		Description: "Public readable S3 bucket",
		Remediation: "Restrict S3 bucket access.",
	},
	{
		Name:        "Open Security Group",
		Regex:       `(?i)ingress\s*\{[^}]*0\.0\.0\.0/0[^}]*\}`,
		Severity:    "HIGH",
		Category:    OWASP_A05,
		Description: "Security group open to the world",
		Remediation: "Restrict security group access to necessary IPs.",
	},

	// New Rules - A06: Vulnerable & Outdated Components
	{
		Name:        "Log4j Vulnerable Version",
		Regex:       `(?i)log4j-core.*2\.(?:0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\.`,
		Severity:    "CRITICAL",
		Category:    OWASP_A06,
		Description: "Log4j vulnerable to Log4Shell (CVE-2021-44228)",
		Remediation: "Upgrade to Log4j 2.15.0 or newer.",
	},
	{
		Name:        "Spring4Shell Vulnerable",
		Regex:       `(?i)spring-(?:framework|core|beans|web).*5\.(?:0|1|2|3)\.`,
		Severity:    "HIGH",
		Category:    OWASP_A06,
		Description: "Spring potentially vulnerable to Spring4Shell",
		Remediation: "Upgrade to Spring Framework 5.3.18+ or 5.2.20+.",
	},
	{
		Name:        "Node.js Outdated Package",
		Regex:       `(?i)(?:"express"\s*:\s*"[~^]?[1-3]\.|"mongoose"\s*:\s*"[~^]?[1-4]\.|"react"\s*:\s*"[~^]?1[0-6]\.)`,
		Severity:    "MEDIUM",
		Category:    OWASP_A06,
		Description: "Outdated npm package with potential vulnerabilities",
		Remediation: "Update to latest stable versions.",
	},

	// New Rules - A07: Identification and Authentication Failures
	{
		Name:        "Weak Password Requirements",
		Regex:       `(?i)(?:minLength|min_length|minimum_length)\s*[:=]\s*(?:[1-7]|["'][1-7]["'])`,
		Severity:    "MEDIUM",
		Category:    OWASP_A07,
		Description: "Weak password requirements (length < 8)",
		Remediation: "Require passwords of at least 8 characters.",
	},
	{
		Name:        "No MFA Support",
		Regex:       `(?i)(?:authentication|auth).*class[^}]*(?:(?!mfa|factor|totp|2fa|two-factor|twoFactor|multi-factor).)*}`,
		Severity:    "MEDIUM",
		Category:    OWASP_A07,
		Description: "Authentication without MFA",
		Remediation: "Implement multi-factor authentication.",
	},
	{
		Name:        "Plain Text Password Storage",
		Regex:       `(?i)(?:password|passwd|pwd).*(?:TEXT|VARCHAR|String)`,
		Severity:    "HIGH",
		Category:    OWASP_A07,
		Description: "Potential plaintext password storage",
		Remediation: "Use password hashing with appropriate algorithms (bcrypt/argon2).",
	},

	// New Rules - A08: Software/Data Integrity Failures
	{
		Name:        "NPM Install with Unsafe Flags",
		Regex:       `(?i)npm\s+(?:install|i).*--no-(?:ignore-scripts|verify-signatures)`,
		Severity:    "HIGH",
		Category:    OWASP_A08,
		Description: "NPM install with unsafe flags",
		Remediation: "Verify package signatures and avoid unsafe flags.",
	},
	{
		Name:        "Unchecked Package Installation",
		Regex:       `(?i)(?:pip\s+install|gem\s+install|npm\s+install|apt\s+install|apt-get\s+install)(?:(?!\s+--hash|\s+--integrity|\s+--verify).)*$`,
		Severity:    "MEDIUM",
		Category:    OWASP_A08,
		Description: "Package installation without integrity verification",
		Remediation: "Verify package integrity before installation.",
	},
	{
		Name:        "Docker Run From Latest",
		Regex:       `(?i)(?:FROM|image:)\s+\w+(?::\s*latest|(?!:))`,
		Severity:    "MEDIUM",
		Category:    OWASP_A08,
		Description: "Docker using 'latest' tag",
		Remediation: "Use specific image versions in Dockerfiles.",
	},
	{
		Name:        "Terraform Unencrypted Storage",
		Regex:       `(?i)(?:encrypted\s*=\s*false|enable_encryption\s*=\s*false)`,
		Severity:    "HIGH",
		Category:    OWASP_A02,
		Description: "Unencrypted storage in Terraform",
		Remediation: "Enable encryption for all storage resources.",
	},

	// New Rules - A09: Security Logging and Monitoring Failures
	{
		Name:        "Missing Error Logging",
		Regex:       `(?i)catch\s*\([^)]*\)\s*\{(?:(?!log|console|report|monitor|track).)*\}`,
		Severity:    "MEDIUM",
		Category:    OWASP_A09,
		Description: "Exception caught without logging",
		Remediation: "Log all caught exceptions.",
	},
	{
		Name:        "Password/Token Logging",
		Regex:       `(?i)(?:console\.log|System\.out\.print|printf|puts|print|logger)\(.*(?:password|credential|token|secret|key)`,
		Severity:    "HIGH",
		Category:    OWASP_A09,
		Description: "Sensitive data in logs",
		Remediation: "Never log credentials or secrets.",
	},
	{
		Name:        "Disabled Audit Logging",
		Regex:       `(?i)(?:audit|logging|logger)\.(?:off|disabled|enable\(false\))`,
		Severity:    "HIGH",
		Category:    OWASP_A09,
		Description: "Disabled audit logging",
		Remediation: "Enable comprehensive audit logging in production.",
	},

	// New Rules - A10: SSRF
	{
		Name:        "Fetch with User Input",
		Regex:       `(?i)fetch\(\s*[^"'\)]*\)`,
		Severity:    "HIGH",
		Category:    OWASP_A10,
		Description: "Potential SSRF with fetch API",
		Remediation: "Validate and sanitize URLs in fetch requests.",
	},
	{
		Name:        "Ruby Open URI",
		Regex:       `(?i)open\(\s*(?:URI|uri|params|request)`,
		Severity:    "HIGH",
		Category:    OWASP_A10,
		Description: "Ruby open-uri with user input",
		Remediation: "Whitelist allowed URLs and hosts.",
	},
	{
		Name:        "PHP SSRF",
		Regex:       `(?i)(?:file_get_contents|curl_exec|curl_init)\(\s*\$(?:_GET|_POST|_REQUEST|request|input)`,
		Severity:    "HIGH",
		Category:    OWASP_A10,
		Description: "PHP SSRF vulnerability",
		Remediation: "Validate URLs against a whitelist.",
	},
}

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
