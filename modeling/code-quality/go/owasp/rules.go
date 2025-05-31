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
	// --- A01: Broken Access Control ---
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
	// --- A02: Cryptographic Failures ---
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
	// --- A03: Injection ---
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
	// --- A05: Security Misconfiguration ---
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
		Remediation: "Disable debug in production.",
	},
	// --- A06: Vulnerable & Outdated Components ---
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
	// --- A07: Identification and Authentication Failures ---
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
	// --- A08: Software/Data Integrity Failures ---
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
	// --- A10: SSRF ---
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
// Extended Rules apply additional checks and often refine rules above.
// --------------------------------------------------------------------------
var extendedRules = []Rule{
	// --- A01 ---
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
	// --- A02 ---
	{
		Name:        "Hardcoded RSA Key",
		Regex:       `(?i)privateKey\s*=\s*["'][^"']+["']`,
		Severity:    "HIGH",
		Category:    OWASP_A02,
		Description: "RSA key in code",
		Remediation: "Use secure key management.",
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
	// --- A03 ---
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
		Remediation: "Sanitize arguments; use allow-lists.",
	},
	// --- A05 ---
	{
		Name:        "Java Debug Enabled",
		Regex:       `(?i)spring\.boot\.devtools\.restart\.enabled\s*=\s*true`,
		Severity:    "MEDIUM",
		Category:    OWASP_A05,
		Description: "Devtools enabled in production",
		Remediation: "Disable devtools in production.",
	},
	{
		Name:        "Node.js Express Error Handler",
		Regex:       `(?i)app\.use\(errorHandler\)`,
		Severity:    "MEDIUM",
		Category:    OWASP_A05,
		Description: "Default error handler in Node.js",
		Remediation: "Implement a custom error handler.",
	},
	// --- A06 ---
	{
		Name:        "Old AngularJS",
		Regex:       `angular\.module\(`,
		Severity:    "HIGH",
		Category:    OWASP_A06,
		Description: "Legacy AngularJS",
		Remediation: "Upgrade to Angular 2+.",
	},
	{
		Name:        "Python Requests Old Version",
		Regex:       `requests==2\.18\.\d+`,
		Severity:    "HIGH",
		Category:    OWASP_A06,
		Description: "Outdated requests package",
		Remediation: "Upgrade to a newer version of requests.",
	},
	{
		Name:        "Go Old Gin Version",
		Regex:       `github\.com/gin-gonic/gin v1\.3\.\d+`,
		Severity:    "HIGH",
		Category:    OWASP_A06,
		Description: "Old Gin framework version",
		Remediation: "Upgrade to the latest Gin version.",
	},
	// --- A07 ---
	{
		Name:        "JS document.cookie",
		Regex:       `(?i)document\.cookie`,
		Severity:    "HIGH",
		Category:    OWASP_A07,
		Description: "Accessing cookies in JS",
		Remediation: "Avoid direct cookie access; use HttpOnly flags.",
	},
	{
		Name:        "Python Flask Markup Unsafe",
		Regex:       `(?i)Markup\(.*\)`,
		Severity:    "HIGH",
		Category:    OWASP_A07,
		Description: "Unsafe use of Flask Markup",
		Remediation: "Use safe rendering methods or escape data.",
	},
	{
		Name:        "Go html/template Unsafe",
		Regex:       `(?i)template\.HTML\(`,
		Severity:    "HIGH",
		Category:    OWASP_A07,
		Description: "Direct use of template.HTML",
		Remediation: "Use auto-escaping templates whenever possible.",
	},
	// --- A08 ---
	{
		Name:        "Python pickle load",
		Regex:       `(?i)pickle\.load\(`,
		Severity:    "HIGH",
		Category:    OWASP_A08,
		Description: "Using pickle.load() can be unsafe",
		Remediation: "Avoid using pickle; use safer data formats.",
	},
	{
		Name:        "Go json.Unmarshal unchecked",
		Regex:       `(?i)json\.Unmarshal\(`,
		Severity:    "MEDIUM",
		Category:    OWASP_A08,
		Description: "json.Unmarshal without validation",
		Remediation: "Validate JSON input before unmarshaling.",
	},
	// --- A10 ---
	{
		Name:        "Java URL openStream",
		Regex:       `(?i)new\s+URL\([^)]*\)\.openStream\(`,
		Severity:    "HIGH",
		Category:    OWASP_A10,
		Description: "Using URL.openStream in Java",
		Remediation: "Whitelist external endpoints.",
	},
	{
		Name:        "Node.js http.request",
		Regex:       `(?i)http\.request\(`,
		Severity:    "HIGH",
		Category:    OWASP_A10,
		Description: "Using http.request in Node.js",
		Remediation: "Whitelist external hosts.",
	},
	{
		Name:        "Python urllib urlopen",
		Regex:       `(?i)urllib\.request\.urlopen\(`,
		Severity:    "HIGH",
		Category:    OWASP_A10,
		Description: "Using urllib.request.urlopen in Python",
		Remediation: "Whitelist external endpoints.",
	},
	{
		Name:        "Go net/http Get",
		Regex:       `(?i)http\.Get\(`,
		Severity:    "HIGH",
		Category:    OWASP_A10,
		Description: "Using http.Get in Go",
		Remediation: "Whitelist external endpoints.",
	},
}

// --------------------------------------------------------------------------
// Extra Rules for 2025 and beyond
// --------------------------------------------------------------------------
var extraRules = []Rule{
	// Previously defined
	{
		Name:        "Java Deserialization",
		Regex:       `(?i)new\s+ObjectInputStream\(`,
		Severity:    "HIGH",
		Category:    OWASP_A08,
		Description: "Java deserialization vulnerability",
		Remediation: "Avoid native deserialization; use safe formats.",
	},
	{
		Name:        "Python YAML load",
		Regex:       `(?i)yaml\.load\(`,
		Severity:    "HIGH",
		Category:    OWASP_A08,
		Description: "Unsafe YAML load can lead to code execution",
		Remediation: "Use yaml.safe_load instead.",
	},
	{
		Name:        "SSTI Jinja2 Environment",
		Regex:       `(?i)jinja2\.Environment\(`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "Potential SSTI via Jinja2 Environment instantiation",
		Remediation: "Avoid dynamic template creation.",
	},
	{
		Name:        "Path Traversal",
		Regex:       `(?i)\.\./\.\./`,
		Severity:    "HIGH",
		Category:    OWASP_A05,
		Description: "Potential path traversal detected",
		Remediation: "Validate and canonicalize file paths.",
	},
	{
		Name:        "Open Redirect",
		Regex:       `(?i)(sendRedirect|res\.redirect)\(`,
		Severity:    "MEDIUM",
		Category:    OWASP_A01,
		Description: "Redirect without validation",
		Remediation: "Whitelist and validate redirect URLs.",
	},
	{
		Name:        "Missing HttpOnly/Secure Cookie",
		Regex:       `(?i)Set-Cookie:`,
		Severity:    "MEDIUM",
		Category:    OWASP_A05,
		Description: "No secure flags on cookies",
		Remediation: "Set HttpOnly and Secure flags on cookies.",
	},
	{
		Name:        "Rails Mass Assignment",
		Regex:       `(?i)params\.permit\(`,
		Severity:    "MEDIUM",
		Category:    OWASP_A01,
		Description: "Mass assignment risk in Rails",
		Remediation: "Whitelist permitted fields explicitly.",
	},

	// New Extra Rules
	{
		Name:        "Go Missing Auth Check",
		// Removed negative lookahead, using simplified pattern.
		Regex:       `(?i)http\.HandleFunc\(["'][^"']+["'],\s*func\s*\([^)]+\)\s*{.*return\s*\}`,
		Severity:    "HIGH",
		Category:    OWASP_A01,
		Description: "Endpoint without proper authentication check",
		Remediation: "Implement authentication middleware and validate inputs.",
	},
	{
		Name:        "Angular Direct DOM Access",
		Regex:       `(?i)(?:bypassSecurityTrust\w+)`,
		Severity:    "HIGH",
		Category:    OWASP_A01,
		Description: "Angular security bypass detected",
		Remediation: "Avoid using bypass methods for sanitization.",
	},
	{
		Name:        "JWT No Expiration",
		// Simplified pattern: match the function call and any characters until closing parenthesis.
		Regex:       `(?i)(?:jwt\.sign\(|jwt\.create\(|token\.add)[^)]*\)`,
		Severity:    "MEDIUM",
		Category:    OWASP_A01,
		Description: "JWT created without setting an expiration",
		Remediation: "Always set appropriate token expirations.",
	},
	{
		Name:        "Weak Random Generation",
		Regex:       `(?i)(?:Math\.random\(\)|rand\.Intn\(|random\.random\(\))`,
		Severity:    "MEDIUM",
		Category:    OWASP_A02,
		Description: "Use of non-cryptographic random generation",
		Remediation: "Switch to cryptographically secure functions.",
	},
	{
		Name:        "Weak Encryption Key Size",
		Regex:       `(?i)(?:key(?:length|size|bits)\s*=\s*(?:512|1024)|RSA\.\w+\(\s*(?:512|1024)\s*\))`,
		Severity:    "HIGH",
		Category:    OWASP_A02,
		Description: "Insufficient encryption key size",
		Remediation: "Use recommended key sizes (e.g., 2048-bit RSA).",
	},
	{
		Name:        "Hardcoded IV",
		Regex:       `(?i)(?:iv\s*=\s*["'][0-9a-f]+["']|InitializationVector\s*\(\s*["'][0-9a-f]+["']\))`,
		Severity:    "HIGH",
		Category:    OWASP_A02,
		Description: "Hardcoded initialization vector",
		Remediation: "Generate a fresh IV for each encryption operation.",
	},
	{
		Name:        "GraphQL Injection",
		Regex:       `(?i)gql(?:['"])\s*\$\{(?:[^\}]*?)\}`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "Potential GraphQL injection vulnerability",
		Remediation: "Use GraphQL variables and parameterized queries.",
	},
	{
		Name:        "LDAP Injection",
		Regex:       `(?i)ldap\.search(?:Request)?\s*\(.+\+.+\)`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "LDAP injection vulnerability",
		Remediation: "Escape user inputs properly when constructing LDAP queries.",
	},
	{
		Name:        "Python Vulnerable Templating",
		Regex:       `(?i)(?:Template\s*\(.*request|render_template_string\()`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "Template injection vulnerability",
		Remediation: "Avoid passing user-controlled data directly to template engines.",
	},
	{
		Name:        "SQL String Concatenation",
		Regex:       `(?i)(?:query|sql|db\.)(?:Execute|Query)\s*\(\s*(?:[f]?["']SELECT|[f]?["']INSERT|[f]?["']UPDATE|[f]?["']DELETE).*?\+.*?\)`,
		Severity:    "HIGH",
		Category:    OWASP_A03,
		Description: "SQL injection vulnerability via concatenation",
		Remediation: "Always use parameterized queries.",
	},
}

func InitRules() map[string]Rule {
	ruleMap := map[string]Rule{}

	// Compile base rules.
	for i := range rules {
		rules[i].Pattern = regexp.MustCompile(rules[i].Regex)
		ruleMap[rules[i].Name] = rules[i]
	}

	// Compile extended rules and append.
	for i := range extendedRules {
		extendedRules[i].Pattern = regexp.MustCompile(extendedRules[i].Regex)
		rules = append(rules, extendedRules[i])
		ruleMap[extendedRules[i].Name] = extendedRules[i]
	}

	// Compile extra rules and append.
	for i := range extraRules {
		extraRules[i].Pattern = regexp.MustCompile(extraRules[i].Regex)
		rules = append(rules, extraRules[i])
		ruleMap[extraRules[i].Name] = extraRules[i]
	}

	return ruleMap
}

func GetAllRules() []Rule {
	allRules := make([]Rule, 0)

	// Compile base rules
	for i := range rules {
		rules[i].Pattern = regexp.MustCompile(rules[i].Regex)
		allRules = append(allRules, rules[i])
	}

	// Compile extended rules
	for i := range extendedRules {
		extendedRules[i].Pattern = regexp.MustCompile(extendedRules[i].Regex)
		allRules = append(allRules, extendedRules[i])
	}

	// Compile extra rules
	for i := range extraRules {
		extraRules[i].Pattern = regexp.MustCompile(extraRules[i].Regex)
		allRules = append(allRules, extraRules[i])
	}

	return allRules
}
//
