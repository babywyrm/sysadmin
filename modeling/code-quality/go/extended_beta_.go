package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
)

type Finding struct {
	File       string    `json:"file"`
	Line       int       `json:"line"`
	RuleName   string    `json:"rule_name"`
	Match      string    `json:"match"`
	Severity   string    `json:"severity"`
	Category   string    `json:"category"`
	Confidence string    `json:"confidence"` // Added confidence level
	Context    string    `json:"context"`    // Added surrounding code context
	Timestamp  time.Time `json:"timestamp"`
}

type Rule struct {
	Name        string
	Regex       string
	Pattern     *regexp.Regexp
	Severity    string
	Category    string
	Description string
	Confidence  string   // Added default confidence level
	FileTypes   []string // Only apply rule to these file types
}

// Maps OWASP categories to their full names for better reporting
var owaspCategories = map[string]string{
	"A01": "Broken Access Control",
	"A02": "Cryptographic Failures",
	"A03": "Injection",
	"A04": "Insecure Design",
	"A05": "Security Misconfiguration",
	"A06": "Vulnerable & Outdated Components",
	"A07": "Identification & Authentication Failures",
	"A08": "Software & Data Integrity Failures",
	"A09": "Security Logging & Monitoring Failures",
	"A10": "Server-Side Request Forgery",
}

var rules = []Rule{
	// 🛡️ A01: Broken Access Control - Improved input detection patterns
	{
		"Node Request Body Input", 
		`(?i)req\.body\.([a-zA-Z0-9_]+)`, 
		nil, "MEDIUM", "A01", 
		"Node.js request body input", 
		"MEDIUM",
		[]string{".js"},
	},
	{
		"Node Request Query Input", 
		`(?i)req\.query\.([a-zA-Z0-9_]+)`, 
		nil, "MEDIUM", "A01", 
		"Node.js query parameter input", 
		"MEDIUM", 
		[]string{".js"},
	},
	{
		"Node Request Params", 
		`(?i)req\.params\.([a-zA-Z0-9_]+)`, 
		nil, "MEDIUM", "A01", 
		"Node.js route parameter", 
		"MEDIUM", 
		[]string{".js"},
	},
	{
		"Java Request Parameter", 
		`(?i)request\.getParameter\(["']([^"']+)["']\)`, 
		nil, "MEDIUM", "A01", 
		"Java servlet parameter access", 
		"MEDIUM", 
		[]string{".java"},
	},
	{
		"Flask Request Args", 
		`(?i)request\.args\.get\(["']([^"']+)["']\)`, 
		nil, "MEDIUM", "A01", 
		"Flask query parameter access", 
		"MEDIUM", 
		[]string{".py"},
	},
	{
		"Express Unsanitized Param", 
		`(?i)(req\.(body|query|params)\.([a-zA-Z0-9_]+))`, 
		nil, "HIGH", "A01", 
		"Potentially unsanitized Express parameter", 
		"HIGH", 
		[]string{".js"},
	},

	// 🧊 A02: Cryptographic Failures - Improved credential detection
	{
		"Hardcoded Password", 
		`(?i)(?:password|passwd|pwd)\s*=\s*["']([^"']{4,})["']`, 
		nil, "HIGH", "A02", 
		"Hardcoded password credential", 
		"HIGH", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"API Key", 
		`(?i)(api[_-]?key|secret|access[_-]token)\s*=\s*["']([a-zA-Z0-9_\-\.]{16,})["']`, 
		nil, "HIGH", "A02", 
		"Hardcoded API key", 
		"HIGH", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"JWT Secret", 
		`(?i)(jwt[_-]?secret|signing[_-]?key)\s*=\s*["']([^"']{8,})["']`, 
		nil, "HIGH", "A02", 
		"Hardcoded JWT secret", 
		"HIGH", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"MD5 Hash", 
		`(?i)\.createHash\(["']md5["']\)|MD5\(|Digest\.getInstance\(["']MD5["']\)|md5\s*\(`, 
		nil, "MEDIUM", "A02", 
		"Weak MD5 hashing algorithm", 
		"HIGH", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"SHA1 Hash", 
		`(?i)\.createHash\(["']sha1["']\)|SHA1\(|Digest\.getInstance\(["']SHA-?1["']\)|sha1\s*\(`, 
		nil, "MEDIUM", "A02", 
		"Weak SHA1 hashing algorithm", 
		"HIGH", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"Weak SSL/TLS Config", 
		`(?i)SSLv3|TLSv1\.0|TLSv1\.1`, 
		nil, "HIGH", "A02", 
		"Obsolete SSL/TLS protocol version", 
		"HIGH", 
		[]string{".js", ".py", ".java", ".go", ".php", ".conf"},
	},

	// 💥 A03: Injection - More precise code injection patterns
	{
		"JavaScript Eval", 
		`(?i)eval\s*\(\s*(.*?)\s*\)`, 
		nil, "HIGH", "A03", 
		"Dangerous eval() usage", 
		"HIGH", 
		[]string{".js", ".html"},
	},
	{
		"OS Command Execution", 
		`(?i)(?:exec|spawn|execSync)\s*\(\s*["'][^"']*\$\{[^}]*\}[^"']*["']`, 
		nil, "HIGH", "A03", 
		"OS command execution with possible injection", 
		"HIGH", 
		[]string{".js", ".py", ".php"},
	},
	{
		"Shell Command", 
		`(?i)(?:system|shell_exec|passthru|popen)\s*\(\s*(.*)\s*\)`, 
		nil, "HIGH", "A03", 
		"Shell command execution", 
		"HIGH", 
		[]string{".py", ".php"},
	},
	{
		"SQL Concat Query", 
		`(?i)(?:execute|query)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*?(?:\+|concat|\$\{)`, 
		nil, "HIGH", "A03", 
		"SQL query with string concatenation", 
		"HIGH", 
		[]string{".js", ".py", ".java", ".php"},
	},
	{
		"Node Child Process", 
		`(?i)require\(["']child_process["']\)`, 
		nil, "MEDIUM", "A03", 
		"Node.js child process module usage", 
		"MEDIUM",
		[]string{".js"},
	},
	{
		"MVEL Expression", 
		`(?i)new\s+Expression\s*\(`, 
		nil, "MEDIUM", "A03", 
		"MVEL expression evaluation", 
		"MEDIUM", 
		[]string{".java"},
	},

	// 🔧 A04: Insecure Design (Added category)
	{
		"Insecure Random", 
		`(?i)Math\.random\(\)|Random\(\)|new Random\(`, 
		nil, "MEDIUM", "A04", 
		"Non-cryptographic random number generator", 
		"MEDIUM", 
		[]string{".js", ".py", ".java", ".go"},
	},
	{
		"Serialization Usage", 
		`(?i)(?:readObject|ObjectInputStream|unserialize|load|pickle\.loads)`, 
		nil, "MEDIUM", "A04", 
		"Object deserialization", 
		"MEDIUM", 
		[]string{".java", ".php", ".py"},
	},

	// 🔧 A05: Security Misconfiguration
	{
		"TLS Validation Disabled", 
		`(?i)(?:InsecureSkipVerify\s*[:=]\s*true|rejectUnauthorized\s*[:=]\s*false)`, 
		nil, "HIGH", "A05", 
		"TLS certificate validation disabled", 
		"HIGH", 
		[]string{".js", ".go", ".java"},
	},
	{
		"Debug Mode", 
		`(?i)(?:app\.run\(.*debug\s*=\s*True|DEBUG\s*[:=]\s*True|debug\s*:\s*true)`, 
		nil, "MEDIUM", "A05", 
		"Application in debug mode", 
		"MEDIUM", 
		[]string{".py", ".js", ".php", ".java"},
	},
	{
		"CORS All Origins", 
		`(?i)(?:Access-Control-Allow-Origin\s*:\s*\*|res\.header\(["']Access-Control-Allow-Origin["'],\s*["']\*["']\))`, 
		nil, "MEDIUM", "A05", 
		"CORS allows all origins", 
		"MEDIUM", 
		[]string{".js", ".py", ".php", ".java", ".conf"},
	},
	{
		"HTTPS Disabled", 
		`(?i)(?:HSTS|StrictTransportSecurity|requireSSL)\s*[:=]\s*false`, 
		nil, "MEDIUM", "A05", 
		"HTTPS requirement disabled", 
		"MEDIUM", 
		[]string{".js", ".py", ".java", ".go", ".php", ".conf"},
	},

	// 🧪 A06: Vulnerable & Outdated Components
	{
		"Outdated jQuery", 
		`(?i)(?:jquery-1\.[0-9]|jquery-2\.[0-4])`, 
		nil, "MEDIUM", "A06", 
		"Outdated jQuery library", 
		"HIGH", 
		[]string{".js", ".html"},
	},
	{
		"Outdated Angular", 
		`(?i)(?:angular(?:\.min)?\.js\?v=1|angular@1\.)`, 
		nil, "MEDIUM", "A06", 
		"Outdated AngularJS", 
		"MEDIUM", 
		[]string{".js", ".html"},
	},
	{
		"Vulnerable Library Version", 
		`(?i)(?:lodash@3|prototype-1\.[0-6]|moment@2\.[0-9]|log4j-core-2\.[0-9]|struts2-core-2\.[0-3])`, 
		nil, "HIGH", "A06", 
		"Known vulnerable library version", 
		"HIGH", 
		[]string{".js", ".html", ".java", ".xml"},
	},

	// 🧬 A07: Identification & Authentication Failures (Updated from XSS)
	{
		"Password Min Length", 
		`(?i)(?:minLength|MIN_PASSWORD_LENGTH|minimum.*password).*[=:]\s*([0-8])`, 
		nil, "MEDIUM", "A07", 
		"Password minimum length too short", 
		"MEDIUM", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"Session Timeout", 
		`(?i)(?:session\.timeout|SESSION_TIMEOUT|maxAge).*[=:]\s*([0-9]+)`, 
		nil, "LOW", "A07", 
		"Check session timeout value", 
		"LOW", 
		[]string{".js", ".py", ".java", ".go", ".php", ".conf"},
	},

	// Cross-Site Scripting rules (moved to correct A03 category but keeping for compatibility)
	{
		"DOM XSS innerHTML", 
		`(?i)\.innerHTML\s*=`, 
		nil, "HIGH", "A03", 
		"DOM XSS via innerHTML", 
		"HIGH", 
		[]string{".js", ".html"},
	},
	{
		"DOM XSS document.write", 
		`(?i)document\.write\s*\(`, 
		nil, "MEDIUM", "A03", 
		"DOM XSS via document.write", 
		"MEDIUM", 
		[]string{".js", ".html"},
	},
	{
		"jQuery HTML Insertion", 
		`(?i)\$\(.*\)\.(?:html|append|prepend|after|before)\(`, 
		nil, "HIGH", "A03", 
		"jQuery HTML manipulation", 
		"MEDIUM", 
		[]string{".js", ".html"},
	},
	{
		"Template Injection", 
		`(?i){{\s*[^}|]+\s*}}`, 
		nil, "MEDIUM", "A03", 
		"Template content without escaping", 
		"MEDIUM", 
		[]string{".html"},
	},
	{
		"EJS Unescaped Variable", 
		`<%=\s+.*%>`, 
		nil, "MEDIUM", "A03", 
		"EJS unescaped output", 
		"MEDIUM", 
		[]string{".ejs", ".html"},
	},
	{
		"Handlebars Unescaped", 
		`{{{.*}}}`, 
		nil, "MEDIUM", "A03", 
		"Handlebars unescaped content", 
		"MEDIUM", 
		[]string{".hbs", ".html"},
	},
	{
		"Event Handler", 
		`(?i)<[^>]+\s+on(?:click|load|mouseover|change|keyup|focus)\s*=\s*["'][^"']*["']`, 
		nil, "LOW", "A03", 
		"Inline JavaScript event handler", 
		"LOW", 
		[]string{".html"},
	},

	// 🔐 A08: Software/Data Integrity Failures
	{
		"Unsafe Deserialization", 
		`(?i)(?:Marshal|Unmarshal|JSON\.parse|fromJSON|deserialize)`, 
		nil, "MEDIUM", "A08", 
		"Check data deserialization", 
		"LOW", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"Package Integrity", 
		`(?i)curl\s+[^|]+\|\s*(?:sh|bash)`, 
		nil, "HIGH", "A08", 
		"Script piped directly to shell", 
		"HIGH", 
		[]string{".sh", ".bash"},
	},
	{
		"Remote Code Download", 
		`(?i)(?:wget|curl)\s+https?://.*\.(?:sh|js|py|exe)\s+`, 
		nil, "MEDIUM", "A08", 
		"Downloading executable content", 
		"MEDIUM", 
		[]string{".sh", ".bash", ".js", ".py"},
	},

	// 📝 A09: Security Logging & Monitoring Failures (New)
	{
		"Console Error Logging", 
		`(?i)console\.(?:error|log)\((?:err|error|exception)`, 
		nil, "LOW", "A09", 
		"Error logged to console only", 
		"LOW", 
		[]string{".js"},
	},
	{
		"Exception Suppression", 
		`(?i)(?:catch\s*\(\s*\w+\s*\)\s*{}|catch\s*\{[\s\n\r]*\})`, 
		nil, "MEDIUM", "A09", 
		"Empty catch block suppresses exceptions", 
		"MEDIUM", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
	{
		"Print Stack Trace", 
		`(?i)\.printStackTrace\(\)`, 
		nil, "LOW", "A09", 
		"Exception details in response", 
		"LOW", 
		[]string{".java"},
	},

	// 🌐 A10: Server-Side Request Forgery
	{
		"Python HTTP Request", 
		`(?i)requests\.(?:get|post|put|delete|options)\(([^),]+)`, 
		nil, "MEDIUM", "A10", 
		"HTTP request with potential user input", 
		"MEDIUM", 
		[]string{".py"},
	},
	{
		"Node HTTP Request", 
		`(?i)(?:https?|axios|superagent|request)\.(?:get|post|put|delete|request)\(`, 
		nil, "MEDIUM", "A10", 
		"HTTP request with potential user input", 
		"MEDIUM", 
		[]string{".js"},
	},
	{
		"Java URL Connection", 
		`(?i)(?:URL|URI|HttpClient|HttpURLConnection)`, 
		nil, "MEDIUM", "A10", 
		"HTTP connection object", 
		"LOW", 
		[]string{".java"},
	},
	{
		"Go HTTP Client", 
		`(?i)http\.(?:Get|Post|Head|Do|NewRequest)`, 
		nil, "MEDIUM", "A10", 
		"Go HTTP client usage", 
		"MEDIUM", 
		[]string{".go"},
	},
	{
		"SSRF Protection Bypass", 
		`(?i)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|internal\.|intranet\.|file:)`, 
		nil, "LOW", "A10", 
		"Potential internal resource indicator", 
		"LOW", 
		[]string{".js", ".py", ".java", ".go", ".php"},
	},
}

// Extended list of supported file extensions
var supportedExtensions = map[string]bool{
	".go":     true,
	".js":     true,
	".ts":     true,
	".py":     true,
	".java":   true,
	".html":   true,
	".php":    true,
	".rb":     true,
	".c":      true,
	".cpp":    true,
	".cs":     true,
	".jsx":    true,
	".tsx":    true,
	".ejs":    true,
	".hbs":    true,
	".xml":    true,
	".yml":    true,
	".yaml":   true,
	".json":   true,
	".scala":  true,
	".sh":     true,
	".bash":   true,
	".conf":   true,
	".config": true,
}

// Suppression patterns for ignoring specific detections for specific files
var suppressPatterns = map[string]map[string]bool{
	"*/test/*": {
		"JavaScript Eval":    true,
		"Hardcoded Password": true,
	},
	"*/tests/*": {
		"JavaScript Eval":    true,
		"Hardcoded Password": true,
	},
	"*/spec/*": {
		"JavaScript Eval":    true,
		"Hardcoded Password": true,
	},
	"*/vendor/*": {
		"*": true, // Suppress all rules for vendor code
	},
	"*/node_modules/*": {
		"*": true, // Suppress all rules for node_modules
	},
}

// Known safe patterns to reduce false positives
var safePatterns = map[string][]string{
	"DOM XSS innerHTML": {
		`\.innerHTML\s*=\s*['"]<[^>]+>['"]\s*;`, // Static HTML
		`\.innerHTML\s*=\s*escapeHTML\(`,        // Properly escaped
	},
	"JavaScript Eval": {
		`eval\s*\(\s*['"]use strict['"]`, // Safe eval use
	},
}

// Post-match validators to reduce false positives
func isSafeMatch(rule, path, line string) bool {
	switch rule {
	case "DOM XSS innerHTML":
		return strings.Contains(line, "escapeHTML") || 
		       strings.Contains(line, "sanitize") ||
		       strings.Contains(line, "DOMPurify")
	case "JavaScript Eval":
		return strings.Contains(line, "use strict")
	case "Template Injection":
		return strings.Contains(line, "|") && (
		       strings.Contains(line, "|escape") || 
		       strings.Contains(line, "|e") || 
		       strings.Contains(line, "|safe"))
	}
	return false
}

func init() {
	// Compile all regex patterns on initialization
	for i := range rules {
		p, err := regexp.Compile(rules[i].Regex)
		if err != nil {
			log.Fatalf("Invalid regex: %s (%v)", rules[i].Name, err)
		}
		rules[i].Pattern = p
	}
}

// Gets files changed in the latest git commit
func getGitChangedFiles() ([]string, error) {
	out, err := exec.Command("git", "diff", "--name-only", "HEAD~1").Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

// Loads ignore patterns from command line flag and .scannerignore file
func loadIgnorePatterns(ignoreFlag string) ([]string, error) {
	var patterns []string
	if ignoreFlag != "" {
		patterns = append(patterns, strings.Split(ignoreFlag, ",")...)
	}
	if f, err := os.Open(".scannerignore"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				patterns = append(patterns, line)
			}
		}
	}
	return patterns, nil
}

// Checks if a file should be ignored based on patterns
func shouldIgnore(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := doublestar.PathMatch(pattern, path); matched {
			return true
		}
	}
	return false
}

// Checks if a rule finding should be suppressed for a specific file
func shouldSuppress(path string, ruleName string) bool {
	for pattern, rules := range suppressPatterns {
		if matched, _ := doublestar.PathMatch(pattern, path); matched {
			if rules["*"] || rules[ruleName] {
				return true
			}
		}
	}
	return false
}

// Gets surrounding code context for better understanding of findings
func getCodeContext(filePath string, lineNum int, contextSize int) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	
	scanner := bufio.NewScanner(f)
	
	// Collect contextSize lines before and after the target line
	var context []string
	lineCount := 0
	startLine := max(1, lineNum-contextSize)
	endLine := lineNum + contextSize
	
	for scanner.Scan() {
		lineCount++
		if lineCount >= startLine && lineCount <= endLine {
			if lineCount == lineNum {
				context = append(context, fmt.Sprintf("> %d: %s", lineCount, scanner.Text()))
			} else {
				context = append(context, fmt.Sprintf("  %d: %s", lineCount, scanner.Text()))
			}
		}
	}
	
	return strings.Join(context, "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Improved scanFile function with better context handling
func scanFile(path string, debug bool) ([]Finding, error) {
	var findings []Finding
	
	// Check file extension against rule requirements
	ext := filepath.Ext(path)
	if !supportedExtensions[ext] {
		return findings, nil
	}
	
	f, err := os.Open(path)
	if err != nil {
		return findings, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		for _, r := range rules {
			// Skip rules that don't apply to this file type
			if len(r.FileTypes) > 0 {
				matchesFileType := false
				for _, ft := range r.FileTypes {
					if ft == ext {
						matchesFileType = true
						break
					}
				}
				if !matchesFileType {
					continue
				}
			}
			
			// Check for rule suppression
			if shouldSuppress(path, r.Name) {
				continue
			}
			
			if r.Pattern.MatchString(line) {
				// Check for false positives using safe patterns
				if isSafeMatch(r.Name, path, line) {
					continue
				}
				
				// Check for false positives using safe patterns
				if safePatterns[r.Name] != nil {
					isSafe := false
					for _, safePattern := range safePatterns[r.Name] {
						safeRegex, _ := regexp.Compile(safePattern)
						if safeRegex.MatchString(line) {
							isSafe = true
							break
						}
					}
					if isSafe {
						continue
					}
				}
				
				// Extract the actual match
				match := r.Pattern.FindString(line)
				
				// Get surrounding code context for better understanding
				codeContext := getCodeContext(path, lineNum, 2)
				
				findings = append(findings, Finding{
					File:       path,
					Line:       lineNum,
					RuleName:   r.Name,
					Match:      match,
					Severity:   r.Severity,
					Category:   r.Category,
					Confidence: r.Confidence,
					Context:    codeContext,
					Timestamp:  time.Now(),
				})
			}
		}
	}
	return findings, scanner.Err()
}

// Scan an entire directory for issues
func scanDir(root string, useGit, debug bool, ignorePatterns []string) ([]Finding, error) {
	var findings []Finding
	var files []string

	if useGit {
		gf, err := getGitChangedFiles()
		if err != nil {
			return nil, err
		}
		files = gf
	} else {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && supportedExtensions[filepath.Ext(path)] {
				if !shouldIgnore(path, ignorePatterns) {
					files = append(files, path)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// Process files with limited concurrency
	for _, f := range files {
		if debug {
			fmt.Printf("Scanning: %s\n", f)
		}
		fs, err := scanFile(f, debug)
		if err == nil {
			findings = append(findings, fs...)
		} else if debug {
			fmt.Printf("Error scanning %s: %v\n", f, err)
		}
	}
	return findings, nil
}

// Summarize findings by severity and category
func summarize(findings []Finding) {
	sev := map[string]int{}
	cat := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
		cat[f.Category]++
	}
	
	fmt.Println("\n[ Severity Summary ]")
	for _, severity := range []string{"HIGH", "MEDIUM", "LOW"} {
		if count, exists := sev[severity]; exists {
			fmt.Printf("  %s: %d\n", severity, count)
		}
	}
	
	fmt.Println("\n[ OWASP Category Summary ]")
	for k, v := range cat {
		categoryName := owaspCategories[k]
		if categoryName != "" {
			fmt.Printf("  %s: %s - %d\n", k, categoryName, v)
		} else {
			fmt.Printf("  %s: %d\n", k, v)
		}
	}
}

// Generate markdown output for findings
func outputMarkdownBody(findings []Finding) string {
	var b strings.Builder
	b.WriteString("### 🔍 Static Analysis Findings\n\n")
	
	// Group findings by OWASP category
	catFindings := make(map[string][]Finding)
	for _, f := range findings {
		catFindings[f.Category] = append(catFindings[f.Category], f)
	}
	
	// Output summary
	b.WriteString("#### Summary\n\n")
	for cat, fs := range catFindings {
		catName := owaspCategories[cat]
		if catName == "" {
			catName = cat
		}
		b.WriteString(fmt.Sprintf("- **%s: %s** - %d finding(s)\n", cat, catName, len(fs)))
	}
	
	b.WriteString("\n#### Detailed Findings\n\n")
	b.WriteString("| Severity | Category | File | Line | Rule | Match |\n")
	b.WriteString("|----------|----------|------|------|------|-------|\n")
	
	// Sort findings by severity first
	highFindings := []Finding{}
	mediumFindings := []Finding{}
	lowFindings := []Finding{}
	
	for _, f := range findings {
		switch f.Severity {
		case "HIGH":
			highFindings = append(highFindings, f)
		case "MEDIUM":
			mediumFindings = append(mediumFindings, f)
		case "LOW":
			lowFindings = append(lowFindings, f)
		}
	}
	
	// Output findings in order of severity
	for _, f := range highFindings {
		b.WriteString(fmt.Sprintf("| **%s** | %s | `%s` | %d | %s | `%s` |\n", 
			f.Severity, f.Category, f.File, f.Line, f.RuleName, f.Match))
	}
	
	for _, f := range mediumFindings {
		b.WriteString(fmt.Sprintf("| **%s** | %s | `%s` | %d | %s | `%s` |\n", 
			f.Severity, f.Category, f.File, f.Line, f.RuleName, f.Match))
	}
	
	for _, f := range lowFindings {
		b.WriteString(fmt.Sprintf("| **%s** | %s | `%s` | %d | %s | `%s` |\n", 
			f.Severity, f.Category, f.File, f.Line, f.RuleName, f.Match))
	}
	
	return b.String()
}

// Load baseline findings from a previous scan
func loadBaseline(path string) ([]Finding, error) {
	var baseline []Finding
	
	data, err := os.ReadFile(path)
	if err != nil {
		return baseline, err
	}
	
	err = json.Unmarshal(data, &baseline)
	if err != nil {
		return baseline, err
	}
	
	return baseline, nil
}

// Compare current findings with baseline to show only new issues
func compareWithBaseline(current []Finding, baseline []Finding) []Finding {
	// Create a map of baseline findings for easy lookup
	baselineMap := make(map[string]bool)
	for _, f := range baseline {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.RuleName)
		baselineMap[key] = true
	}
	
	// Filter out findings that already exist in baseline
	var newFindings []Finding
	for _, f := range current {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.RuleName)
		if !baselineMap[key] {
			newFindings = append(newFindings, f)
		}
	}
	
	return newFindings
}

// Post results as a comment on GitHub PR
func postGitHubComment(body string) error {
	repo := os.Getenv("GITHUB_REPOSITORY")
	pr := os.Getenv("GITHUB_PR_NUMBER")
	token := os.Getenv("GITHUB_TOKEN")

	if repo == "" || pr == "" || token == "" {
		return fmt.Errorf("GitHub environment variables not set")
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%s/comments", repo, pr)
	payload := map[string]string{"body": body}
	data, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 201 {
		return fmt.Errorf("GitHub comment failed with status %d", resp.StatusCode)
	}
	return nil
}

func main() {
	dir := flag.String("dir", ".", "Directory to scan")
	output := flag.String("output", "text", "Output: text/json/markdown")
	debug := flag.Bool("debug", false, "Debug mode")
	useGit := flag.Bool("git-diff", false, "Scan changed files only")
	exitHigh := flag.Bool("exit-high", false, "Exit 1 if HIGH finding")
	exitNonZero := flag.Bool("exit-nonzero", false, "Exit 1 if any finding")
	ignoreFlag := flag.String("ignore", "vendor,node_modules,dist,public,build", "Ignore patterns")
	postToGitHub := flag.Bool("github-pr", false, "Post results to GitHub PR")
	minSeverity := flag.String("min-severity", "LOW", "Minimum severity to report (LOW, MEDIUM, HIGH)")
	contextLines := flag.Int("context", 2, "Number of context lines to show")
	category := flag.String("category", "", "Filter by OWASP category (A01-A10)")
	baselinePath := flag.String("baseline", "", "Path to baseline file for comparing results")
	outputBaseline := flag.String("save-baseline", "", "Save results as baseline to specified file")
	flag.Parse()

	fmt.Println("🔍 OWASP Security Scanner")
	fmt.Println("=========================")
	fmt.Printf("Scanning directory: %s\n", *dir)

	ignorePatterns, _ := loadIgnorePatterns(*ignoreFlag)
	findings, err := scanDir(*dir, *useGit, *debug, ignorePatterns)
	if err != nil {
		log.Fatalf("❌ Scan error: %v", err)
	}

	// Filter findings by minimum severity
	var filteredFindings []Finding
	for _, f := range findings {
		include := true
		
		// Filter by severity
		if *minSeverity == "HIGH" && f.Severity != "HIGH" {
			include = false
		} else if *minSeverity == "MEDIUM" && f.Severity != "HIGH" && f.Severity != "MEDIUM" {
			include = false
		}
		
		// Filter by category if specified
		if *category != "" && f.Category != *category {
			include = false
		}
		
		if include {
			filteredFindings = append(filteredFindings, f)
		}
	}
	findings = filteredFindings

	// Compare with baseline if provided
	if *baselinePath != "" {
		baselineFindings, err := loadBaseline(*baselinePath)
		if err != nil {
			log.Printf("Warning: Could not load baseline: %v", err)
		} else {
			findings = compareWithBaseline(findings, baselineFindings)
			fmt.Printf("✅ Compared findings with baseline from %s\n", *baselinePath)
		}
	}

	if len(findings) == 0 {
		fmt.Println("✅ No issues found.")
		return
	}

	// Output findings summary
	summarize(findings)

	// Handle different output formats
	switch *output {
	case "text":
		fmt.Println("\n[ Detailed Findings ]")
		for _, f := range findings {
			fmt.Printf("[%s] %s:%d – %s (%s)\n", f.Severity, f.File, f.Line, f.RuleName, f.Match)
			if *contextLines > 0 {
				fmt.Println(f.Context)
				fmt.Println("---")
			}
		}
	case "json":
		data, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(data))
	case "markdown":
		body := outputMarkdownBody(findings)
		fmt.Println(body)
		if *postToGitHub {
			if err := postGitHubComment(body); err != nil {
				log.Printf("GitHub comment failed: %v", err)
			} else {
				fmt.Println("✅ Comment posted to PR.")
			}
		}
	default:
		log.Fatalf("Unsupported output: %s", *output)
	}

	// Save baseline if requested
	if *outputBaseline != "" {
		data, _ := json.MarshalIndent(findings, "", "  ")
		err := os.WriteFile(*outputBaseline, data, 0644)
		if err != nil {
			log.Printf("Error saving baseline: %v", err)
		} else {
			fmt.Printf("✅ Baseline saved to %s\n", *outputBaseline)
		}
	}

	// Exit with appropriate code based on findings
	if *exitHigh {
		for _, f := range findings {
			if f.Severity == "HIGH" {
				fmt.Println("❌ Exiting with code 1 due to HIGH severity findings")
				os.Exit(1)
			}
		}
	} else if *exitNonZero && len(findings) > 0 {
		fmt.Println("❌ Exiting with code 1 due to findings")
		os.Exit(1)
	}
}
