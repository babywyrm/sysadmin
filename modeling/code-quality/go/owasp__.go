package main

import (
	"bufio"
	"bytes"
	"context"
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

// OWASP category constants for clarity and consistency
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

// Finding represents a single security finding in a file.
type Finding struct {
	File      string    `json:"file"`
	Line      int       `json:"line"`
	RuleName  string    `json:"rule_name"`
	Match     string    `json:"match"`
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	Timestamp time.Time `json:"timestamp"`
}

// Rule defines a scanning rule with regex and metadata.
type Rule struct {
	Name        string
	Regex       string
	Pattern     *regexp.Regexp
	Severity    string
	Category    string
	Description string
}

// OWASP-related rules grouped clearly for readability and easy extension
var rules = []Rule{
	// 🛡️ A01: Broken Access Control
	{"Go FormValue", `(?i)r\.FormValue\(`, nil, "HIGH", OWASP_A01, "Go input"},
	{"Java getParameter", `(?i)request\.getParameter\(`, nil, "HIGH", OWASP_A01, "Java input"},
	{"Node req.query/body", `(?i)(req\.body|req\.query)\s*[\.\[]`, nil, "HIGH", OWASP_A01, "Node.js input"},
	{"Flask Input", `(?i)(request\.args|getattr\(request, )`, nil, "HIGH", OWASP_A01, "Flask input"},

	// 🧊 A02: Cryptographic Failures
	{"Hardcoded Password", `(?i)password\s*=\s*["'][^"']+["']`, nil, "HIGH", OWASP_A02, "Password in code"},
	{"API Key", `(?i)(api[_-]?key|secret)\s*=\s*["'][^"']+["']`, nil, "HIGH", OWASP_A02, "Hardcoded API key"},
	{"JWT Secret", `(?i)(jwt.*secret|signingkey)\s*=\s*["'][^"']+["']`, nil, "HIGH", OWASP_A02, "Hardcoded JWT"},
	{"MD5", `(?i)md5\s*\(`, nil, "MEDIUM", OWASP_A02, "Weak MD5 hash"},
	{"SHA1", `(?i)sha1\s*\(`, nil, "MEDIUM", OWASP_A02, "Weak SHA1 hash"},

	// 💥 A03: Injection
	{"Eval Usage", `(?i)eval\s*\(`, nil, "MEDIUM", OWASP_A03, "Eval detected"},
	{"Command Exec", `(?i)(system|exec)\s*\(`, nil, "HIGH", OWASP_A03, "Command injection risk"},

	// 🔧 A05: Security Misconfiguration
	{"TLS SkipVerify", `(?i)InsecureSkipVerify\s*:\s*true`, nil, "HIGH", OWASP_A05, "TLS validation off"},
	{"Flask Debug", `(?i)app\.run\(.*debug\s*=\s*True`, nil, "MEDIUM", OWASP_A05, "Flask debug mode"},

	// 🧪 A06: Vulnerable & Outdated Components
	{"Old jQuery", `jquery-1\.(3|4|5|6|7|8|9)`, nil, "HIGH", OWASP_A06, "Old jQuery library"},
	{"Known Vuln Lib", `(?i)(flask==0\.10|lodash@3)`, nil, "HIGH", OWASP_A06, "Known vulnerable version"},

	// 🧬 A07: Cross-Site Scripting (XSS)
	{"Raw Jinja2", `(?i){{\s*[^}]+\s*}}`, nil, "HIGH", OWASP_A07, "Unescaped template"},
	{"innerHTML", `(?i)\.innerHTML\s*=`, nil, "HIGH", OWASP_A07, "DOM XSS"},
	{"document.write", `(?i)document\.write\s*\(`, nil, "MEDIUM", OWASP_A07, "DOM XSS sink"},
	{"jQuery .html()", `(?i)\$\(.+\)\.html\(`, nil, "HIGH", OWASP_A07, "jQuery XSS sink"},
	{"Inline JS Handler", `(?i)on\w+\s*=\s*["'].*["']`, nil, "MEDIUM", OWASP_A07, "Inline JS handlers"},

	// 🔐 A08: Software/Data Integrity Failures
	{"Go: exec w/ download", `(?i)http\.Get.*\|\s*exec\.Command`, nil, "HIGH", OWASP_A08, "Remote code exec from download"},
	{"Shell curl + sh", `curl.*\|\s*sh`, nil, "HIGH", OWASP_A08, "Downloading + executing code"},

	// 🌐 A10: SSRF
	{"Python SSRF", `requests\.get\([^)]+\)`, nil, "HIGH", OWASP_A10, "Unvalidated remote fetch"},
	{"Go SSRF", `http\.Get\([^)]+\)`, nil, "HIGH", OWASP_A10, "Unvalidated http.Get"},
}

// Supported file extensions for scanning
var supportedExtensions = map[string]bool{
	".go":   true,
	".js":   true,
	".py":   true,
	".java": true,
	".html": true,
}

func init() {
	for i := range rules {
		p, err := regexp.Compile(rules[i].Regex)
		if err != nil {
			log.Fatalf("Invalid regex for rule %q: %v", rules[i].Name, err)
		}
		rules[i].Pattern = p
	}
}

// runCommand runs a command with context and returns output or error.
func runCommand(ctx context.Context, cmd string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, cmd, args...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// getGitChangedFiles returns list of files changed in last commit.
func getGitChangedFiles(ctx context.Context) ([]string, error) {
	out, err := runCommand(ctx, "git", "diff", "--name-only", "HEAD~1")
	if err != nil {
		return nil, fmt.Errorf("git diff failed: %w", err)
	}
	files := strings.Split(strings.TrimSpace(out), "\n")
	return files, nil
}

// loadIgnorePatterns loads ignore patterns from flag and .scannerignore file.
func loadIgnorePatterns(ignoreFlag string) ([]string, error) {
	var patterns []string
	if ignoreFlag != "" {
		patterns = append(patterns, strings.Split(ignoreFlag, ",")...)
	}
	f, err := os.Open(".scannerignore")
	if err != nil {
		if os.IsNotExist(err) {
			return patterns, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, scanner.Err()
}

// shouldIgnore checks if path matches any ignore pattern.
func shouldIgnore(path string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, _ := doublestar.PathMatch(pattern, path)
		if matched {
			return true
		}
	}
	return false
}

// scanFile scans a single file for all rules and returns findings.
func scanFile(path string, debug bool) ([]Finding, error) {
	if debug {
		log.Printf("Scanning file: %s", path)
	}
	var findings []Finding
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
			if r.Pattern.MatchString(line) {
				fullMatch := r.Pattern.FindString(line)
				maxLen := 80
				if len(fullMatch) > maxLen {
					fullMatch = fullMatch[:maxLen] + "..."
				}
				findings = append(findings, Finding{
					File:      path,
					Line:      lineNum,
					RuleName:  r.Name,
					Match:     fullMatch,
					Severity:  r.Severity,
					Category:  r.Category,
					Timestamp: time.Now(),
				})
			}
		}
	}
	return findings, scanner.Err()
}

// scanDir scans files in a directory or git diff files.
func scanDir(ctx context.Context, root string, useGit, debug bool, ignorePatterns []string) ([]Finding, error) {
	if debug {
		log.Printf("Starting scan in directory: %s, useGit: %v", root, useGit)
	}
	var findings []Finding
	var files []string
	var err error

	if useGit {
		files, err = getGitChangedFiles(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && supportedExtensions[filepath.Ext(path)] && !shouldIgnore(path, ignorePatterns) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	for _, f := range files {
		fs, err := scanFile(f, debug)
		if err == nil {
			findings = append(findings, fs...)
		} else {
			log.Printf("Warning: failed to scan %s: %v", f, err)
		}
	}
	return findings, nil
}

// summarize prints a summary of findings by severity and category.
func summarize(findings []Finding) {
	sev := map[string]int{}
	cat := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
		cat[f.Category]++
	}
	fmt.Println("\n[ Severity Summary ]")
	for k, v := range sev {
		fmt.Printf("  %s: %d\n", k, v)
	}
	fmt.Println("\n[ OWASP Category Summary ]")
	for k, v := range cat {
		fmt.Printf("  %s: %d\n", k, v)
	}
}

// outputMarkdownBody formats findings as a markdown table.
func outputMarkdownBody(findings []Finding) string {
	var b strings.Builder
	b.WriteString("### 🔍 Static Analysis Findings\n\n")
	b.WriteString("| File | Line | Rule | Match | Severity | OWASP |\n")
	b.WriteString("|------|------|------|-------|----------|-------|\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("| `%s` | %d | %s | `%s` | **%s** | %s |\n",
			f.File, f.Line, f.RuleName, f.Match, f.Severity, f.Category))
	}
	return b.String()
}

// postGitHubComment posts the markdown body as a comment on a GitHub PR.
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
	ctx := context.Background()

	dir := flag.String("dir", ".", "Directory to scan")
	output := flag.String("output", "text", "Output: text/json/markdown")
	debug := flag.Bool("debug", false, "Debug mode")
	useGit := flag.Bool("git-diff", false, "Scan changed files only")
	exitHigh := flag.Bool("exit-high", false, "Exit 1 if HIGH finding")
	ignoreFlag := flag.String("ignore", "vendor,node_modules,dist,public,build", "Ignore patterns")
	postToGitHub := flag.Bool("github-pr", false, "Post results to GitHub PR")
	flag.Parse()

	if *debug {
		log.Println("Debug mode enabled")
	}

	ignorePatterns, err := loadIgnorePatterns(*ignoreFlag)
	if err != nil {
		log.Fatalf("Failed to load ignore patterns: %v", err)
	}

	findings, err := scanDir(ctx, *dir, *useGit, *debug, ignorePatterns)
	if err != nil {
		log.Fatalf("Scan error: %v", err)
	}

	if len(findings) == 0 {
		fmt.Println("✅ No issues found.")
		return
	}

	summarize(findings)

	switch *output {
	case "text":
		for _, f := range findings {
			fmt.Printf("[%s] %s:%d – %s (%s)\n", f.Severity, f.File, f.Line, f.RuleName, f.Match)
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

	if *exitHigh {
		for _, f := range findings {
			if f.Severity == "HIGH" {
				os.Exit(1)
			}
		}
	}
}
