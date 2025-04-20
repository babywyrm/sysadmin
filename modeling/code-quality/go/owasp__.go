package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Finding represents a rule match
type Finding struct {
	File      string    `json:"file"`
	Line      int       `json:"line"`
	RuleName  string    `json:"rule_name"`
	Match     string    `json:"match"`
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	Timestamp time.Time `json:"timestamp"`
}

// Rule defines a scanning rule with OWASP category
type Rule struct {
	Name        string
	Regex       string
	Pattern     *regexp.Regexp
	Severity    string
	Category    string // OWASP category (e.g. A01, A03)
	Description string
}

var rules = []Rule{
	// A01: Broken Access Control
	{"Go FormValue", `(?i)r\.FormValue\(`, nil, "HIGH", "A01", "Go user input"},
	{"Java getParameter", `(?i)request\.getParameter\(`, nil, "HIGH", "A01", "Java user input"},
	{"Node req.body/query", `(?i)(req\.body|req\.query)\s*[\.\[]`, nil, "HIGH", "A01", "Node user input"},
	{"Flask request.args", `(?i)(request\.args|getattr\(request, )`, nil, "HIGH", "A01", "Python web input"},

	// A02: Cryptographic Failures
	{"Hardcoded Password", `(?i)password\s*=\s*["'][^"']+["']`, nil, "HIGH", "A02", "Hardcoded password"},
	{"Hardcoded API Key", `(?i)(api[_-]?key|secret)\s*=\s*["'][^"']+["']`, nil, "HIGH", "A02", "Hardcoded key/secret"},
	{"JWT Secret", `(?i)(jwt.*secret|signingkey)\s*=\s*["'][^"']+["']`, nil, "HIGH", "A02", "Hardcoded JWT secret"},
	{"MD5 Usage", `(?i)md5\s*\(`, nil, "MEDIUM", "A02", "Weak MD5 hash"},
	{"SHA1 Usage", `(?i)sha1\s*\(`, nil, "MEDIUM", "A02", "Weak SHA1 hash"},

	// A03: Injection
	{"Eval Usage", `(?i)eval\s*\(`, nil, "MEDIUM", "A03", "Dynamic code execution"},
	{"Command Injection", `(?i)(system|exec)\s*\(`, nil, "HIGH", "A03", "Potential command execution"},

	// A05: Security Misconfiguration
	{"TLS SkipVerify", `(?i)InsecureSkipVerify\s*:\s*true`, nil, "HIGH", "A05", "TLS cert validation skipped"},
	{"Flask Debug", `(?i)app\.run\(.*debug\s*=\s*True`, nil, "MEDIUM", "A05", "Flask debug mode"},

	// A07: Cross-Site Scripting (XSS)
	{"Raw Jinja2 Output", `(?i){{\s*[^}]+\s*}}`, nil, "HIGH", "A07", "Unsanitized template output"},
	{"innerHTML", `(?i)\.innerHTML\s*=`, nil, "HIGH", "A07", "DOM XSS via innerHTML"},
	{"document.write", `(?i)document\.write\s*\(`, nil, "MEDIUM", "A07", "DOM XSS via document.write"},
	{"jQuery.html()", `(?i)\$\(.+\)\.html\(`, nil, "HIGH", "A07", "XSS sink via jQuery.html"},
	{"Inline JS Handler", `(?i)on\w+\s*=\s*["'].*["']`, nil, "MEDIUM", "A07", "Inline JS event handlers"},
}

var supportedExtensions = map[string]bool{
	".go":   true,
	".js":   true,
	".py":   true,
	".java": true,
	".html": true,
}

func init() {
	for i, r := range rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			log.Fatalf("Failed to compile regex for rule %s: %v", r.Name, err)
		}
		rules[i].Pattern = re
	}
}

func getGitChangedFiles() ([]string, error) {
	out, err := exec.Command("git", "diff", "--name-only", "HEAD~1").Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func scanFile(path string, debug bool) ([]Finding, error) {
	var findings []Finding

	file, err := os.Open(path)
	if err != nil {
		return findings, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, r := range rules {
			if r.Pattern.MatchString(line) {
				findings = append(findings, Finding{
					File:      path,
					Line:      lineNum,
					RuleName:  r.Name,
					Match:     r.Pattern.FindString(line),
					Severity:  r.Severity,
					Category:  r.Category,
					Timestamp: time.Now(),
				})
			}
		}
	}
	return findings, scanner.Err()
}

func scanDir(root string, useGit, debug bool) ([]Finding, error) {
	var findings []Finding
	var files []string

	if useGit {
		gf, err := getGitChangedFiles()
		if err != nil {
			return nil, err
		}
		files = gf
	} else {
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if !d.IsDir() && supportedExtensions[filepath.Ext(path)] {
				files = append(files, path)
			}
			return nil
		})
	}

	for _, f := range files {
		if supportedExtensions[filepath.Ext(f)] {
			fs, err := scanFile(f, debug)
			if err == nil {
				findings = append(findings, fs...)
			}
		}
	}
	return findings, nil
}

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

func main() {
	dir := flag.String("dir", ".", "Directory to scan")
	output := flag.String("output", "text", "Output format: text or json")
	debug := flag.Bool("debug", false, "Enable debug output")
	useGit := flag.Bool("git-diff", false, "Only scan changed files")
	exitHigh := flag.Bool("exit-high", false, "Exit 1 if any HIGH severity issue found")
	flag.Parse()

	findings, err := scanDir(*dir, *useGit, *debug)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
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
		out, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(out))
	default:
		log.Fatalf("Unsupported output format: %s", *output)
	}

	if *exitHigh {
		for _, f := range findings {
			if f.Severity == "HIGH" {
				os.Exit(1)
			}
		}
	}
}

