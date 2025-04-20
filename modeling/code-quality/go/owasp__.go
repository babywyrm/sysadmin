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

// Finding structure
type Finding struct {
	File      string    `json:"file"`
	Line      int       `json:"line"`
	RuleName  string    `json:"rule_name"`
	Match     string    `json:"match"`
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	Timestamp time.Time `json:"timestamp"`
}

// Rule with OWASP mapping
type Rule struct {
	Name        string
	Regex       string
	Pattern     *regexp.Regexp
	Severity    string
	Category    string
	Description string
}

var rules = []Rule{
	// A01: Broken Access Control
	{"Go FormValue", `(?i)r\.FormValue\(`, nil, "HIGH", "A01", "Go input"},
	{"Java getParameter", `(?i)request\.getParameter\(`, nil, "HIGH", "A01", "Java input"},
	{"Node req.query/body", `(?i)(req\.body|req\.query)\s*[\.\[]`, nil, "HIGH", "A01", "Node.js input"},
	{"Flask Input", `(?i)(request\.args|getattr\(request, )`, nil, "HIGH", "A01", "Flask input"},

	// A02: Cryptographic Failures
	{"Hardcoded Password", `(?i)password\s*=\s*["'][^"']+["']`, nil, "HIGH", "A02", "Password in code"},
	{"API Key", `(?i)(api[_-]?key|secret)\s*=\s*["'][^"']+["']`, nil, "HIGH", "A02", "Hardcoded API key"},
	{"JWT Secret", `(?i)(jwt.*secret|signingkey)\s*=\s*["'][^"']+["']`, nil, "HIGH", "A02", "Hardcoded JWT"},
	{"MD5", `(?i)md5\s*\(`, nil, "MEDIUM", "A02", "Weak MD5 hash"},
	{"SHA1", `(?i)sha1\s*\(`, nil, "MEDIUM", "A02", "Weak SHA1 hash"},

	// A03: Injection
	{"Eval Usage", `(?i)eval\s*\(`, nil, "MEDIUM", "A03", "Eval detected"},
	{"Command Exec", `(?i)(system|exec)\s*\(`, nil, "HIGH", "A03", "Command injection risk"},

	// A05: Misconfiguration
	{"TLS SkipVerify", `(?i)InsecureSkipVerify\s*:\s*true`, nil, "HIGH", "A05", "TLS validation off"},
	{"Flask Debug", `(?i)app\.run\(.*debug\s*=\s*True`, nil, "MEDIUM", "A05", "Flask debug mode"},

	// A06: Vulnerable Components
	{"Old jQuery", `jquery-1\.(3|4|5|6|7|8|9)`, nil, "HIGH", "A06", "Old jQuery library"},
	{"Known Vuln Lib", `(?i)(flask==0\.10|lodash@3)`, nil, "HIGH", "A06", "Known vulnerable version"},

	// A07: Cross-Site Scripting
	{"Raw Jinja2", `(?i){{\s*[^}]+\s*}}`, nil, "HIGH", "A07", "Unescaped template"},
	{"innerHTML", `(?i)\.innerHTML\s*=`, nil, "HIGH", "A07", "DOM XSS"},
	{"document.write", `(?i)document\.write\s*\(`, nil, "MEDIUM", "A07", "DOM XSS sink"},
	{"jQuery .html()", `(?i)\$\(.+\)\.html\(`, nil, "HIGH", "A07", "jQuery XSS sink"},
	{"Inline JS Handler", `(?i)on\w+\s*=\s*["'].*["']`, nil, "MEDIUM", "A07", "Inline JS handlers"},

	// A08: Software/Data Integrity
	{"Go: exec w/ download", `(?i)http\.Get.*\|\s*exec\.Command`, nil, "HIGH", "A08", "Remote code exec from download"},
	{"Shell curl + sh", `curl.*\|\s*sh`, nil, "HIGH", "A08", "Downloading + executing code"},

	// A10: SSRF
	{"Python SSRF", `requests\.get\([^)]+\)`, nil, "HIGH", "A10", "Unvalidated remote fetch"},
	{"Go SSRF", `http\.Get\([^)]+\)`, nil, "HIGH", "A10", "Unvalidated http.Get"},
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
			log.Fatalf("Regex error in %s: %v", r.Name, err)
		}
		rules[i].Pattern = re
	}
}

func getGitFiles() ([]string, error) {
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
		gf, err := getGitFiles()
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

func interactiveMode(findings []Finding) {
	reader := bufio.NewReader(os.Stdin)
	for i, f := range findings {
		fmt.Printf("\n[%d/%d] %s:%d\n", i+1, len(findings), f.File, f.Line)
		fmt.Printf("  Rule    : %s\n", f.RuleName)
		fmt.Printf("  Match   : %s\n", f.Match)
		fmt.Printf("  Severity: %s\n", f.Severity)
		fmt.Printf("  OWASP   : %s\n", f.Category)
		fmt.Printf("  Time    : %s\n", f.Timestamp.Format(time.RFC3339))
		fmt.Print("Press Enter to continue, or 'q' to quit: ")
		in, _ := reader.ReadString('\n')
		if strings.TrimSpace(in) == "q" {
			break
		}
	}
}

func main() {
	dir := flag.String("dir", ".", "Directory to scan")
	output := flag.String("output", "text", "Output format: text or json")
	debug := flag.Bool("debug", false, "Debug mode")
	useGit := flag.Bool("git-diff", false, "Scan git diff only")
	exitHigh := flag.Bool("exit-high", false, "Exit 1 if any HIGH severity issue")
	interactive := flag.Bool("interactive", false, "Interactive review mode")
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

	if *interactive {
		interactiveMode(findings)
		return
	}

	switch *output {
	case "text":
		for _, f := range findings {
			fmt.Printf("[%s] %s:%d – %s (%s)\n", f.Severity, f.File, f.Line, f.RuleName, f.Match)
		}
	case "json":
		data, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(data))
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

