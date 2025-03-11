package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Finding represents a detected issue in the source code.
type Finding struct {
	File      string    `json:"file"`
	Line      int       `json:"line"`
	RuleName  string    `json:"rule_name"`
	Match     string    `json:"match"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}

// Rule defines a code scanning rule.
type Rule struct {
	Name        string
	Regex       string
	Pattern     *regexp.Regexp
	Severity    string
	Description string
}

// Define rules targeting common code flaws, including input validation issues.
// The new rules below are intended to flag places where user input is handled
// without obvious sanitization.
var rules = []Rule{
	{
		Name:        "Hardcoded Password",
		Regex:       `(?i)password\s*=\s*["'][^"']+["']`,
		Severity:    "HIGH",
		Description: "Detects hardcoded passwords in code.",
	},
	{
		Name:        "Hardcoded API Key",
		Regex:       `(?i)(api[_-]?key|secret)\s*=\s*["'][^"']+["']`,
		Severity:    "HIGH",
		Description: "Detects hardcoded API keys or secrets.",
	},
	{
		Name:        "Insecure Eval",
		Regex:       `(?i)eval\s*\(`,
		Severity:    "MEDIUM",
		Description: "Detects usage of eval, which may lead to code injection.",
	},
	{
		Name:        "Unsafe innerHTML",
		Regex:       `(?i)\.innerHTML\s*=`,
		Severity:    "MEDIUM",
		Description: "Detects assignment to innerHTML without sanitization.",
	},
	{
		Name:        "Weak Hashing Function (MD5)",
		Regex:       `(?i)md5\s*\(`,
		Severity:    "MEDIUM",
		Description: "Detects usage of MD5 for hashing, which is considered weak.",
	},
	{
		Name:        "Weak Hashing Function (SHA1)",
		Regex:       `(?i)sha1\s*\(`,
		Severity:    "MEDIUM",
		Description: "Detects usage of SHA1 for hashing, which is considered weak.",
	},
	{
		Name:        "Insecure Deserialization (Python Pickle)",
		Regex:       `(?i)pickle\.loads\s*\(`,
		Severity:    "HIGH",
		Description: "Detects usage of pickle.loads without safeguards in Python.",
	},
	{
		Name:        "Command Injection Risk",
		Regex:       `(?i)(system|exec)\s*\(`,
		Severity:    "HIGH",
		Description: "Detects potential command injection via system/exec calls.",
	},
	// New rules focusing on input validation issues:
	{
		Name:        "Unvalidated Request Parameter in Java",
		Regex:       `(?i)request\.getParameter\(`,
		Severity:    "HIGH",
		Description: "Detects retrieval of request parameters in Java. Look for missing sanitization.",
	},
	{
		Name:        "Unvalidated Request Data in Node.js",
		Regex:       `(?i)(req\.body|req\.query)\s*[\.\[]`,
		Severity:    "HIGH",
		Description: "Detects usage of request data in Node.js. Ensure input is validated and sanitized.",
	},
	{
		Name:        "Unvalidated Input in Python Web Apps",
		Regex:       `(?i)(request\.args|getattr\(request, )`,
		Severity:    "HIGH",
		Description: "Detects retrieval of input in Python web frameworks (e.g., Flask) without clear sanitization.",
	},
	{
		Name:        "Direct Use of User Input in Go",
		Regex:       `(?i)r\.FormValue\(`,
		Severity:    "HIGH",
		Description: "Detects usage of r.FormValue() in Go's net/http without further sanitization.",
	},
}

var supportedExtensions = map[string]bool{
	".go":   true,
	".js":   true,
	".py":   true,
	".java": true,
	".html": true, // to catch innerHTML assignments in web templates
}

func init() {
	// Compile regex patterns for each rule.
	for i, r := range rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			log.Fatalf("Error compiling regex for rule '%s': %v", r.Name, err)
		}
		rules[i].Pattern = re
	}
}

// sanitizeString escapes HTML special characters if sanitization is enabled.
func sanitizeString(s string, sanitize bool) string {
	if sanitize {
		return html.EscapeString(s)
	}
	return s
}

// validateDirectory checks that the given path exists and is a directory.
func validateDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("error accessing directory %s: %v", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

// validateOutputFormat ensures the output format is one of the allowed values.
func validateOutputFormat(fmtStr string) error {
	switch fmtStr {
	case "text", "csv", "json":
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", fmtStr)
	}
}

// scanFile opens and scans a file line-by-line for rule violations.
func scanFile(filePath string, verbose, debug bool) ([]Finding, error) {
	var findings []Finding

	file, err := os.Open(filePath)
	if err != nil {
		return findings, err
	}
	defer file.Close()

	if verbose {
		log.Printf("Scanning file: %s", filePath)
	}

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for _, rule := range rules {
			if rule.Pattern.MatchString(line) {
				match := rule.Pattern.FindString(line)
				if debug {
					log.Printf("[DEBUG] %s:%d: Rule '%s' matched: %s", filePath, lineNumber, rule.Name, match)
				}
				finding := Finding{
					File:      filePath,
					Line:      lineNumber,
					RuleName:  rule.Name,
					Match:     match,
					Severity:  rule.Severity,
					Timestamp: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return findings, err
	}
	return findings, nil
}

// scanDirectory walks the specified directory recursively, scanning files.
func scanDirectory(root string, verbose, debug bool, ignoreDirs []string) ([]Finding, error) {
	var allFindings []Finding
	ignoreMap := make(map[string]bool)
	for _, dir := range ignoreDirs {
		ignoreMap[dir] = true
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Printf("Warning: skipping %q due to error: %v", path, err)
			return nil // Skip this path and continue.
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if ignoreMap[base] {
				if verbose {
					log.Printf("Skipping directory: %s", path)
				}
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if supportedExtensions[ext] {
			f, err := scanFile(path, verbose, debug)
			if err != nil {
				log.Printf("Error scanning file %s: %v", path, err)
			} else {
				allFindings = append(allFindings, f...)
			}
		}
		return nil
	})
	return allFindings, err
}

// outputText prints findings in plain text.
func outputText(findings []Finding, sanitize bool) {
	for _, f := range findings {
		fmt.Printf("%s:%d: [%s] %s (Severity: %s)\n",
			sanitizeString(f.File, sanitize),
			f.Line,
			sanitizeString(f.RuleName, sanitize),
			sanitizeString(f.Match, sanitize),
			sanitizeString(f.Severity, sanitize))
	}
}

// outputCSV writes findings as CSV.
func outputCSV(findings []Finding, filename string, sanitize bool) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"File", "Line", "Rule", "Match", "Severity", "Timestamp"}
	if err := writer.Write(headers); err != nil {
		return err
	}
	for _, f := range findings {
		row := []string{
			sanitizeString(f.File, sanitize),
			fmt.Sprintf("%d", f.Line),
			sanitizeString(f.RuleName, sanitize),
			sanitizeString(f.Match, sanitize),
			sanitizeString(f.Severity, sanitize),
			f.Timestamp.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// outputJSON writes findings as a JSON array.
func outputJSON(findings []Finding, filename string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func main() {
	// Command-line flags
	dirPtr := flag.String("dir", ".", "Directory to scan")
	outputPtr := flag.String("output", "text", "Output format: text, json, csv")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output")
	debugPtr := flag.Bool("debug", false, "Enable debug mode with detailed logging")
	ignorePtr := flag.String("ignore", ".git,.Trash,vendor,node_modules", "Comma-separated list of directories to ignore")
	sanitizePtr := flag.Bool("sanitize", false, "Sanitize output to prevent XSS when embedding in HTML")
	flag.Parse()

	// Validate directory.
	if err := validateDirectory(*dirPtr); err != nil {
		log.Fatalf("Invalid directory: %v", err)
	}
	// Validate output format.
	if err := validateOutputFormat(*outputPtr); err != nil {
		log.Fatalf("Output format error: %v", err)
	}

	ignoreDirs := strings.Split(*ignorePtr, ",")

	findings, err := scanDirectory(*dirPtr, *verbosePtr, *debugPtr, ignoreDirs)
	if err != nil {
		log.Fatalf("Error scanning directory: %v", err)
	}

	switch *outputPtr {
	case "text":
		outputText(findings, *sanitizePtr)
	case "csv":
		filename := fmt.Sprintf("findings_%d.csv", time.Now().Unix())
		if err := outputCSV(findings, filename, *sanitizePtr); err != nil {
			log.Fatalf("Error writing CSV output: %v", err)
		}
		fmt.Printf("Findings written to %s\n", filename)
	case "json":
		filename := fmt.Sprintf("findings_%d.json", time.Now().Unix())
		if err := outputJSON(findings, filename); err != nil {
			log.Fatalf("Error writing JSON output: %v", err)
		}
		fmt.Printf("Findings written to %s\n", filename)
	default:
		fmt.Println("Unknown output format. Options: text, json, csv")
	}
}

// go run scanner.go -dir ./your-target-repo -output text -verbose -debug -sanitize
// go run scanner.go -dir ./your-target-repo -output csv -sanitize
// go run scanner.go -dir ./your-target-repo -output json
