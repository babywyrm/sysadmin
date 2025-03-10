package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
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

// Define rules targeting common code flaws (OWASP Top Ten themes).
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
	// You can add more rules as needed.
}

// Supported file extensions for scanning.
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

func scanDirectory(root string, verbose, debug bool) ([]Finding, error) {
	var allFindings []Finding

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Printf("Warning: skipping %q due to error: %v", path, err)
			return nil // Skip path and continue
		}
		if !d.IsDir() {
			ext := filepath.Ext(path)
			if supportedExtensions[ext] {
				f, err := scanFile(path, verbose, debug)
				if err != nil {
					log.Printf("Error scanning file %s: %v", path, err)
				} else {
					allFindings = append(allFindings, f...)
				}
			}
		}
		return nil
	})
	return allFindings, err
}

func outputText(findings []Finding) {
	for _, f := range findings {
		fmt.Printf("%s:%d: [%s] %s (Severity: %s)\n", f.File, f.Line, f.RuleName, f.Match, f.Severity)
	}
}

func outputCSV(findings []Finding, filename string) error {
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
			f.File,
			fmt.Sprintf("%d", f.Line),
			f.RuleName,
			f.Match,
			f.Severity,
			f.Timestamp.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func outputJSON(findings []Finding, filename string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func main() {
	dirPtr := flag.String("dir", ".", "Directory to scan")
	outputPtr := flag.String("output", "text", "Output format: text, json, csv")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output")
	debugPtr := flag.Bool("debug", false, "Enable debug mode for detailed logging")
	flag.Parse()

	findings, err := scanDirectory(*dirPtr, *verbosePtr, *debugPtr)
	if err != nil {
		log.Fatalf("Error scanning directory: %v", err)
	}

	switch *outputPtr {
	case "text":
		outputText(findings)
	case "csv":
		filename := fmt.Sprintf("findings_%d.csv", time.Now().Unix())
		if err := outputCSV(findings, filename); err != nil {
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

// go run scanner.go -dir ./your-source-code -output text
// go run scanner.go -dir ./your-source-code -output json
// go run scanner.go -dir ./your-source-code -output csv
// go run scanner.go -dir ./your-source-code -output text -verbose -debug
