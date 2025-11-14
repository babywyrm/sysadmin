// cors_tester.go
//
// Advanced CORS Security Tester (2025 Edition)
//
// Usage:
//   go run cors_tester.go --url http://localhost:8000/api/resource
//   go run cors_tester.go --url http://localhost:8000/api/resource --token mytoken --verbose

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"
)

// Config holds test configuration
type Config struct {
	URL          string            `json:"url"`
	Token        string            `json:"token,omitempty"`
	Origins      []string          `json:"origins"`
	Cookies      []string          `json:"cookies"`
	Headers      map[string]string `json:"headers"`
	Timeout      time.Duration     `json:"timeout"`
	Verbose      bool              `json:"verbose"`
	Parallel     bool              `json:"parallel"`
	Insecure     bool              `json:"insecure"`
	OutputFormat string            `json:"output_format"`
	SaveFile     string            `json:"save_file,omitempty"`
}

// TestCase represents a CORS test
type TestCase struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body,omitempty"`
	ExpectedCode []int             `json:"expected_code"`
	RequiredHdrs map[string]string `json:"required_headers"`
	ForbiddenHdrs []string         `json:"forbidden_headers"`
	Category     string            `json:"category"`
	Severity     string            `json:"severity"`
	CheckFunc    func(*http.Response, *TestCase) (bool, []string) `json:"-"`
}

// Result represents test execution result
type Result struct {
	TestCase  *TestCase     `json:"test_case"`
	Response  *http.Response `json:"-"`
	Error     error         `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Passed    bool          `json:"passed"`
	Issues    []string      `json:"issues"`
	Warnings  []string      `json:"warnings"`
}

// Summary provides test statistics
type Summary struct {
	Total      int               `json:"total"`
	Passed     int               `json:"passed"`
	Failed     int               `json:"failed"`
	Errors     int               `json:"errors"`
	Duration   time.Duration     `json:"duration"`
	Issues     []SecurityIssue   `json:"issues"`
	StartTime  time.Time         `json:"start_time"`
}

// SecurityIssue represents a security vulnerability
type SecurityIssue struct {
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	Description string `json:"description"`
	TestName    string `json:"test_name"`
	Evidence    string `json:"evidence"`
	Mitigation  string `json:"mitigation"`
}

// Tester manages CORS testing
type Tester struct {
	Config  *Config
	Client  *http.Client
	Results []Result
	Summary Summary
}

// NewTester creates a new CORS tester
func NewTester(config *Config) *Tester {
	return &Tester{
		Config: config,
		Client: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
			},
		},
		Summary: Summary{StartTime: time.Now()},
	}
}

// Run executes all CORS tests
func (t *Tester) Run() error {
	tests := t.buildTests()
	
	fmt.Printf("Starting CORS Security Tests\n")
	fmt.Printf("Target: %s\n", t.Config.URL)
	fmt.Printf("Tests: %d\n\n", len(tests))

	if t.Config.Parallel {
		t.runParallel(tests)
	} else {
		t.runSequential(tests)
	}

	t.Summary.Duration = time.Since(t.Summary.StartTime)
	t.analyze()
	t.printResults()

	if t.Config.SaveFile != "" {
		return t.saveResults()
	}

	return nil
}

// runSequential runs tests sequentially
func (t *Tester) runSequential(tests []*TestCase) {
	for i, test := range tests {
		fmt.Printf("[%d/%d] %s", i+1, len(tests), test.Name)
		result := t.executeTest(test)
		t.Results = append(t.Results, result)
		
		if result.Passed {
			fmt.Printf(" %sPASS%s", Green, Reset)
		} else {
			fmt.Printf(" %sFAIL%s", Red, Reset)
		}
		fmt.Printf(" (%v)\n", result.Duration)
	}
}

// runParallel runs tests in parallel
func (t *Tester) runParallel(tests []*TestCase) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]Result, len(tests))

	for i, test := range tests {
		wg.Add(1)
		go func(idx int, tc *TestCase) {
			defer wg.Done()
			result := t.executeTest(tc)
			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, test)
	}

	wg.Wait()
	t.Results = results
}

// executeTest runs a single test
func (t *Tester) executeTest(test *TestCase) Result {
	start := time.Now()
	result := Result{
		TestCase: test,
		Issues:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), t.Config.Timeout)
	defer cancel()

	var body io.Reader
	if test.Body != "" {
		body = bytes.NewBufferString(test.Body)
	}

	req, err := http.NewRequestWithContext(ctx, test.Method, test.URL, body)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	// Apply headers
	t.applyHeaders(req, test)

	// Execute request
	resp, err := t.Client.Do(req)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	result.Response = resp
	result.Duration = time.Since(start)
	result.Passed = t.validateResponse(resp, test, &result)

	return result
}

// applyHeaders sets request headers
func (t *Tester) applyHeaders(req *http.Request, test *TestCase) {
	// Test headers
	for k, v := range test.Headers {
		req.Header.Set(k, v)
	}

	// Global headers
	for k, v := range t.Config.Headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	// Cookies
	if len(t.Config.Cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(t.Config.Cookies, "; "))
	}

	// Token
	if t.Config.Token != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+t.Config.Token)
	}
}

// validateResponse checks response against expectations
func (t *Tester) validateResponse(resp *http.Response, test *TestCase, result *Result) bool {
	passed := true

	// Check status codes
	if len(test.ExpectedCode) > 0 {
		validStatus := false
		for _, code := range test.ExpectedCode {
			if resp.StatusCode == code {
				validStatus = true
				break
			}
		}
		if !validStatus {
			result.Issues = append(result.Issues, 
				fmt.Sprintf("Expected status %v, got %d", test.ExpectedCode, resp.StatusCode))
			passed = false
		}
	}

	// Check required headers
	for header, expected := range test.RequiredHdrs {
		actual := resp.Header.Get(header)
		if expected == "*" {
			if actual == "" {
				result.Issues = append(result.Issues, fmt.Sprintf("Missing header: %s", header))
				passed = false
			}
		} else if actual != expected {
			result.Issues = append(result.Issues, 
				fmt.Sprintf("Header %s: expected '%s', got '%s'", header, expected, actual))
			passed = false
		}
	}

	// Check forbidden headers
	for _, header := range test.ForbiddenHdrs {
		if resp.Header.Get(header) != "" {
			result.Issues = append(result.Issues, fmt.Sprintf("Forbidden header present: %s", header))
			passed = false
		}
	}

	// Run custom checks
	if test.CheckFunc != nil {
		if checkPassed, issues := test.CheckFunc(resp, test); !checkPassed {
			result.Issues = append(result.Issues, issues...)
			passed = false
		}
	}

	return passed
}

// buildTests creates all test cases
func (t *Tester) buildTests() []*TestCase {
	origins := t.Config.Origins
	if len(origins) == 0 {
		origins = []string{
			"http://trusted.com",
			"http://test.com",
			"http://malicious.com",
			"https://example.com",
		}
	}

	jsonBody, _ := json.Marshal(map[string]interface{}{"test": "data"})

	return []*TestCase{
		// Basic CORS tests
		{
			Name:        "Simple GET Request",
			Description: "Basic CORS handling for GET requests",
			Method:      "GET",
			URL:         t.Config.URL,
			Headers:     map[string]string{"Origin": origins[0]},
			ExpectedCode: []int{200, 204},
			RequiredHdrs: map[string]string{"Access-Control-Allow-Origin": "*"},
			Category:    "Basic",
			Severity:    "Medium",
		},
		{
			Name:        "POST with JSON",
			Description: "CORS handling for POST with JSON",
			Method:      "POST",
			URL:         t.Config.URL,
			Headers: map[string]string{
				"Origin":       origins[0],
				"Content-Type": "application/json",
			},
			Body:         string(jsonBody),
			ExpectedCode: []int{200, 201, 204},
			RequiredHdrs: map[string]string{"Access-Control-Allow-Origin": "*"},
			Category:     "Basic",
			Severity:     "Medium",
		},

		// Preflight tests
		{
			Name:        "Standard Preflight",
			Description: "OPTIONS preflight request",
			Method:      "OPTIONS",
			URL:         t.Config.URL,
			Headers: map[string]string{
				"Origin":                         origins[0],
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "Content-Type",
			},
			ExpectedCode: []int{200, 204},
			RequiredHdrs: map[string]string{
				"Access-Control-Allow-Methods": "*",
				"Access-Control-Allow-Headers": "*",
			},
			Category: "Preflight",
			Severity: "High",
		},
		{
			Name:        "Complex Preflight",
			Description: "Preflight with multiple headers",
			Method:      "OPTIONS",
			URL:         t.Config.URL,
			Headers: map[string]string{
				"Origin":                         origins[0],
				"Access-Control-Request-Method":  "PUT",
				"Access-Control-Request-Headers": "X-Custom, Authorization, Content-Type",
			},
			ExpectedCode: []int{200, 204},
			RequiredHdrs: map[string]string{
				"Access-Control-Allow-Methods": "*",
				"Access-Control-Allow-Headers": "*",
			},
			Category: "Preflight",
			Severity: "High",
		},

		// Security tests
		{
			Name:        "Origin Reflection Attack",
			Description: "Tests for dangerous origin reflection",
			Method:      "GET",
			URL:         t.Config.URL,
			Headers:     map[string]string{"Origin": "http://attacker.com"},
			ExpectedCode: []int{200, 204},
			Category:    "Security",
			Severity:    "Critical",
			CheckFunc: func(resp *http.Response, test *TestCase) (bool, []string) {
				origin := resp.Header.Get("Access-Control-Allow-Origin")
				reqOrigin := test.Headers["Origin"]
				if origin == reqOrigin && origin != "*" {
					return false, []string{fmt.Sprintf("SECURITY: Origin reflection detected - %s", origin)}
				}
				return true, nil
			},
		},
		{
			Name:        "Wildcard with Credentials",
			Description: "Tests wildcard + credentials vulnerability",
			Method:      "GET",
			URL:         t.Config.URL,
			Headers: map[string]string{
				"Origin": origins[0],
				"Cookie": "sessionid=test123",
			},
			ExpectedCode: []int{200, 204},
			Category:    "Security",
			Severity:    "Critical",
			CheckFunc: func(resp *http.Response, test *TestCase) (bool, []string) {
				origin := resp.Header.Get("Access-Control-Allow-Origin")
				creds := resp.Header.Get("Access-Control-Allow-Credentials")
				if origin == "*" && strings.ToLower(creds) == "true" {
					return false, []string{"SECURITY: Wildcard origin with credentials enabled"}
				}
				return true, nil
			},
		},

		// Edge cases
		{
			Name:         "Invalid Origin",
			Description:  "Handling of malformed origin",
			Method:       "GET",
			URL:          t.Config.URL,
			Headers:      map[string]string{"Origin": "not-valid"},
			ExpectedCode: []int{200, 400, 403},
			Category:     "Edge",
			Severity:     "Low",
		},
		{
			Name:         "Null Origin",
			Description:  "Handling of null origin",
			Method:       "GET",
			URL:          t.Config.URL,
			Headers:      map[string]string{"Origin": "null"},
			ExpectedCode: []int{200, 204},
			Category:     "Edge",
			Severity:     "Medium",
		},
		{
			Name:         "No Origin Header",
			Description:  "Behavior without Origin header",
			Method:       "GET",
			URL:          t.Config.URL,
			Headers:      map[string]string{},
			ExpectedCode: []int{200, 204},
			Category:     "Edge",
			Severity:     "Low",
		},

		// Method tests
		{
			Name:         "PUT Request",
			Description:  "CORS for PUT method",
			Method:       "PUT",
			URL:          t.Config.URL,
			Headers:      map[string]string{"Origin": origins[0], "Content-Type": "application/json"},
			Body:         string(jsonBody),
			ExpectedCode: []int{200, 201, 204, 405},
			Category:     "Methods",
			Severity:     "Medium",
		},
		{
			Name:         "DELETE Request",
			Description:  "CORS for DELETE method",
			Method:       "DELETE",
			URL:          t.Config.URL,
			Headers:      map[string]string{"Origin": origins[0]},
			ExpectedCode: []int{200, 204, 405},
			Category:     "Methods",
			Severity:     "Medium",
		},
	}
}

// analyze processes test results
func (t *Tester) analyze() {
	t.Summary.Total = len(t.Results)
	
	for _, result := range t.Results {
		if result.Error != nil {
			t.Summary.Errors++
			continue
		}
		
		if result.Passed {
			t.Summary.Passed++
		} else {
			t.Summary.Failed++
			
			// Convert issues to security problems
			for _, issue := range result.Issues {
				severity := "Medium"
				if strings.Contains(strings.ToUpper(issue), "SECURITY") {
					severity = "Critical"
				}
				
				t.Summary.Issues = append(t.Summary.Issues, SecurityIssue{
					Severity:    severity,
					Type:        result.TestCase.Category,
					Description: issue,
					TestName:    result.TestCase.Name,
					Evidence:    fmt.Sprintf("Status: %d", result.Response.StatusCode),
					Mitigation:  t.getMitigation(issue),
				})
			}
		}
	}
}

// getMitigation provides fix suggestions
func (t *Tester) getMitigation(issue string) string {
	if strings.Contains(issue, "reflection") {
		return "Use explicit origin whitelist instead of reflecting arbitrary origins"
	}
	if strings.Contains(issue, "Wildcard") && strings.Contains(issue, "credentials") {
		return "Use specific origins when credentials are enabled"
	}
	if strings.Contains(issue, "Missing") {
		return "Configure proper CORS headers"
	}
	return "Review CORS configuration"
}

// printResults displays test results
func (t *Tester) printResults() {
	fmt.Printf("\nTest Results Summary\n")
	fmt.Printf("====================\n")
	fmt.Printf("Total: %d\n", t.Summary.Total)
	fmt.Printf("%sPassed: %d%s\n", Green, t.Summary.Passed, Reset)
	fmt.Printf("%sFailed: %d%s\n", Red, t.Summary.Failed, Reset)
	fmt.Printf("%sErrors: %d%s\n", Yellow, t.Summary.Errors, Reset)
	fmt.Printf("Duration: %v\n\n", t.Summary.Duration)

	if t.Config.Verbose {
		t.printDetailedResults()
	}

	if len(t.Summary.Issues) > 0 {
		t.printSecurityIssues()
	} else {
		fmt.Printf("%sNo critical security issues detected%s\n", Green, Reset)
	}
}

// printDetailedResults shows verbose output
func (t *Tester) printDetailedResults() {
	fmt.Printf("Detailed Results:\n")
	fmt.Printf("=================\n")

	for i, result := range t.Results {
		status := "PASS"
		color := Green
		if !result.Passed || result.Error != nil {
			status = "FAIL"
			color = Red
		}

		fmt.Printf("[%d] %s%s%s %s (%v)\n", i+1, color, status, Reset, result.TestCase.Name, result.Duration)
		
		if result.Error != nil {
			fmt.Printf("    %sError: %v%s\n", Red, result.Error, Reset)
		}
		
		for _, issue := range result.Issues {
			fmt.Printf("    %s- %s%s\n", Red, issue, Reset)
		}

		if t.Config.Verbose && result.Response != nil {
			fmt.Printf("    Status: %d\n", result.Response.StatusCode)
			corsHeaders := []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Methods",
				"Access-Control-Allow-Headers",
				"Access-Control-Allow-Credentials",
			}
			for _, header := range corsHeaders {
				if value := result.Response.Header.Get(header); value != "" {
					fmt.Printf("    %s: %s\n", header, value)
				}
			}
		}
		fmt.Println()
	}
}

// printSecurityIssues displays security problems
func (t *Tester) printSecurityIssues() {
	fmt.Printf("%sSecurity Issues Detected:%s\n", Red, Reset)
	fmt.Printf("=========================\n")

	criticalIssues := make([]SecurityIssue, 0)
	otherIssues := make([]SecurityIssue, 0)

	for _, issue := range t.Summary.Issues {
		if issue.Severity == "Critical" {
			criticalIssues = append(criticalIssues, issue)
		} else {
			otherIssues = append(otherIssues, issue)
		}
	}

	if len(criticalIssues) > 0 {
		fmt.Printf("\n%sCRITICAL (%d issues):%s\n", Red, len(criticalIssues), Reset)
		for i, issue := range criticalIssues {
			fmt.Printf("[%d] %s\n", i+1, issue.Description)
			fmt.Printf("    Test: %s\n", issue.TestName)
			fmt.Printf("    Fix: %s\n", issue.Mitigation)
			fmt.Println()
		}
	}

	if len(otherIssues) > 0 {
		fmt.Printf("\n%sOTHER (%d issues):%s\n", Yellow, len(otherIssues), Reset)
		for i, issue := range otherIssues {
			fmt.Printf("[%d] %s\n", i+1, issue.Description)
			fmt.Printf("    Test: %s\n", issue.TestName)
			fmt.Println()
		}
	}
}

// saveResults saves results to file
func (t *Tester) saveResults() error {
	data := map[string]interface{}{
		"summary":   t.Summary,
		"results":   t.Results,
		"config":    t.Config,
		"timestamp": time.Now(),
	}

	var output []byte
	var err error

	switch t.Config.OutputFormat {
	case "json":
		output, err = json.MarshalIndent(data, "", "  ")
	default:
		var buf strings.Builder
		buf.WriteString(fmt.Sprintf("CORS Test Results - %s\n", time.Now().Format(time.RFC3339)))
		buf.WriteString(fmt.Sprintf("Target: %s\n", t.Config.URL))
		buf.WriteString(fmt.Sprintf("Passed: %d, Failed: %d, Errors: %d\n\n", 
			t.Summary.Passed, t.Summary.Failed, t.Summary.Errors))
		
		for _, result := range t.Results {
			status := "PASS"
			if !result.Passed {
				status = "FAIL"
			}
			buf.WriteString(fmt.Sprintf("%s: %s\n", result.TestCase.Name, status))
			for _, issue := range result.Issues {
				buf.WriteString(fmt.Sprintf("  - %s\n", issue))
			}
		}
		output = []byte(buf.String())
	}

	if err != nil {
		return err
	}

	return os.WriteFile(t.Config.SaveFile, output, 0644)
}

// MultiFlag allows repeated flags
type MultiFlag []string

func (m *MultiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *MultiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// parseHeaders converts header strings to map
func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func main() {
	var (
		url       string
		token     string
		timeout   time.Duration
		verbose   bool
		parallel  bool
		insecure  bool
		output    string
		save      string
		help      bool
	)

	var origins, cookies, headerStrs MultiFlag

	flag.StringVar(&url, "url", "", "Target URL (required)")
	flag.StringVar(&url, "u", "", "Target URL")
	flag.StringVar(&token, "token", "", "Bearer token")
	flag.StringVar(&token, "t", "", "Bearer token")
	flag.Var(&origins, "origins", "Custom origins")
	flag.Var(&cookies, "cookie", "Cookies to send")
	flag.Var(&cookies, "c", "Cookies to send")
	flag.Var(&headerStrs, "header", "Extra headers")
	flag.Var(&headerStrs, "H", "Extra headers")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "Request timeout")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&parallel, "parallel", false, "Run tests in parallel")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS verification")
	flag.StringVar(&output, "output", "text", "Output format (text|json)")
	flag.StringVar(&save, "save", "", "Save results to file")
	flag.BoolVar(&help, "help", false, "Show help")
	flag.BoolVar(&help, "h", false, "Show help")

	flag.Parse()

	if help || url == "" {
		fmt.Printf(`Advanced CORS Security Tester

Usage: cors_tester --url <endpoint> [options]

Options:
  --url, -u      Target URL (required)
  --token, -t    Bearer token
  --origins      Custom origins to test
  --cookie, -c   Cookies (repeatable)
  --header, -H   Headers (repeatable)
  --timeout      Request timeout (default: 10s)
  --verbose, -v  Detailed output
  --parallel     Run tests concurrently
  --insecure     Skip TLS verification
  --output       Output format: text|json
  --save         Save results to file
  --help, -h     Show help

Examples:
  cors_tester --url http://localhost:8000/api
  cors_tester --url https://api.com --token abc123 --verbose
  cors_tester --url http://localhost:8000 --parallel --save report.json
`)
		if url == "" {
			os.Exit(1)
		}
		return
	}

	// Validate URL
	if _, err := url.Parse(url); err != nil {
		fmt.Printf("%sInvalid URL: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	config := &Config{
		URL:          url,
		Token:        token,
		Origins:      origins,
		Cookies:      cookies,
		Headers:      parseHeaders(headerStrs),
		Timeout:      timeout,
		Verbose:      verbose,
		Parallel:     parallel,
		Insecure:     insecure,
		OutputFormat: output,
		SaveFile:     save,
	}

	tester := NewTester(config)
	if err := tester.Run(); err != nil {
		fmt.Printf("%sError: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	// Exit with error if critical issues found
	for _, issue := range tester.Summary.Issues {
		if issue.Severity == "Critical" {
			fmt.Printf("\n%sCritical security issues found!%s\n", Red, Reset)
			os.Exit(2)
		}
	}
}
