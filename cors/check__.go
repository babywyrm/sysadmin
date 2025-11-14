// cors_tester.go
//
// Advanced CORS Security Tester (2025 Edition)
//
// A comprehensive tool for testing CORS configurations and identifying potential security vulnerabilities
//
// Usage:
//   go run cors_tester.go --url http://localhost:8000/api/resource
//   go run cors_tester.go --url http://localhost:8000/api/resource --token mytoken --cookie "sessionId=abc123" --header "X-Session-Token: mytoken" --verbose
//
// Build:
//   go build -o cors_tester cors_tester.go

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
	"sort"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[90m"
)

// Configuration holds all test configuration
type Config struct {
	URL          string
	Token        string
	Origins      []string
	Cookies      []string
	Headers      map[string]string
	Verbose      bool
	Timeout      time.Duration
	Insecure     bool
	Parallel     bool
	OutputFormat string
	SaveResults  string
}

// TestResult represents the result of a single CORS test
type TestResult struct {
	TestCase    *CORSTestCase
	Response    *http.Response
	Error       error
	Duration    time.Duration
	Passed      bool
	Issues      []string
	Warnings    []string
}

// TestSuite manages and runs all CORS tests
type TestSuite struct {
	Config    *Config
	Client    *http.Client
	Results   []TestResult
	Summary   TestSummary
	StartTime time.Time
}

// TestSummary provides overall test statistics
type TestSummary struct {
	Total    int
	Passed   int
	Failed   int
	Errors   int
	Duration time.Duration
	Issues   []SecurityIssue
}

// SecurityIssue represents a potential security vulnerability
type SecurityIssue struct {
	Severity    string
	Type        string
	Description string
	TestName    string
	Evidence    string
	Mitigation  string
}

// CORSTestCase represents a single test case
type CORSTestCase struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body,omitempty"`
	Expectations Expectations      `json:"expectations"`
	Category     string            `json:"category"`
	Severity     string            `json:"severity"`
}

// Expectations defines what we expect from a test
type Expectations struct {
	StatusCodes       []int             `json:"status_codes"`
	RequiredHeaders   map[string]string `json:"required_headers"`
	ForbiddenHeaders  []string          `json:"forbidden_headers"`
	SecurityChecks    []SecurityCheck   `json:"security_checks"`
	AllowCredentials  *bool             `json:"allow_credentials,omitempty"`
}

// SecurityCheck defines security-related checks
type SecurityCheck struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CheckFunc   func(*http.Response, *CORSTestCase) (bool, string) `json:"-"`
}

// NewTestSuite creates a new test suite with the given configuration
func NewTestSuite(config *Config) *TestSuite {
	// Create HTTP client with proper timeout and TLS settings
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
		},
	}

	return &TestSuite{
		Config:    config,
		Client:    client,
		Results:   make([]TestResult, 0),
		StartTime: time.Now(),
	}
}

// Run executes all CORS tests
func (ts *TestSuite) Run() error {
	tests := ts.buildTestCases()
	
	fmt.Printf("%s%s🔍 Starting Advanced CORS Security Tests%s%s\n", Bold, Cyan, Reset, Reset)
	fmt.Printf("Target: %s\n", ts.Config.URL)
	fmt.Printf("Tests: %d\n", len(tests))
	fmt.Printf("Parallel: %v\n\n", ts.Config.Parallel)

	if ts.Config.Parallel {
		ts.runParallel(tests)
	} else {
		ts.runSequential(tests)
	}

	ts.Summary.Duration = time.Since(ts.StartTime)
	ts.analyzeSecurity()
	ts.printResults()
	
	if ts.Config.SaveResults != "" {
		return ts.saveResults()
	}

	return nil
}

// runSequential runs tests one by one
func (ts *TestSuite) runSequential(tests []*CORSTestCase) {
	for i, test := range tests {
		fmt.Printf("[%d/%d] %s", i+1, len(tests), test.Name)
		result := ts.executeTest(test)
		ts.Results = append(ts.Results, result)
		
		if result.Passed {
			fmt.Printf(" %s✓%s", Green, Reset)
		} else {
			fmt.Printf(" %s✗%s", Red, Reset)
		}
		fmt.Printf(" (%v)\n", result.Duration)
	}
}

// runParallel runs tests concurrently
func (ts *TestSuite) runParallel(tests []*CORSTestCase) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]TestResult, len(tests))

	for i, test := range tests {
		wg.Add(1)
		go func(idx int, tc *CORSTestCase) {
			defer wg.Done()
			result := ts.executeTest(tc)
			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, test)
	}

	wg.Wait()
	ts.Results = results
}

// executeTest runs a single test case
func (ts *TestSuite) executeTest(test *CORSTestCase) TestResult {
	start := time.Now()
	result := TestResult{
		TestCase: test,
		Issues:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), ts.Config.Timeout)
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

	// Set headers
	ts.setRequestHeaders(req, test)

	// Execute request
	resp, err := ts.Client.Do(req)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	result.Response = resp
	result.Duration = time.Since(start)
	result.Passed = ts.validateResponse(resp, test, &result)

	return result
}

// setRequestHeaders applies headers to the request
func (ts *TestSuite) setRequestHeaders(req *http.Request, test *CORSTestCase) {
	// Apply test-specific headers
	for key, value := range test.Headers {
		req.Header.Set(key, value)
	}

	// Apply global headers
	for key, value := range ts.Config.Headers {
		if req.Header.Get(key) == "" { // Don't override test-specific headers
			req.Header.Set(key, value)
		}
	}

	// Apply cookies
	if len(ts.Config.Cookies) > 0 {
		existing := req.Header.Get("Cookie")
		allCookies := append(ts.Config.Cookies, existing)
		cookieStr := strings.Join(allCookies, "; ")
		req.Header.Set("Cookie", strings.TrimSpace(cookieStr))
	}

	// Apply token if provided
	if ts.Config.Token != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+ts.Config.Token)
	}
}

// validateResponse checks if the response meets expectations
func (ts *TestSuite) validateResponse(resp *http.Response, test *CORSTestCase, result *TestResult) bool {
	passed := true

	// Check status codes
	if len(test.Expectations.StatusCodes) > 0 {
		validStatus := false
		for _, code := range test.Expectations.StatusCodes {
			if resp.StatusCode == code {
				validStatus = true
				break
			}
		}
		if !validStatus {
			result.Issues = append(result.Issues, 
				fmt.Sprintf("Expected status %v, got %d", test.Expectations.StatusCodes, resp.StatusCode))
			passed = false
		}
	}

	// Check required headers
	for header, expectedValue := range test.Expectations.RequiredHeaders {
		actualValue := resp.Header.Get(header)
		if expectedValue == "*" {
			if actualValue == "" {
				result.Issues = append(result.Issues, 
					fmt.Sprintf("Required header %s is missing", header))
				passed = false
			}
		} else if actualValue != expectedValue {
			result.Issues = append(result.Issues, 
				fmt.Sprintf("Header %s: expected '%s', got '%s'", header, expectedValue, actualValue))
			passed = false
		}
	}

	// Check forbidden headers
	for _, header := range test.Expectations.ForbiddenHeaders {
		if resp.Header.Get(header) != "" {
			result.Issues = append(result.Issues, 
				fmt.Sprintf("Forbidden header %s is present", header))
			passed = false
		}
	}

	// Run security checks
	for _, check := range test.Expectations.SecurityChecks {
		if checkPassed, message := check.CheckFunc(resp, test); !checkPassed {
			result.Issues = append(result.Issues, message)
			passed = false
		}
	}

	return passed
}

// buildTestCases creates all CORS test cases
func (ts *TestSuite) buildTestCases() []*CORSTestCase {
	// Default origins if not provided
	origins := ts.Config.Origins
	if len(origins) == 0 {
		origins = []string{
			"http://trusted-origin.com",
			"http://test-origin.com", 
			"http://malicious-origin.com",
			"https://example.com",
		}
	}

	var tests []*CORSTestCase

	// Basic CORS tests
	tests = append(tests, ts.buildBasicTests(origins)...)
	
	// Preflight tests
	tests = append(tests, ts.buildPreflightTests(origins)...)
	
	// Security tests
	tests = append(tests, ts.buildSecurityTests(origins)...)
	
	// Edge case tests
	tests = append(tests, ts.buildEdgeCaseTests(origins)...)

	return tests
}

// buildBasicTests creates basic CORS functionality tests
func (ts *TestSuite) buildBasicTests(origins []string) []*CORSTestCase {
	jsonBody, _ := json.Marshal(map[string]interface{}{
		"test": "data",
		"timestamp": time.Now().Unix(),
	})

	return []*CORSTestCase{
		{
			Name:        "Simple GET Request",
			Description: "Tests basic CORS handling for GET requests",
			Method:      "GET",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin": origins[0],
			},
			Expectations: Expectations{
				StatusCodes: []int{200, 204},
				RequiredHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
			Category: "Basic",
			Severity: "Medium",
		},
		{
			Name:        "POST with JSON",
			Description: "Tests CORS handling for POST requests with JSON payload",
			Method:      "POST",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin":       origins[0],
				"Content-Type": "application/json",
			},
			Body: string(jsonBody),
			Expectations: Expectations{
				StatusCodes: []int{200, 201, 204},
				RequiredHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
			Category: "Basic",
			Severity: "Medium",
		},
		{
			Name:        "PUT Request",
			Description: "Tests CORS handling for PUT requests",
			Method:      "PUT",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin":       origins[0],
				"Content-Type": "application/json",
			},
			Body: string(jsonBody),
			Expectations: Expectations{
				StatusCodes: []int{200, 201, 204, 405}, // 405 if PUT not allowed
			},
			Category: "Basic",
			Severity: "Low",
		},
	}
}

// buildPreflightTests creates preflight-specific tests
func (ts *TestSuite) buildPreflightTests(origins []string) []*CORSTestCase {
	return []*CORSTestCase{
		{
			Name:        "Standard Preflight",
			Description: "Tests standard OPTIONS preflight request",
			Method:      "OPTIONS",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin":                        origins[0],
				"Access-Control-Request-Method": "POST",
				"Access-Control-Request-Headers": "Content-Type",
			},
			Expectations: Expectations{
				StatusCodes: []int{200, 204},
				RequiredHeaders: map[string]string{
					"Access-Control-Allow-Methods": "*",
					"Access-Control-Allow-Headers": "*",
				},
			},
			Category: "Preflight",
			Severity: "High",
		},
		{
			Name:        "Complex Preflight",
			Description: "Tests preflight with multiple custom headers",
			Method:      "OPTIONS", 
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin":                        origins[0],
				"Access-Control-Request-Method": "PUT",
				"Access-Control-Request-Headers": "X-Custom-Header, Authorization, Content-Type",
			},
			Expectations: Expectations{
				StatusCodes: []int{200, 204},
				RequiredHeaders: map[string]string{
					"Access-Control-Allow-Methods": "*",
					"Access-Control-Allow-Headers": "*",
				},
			},
			Category: "Preflight",
			Severity: "High",
		},
	}
}

// buildSecurityTests creates security-focused CORS tests
func (ts *TestSuite) buildSecurityTests(origins []string) []*CORSTestCase {
	return []*CORSTestCase{
		{
			Name:        "Origin Reflection Attack",
			Description: "Tests if server reflects arbitrary origins (security vulnerability)",
			Method:      "GET",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin": "http://malicious-attacker.com",
			},
			Expectations: Expectations{
				StatusCodes: []int{200, 204},
				ForbiddenHeaders: []string{"Access-Control-Allow-Origin"},
				SecurityChecks: []SecurityCheck{
					{
						Type: "origin_reflection",
						Description: "Checks for dangerous origin reflection",
						CheckFunc: func(resp *http.Response, test *CORSTestCase) (bool, string) {
							origin := resp.Header.Get("Access-Control-Allow-Origin")
							requestOrigin := test.Headers["Origin"]
							if origin == requestOrigin && origin != "*" {
								return false, fmt.Sprintf("SECURITY ISSUE: Server reflects untrusted origin '%s'", origin)
							}
							return true, ""
						},
					},
				},
			},
			Category: "Security",
			Severity: "Critical",
		},
		{
			Name:        "Wildcard with Credentials",
			Description: "Tests for wildcard origin with credentials (security vulnerability)",
			Method:      "GET",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin": origins[0],
				"Cookie": "sessionid=test123",
			},
			Expectations: Expectations{
				StatusCodes: []int{200, 204},
				SecurityChecks: []SecurityCheck{
					{
						Type: "wildcard_credentials",
						Description: "Checks for dangerous wildcard + credentials combination",
						CheckFunc: func(resp *http.Response, test *CORSTestCase) (bool, string) {
							origin := resp.Header.Get("Access-Control-Allow-Origin")
							credentials := resp.Header.Get("Access-Control-Allow-Credentials")
							if origin == "*" && strings.ToLower(credentials) == "true" {
								return false, "SECURITY ISSUE: Wildcard origin with credentials enabled"
							}
							return true, ""
						},
					},
				},
			},
			Category: "Security",
			Severity: "Critical",
		},
	}
}

// buildEdgeCaseTests creates edge case and error condition tests
func (ts *TestSuite) buildEdgeCaseTests(origins []string) []*CORSTestCase {
	return []*CORSTestCase{
		{
			Name:        "Invalid Origin Format",
			Description: "Tests handling of malformed origin headers",
			Method:      "GET",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin": "not-a-valid-origin",
			},
			Expectations: Expectations{
				StatusCodes: []int{200, 400, 403},
			},
			Category: "Edge Cases",
			Severity: "Low",
		},
		{
			Name:        "Null Origin",
			Description: "Tests handling of null origin (common in sandboxed contexts)",
			Method:      "GET",
			URL:         ts.Config.URL,
			Headers: map[string]string{
				"Origin": "null",
			},
			Expectations: Expectations{
				StatusCodes: []int{200, 204},
			},
			Category: "Edge Cases", 
			Severity: "Medium",
		},
		{
			Name:        "No Origin Header",
			Description: "Tests behavior when no Origin header is present",
			Method:      "GET",
			URL:         ts.Config.URL,
			Headers:     map[string]string{},
			Expectations: Expectations{
				StatusCodes: []int{200, 204},
			},
			Category: "Edge Cases",
			Severity: "Low",
		},
	}
}

// analyzeSecurity analyzes test results for security issues
func (ts *TestSuite) analyzeSecurity() {
	ts.Summary.Total = len(ts.Results)
	
	for _, result := range ts.Results {
		if result.Error != nil {
			ts.Summary.Errors++
			continue
		}
		
		if result.Passed {
			ts.Summary.Passed++
		} else {
			ts.Summary.Failed++
			
			// Convert failed tests to security issues
			for _, issue := range result.Issues {
				severity := "Medium"
				if strings.Contains(strings.ToUpper(issue), "SECURITY ISSUE") {
					severity = "Critical"
				}
				
				ts.Summary.Issues = append(ts.Summary.Issues, SecurityIssue{
					Severity:    severity,
					Type:        result.TestCase.Category,
					Description: issue,
					TestName:    result.TestCase.Name,
					Evidence:    fmt.Sprintf("Status: %d", result.Response.StatusCode),
					Mitigation:  ts.getSuggestedMitigation(issue),
				})
			}
		}
	}
}

// getSuggestedMitigation provides mitigation suggestions for issues
func (ts *TestSuite) getSuggestedMitigation(issue string) string {
	if strings.Contains(issue, "reflects untrusted origin") {
		return "Configure a whitelist of allowed origins instead of reflecting arbitrary origins"
	}
	if strings.Contains(issue, "Wildcard origin with credentials") {
		return "Use specific origins instead of wildcard when credentials are required"
	}
	if strings.Contains(issue, "missing") {
		return "Ensure proper CORS headers are configured on the server"
	}
	return "Review CORS configuration and security best practices"
}

// printResults outputs the test results in a formatted way
func (ts *TestSuite) printResults() {
	fmt.Printf("\n%s%s📊 Test Results Summary%s%s\n", Bold, Cyan, Reset, Reset)
	fmt.Printf("================================\n")
	fmt.Printf("Total Tests: %d\n", ts.Summary.Total)
	fmt.Printf("%sPassed: %d%s\n", Green, ts.Summary.Passed, Reset)
	fmt.Printf("%sFailed: %d%s\n", Red, ts.Summary.Failed, Reset)
	fmt.Printf("%sErrors: %d%s\n", Yellow, ts.Summary.Errors, Reset)
	fmt.Printf("Duration: %v\n\n", ts.Summary.Duration)

	// Print detailed results if verbose
	if ts.Config.Verbose {
		ts.printDetailedResults()
	}

	// Print security issues
	if len(ts.Summary.Issues) > 0 {
		ts.printSecurityIssues()
	} else {
		fmt.Printf("%s🛡️  No critical security issues detected%s\n", Green, Reset)
	}
}

// printDetailedResults shows detailed test results
func (ts *TestSuite) printDetailedResults() {
	fmt.Printf("%s%sDetailed Results:%s%s\n", Bold, Blue, Reset, Reset)
	fmt.Printf("==================\n")

	for i, result := range ts.Results {
		status := "✓"
		color := Green
		if !result.Passed || result.Error != nil {
			status = "✗"
			color = Red
		}

		fmt.Printf("[%d] %s%s%s %s (%v)\n", i+1, color, status, Reset, result.TestCase.Name, result.Duration)
		
		if result.Error != nil {
			fmt.Printf("    %sError: %v%s\n", Red, result.Error, Reset)
		}
		
		if len(result.Issues) > 0 {
			for _, issue := range result.Issues {
				fmt.Printf("    %s- %s%s\n", Red, issue, Reset)
			}
		}
		
		if len(result.Warnings) > 0 {
			for _, warning := range result.Warnings {
				fmt.Printf("    %s⚠ %s%s\n", Yellow, warning, Reset)
			}
		}

		if ts.Config.Verbose && result.Response != nil {
			fmt.Printf("    Status: %d\n", result.Response.StatusCode)
			if len(result.Response.Header) > 0 {
				fmt.Printf("    CORS Headers:\n")
				corsHeaders := []string{
					"Access-Control-Allow-Origin",
					"Access-Control-Allow-Methods", 
					"Access-Control-Allow-Headers",
					"Access-Control-Allow-Credentials",
					"Access-Control-Max-Age",
					"Access-Control-Expose-Headers",
				}
				for _, header := range corsHeaders {
					if value := result.Response.Header.Get(header); value != "" {
						fmt.Printf("      %s: %s\n", header, value)
					}
				}
			}
		}
		fmt.Println()
	}
}

// printSecurityIssues displays security vulnerabilities found
func (ts *TestSuite) printSecurityIssues() {
	fmt.Printf("%s%s🚨 Security Issues Detected:%s%s\n", Bold, Red, Reset, Reset)
	fmt.Printf("==============================\n")

	// Group issues by severity
	criticalIssues := make([]SecurityIssue, 0)
	highIssues := make([]SecurityIssue, 0)
	mediumIssues := make([]SecurityIssue, 0)
	lowIssues := make([]SecurityIssue, 0)

	for _, issue := range ts.Summary.Issues {
		switch issue.Severity {
		case "Critical":
			criticalIssues = append(criticalIssues, issue)
		case "High":
			highIssues = append(highIssues, issue)
		case "Medium":
			mediumIssues = append(mediumIssues, issue)
		case "Low":
			lowIssues = append(lowIssues, issue)
		}
	}

	printIssueGroup("CRITICAL", criticalIssues, Red)
	printIssueGroup("HIGH", highIssues, Magenta)
	printIssueGroup("MEDIUM", mediumIssues, Yellow)
	printIssueGroup("LOW", lowIssues, Blue)
}

// printIssueGroup prints a group of security issues
func printIssueGroup(severity string, issues []SecurityIssue, color string) {
	if len(issues) == 0 {
		return
	}

	fmt.Printf("\n%s%s %s SEVERITY (%d issues)%s\n", color, severity, severity, len(issues), Reset)
	fmt.Printf("%s%s%s\n", color, strings.Repeat("=", len(severity)+20), Reset)

	for i, issue := range issues {
		fmt.Printf("[%d] %s\n", i+1, issue.Description)
		fmt.Printf("    Test: %s\n", issue.TestName)
		if issue.Evidence != "" {
			fmt.Printf("    Evidence: %s\n", issue.Evidence)
		}
		if issue.Mitigation != "" {
			fmt.Printf("    %sMitigation: %s%s\n", Green, issue.Mitigation, Reset)
		}
		fmt.Println()
	}
}

// saveResults saves test results to a file
func (ts *TestSuite) saveResults() error {
	switch ts.Config.OutputFormat {
	case "json":
		return ts.saveResultsAsJSON()
	case "html":
		return ts.saveResultsAsHTML()
	default:
		return ts.saveResultsAsText()
	}
}

// saveResultsAsJSON saves results in JSON format
func (ts *TestSuite) saveResultsAsJSON() error {
	data := map[string]interface{}{
		"summary":     ts.Summary,
		"results":     ts.Results,
		"config":      ts.Config,
		"timestamp":   time.Now(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ts.Config.SaveResults, jsonData, 0644)
}

// saveResultsAsText saves results in plain text format
func (ts *TestSuite) saveResultsAsText() error {
	var buf strings.Builder
	
	buf.WriteString(fmt.Sprintf("CORS Test Results - %s\n", time.Now().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("Target: %s\n", ts.Config.URL))
	buf.WriteString(fmt.Sprintf("Total Tests: %d\n", ts.Summary.Total))
	buf.WriteString(fmt.Sprintf("Passed: %d\n", ts.Summary.Passed))
	buf.WriteString(fmt.Sprintf("Failed: %d\n", ts.Summary.Failed))
	buf.WriteString(fmt.Sprintf("Errors: %d\n", ts.Summary.Errors))
	buf.WriteString(fmt.Sprintf("Duration: %v\n\n", ts.Summary.Duration))

	for _, result := range ts.Results {
		buf.WriteString(fmt.Sprintf("Test: %s\n", result.TestCase.Name))
		buf.WriteString(fmt.Sprintf("Status: %s\n", map[bool]string{true: "PASSED", false: "FAILED"}[result.Passed]))
		
		if result.Error != nil {
			buf.WriteString(fmt.Sprintf("Error: %v\n", result.Error))
		}
		
		for _, issue := range result.Issues {
			buf.WriteString(fmt.Sprintf("Issue: %s\n", issue))
		}
		buf.WriteString("\n")
	}

	return os.WriteFile(ts.Config.SaveResults, []byte(buf.String()), 0644)
}

// saveResultsAsHTML saves results in HTML format
func (ts *TestSuite) saveResultsAsHTML() error {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>CORS Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .passed { color: green; }
        .failed { color: red; }
        .critical { background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 5px 0; }
        .medium { background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 5px 0; }
        .test-result { margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
    </style>
</head>
<body>`

	html += fmt.Sprintf(`
    <h1>CORS Test Results</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Target: %s</p>
        <p>Total Tests: %d</p>
        <p class="passed">Passed: %d</p>
        <p class="failed">Failed: %d</p>
        <p>Duration: %v</p>
    </div>`, ts.Config.URL, ts.Summary.Total, ts.Summary.Passed, ts.Summary.Failed, ts.Summary.Duration)

	if len(ts.Summary.Issues) > 0 {
		html += "<h2>Security Issues</h2>"
		for _, issue := range ts.Summary.Issues {
			class := "medium"
			if issue.Severity == "Critical" {
				class = "critical"
			}
			html += fmt.Sprintf(`<div class="%s"><strong>%s:</strong> %s</div>`, class, issue.Severity, issue.Description)
		}
	}

	html += "<h2>Detailed Results</h2>"
	for _, result := range ts.Results {
		status := "passed"
		if !result.Passed {
			status = "failed"
		}
		html += fmt.Sprintf(`<div class="test-result">
            <h3 class="%s">%s</h3>
            <p>%s</p>`, status, result.TestCase.Name, result.TestCase.Description)
		
		if len(result.Issues) > 0 {
			html += "<ul>"
			for _, issue := range result.Issues {
				html += fmt.Sprintf("<li>%s</li>", issue)
			}
			html += "</ul>"
		}
		html += "</div>"
	}

	html += "</body></html>"

	return os.WriteFile(ts.Config.SaveResults, []byte(html), 0644)
}

// MultiFlag allows repeated string flags
type MultiFlag []string

func (m *MultiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *MultiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// parseHeaders converts header strings to map
func parseHeaders(headerStrings []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range headerStrings {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

// validateURL checks if URL is valid
func validateURL(urlStr string) error {
	_, err := url.Parse(urlStr)
	return err
}

// printHelp displays usage information
func printHelp() {
	fmt.Printf(`%s%sAdvanced CORS Security Tester (2025 Edition)%s%s

%sUSAGE:%s
  cors_tester --url <endpoint> [options]

%sOPTIONS:%s
  --url, -u           Target API endpoint (required)
  --token, -t         Bearer token for Authorization header
  --origins           Custom origins to test (space-separated)
  --cookie, -c        Cookie to send (repeatable)
  --header, -H        Extra header to send (repeatable)
  --timeout           Request timeout (default: 10s)
  --insecure         Skip TLS certificate verification
  --parallel          Run tests in parallel
  --verbose, -v       Show detailed output
  --output            Output format: text|json|html (default: text)
  --save              Save results to file
  --help, -h          Show this help

%sEXAMPLES:%s
  # Basic test
  cors_tester --url http://localhost:8000/api/resource

  # Full security audit with custom headers
  cors_tester --url https://api.example.com/v1/users \
    --token eyJhbGciOiJIUzI1NiIs... \
    --cookie "sessionId=abc123" \
    --header "X-API-Key: secret" \
    --verbose --parallel

  # Save results as JSON report
  cors_tester --url http://localhost:8000/api \
    --output json --save cors_report.json

  # Test with custom origins
  cors_tester --url http://localhost:8000/api \
    --origins http://trusted.com http://attacker.com \
    --verbose

%sSECURITY CHECKS:%s
  ✓ Origin reflection vulnerabilities
  ✓ Wildcard with credentials misconfigurations  
  ✓ Missing CORS headers
  ✓ Overly permissive configurations
  ✓ Preflight bypass attempts
  ✓ Edge cases and malformed requests

`, Bold, Cyan, Reset, Reset, Bold, Reset, Bold, Reset, Bold, Reset, Bold, Reset)
}

func main() {
	var (
		url         string
		token       string
		timeout     time.Duration
		insecure    bool
		parallel    bool
		verbose     bool
		outputFmt   string
		saveFile    string
		help        bool
	)

	var origins, cookies, headerStrings MultiFlag

	// Define flags
	flag.StringVar(&url, "url", "", "Target API endpoint")
	flag.StringVar(&url, "u", "", "Target API endpoint")
	flag.StringVar(&token, "token", "", "Bearer token")
	flag.StringVar(&token, "t", "", "Bearer token")
	flag.Var(&origins, "origins", "Custom origins to test")
	flag.Var(&cookies, "cookie", "Cookie to send")
	flag.Var(&cookies, "c", "Cookie to send")
	flag.Var(&headerStrings, "header", "Extra header")
	flag.Var(&headerStrings, "H", "Extra header")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "Request timeout")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS verification")
	flag.BoolVar(&parallel, "parallel", false, "Run tests in parallel")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&outputFmt, "output", "text", "Output format (text|json|html)")
	flag.StringVar(&saveFile, "save", "", "Save results to file")
	flag.BoolVar(&help, "help", false, "Show help")
	flag.BoolVar(&help, "h", false, "Show help")

	flag.Parse()

	if help {
		printHelp()
		return
	}

	if url == "" {
		fmt.Printf("%sError: --url is required%s\n", Red, Reset)
		printHelp()
		os.Exit(1)
	}

	if err := validateURL(url); err != nil {
		fmt.Printf("%sError: Invalid URL: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	// Create configuration
	config := &Config{
		URL:          url,
		Token:        token,
		Origins:      origins,
		Cookies:      cookies,
		Headers:      parseHeaders(headerStrings),
		Verbose:      verbose,
		Timeout:      timeout,
		Insecure:     insecure,
		Parallel:     parallel,
		OutputFormat: outputFmt,
		SaveResults:  saveFile,
	}

	// Create and run test suite
	suite := NewTestSuite(config)
	if err := suite.Run(); err != nil {
		fmt.Printf("%sError running tests: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}

	// Exit with error code if critical issues found
	for _, issue := range suite.Summary.Issues {
		if issue.Severity == "Critical" {
			fmt.Printf("\n%s⚠️  Critical security issues detected! Review the results above.%s\n", Red, Reset)
			os.Exit(2)
		}
	}

	fmt.Printf("\n%s✅ CORS security assessment completed successfully%s\n", Green, Reset)
}
