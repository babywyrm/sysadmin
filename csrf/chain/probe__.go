package main

//
//  (..testing..)
//

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type SecurityHeaders struct {
	CSP                    string `json:"content_security_policy"`
	XFrameOptions          string `json:"x_frame_options"`
	XContentTypeOptions    string `json:"x_content_type_options"`
	StrictTransportSecurity string `json:"strict_transport_security"`
	ReferrerPolicy         string `json:"referrer_policy"`
	PermissionsPolicy      string `json:"permissions_policy"`
}

type CookieAnalysis struct {
	Name     string `json:"name"`
	SameSite string `json:"samesite"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httponly"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
}

type CSPAnalysis struct {
	Raw              string              `json:"raw"`
	Directives       map[string][]string `json:"directives"`
	UnsafeInline     bool                `json:"unsafe_inline"`
	UnsafeEval       bool                `json:"unsafe_eval"`
	AllowsData       bool                `json:"allows_data"`
	AllowsWildcard   bool                `json:"allows_wildcard"`
	BypassSuggestions []string           `json:"bypass_suggestions"`
}

type CORSAnalysis struct {
	AllowOrigin      string   `json:"allow_origin"`
	AllowMethods     []string `json:"allow_methods"`
	AllowHeaders     []string `json:"allow_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	Vulnerable       bool     `json:"vulnerable"`
	Issues           []string `json:"issues"`
}

type XSSTest struct {
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Reflected bool   `json:"reflected"`
	Filtered  bool   `json:"filtered"`
	Context   string `json:"context"`
}

type SecurityReport struct {
	Target          string            `json:"target"`
	Timestamp       string            `json:"timestamp"`
	StatusCode      int               `json:"status_code"`
	SecurityHeaders SecurityHeaders   `json:"security_headers"`
	Cookies         []CookieAnalysis  `json:"cookies"`
	CSP             CSPAnalysis       `json:"csp_analysis"`
	CORS            CORSAnalysis      `json:"cors_analysis"`
	XSSTests        []XSSTest         `json:"xss_tests"`
	CSRFRisk        string            `json:"csrf_risk"`
	XSSRisk         string            `json:"xss_risk"`
	Recommendations []string          `json:"recommendations"`
}

type SecurityProbe struct {
	client    *http.Client
	userAgent string
	proxy     string
}

func NewSecurityProbe(timeout int, proxy string, skipTLS bool) *SecurityProbe {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	return &SecurityProbe{
		client:    client,
		userAgent: "SecurityProbe/1.0 (XSS-CSRF-Scanner)",
		proxy:     proxy,
	}
}

func (sp *SecurityProbe) ProbeTarget(targetURL string) (*SecurityReport, error) {
	report := &SecurityReport{
		Target:    targetURL,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Initial request to get headers
	resp, err := sp.makeRequest("GET", targetURL, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to probe target: %v", err)
	}
	defer resp.Body.Close()

	report.StatusCode = resp.StatusCode

	// Analyze security headers
	report.SecurityHeaders = sp.analyzeSecurityHeaders(resp.Header)

	// Analyze cookies
	report.Cookies = sp.analyzeCookies(resp.Cookies())

	// Analyze CSP
	report.CSP = sp.analyzeCSP(resp.Header.Get("Content-Security-Policy"))

	// Test CORS
	report.CORS = sp.testCORS(targetURL)

	// Basic XSS tests
	report.XSSTests = sp.testXSS(targetURL)

	// Risk assessment
	report.CSRFRisk = sp.assessCSRFRisk(report)
	report.XSSRisk = sp.assessXSSRisk(report)

	// Generate recommendations
	report.Recommendations = sp.generateRecommendations(report)

	return report, nil
}

func (sp *SecurityProbe) makeRequest(method, url string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", sp.userAgent)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return sp.client.Do(req)
}

func (sp *SecurityProbe) analyzeSecurityHeaders(headers http.Header) SecurityHeaders {
	return SecurityHeaders{
		CSP:                    headers.Get("Content-Security-Policy"),
		XFrameOptions:          headers.Get("X-Frame-Options"),
		XContentTypeOptions:    headers.Get("X-Content-Type-Options"),
		StrictTransportSecurity: headers.Get("Strict-Transport-Security"),
		ReferrerPolicy:         headers.Get("Referrer-Policy"),
		PermissionsPolicy:      headers.Get("Permissions-Policy"),
	}
}

func (sp *SecurityProbe) analyzeCookies(cookies []*http.Cookie) []CookieAnalysis {
	var analysis []CookieAnalysis

	for _, cookie := range cookies {
		sameSite := "None" // Default
		switch cookie.SameSite {
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}

		analysis = append(analysis, CookieAnalysis{
			Name:     cookie.Name,
			SameSite: sameSite,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
		})
	}

	return analysis
}

func (sp *SecurityProbe) analyzeCSP(cspHeader string) CSPAnalysis {
	analysis := CSPAnalysis{
		Raw:        cspHeader,
		Directives: make(map[string][]string),
	}

	if cspHeader == "" {
		analysis.BypassSuggestions = []string{"No CSP detected - all XSS vectors should work"}
		return analysis
	}

	// Parse CSP directives
	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		if len(parts) > 0 {
			directiveName := parts[0]
			sources := parts[1:]
			analysis.Directives[directiveName] = sources

			// Check for unsafe settings
			for _, source := range sources {
				switch source {
				case "'unsafe-inline'":
					analysis.UnsafeInline = true
				case "'unsafe-eval'":
					analysis.UnsafeEval = true
				case "data:":
					analysis.AllowsData = true
				case "*":
					analysis.AllowsWildcard = true
				}
			}
		}
	}

	// Generate bypass suggestions
	analysis.BypassSuggestions = sp.generateCSPBypasses(analysis)

	return analysis
}

func (sp *SecurityProbe) generateCSPBypasses(csp CSPAnalysis) []string {
	var suggestions []string

	if csp.UnsafeInline {
		suggestions = append(suggestions, "unsafe-inline allows direct script injection")
	}

	if csp.UnsafeEval {
		suggestions = append(suggestions, "unsafe-eval allows eval() and Function() bypasses")
	}

	if csp.AllowsWildcard {
		suggestions = append(suggestions, "Wildcard (*) allows external script injection")
	}

	if csp.AllowsData {
		suggestions = append(suggestions, "data: URIs allowed - try data:text/html,<script>alert(1)</script>")
	}

	// Check for JSONP endpoints
	scriptSrc := csp.Directives["script-src"]
	for _, source := range scriptSrc {
		if strings.Contains(source, "googleapis.com") {
			suggestions = append(suggestions, "Google APIs detected - potential JSONP bypass")
		}
		if strings.Contains(source, "ajax.cloudflare.com") {
			suggestions = append(suggestions, "Cloudflare AJAX - potential JSONP bypass")
		}
	}

	// Check for nonces/hashes
	for _, source := range scriptSrc {
		if strings.HasPrefix(source, "'nonce-") {
			suggestions = append(suggestions, "Nonce-based CSP - look for nonce extraction")
		}
		if strings.HasPrefix(source, "'sha") {
			suggestions = append(suggestions, "Hash-based CSP - need exact script match")
		}
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Restrictive CSP - limited bypass options")
	}

	return suggestions
}

func (sp *SecurityProbe) testCORS(targetURL string) CORSAnalysis {
	analysis := CORSAnalysis{}

	// Test with different origins
	testOrigins := []string{
		"https://evil.com",
		"null",
		"https://attacker.evil.com",
	}

	for _, origin := range testOrigins {
		headers := map[string]string{
			"Origin": origin,
		}

		resp, err := sp.makeRequest("GET", targetURL, headers, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		if allowOrigin != "" {
			analysis.AllowOrigin = allowOrigin

			if allowOrigin == "*" || allowOrigin == origin {
				analysis.Vulnerable = true
				analysis.Issues = append(analysis.Issues, 
					fmt.Sprintf("CORS allows origin: %s", origin))
			}
		}

		allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
		if allowMethods != "" {
			analysis.AllowMethods = strings.Split(allowMethods, ",")
		}

		allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
		if allowHeaders != "" {
			analysis.AllowHeaders = strings.Split(allowHeaders, ",")
		}

		allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
		if strings.ToLower(allowCredentials) == "true" {
			analysis.AllowCredentials = true
		}
	}

	// Test preflight
	preflight := map[string]string{
		"Origin":                        "https://evil.com",
		"Access-Control-Request-Method": "POST",
		"Access-Control-Request-Headers": "Content-Type",
	}

	resp, err := sp.makeRequest("OPTIONS", targetURL, preflight, nil)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			analysis.Issues = append(analysis.Issues, "Preflight requests allowed")
		}
	}

	return analysis
}

func (sp *SecurityProbe) testXSS(targetURL string) []XSSTest {
	var tests []XSSTest

	// Basic XSS payloads
	payloads := []string{
		"<script>alert(1)</script>",
		"'><script>alert(1)</script>",
		"\"><script>alert(1)</script>",
		"javascript:alert(1)",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
	}

	// Common parameter names
	params := []string{"q", "search", "name", "comment", "message", "input"}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", targetURL, param, url.QueryEscape(payload))
			
			resp, err := sp.makeRequest("GET", testURL, nil, nil)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := string(body)
			
			test := XSSTest{
				Parameter: param,
				Payload:   payload,
				Reflected: strings.Contains(bodyStr, payload),
				Context:   sp.detectXSSContext(bodyStr, payload),
			}

			// Check if filtered
			if !test.Reflected && (strings.Contains(bodyStr, "script") || 
				strings.Contains(bodyStr, "alert")) {
				test.Filtered = true
			}

			tests = append(tests, test)
		}
	}

	return tests
}

func (sp *SecurityProbe) detectXSSContext(body, payload string) string {
	// Simple context detection
	escapedPayload := regexp.QuoteMeta(payload)
	
	// Check if in HTML attribute
	attrPattern := regexp.MustCompile(`<[^>]*` + escapedPayload + `[^>]*>`)
	if attrPattern.MatchString(body) {
		return "HTML_ATTRIBUTE"
	}

	// Check if in script tag
	scriptPattern := regexp.MustCompile(`<script[^>]*>.*` + escapedPayload + `.*</script>`)
	if scriptPattern.MatchString(body) {
		return "SCRIPT_TAG"
	}

	// Check if in HTML content
	if strings.Contains(body, payload) {
		return "HTML_CONTENT"
	}

	return "UNKNOWN"
}

func (sp *SecurityProbe) assessCSRFRisk(report *SecurityReport) string {
	risk := "HIGH"

	// Check SameSite cookies
	strictCookies := 0
	for _, cookie := range report.Cookies {
		if cookie.SameSite == "Strict" {
			strictCookies++
		}
	}

	if strictCookies > 0 {
		risk = "MEDIUM"
	}

	// Check for CSRF tokens (basic check)
	// This would need more sophisticated analysis in practice
	if report.StatusCode == 200 {
		// Assume some CSRF protection if we see common patterns
		// In practice, you'd analyze form tokens here
	}

	return risk
}

func (sp *SecurityProbe) assessXSSRisk(report *SecurityReport) string {
	risk := "LOW"

	// No CSP = high risk
	if report.CSP.Raw == "" {
		risk = "HIGH"
	} else if report.CSP.UnsafeInline {
		risk = "HIGH"
	} else if len(report.CSP.BypassSuggestions) > 1 {
		risk = "MEDIUM"
	}

	// Check for reflected XSS
	for _, test := range report.XSSTests {
		if test.Reflected && !test.Filtered {
			risk = "HIGH"
			break
		}
	}

	return risk
}

func (sp *SecurityProbe) generateRecommendations(report *SecurityReport) []string {
	var recommendations []string

	if report.CSP.Raw == "" {
		recommendations = append(recommendations, "Implement Content Security Policy")
	}

	if report.SecurityHeaders.XFrameOptions == "" {
		recommendations = append(recommendations, "Add X-Frame-Options header to prevent clickjacking")
	}

	if report.CORS.Vulnerable {
		recommendations = append(recommendations, "Review CORS configuration - overly permissive")
	}

	hasSecureCookies := false
	for _, cookie := range report.Cookies {
		if cookie.Secure && cookie.SameSite != "None" {
			hasSecureCookies = true
			break
		}
	}

	if !hasSecureCookies {
		recommendations = append(recommendations, "Implement Secure and SameSite cookie attributes")
	}

	for _, test := range report.XSSTests {
		if test.Reflected {
			recommendations = append(recommendations, 
				fmt.Sprintf("XSS vulnerability detected in parameter: %s", test.Parameter))
		}
	}

	return recommendations
}

func probeBatch(targets []string, workers int, timeout int, proxy string, skipTLS bool, output string) {
	jobs := make(chan string, len(targets))
	results := make(chan *SecurityReport, len(targets))
	
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probe := NewSecurityProbe(timeout, proxy, skipTLS)
			
			for target := range jobs {
				fmt.Printf("Probing: %s\n", target)
				report, err := probe.ProbeTarget(target)
				if err != nil {
					fmt.Printf("Error probing %s: %v\n", target, err)
					continue
				}
				results <- report
			}
		}()
	}

	// Send jobs
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var reports []*SecurityReport
	for report := range results {
		reports = append(reports, report)
	}

	// Output results
	if output != "" {
		outputFile, err := os.Create(output)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			return
		}
		defer outputFile.Close()

		encoder := json.NewEncoder(outputFile)
		encoder.SetIndent("", "  ")
		encoder.Encode(reports)
		fmt.Printf("Results saved to: %s\n", output)
	} else {
		for _, report := range reports {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			encoder.Encode(report)
		}
	}
}

func main() {
	var (
		target     = flag.String("target", "", "Target URL to probe")
		file       = flag.String("file", "", "File containing list of URLs")
		workers    = flag.Int("workers", 10, "Number of concurrent workers")
		timeout    = flag.Int("timeout", 10, "Request timeout in seconds")
		proxy      = flag.String("proxy", "", "HTTP proxy (e.g., http://127.0.0.1:8080)")
		skipTLS    = flag.Bool("skip-tls", false, "Skip TLS certificate verification")
		output     = flag.String("output", "", "Output file for JSON results")
	)
	flag.Parse()

	if *target == "" && *file == "" {
		fmt.Println("Usage: security-probe -target <URL> OR -file <url-list>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var targets []string

	if *target != "" {
		targets = append(targets, *target)
	}

	if *file != "" {
		fileContent, err := os.ReadFile(*file)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}

		lines := strings.Split(string(fileContent), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	probeBatch(targets, *workers, *timeout, *proxy, *skipTLS, *output)
}
