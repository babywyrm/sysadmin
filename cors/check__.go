// cors_tester.go
//
// Advanced CORS Tester (2025 Edition) in Go
//
// Usage:
//   go run cors_tester.go --url http://localhost:8000/api/resource
//   go run cors_tester.go --url http://localhost:8000/api/resource --token mytoken --cookie "sessionId=abc123" --header "X-Session-Token: mytoken" --verbose
//
// Build:
//   go build -o cors_tester cors_tester.go
//
//
/* # Basic usage
go run cors_tester.go --url http://localhost:8000/api/resource

# With session token, cookies, and custom headers
go run cors_tester.go --url http://localhost:8000/api/resource \
  --token mytoken \
  --cookie "sessionId=abc123" --cookie "foo=bar" \
  --header "X-Session-Token: mytoken" --header "Authorization: Bearer mytoken" \
  --verbose
*/


package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Color codes for output
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
)

type CORSTestCase struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Expect      CORSTestExpect
	Description string
	Verbose     bool
}

type CORSTestExpect struct {
	Status        int
	Headers       map[string]string
	HeadersAbsent []string
}

func (tc *CORSTestCase) Run(extraHeaders map[string]string, cookies []string) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var body io.Reader
	if tc.Body != "" {
		body = bytes.NewBuffer([]byte(tc.Body))
	}
	req, err := http.NewRequest(tc.Method, tc.URL, body)
	if err != nil {
		return nil, err
	}
	// Merge test headers and extra headers (extraHeaders take precedence)
	for k, v := range tc.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	// Merge cookies
	if len(cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(cookies, "; "))
	}
	return client.Do(req)
}

func (tc *CORSTestCase) PrintResult(resp *http.Response) {
	fmt.Printf("%s=== %s ===%s\n", Cyan, tc.Name, Reset)
	if tc.Description != "" {
		fmt.Println(tc.Description)
	}
	if resp != nil && tc.Verbose {
		fmt.Printf("Status: %d\n", resp.StatusCode)
		fmt.Println("Headers:")
		for k, v := range resp.Header {
			fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(body) > 0 && len(body) < 1000 {
			fmt.Println("Body:")
			fmt.Println(string(body))
		}
	}
	fmt.Println(strings.Repeat("-", 40))
}

func (tc *CORSTestCase) Check(resp *http.Response) bool {
	if resp == nil {
		fmt.Printf("%s  ✗ No response%s\n", Red, Reset)
		return false
	}
	passed := true
	if tc.Expect.Status != 0 && resp.StatusCode != tc.Expect.Status {
		fmt.Printf("%s  ✗ Expected status %d, got %d%s\n", Red, tc.Expect.Status, resp.StatusCode, Reset)
		passed = false
	}
	for h, v := range tc.Expect.Headers {
		actual := resp.Header.Get(h)
		if v == "*" {
			if actual == "" {
				fmt.Printf("%s  ✗ Expected header %s to be present%s\n", Red, h, Reset)
				passed = false
			}
		} else if actual != v {
			fmt.Printf("%s  ✗ Expected header %s: %s, got: %s%s\n", Red, h, v, actual, Reset)
			passed = false
		}
	}
	for _, h := range tc.Expect.HeadersAbsent {
		if resp.Header.Get(h) != "" {
			fmt.Printf("%s  ✗ Header %s should NOT be present%s\n", Red, h, Reset)
			passed = false
		}
	}
	if passed {
		fmt.Printf("%s  ✓ Passed%s\n", Green, Reset)
	}
	return passed
}

func buildTests(apiURL, token string, origins []string, verbose bool) []CORSTestCase {
	// Use provided origins or defaults
	trustedOrigin := "http://trusted-origin.com"
	testOrigin := "http://test-origin.com"
	untrustedOrigin := "http://untrusted-origin.com"
	wildcardOrigin := "http://wildcard-test.com"
	if len(origins) > 0 {
		trustedOrigin = origins[0]
	}
	if len(origins) > 1 {
		testOrigin = origins[1]
	}
	if len(origins) > 2 {
		untrustedOrigin = origins[2]
	}
	if len(origins) > 3 {
		wildcardOrigin = origins[3]
	}

	jsonBody, _ := json.Marshal(map[string]string{"key": "value"})
	patchBody, _ := json.Marshal(map[string]string{"patch": "value"})

	return []CORSTestCase{
		{
			Name:   "Preflight OPTIONS",
			Method: "OPTIONS",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin":                        testOrigin,
				"Access-Control-Request-Method": "GET",
				"Access-Control-Request-Headers": "Content-Type",
			},
			Expect: CORSTestExpect{
				Status: 200,
				Headers: map[string]string{
					"Access-Control-Allow-Origin":  testOrigin,
					"Access-Control-Allow-Methods": "*",
					"Access-Control-Allow-Headers": "*",
				},
			},
			Description: "Checks if preflight OPTIONS returns correct CORS headers.",
			Verbose:     verbose,
		},
		{
			Name:   "Simple GET with Origin",
			Method: "GET",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin": testOrigin,
			},
			Expect: CORSTestExpect{
				Status: 200,
				Headers: map[string]string{
					"Access-Control-Allow-Origin": testOrigin,
				},
			},
			Description: "Checks if GET with Origin returns Access-Control-Allow-Origin.",
			Verbose:     verbose,
		},
		{
			Name:   "POST with Custom Header",
			Method: "POST",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin":          testOrigin,
				"X-Custom-Header": "custom-value",
				"Content-Type":    "application/json",
			},
			Body: string(jsonBody),
			Expect: CORSTestExpect{
				Status: 200,
				Headers: map[string]string{
					"Access-Control-Allow-Headers": "*",
				},
			},
			Description: "Checks if custom headers are allowed in CORS.",
			Verbose:     verbose,
		},
		{
			Name:   "DELETE Not Allowed",
			Method: "DELETE",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin": testOrigin,
			},
			Expect: CORSTestExpect{
				Status:        405,
				HeadersAbsent: []string{"Access-Control-Allow-Origin"},
			},
			Description: "Checks if disallowed methods are blocked by CORS.",
			Verbose:     verbose,
		},
		{
			Name:   "Origin Reflection (Untrusted)",
			Method: "GET",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin": untrustedOrigin,
			},
			Expect: CORSTestExpect{
				Status:        200,
				HeadersAbsent: []string{"Access-Control-Allow-Origin"},
			},
			Description: "Checks if server reflects untrusted Origin (should not).",
			Verbose:     verbose,
		},
		{
			Name:   "Wildcard Origin",
			Method: "GET",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin": wildcardOrigin,
			},
			Expect: CORSTestExpect{
				Status: 200,
				Headers: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
			Description: "Checks if server uses wildcard for Access-Control-Allow-Origin.",
			Verbose:     verbose,
		},
		{
			Name:   "Credentials Handling",
			Method: "GET",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin":        trustedOrigin,
				"Authorization": "Bearer " + token,
				"Cookie":        "sessionId=abc123",
			},
			Expect: CORSTestExpect{
				Status: 200,
				Headers: map[string]string{
					"Access-Control-Allow-Origin":      trustedOrigin,
					"Access-Control-Allow-Credentials": "true",
				},
			},
			Description: "Checks if credentials are allowed and CORS headers are correct.",
			Verbose:     verbose,
		},
		{
			Name:   "Invalid Origin",
			Method: "GET",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin": untrustedOrigin,
			},
			Expect: CORSTestExpect{
				Status:        200,
				HeadersAbsent: []string{"Access-Control-Allow-Origin"},
			},
			Description: "Checks if untrusted origins are blocked.",
			Verbose:     verbose,
		},
		{
			Name:   "Malformed Preflight",
			Method: "OPTIONS",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin":                        "malformed",
				"Access-Control-Request-Method": "PUT",
			},
			Expect: CORSTestExpect{
				Status: 400,
			},
			Description: "Checks if malformed preflight is rejected.",
			Verbose:     verbose,
		},
		{
			Name:   "PATCH with Origin",
			Method: "PATCH",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin":       testOrigin,
				"Content-Type": "application/json",
			},
			Body: string(patchBody),
			Expect: CORSTestExpect{
				Status: 200,
				Headers: map[string]string{
					"Access-Control-Allow-Origin": testOrigin,
				},
			},
			Description: "Checks PATCH method CORS handling.",
			Verbose:     verbose,
		},
		{
			Name:   "WebDAV PROPFIND",
			Method: "PROPFIND",
			URL:    apiURL,
			Headers: map[string]string{
				"Origin": testOrigin,
			},
			Expect: CORSTestExpect{
				Status: 405,
			},
			Description: "Checks WebDAV method CORS handling (should be blocked unless allowed).",
			Verbose:     verbose,
		},
	}
}

func printHelp() {
	fmt.Println(`Advanced CORS Tester (2025 Edition) in Go

Usage:
  cors_tester --url <endpoint> [--token <token>] [--origins <trusted> <test> <untrusted> <wildcard>] [--cookie "name=value"] [--header "Header: value"] [--verbose]

Options:
  --url, -u      Target API endpoint (e.g., http://localhost:8000/api/resource) [required]
  --token, -t    Bearer token for Authorization header (used in credentials test)
  --origins, -o  List of origins: trusted test untrusted wildcard (default: built-in)
  --cookie, -c   Cookie to send (repeatable, e.g., --cookie "sessionId=abc123" --cookie "foo=bar")
  --header, -H   Extra header to send (repeatable, e.g., --header "X-Session-Token: mytoken")
  --verbose, -v  Show full response headers and body
  --help, -h     Show this help message

Examples:
  cors_tester --url http://localhost:8000/api/resource
  cors_tester --url http://localhost:8000/api/resource --token mytoken
  cors_tester --url http://localhost:8000/api/resource --origins http://trusted.com http://test.com http://untrusted.com http://wildcard.com --cookie "sessionId=abc123" --header "X-Session-Token: mytoken" --verbose
`)
}

func main() {
	var (
		apiURL  string
		token   string
		verbose bool
	)
	var origins multiFlag
	var cookies multiFlag
	var headers multiFlag

	flag.StringVar(&apiURL, "url", "", "Target API endpoint (required)")
	flag.StringVar(&apiURL, "u", "", "Target API endpoint (required)")
	flag.StringVar(&token, "token", "", "Bearer token for Authorization header")
	flag.StringVar(&token, "t", "", "Bearer token for Authorization header")
	flag.Var(&origins, "origins", "List of origins: trusted test untrusted wildcard")
	flag.Var(&origins, "o", "List of origins: trusted test untrusted wildcard")
	flag.Var(&cookies, "cookie", "Cookie to send (repeatable, e.g., --cookie \"sessionId=abc123\")")
	flag.Var(&cookies, "c", "Cookie to send (repeatable, e.g., --cookie \"sessionId=abc123\")")
	flag.Var(&headers, "header", "Extra header to send (repeatable, e.g., --header \"X-Session-Token: mytoken\")")
	flag.Var(&headers, "H", "Extra header to send (repeatable, e.g., --header \"X-Session-Token: mytoken\")")
	flag.BoolVar(&verbose, "verbose", false, "Show full response headers and body")
	flag.BoolVar(&verbose, "v", false, "Show full response headers and body")
	help := flag.Bool("help", false, "Show help")
	flag.BoolVar(help, "h", false, "Show help")
	flag.Parse()

	if *help || apiURL == "" {
		printHelp()
		os.Exit(0)
	}

	// Parse extra headers into a map
	extraHeaders := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			extraHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	tests := buildTests(apiURL, token, origins, verbose)

	fmt.Printf("%sStarting Advanced CORS Tests...%s\n\n", Yellow, Reset)
	for _, test := range tests {
		resp, err := test.Run(extraHeaders, cookies)
		test.PrintResult(resp)
		test.Check(resp)
		fmt.Println()
	}
	fmt.Printf("%sAll tests completed. Review results above.%s\n", Green, Reset)
}

// multiFlag allows repeated string flags (for --origins, --cookie, --header)
type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", *m)
}
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}
