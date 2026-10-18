package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func parseCookies(cookieString string) map[string]string {
	cookies := make(map[string]string)
	cookiePairs := strings.Split(cookieString, ";")
	for _, pair := range cookiePairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			cookies[parts[0]] = parts[1]
		}
	}
	return cookies
}

func parseHeaders(headerStrings []string) map[string]string {
	headers := make(map[string]string)
	for _, header := range headerStrings {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func checkCors(targetURL string, headers map[string]string, cookies map[string]string) []map[string]interface{} {
	testOrigins := []string{
		"https://evil.com",
		"http://example.com",
		"null",
	}

	results := []map[string]interface{}{}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, origin := range testOrigins {
		req, err := http.NewRequest("OPTIONS", targetURL, nil)
		if err != nil {
			results = append(results, map[string]interface{}{
				"origin": origin,
				"error":  err.Error(),
			})
			continue
		}

		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "GET")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		for key, value := range cookies {
			req.AddCookie(&http.Cookie{Name: key, Value: value})
		}

		resp, err := client.Do(req)
		if err != nil {
			results = append(results, map[string]interface{}{
				"origin": origin,
				"error":  err.Error(),
			})
			continue
		}

		corsHeaders := make(map[string]string)
		for key, values := range resp.Header {
			if strings.HasPrefix(strings.ToLower(key), "access-control-") {
				corsHeaders[key] = values[0]
			}
		}

		results = append(results, map[string]interface{}{
			"origin":      origin,
			"status_code": resp.StatusCode,
			"cors_headers": corsHeaders,
		})
	}

	return results
}

func analyzeResults(results []map[string]interface{}) {
	for _, result := range results {
		if err, ok := result["error"]; ok {
			fmt.Printf("Origin: %s, Error: %s\n", result["origin"], err)
		} else {
			fmt.Printf("Origin: %s, Status Code: %d\n", result["origin"], result["status_code"])
			if corsHeaders, ok := result["cors_headers"].(map[string]string); ok {
				if len(corsHeaders) > 0 {
					for key, value := range corsHeaders {
						fmt.Printf("  %s: %s\n", key, value)
					}
				} else {
					fmt.Println("  No CORS headers found.")
				}

				// Security analysis
				if value, ok := corsHeaders["Access-Control-Allow-Origin"]; ok {
					if value == "*" {
						fmt.Println("  Warning: Access-Control-Allow-Origin is set to '*', which is risky.")
					} else {
						fmt.Printf("  Access-Control-Allow-Origin is set to '%s'\n", value)
					}
				} else {
					fmt.Println("  Warning: No Access-Control-Allow-Origin header found.")
				}

				if value, ok := corsHeaders["Access-Control-Allow-Credentials"]; ok {
					if strings.ToLower(value) == "true" {
						fmt.Println("  Warning: Access-Control-Allow-Credentials is 'true', which can be risky.")
					}
				}
			} else {
				fmt.Println("  No CORS headers found. This may be secure if no cross-origin access is needed.")
			}
			fmt.Println()
		}
	}
}

func main() {
	url := flag.String("url", "", "Target URL to scan")
	cookieString := flag.String("cookies", "", "Cookies to include in the requests, separated by ';'")
	headerStrings := flag.String("header", "", "Additional headers to include in the requests, separated by ','")

	flag.Parse()

	if *url == "" {
		fmt.Println("URL is required")
		flag.Usage()
		return
	}

	headers := parseHeaders(strings.Split(*headerStrings, ","))
	cookies := parseCookies(*cookieString)

	results := checkCors(*url, headers, cookies)
	analyzeResults(results)
}


//
//
// Build the Script: Open a terminal and navigate to the directory where you saved the script. Run the following command to build the script:
//
// go build cors_scanner.go
// Run the Script: Execute the compiled binary with the required arguments. For example:
//
// ./cors_scanner --url https://target-host.com --cookies "sessionid=abc123;othercookie=value" --header "Authorization: Bearer token,X-Custom-Header: value"
// This Go version replicates the functionality of the Python script, checking CORS headers for different origins and reporting the results with a security analysis.
//
//




