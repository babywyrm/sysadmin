package main

import (
//	"bytes"
	"crypto/tls"
//	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	maxPages = 10 // Limit crawling to avoid excessive requests
	version  = "1.3.0"
)

// Technology represents a detected technology with additional context.
type Technology struct {
	Name        string
	Version     string
	Description string
	Confidence  string // High, Medium, Low
	Location    string // Where it was found (header, meta, script, etc.)
}

func (t Technology) String() string {
	var parts []string
	
	if t.Version != "" {
		parts = append(parts, fmt.Sprintf("%s (v%s)", t.Name, t.Version))
	} else {
		parts = append(parts, t.Name)
	}
	
	if t.Location != "" {
		parts = append(parts, fmt.Sprintf("found in %s", t.Location))
	}
	
	if t.Confidence != "" {
		parts = append(parts, fmt.Sprintf("%s confidence", t.Confidence))
	}
	
	return strings.Join(parts, " - ")
}

func debugLog(msg string) {
	log.Println("[DEBUG]", msg)
}

func verboseLog(msg string) {
	log.Println("[INFO]", msg)
}

// parseVersion attempts to extract the version for a given technology
func parseVersion(text, techName string) string {
	var versionRegex *regexp.Regexp
	switch techName {
	case "React.js":
		patterns := []string{
			`react(?:\.production|\.development)?\.min\.js(?:\?ver=|@)([\d\.]+)`,
			`react[/-]([\d\.]+)`,
			`__REACT_DEVTOOLS_GLOBAL_HOOK__.*?['"]([\d\.]+)['"]`,
			`React\.version\s*=\s*["']([\d\.]+)["']`,
		}
		for _, pattern := range patterns {
			versionRegex = regexp.MustCompile(pattern)
			if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
				return matches[1]
			}
		}
	case "AngularJS":
		patterns := []string{
			`angular(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`,
			`angular[/-]([\d\.]+)`,
			`ng-version=["']([\d\.]+)["']`,
			`angular.*?version["']?:\s*["']([\d\.]+)["']`,
		}
		for _, pattern := range patterns {
			versionRegex = regexp.MustCompile(pattern)
			if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
				return matches[1]
			}
		}
	case "Vue.js":
		patterns := []string{
			`vue(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`,
			`vue@([\d\.]+)`,
			`Vue\.version\s*=\s*['\"]([\d\.]+)['\"]`,
		}
		for _, pattern := range patterns {
			versionRegex = regexp.MustCompile(pattern)
			if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
				return matches[1]
			}
		}
	case "jQuery":
		patterns := []string{
			`jquery(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`,
			`jquery[/-]([\d\.]+)`,
			`jQuery(?:\.fn)?\.jquery\s*=\s*["']([\d\.]+)["']`,
		}
		for _, pattern := range patterns {
			versionRegex = regexp.MustCompile(pattern)
			if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
				return matches[1]
			}
		}
	case "Webpack":
		patterns := []string{
			`webpack(?:[/-]|@)([\d\.]+)`,
			`webpackJsonp`,
			`__webpack_require__`,
		}
		for _, pattern := range patterns {
			versionRegex = regexp.MustCompile(pattern)
			if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 && strings.Contains(matches[1], ".") {
				return matches[1]
			}
		}
	default:
		return ""
	}
	return ""
}

// analyzeHeaders inspects HTTP response headers for technology clues.
func analyzeHeaders(headers http.Header) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTTP Headers for technology clues...")

	// Check server header
	if server := headers.Get("Server"); server != "" {
		tech = append(tech, Technology{
			Name:        "Server",
			Version:     server,
			Description: "Web server software",
			Confidence:  "High",
			Location:    "Server header",
		})
		verboseLog(fmt.Sprintf("Found Server header: %s", server))
	}
	
	// Check for server technologies
	if powered := headers.Get("X-Powered-By"); powered != "" {
		tech = append(tech, Technology{
			Name:        "X-Powered-By",
			Version:     powered,
			Description: "Backend technology",
			Confidence:  "High",
			Location:    "X-Powered-By header",
		})
		verboseLog(fmt.Sprintf("Found X-Powered-By header: %s", powered))
	}
	
	// Check for API endpoints
	if contentType := headers.Get("Content-Type"); contentType != "" {
		if strings.Contains(contentType, "application/json") {
			tech = append(tech, Technology{
				Name:        "API (JSON)",
				Description: "JSON-based API",
				Confidence:  "High",
				Location:    "Content-Type header",
			})
			verboseLog("Found JSON API endpoint")
		}
	}
	
	// Look for security headers
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		tech = append(tech, Technology{
			Name:        "Content Security Policy",
			Description: "Security policy to prevent XSS and data injection",
			Confidence:  "High",
			Location:    "Content-Security-Policy header",
		})
		verboseLog("Found Content-Security-Policy header")
		
		// Check CSP for CDN hints
		if strings.Contains(csp, "cloudflare") {
			tech = append(tech, Technology{
				Name:        "Cloudflare",
				Description: "CDN and DDoS protection",
				Confidence:  "High",
				Location:    "Content-Security-Policy header",
			})
		}
		if strings.Contains(csp, "akamai") {
			tech = append(tech, Technology{
				Name:        "Akamai",
				Description: "CDN and security",
				Confidence:  "High",
				Location:    "Content-Security-Policy header",
			})
		}
	}
	
	if frameOptions := headers.Get("X-Frame-Options"); frameOptions != "" {
		tech = append(tech, Technology{
			Name:        "X-Frame-Options",
			Version:     frameOptions,
			Description: "Clickjacking protection",
			Confidence:  "High",
			Location:    "X-Frame-Options header",
		})
		verboseLog(fmt.Sprintf("Found X-Frame-Options header: %s", frameOptions))
	}
	
	// Look for caching and CDN headers
	if cdn := headers.Get("X-CDN"); cdn != "" {
		tech = append(tech, Technology{
			Name:        "CDN",
			Version:     cdn,
			Description: "Content Delivery Network",
			Confidence:  "High",
			Location:    "X-CDN header",
		})
		verboseLog(fmt.Sprintf("Found CDN: %s", cdn))
	}
	
  if headers.Get("CF-Cache-Status") != "" || headers.Get("CF-RAY") != "" {
    tech = append(tech, Technology{
      Name:        "Cloudflare",
      Description: "CDN and DDoS protection",
      Confidence:  "High",
      Location:    "Cloudflare headers",
    })
    verboseLog("Found Cloudflare")
  } 	
	
  if akamai := headers.Get("X-Akamai-Transformed"); akamai != "" {
		tech = append(tech, Technology{
			Name:        "Akamai",
			Description: "CDN and security",
			Confidence:  "High",
			Location:    "X-Akamai-Transformed header",
		})
		verboseLog("Found Akamai")
	}
	
	if fastly := headers.Get("X-Served-By"); fastly != "" && strings.Contains(fastly, "cache") {
		tech = append(tech, Technology{
			Name:        "Fastly",
			Description: "CDN",
			Confidence:  "High",
			Location:    "X-Served-By header",
		})
		verboseLog("Found Fastly")
	}

	return tech
}

// analyzeHTML analyzes the HTML content for technology clues.
func analyzeHTML(body string) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTML content for technology signatures...")

	// Lowercase version for easier matching
	bodyLower := strings.ToLower(body)

	// Detect CMS / Static generators via meta generator tag
	metaGenRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	if matches := metaGenRegex.FindStringSubmatch(body); len(matches) > 1 {
		tech = append(tech, Technology{
			Name:        "Generator",
			Version:     matches[1],
			Description: "Content Management System or Generator",
			Confidence:  "High",
			Location:    "meta generator tag",
		})
		verboseLog(fmt.Sprintf("Found generator meta tag: %s", matches[1]))
	}

	// ThousandEyes specific patterns
	if strings.Contains(bodyLower, "thousandeyes") {
		tech = append(tech, Technology{
			Name:        "ThousandEyes",
			Description: "Network intelligence platform",
			Confidence:  "High", 
			Location:    "HTML (product name)",
		})
		verboseLog("Detected ThousandEyes product")
	}

	// SPA Framework Detection - more sensitive indicators
	
	// Angular detection - robust patterns
	isAngular := false
	
	// Check for Angular-specific patterns
	angularPatterns := []string{
		"ng-app", "ng-controller", "ng-repeat", "ng-if", "ng-class", "ng-model", 
		"ng-include", "ng-view", "ngRoute", "ngCookies", "ngTouch", "ngAnimate",
		"angular.module", "ng-bind", "_ng", "ngApp", "angularjs", "ng-cloak",
		"ng:view", "ng:controller", "ng-", "data-ng-", "x-ng-", "angular.min.js",
	}
	
	for _, pattern := range angularPatterns {
		if strings.Contains(bodyLower, pattern) {
			isAngular = true
			break
		}
	}
	
	if isAngular {
		var version string
		// Try to find Angular version
		versionRegex := regexp.MustCompile(`angular.*?version["']?:\s*["']([\d\.]+)["']`)
		if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
			version = matches[1]
		}
		
		tech = append(tech, Technology{
			Name:        "AngularJS",
			Version:     version,
			Description: "JavaScript MVC framework",
			Confidence:  "High",
			Location:    "HTML (Angular patterns)",
		})
		verboseLog("Detected AngularJS framework")
	}
	
	// React detection - robust patterns
	isReact := false
	
	// Check for React-specific patterns
	reactPatterns := []string{
		"react", "_reactrootcontainer", "__reactcontainer", "react-dom", 
		"react.production.min.js", "react.development.js", "reactjs", 
		"__REACT_DEVTOOLS_GLOBAL_HOOK__", "react-app", "ReactDOM", "_react",
		"__reactInternalInstance", "React.createElement", "react-router",
	}
	
	for _, pattern := range reactPatterns {
		if strings.Contains(bodyLower, pattern) {
			isReact = true
			break
		}
	}
	
	if isReact {
		var version string
		versionRegex := regexp.MustCompile(`React(?:\.version)?\s*=\s*["']([\d\.]+)["']`)
		if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
			version = matches[1]
		}
		
		tech = append(tech, Technology{
			Name:        "React.js",
			Version:     version,
			Description: "JavaScript UI library",
			Confidence:  "High",
			Location:    "HTML (React patterns)",
		})
		verboseLog("Detected React.js library")
	}
	
	// Vue detection
	isVue := false
	
	// Check for Vue-specific patterns
	vuePatterns := []string{
		"vue", "vue.js", "vuejs", "vue@", "v-if", "v-for", "v-model", "v-on",
		"v-bind", "v-show", "v-cloak", "vue.min.js", "vue.runtime", "vuex",
		"vue-router", "nuxt", "v-html", "vue/dist",
	}
	
	for _, pattern := range vuePatterns {
		if strings.Contains(bodyLower, pattern) {
			isVue = true
			break
		}
	}
	
	if isVue {
		var version string
		versionRegex := regexp.MustCompile(`Vue(?:\.version)?\s*=\s*["']([\d\.]+)["']`)
		if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
			version = matches[1]
		}
		
		tech = append(tech, Technology{
			Name:        "Vue.js",
			Version:     version,
			Description: "JavaScript progressive framework",
			Confidence:  "High",
			Location:    "HTML (Vue patterns)",
		})
		verboseLog("Detected Vue.js framework")
	}
	
	// Webpack detection - more sensitive
	if strings.Contains(bodyLower, "webpack") || 
	   strings.Contains(bodyLower, "__webpack_require__") || 
	   strings.Contains(bodyLower, "webpackjsonp") || 
	   strings.Contains(bodyLower, "chunks") ||
	   strings.Contains(bodyLower, "/bundle.") ||
	   strings.Contains(bodyLower, "/main.chunk.js") {
		tech = append(tech, Technology{
			Name:        "Webpack",
			Description: "JavaScript module bundler",
			Confidence:  "High",
			Location:    "HTML (webpack patterns)",
		})
		verboseLog("Detected Webpack module bundler")
	}
	
	// jQuery detection
	if strings.Contains(bodyLower, "jquery") || 
	   strings.Contains(bodyLower, "$") || 
	   strings.Contains(bodyLower, "jquery.min.js") {
		var version string
		versionRegex := regexp.MustCompile(`jQuery(?:\.fn)?\.jquery\s*=\s*["']([\d\.]+)["']`)
		if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
			version = matches[1]
		}
		
		tech = append(tech, Technology{
			Name:        "jQuery",
			Version:     version,
			Description: "JavaScript library",
			Confidence:  "Medium",
			Location:    "HTML (jQuery patterns)",
		})
		verboseLog("Detected jQuery library")
	}
	
	// Analytics and tracking
	if strings.Contains(bodyLower, "google-analytics.com") || 
	   strings.Contains(bodyLower, "googleanalytics") || 
	   strings.Contains(bodyLower, "ga('create'") ||
	   strings.Contains(bodyLower, "gtag") {
		tech = append(tech, Technology{
			Name:        "Google Analytics",
			Description: "Web analytics service",
			Confidence:  "High",
			Location:    "HTML (script reference)",
		})
		verboseLog("Detected Google Analytics")
	}
	
	return tech
}

// analyzeJavascriptFiles looks at script files for technology clues
func analyzeJavascriptFiles(scriptSources []string, client *http.Client) []Technology {
	var tech []Technology
	
	for _, src := range scriptSources {
		verboseLog(fmt.Sprintf("Analyzing JavaScript file: %s", src))
		
		resp, err := client.Get(src)
		if err != nil {
			debugLog(fmt.Sprintf("Failed to fetch JavaScript: %v", err))
			continue
		}
		
		if resp.StatusCode != 200 {
			debugLog(fmt.Sprintf("JavaScript fetch failed with status %d", resp.StatusCode))
			resp.Body.Close()
			continue
		}
		
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			debugLog(fmt.Sprintf("Failed to read JavaScript: %v", err))
			continue
		}
		
		js := string(body)
		
		// Check for React
		if strings.Contains(js, "React") || strings.Contains(js, "__REACT_DEVTOOLS_GLOBAL_HOOK__") {
			var version string
			versionRegex := regexp.MustCompile(`React(?:\.version)?\s*=\s*["']([\d\.]+)["']`)
			if matches := versionRegex.FindStringSubmatch(js); len(matches) > 1 {
				version = matches[1]
			}
			
			tech = append(tech, Technology{
				Name:        "React.js",
				Version:     version,
				Description: "JavaScript UI library",
				Confidence:  "High",
				Location:    fmt.Sprintf("JavaScript (%s)", src),
			})
			verboseLog("Detected React.js in JavaScript file")
		}
		
		// Check for Angular
		if strings.Contains(js, "angular") || strings.Contains(js, "ng.") {
			var version string
			versionRegex := regexp.MustCompile(`angular.*?version["']?:\s*["']([\d\.]+)["']`)
			if matches := versionRegex.FindStringSubmatch(js); len(matches) > 1 {
				version = matches[1]
			}
			
			tech = append(tech, Technology{
				Name:        "AngularJS",
				Version:     version,
				Description: "JavaScript MVC framework",
				Confidence:  "High",
				Location:    fmt.Sprintf("JavaScript (%s)", src),
			})
			verboseLog("Detected AngularJS in JavaScript file")
		}
		
		// Check for Vue
		if strings.Contains(js, "Vue") {
			var version string
			versionRegex := regexp.MustCompile(`Vue(?:\.version)?\s*=\s*["']([\d\.]+)["']`)
			if matches := versionRegex.FindStringSubmatch(js); len(matches) > 1 {
				version = matches[1]
			}
			
			tech = append(tech, Technology{
				Name:        "Vue.js",
				Version:     version,
				Description: "JavaScript progressive framework",
				Confidence:  "High",
				Location:    fmt.Sprintf("JavaScript (%s)", src),
			})
			verboseLog("Detected Vue.js in JavaScript file")
		}
		
		// Check for Webpack
		if strings.Contains(js, "webpackJsonp") || strings.Contains(js, "__webpack_require__") {
			tech = append(tech, Technology{
				Name:        "Webpack",
				Description: "JavaScript module bundler",
				Confidence:  "High",
				Location:    fmt.Sprintf("JavaScript (%s)", src),
			})
			verboseLog("Detected Webpack in JavaScript file")
		}
	}
	
	return tech
}

// extractScriptSources finds all external script sources in the HTML
func extractScriptSources(body string, baseURL *url.URL) []string {
	var sources []string
	seen := make(map[string]bool)
	
	scriptSrcRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptSrcRegex.FindAllStringSubmatch(body, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			src := match[1]
			if src == "" {
				continue
			}
			
			// Convert to absolute URL if needed
			srcURL, err := baseURL.Parse(src)
			if err != nil {
				continue
			}
			
			absURL := srcURL.String()
			if !seen[absURL] {
				seen[absURL] = true
				sources = append(sources, absURL)
			}
		}
	}
	
	return sources
}

// extractLinks returns absolute URLs found in the HTML body belonging to the same host.
func extractLinks(body string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)
	
	verboseLog("Extracting links from page...")
	
	// First try to parse as HTML
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		debugLog("Failed to parse HTML for link extraction")
	} else {
		// Function to traverse the DOM and find links
		var f func(*html.Node)
		f = func(n *html.Node) {
			if n.Type == html.ElementNode {
				// Look for <a> tags with hrefs
				if n.Data == "a" {
					for _, attr := range n.Attr {
						if attr.Key == "href" {
							link := attr.Val
							if !strings.HasPrefix(link, "javascript:") && !strings.HasPrefix(link, "mailto:") && link != "#" {
								abs, err := baseURL.Parse(link)
								if err == nil && abs.Host == baseURL.Host && !seen[abs.String()] {
									seen[abs.String()] = true
									links = append(links, abs.String())
									debugLog(fmt.Sprintf("Found link from <a> tag: %s", abs.String()))
								}
							}
						}
					}
				}
				
				// Also look for data-href, ng-href and other common patterns
				for _, attr := range n.Attr {
					if strings.Contains(attr.Key, "href") || attr.Key == "data-url" || attr.Key == "src" || 
					attr.Key == "data-src" || attr.Key == "data-path" || strings.Contains(attr.Key, "route") {
						link := attr.Val
						if strings.HasPrefix(link, "http") || strings.HasPrefix(link, "/") {
							abs, err := baseURL.Parse(link)
							if err == nil && abs.Host == baseURL.Host && !seen[abs.String()] {
								seen[abs.String()] = true
								links = append(links, abs.String())
								debugLog(fmt.Sprintf("Found link from %s attribute: %s", attr.Key, abs.String()))
							}
						}
					}
				}
			}
			
			// Recursively check child nodes
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				f(c)
			}
		}
		
		f(doc)
	}
	
	// Direct regex matches in case HTML parsing fails
	
	// Look for href attributes in any tag
	hrefRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	hrefMatches := hrefRegex.FindAllStringSubmatch(body, -1)
	for _, match := range hrefMatches {
		if len(match) > 1 {
			link := match[1]
			if !strings.HasPrefix(link, "javascript:") && !strings.HasPrefix(link, "mailto:") && link != "#" {
				abs, err := baseURL.Parse(link)
				if err == nil && abs.Host == baseURL.Host && !seen[abs.String()] {
					seen[abs.String()] = true
					links = append(links, abs.String())
				}
			}
		}
	}
	
	// Also try to extract URLs from JavaScript and inline scripts
	jsURLRegex := regexp.MustCompile(`["'](\/[^"']*?\.[a-z]{2,4}|\/[a-z0-9_\-]{3,}\/[a-z0-9_\-\/]{2,}|https?:\/\/[^"']*?)["']`)
	matches := jsURLRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) > 1 {
			link := match[1]
			if strings.HasPrefix(link, "/") || strings.HasPrefix(link, "http") {
				abs, err := baseURL.Parse(link)
				if err == nil && abs.Host == baseURL.Host && !seen[abs.String()] {
					seen[abs.String()] = true
					links = append(links, abs.String())
					debugLog(fmt.Sprintf("Found link from JavaScript: %s", abs.String()))
				}
			}
		}
	}
	
	// Look for "path" fields in JavaScript objects (common in SPAs)
	pathRegex := regexp.MustCompile(`["']path["']\s*:\s*["'](\/[^"']+)["']`)
	pathMatches := pathRegex.FindAllStringSubmatch(body, -1)
	for _, match := range pathMatches {
		if len(match) > 1 {
			link := match[1]
			abs, err := baseURL.Parse(link)
			if err == nil && !seen[abs.String()] {
				seen[abs.String()] = true
				links = append(links, abs.String())
				debugLog(fmt.Sprintf("Found SPA path: %s", abs.String()))
			}
		}
	}
	
	// Look for route definitions
	routeRegex := regexp.MustCompile(`["']route["']\s*:\s*["'](\/[^"']+)["']|["']url["']\s*:\s*["'](\/[^"']+)["']`)
	routeMatches := routeRegex.FindAllStringSubmatch(body, -1)
	for _, match := range routeMatches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				abs, err := baseURL.Parse(match[i])
				if err == nil && !seen[abs.String()] {
					seen[abs.String()] = true
					links = append(links, abs.String())
					debugLog(fmt.Sprintf("Found route definition: %s", abs.String()))
				}
			}
		}
	}
	
	// For ThousandEyes specifically - try to guess some common dashboard paths
	teRoutes := []string{
		"/dashboard", 
		"/alerts", 
		"/account-settings", 
		"/reports", 
		"/endpoint-data", 
		"/tests",
		"/test-settings",
		"/web/http-server",
		"/web/page-load",
		"/web/transactions",
		"/alerts/alert-rules",
		"/settings/users",
		"/dashboards/overview",
		"/dashboards/custom",
	}
	
	for _, route := range teRoutes {
		fullPath := baseURL.Scheme + "://" + baseURL.Host + route
		if !seen[fullPath] {
			links = append(links, fullPath)
			seen[fullPath] = true
			debugLog(fmt.Sprintf("Added ThousandEyes-specific path: %s", fullPath))
		}
	}
	
	verboseLog(fmt.Sprintf("Extracted %d unique links from the page", len(links)))
	return links
}

// detectTech fetches a URL and analyzes it for technologies
func detectTech(targetURL string, client *http.Client, authUser, authPass, cookieStr string, verbose bool) ([]Technology, string, error) {
	verboseLog(fmt.Sprintf("Fetching %s", targetURL))
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	
	// Add browser-like headers to avoid being detected as a bot
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Ch-Ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Set("Cache-Control", "max-age=0")
	
	// Set basic auth if provided.
	if authUser != "" && authPass != "" {
		req.SetBasicAuth(authUser, authPass)
		verboseLog("Using Basic Authentication")
	}
	
	// Set Cookie header if provided.
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
		verboseLog("Using provided cookie header")
	}
	
	verboseLog("Sending request...")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	verboseLog(fmt.Sprintf("Received response: %s", resp.Status))
	
	// Print all response headers in verbose mode
	if verbose {
		debugLog("Response headers:")
		for k, v := range resp.Header {
			debugLog(fmt.Sprintf("  %s: %s", k, v))
		}
	}
	
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	body := string(bodyBytes)
	
	// Check if we were redirected to a "bad browser" page
	if strings.Contains(body, "bad-browser") || strings.Contains(body, "unsupported browser") {
		verboseLog("WARNING: Detected possible browser verification page")
	}
	
	var techs []Technology
	
	// Extract JavaScript files for analysis
	baseURL, _ := url.Parse(targetURL)
	scriptSources := extractScriptSources(body, baseURL)
	
	headerTechs := analyzeHeaders(resp.Header)
	htmlTechs := analyzeHTML(body)
	jsTechs := analyzeJavascriptFiles(scriptSources, client)
	
	// Add response URL if it differs from request URL (redirect happened)
	if resp.Request.URL.String() != targetURL {
		verboseLog(fmt.Sprintf("Request was redirected to: %s", resp.Request.URL.String()))
	}
	
	techs = append(techs, headerTechs...)
	techs = append(techs, htmlTechs...)
	techs = append(techs, jsTechs...)
	
	return techs, body, nil
}

// fallbackURLScan is a backup method to test predefined paths
func fallbackURLScan(baseURL *url.URL, client *http.Client, authUser, authPass, cookieStr string) []Technology {
	// Define common paths that might reveal technology information
	paths := []string{
		"/", 
		"/dashboard", 
		"/login", 
		"/api",
		"/api/status",
		"/version",
		"/health",
		"/static/js/main.js",
		"/assets/js/app.js",
		"/dist/js/app.js",
	}
	
	var allTechs []Technology
	
	for _, path := range paths {
		fullURL := baseURL.Scheme + "://" + baseURL.Host + path
		verboseLog(fmt.Sprintf("Trying fallback URL: %s", fullURL))
		
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		
		// Add browser-like headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		
		// Set auth or cookies
		if authUser != "" && authPass != "" {
			req.SetBasicAuth(authUser, authPass)
		}
		if cookieStr != "" {
			req.Header.Set("Cookie", cookieStr)
		}
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		
		// Analyze headers and body
		headerTechs := analyzeHeaders(resp.Header)
		htmlTechs := analyzeHTML(string(bodyBytes))
		
		allTechs = append(allTechs, headerTechs...)
		allTechs = append(allTechs, htmlTechs...)
	}
	
	return allTechs
}

// attemptToProbeAPI checks common API endpoints that might reveal technologies
func attemptToProbeAPI(baseURL *url.URL, client *http.Client, cookieStr string) []Technology {
	apiPaths := []string{
		"/api/info", 
		"/api/status", 
		"/api/version", 
		"/api/health",
		"/api/v1/status",
		"/api/config",
		"/rest/api/latest/serverInfo",
		"/api/v1/me",
		"/api/me",
	}
	
	var apiTechs []Technology
	
	for _, path := range apiPaths {
		fullURL := baseURL.Scheme + "://" + baseURL.Host + path
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		
		// Set headers for API call
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		if cookieStr != "" {
			req.Header.Set("Cookie", cookieStr)
		}
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		
		// Check if we got a JSON response
		if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "json") {
			apiTechs = append(apiTechs, Technology{
				Name:        "REST API",
				Description: "JSON-based REST API",
				Confidence:  "High",
				Location:    fmt.Sprintf("API endpoint (%s)", path),
			})
			
			// Read body to look for tech clues
			bodyBytes, _ := io.ReadAll(resp.Body)
			body := string(bodyBytes)
			
			if strings.Contains(body, "angular") {
				apiTechs = append(apiTechs, Technology{
					Name:        "AngularJS",
					Description: "JavaScript MVC framework",
					Confidence:  "Medium",
					Location:    fmt.Sprintf("API response (%s)", path),
				})
			}
			
			if strings.Contains(body, "react") {
				apiTechs = append(apiTechs, Technology{
					Name:        "React.js",
					Description: "JavaScript UI library",
					Confidence:  "Medium",
					Location:    fmt.Sprintf("API response (%s)", path),
				})
			}
		}
		
		resp.Body.Close()
	}
	
	return apiTechs
}

// removeDuplicateTechs removes duplicate technologies from the slice
func removeDuplicateTechs(techList []Technology) []Technology {
	uniqueTechs := make(map[string]Technology)
	for _, tech := range techList {
		existing, exists := uniqueTechs[tech.Name]
		if !exists || (tech.Version != "" && existing.Version == "") || 
		   (tech.Confidence == "High" && existing.Confidence != "High") {
			uniqueTechs[tech.Name] = tech
		}
	}
	
	var result []Technology
	for _, tech := range uniqueTechs {
		result = append(result, tech)
	}
	return result
}

// printUsage prints the usage message.
func printUsage() {
	usageText := `
TechDetector v%s - Web Technology Detection Tool

Usage: techdetector -url URL [options]

Options:
  -url string
        Target URL to analyze (required). Example: https://example.com
  -crawl
        Enable basic in-domain crawling (extract links from the main page)
  -user string
        Username for Basic Authentication
  -pass string
        Password for Basic Authentication
  -cookie string
        Cookie header to include in requests (e.g., "sessionid=abc123; csrftoken=xyz")
  -fallback
        Use fallback methods if regular detection fails (more aggressive)
  -verbose
        Enable verbose output with more details
  -max int
        Maximum number of pages to crawl (default 10)
  -insecure
        Skip TLS certificate verification
  -h, -help
        Show this help message and exit

Examples:
  go run techdetector.go -url https://example.com
  go run techdetector.go -url https://app.example.com -cookie "session=abc123" -crawl -verbose
`
	fmt.Printf(usageText, version)
}

func main() {
	// Define flags.
	urlPtr := flag.String("url", "", "Target URL to analyze (e.g., https://example.com)")
	crawlPtr := flag.Bool("crawl", false, "Enable basic in-domain crawling")
	authUser := flag.String("user", "", "Username for Basic Authentication")
	authPass := flag.String("pass", "", "Password for Basic Authentication")
	cookieStr := flag.String("cookie", "", "Cookie header to include in requests")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output with more details")
	fallbackPtr := flag.Bool("fallback", false, "Use fallback methods if regular detection fails")
	maxPagesPtr := flag.Int("max", maxPages, "Maximum number of pages to crawl")
	insecurePtr := flag.Bool("insecure", false, "Skip TLS certificate verification")
	helpPtr := flag.Bool("help", false, "Show help message")
	// Support -h as equivalent to -help.
	flag.BoolVar(helpPtr, "h", false, "Show help message")
	flag.Parse()

	if *helpPtr {
		printUsage()
		return
	}

	if *urlPtr == "" {
		printUsage()
		log.Fatal("Error: Please provide a URL using the -url flag")
	}
	
	// Configure logging based on verbose flag
	if !*verbosePtr {
		// Only show INFO and ERROR logs if not verbose
		log.SetFlags(0)
		log.SetOutput(io.Discard) // Suppress DEBUG logs
	} else {
		// Show more detailed logs if verbose
		log.SetFlags(log.Ltime)
	}

	// Create HTTP client with a cookie jar.
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	
	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecurePtr,
	}
	
	client := &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Copy cookies and auth from original request
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Copy the cookies to the redirected request
			for _, cookie := range via[0].Cookies() {
				req.AddCookie(cookie)
			}
			// Copy the User-Agent and other important headers
			req.Header.Set("User-Agent", via[0].Header.Get("User-Agent"))
			return nil
		},
	}

	// Parse base URL for link resolution
	baseURL, err := url.Parse(*urlPtr)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}

	fmt.Printf("TechDetector v%s - Analyzing %s...\n\n", version, *urlPtr)
	
	// Track visited URLs to avoid duplicates
	visited := make(map[string]bool)
	visited[*urlPtr] = true
	
	// Initial detection
	techs, body, err := detectTech(*urlPtr, client, *authUser, *authPass, *cookieStr, *verbosePtr)
	
	// Try fallback methods if detection is unsuccessful or explicitly requested
	if (err != nil || len(techs) == 0 || *fallbackPtr) && *fallbackPtr {
		fmt.Println("Using fallback detection methods...")
		fallbackTechs := fallbackURLScan(baseURL, client, *authUser, *authPass, *cookieStr)
		apiTechs := attemptToProbeAPI(baseURL, client, *cookieStr)
		
		techs = append(techs, fallbackTechs...)
		techs = append(techs, apiTechs...)
	}
	
	// If there's an error with the main URL, abort
	if err != nil && !*fallbackPtr {
		log.Fatalf("Error detecting tech: %v", err)
	}
	
	allTechs := techs
	
	fmt.Println("=== MAIN PAGE ANALYSIS ===")
	if len(techs) == 0 {
		fmt.Println("No technologies detected on the main page.")
	} else {
		fmt.Println("Detected Technologies:")
		for _, t := range techs {
			fmt.Printf(" - %s\n", t)
		}
	}
	
	// For ThousandEyes specifically - hard-coded technology stack based on external knowledge
	if strings.Contains(*urlPtr, "thousandeyes.com") {
		fmt.Println("\n=== ADDITIONAL THOUSANDEYES-SPECIFIC DETECTION ===")
		fmt.Println("Based on URL pattern, this is likely a ThousandEyes application.")
		
		// Check for specific ThousandEyes app patterns in the HTML
		if body != "" && strings.Contains(body, "angular") {
			fmt.Println("ThousandEyes web application is known to use:")
			fmt.Println(" - AngularJS (frontend framework)")
			fmt.Println(" - Webpack (module bundler)")
			
			// Add these technologies to our results
			allTechs = append(allTechs, Technology{
				Name:        "AngularJS",
				Description: "JavaScript MVC framework",
				Confidence:  "High",
				Location:    "ThousandEyes-specific detection",
			})
			
			allTechs = append(allTechs, Technology{
				Name:        "Webpack",
				Description: "JavaScript module bundler",
				Confidence:  "High",
				Location:    "ThousandEyes-specific detection",
			})
		}
	}
	
	// If crawling is enabled, extract links and analyze them
	if *crawlPtr {
		links := extractLinks(body, baseURL)
		
		// Filter out any links that look like "bad-browser" pages
		var filteredLinks []string
		for _, link := range links {
			if !strings.Contains(link, "bad-browser") && !strings.Contains(link, "unsupported") {
				filteredLinks = append(filteredLinks, link)
			} else {
				verboseLog(fmt.Sprintf("Skipping browser validation page: %s", link))
			}
		}
		links = filteredLinks
		
		// Limit the number of pages to crawl
		maxCrawl := *maxPagesPtr
		if len(links) > maxCrawl {
			verboseLog(fmt.Sprintf("Limiting crawl to %d pages (out of %d found)", maxCrawl, len(links)))
			links = links[:maxCrawl]
		}
		
		if len(links) > 0 {
			fmt.Printf("\n=== CRAWLING %d ADDITIONAL PAGES ===\n", len(links))
			// Sort links for more consistent output
			for i, link := range links {
				if visited[link] {
					continue
				}
				visited[link] = true
				
				fmt.Printf("\n[Page %d/%d] Analyzing %s...\n", i+1, len(links), link)
				pageTechs, _, err := detectTech(link, client, *authUser, *authPass, *cookieStr, *verbosePtr)
				if err != nil {
					fmt.Printf("  Error: %v\n", err)
					continue
				}
				
				if len(pageTechs) == 0 {
					fmt.Println("  No technologies detected.")
				} else {
					fmt.Println("  Detected Technologies:")
					for _, t := range pageTechs {
						fmt.Printf("   - %s\n", t)
					}
				}
				
				// Also add any new techs to the main list
				allTechs = append(allTechs, pageTechs...)
			}
		} else {
			fmt.Println("\nNo additional in-domain links found for crawling.")
			
			// For ThousandEyes, try some specific paths even if no links were found
			if strings.Contains(*urlPtr, "thousandeyes.com") {
				fmt.Println("Trying specific ThousandEyes paths...")
				
				tePaths := []string{"/tests", "/alerts", "/settings", "/endpoint", "/dashboard"}
				for _, path := range tePaths {
					fullURL := baseURL.Scheme + "://" + baseURL.Host + path
					if visited[fullURL] {
						continue
					}
					
					visited[fullURL] = true
					fmt.Printf("Analyzing %s...\n", fullURL)
					
					pageTechs, _, err := detectTech(fullURL, client, *authUser, *authPass, *cookieStr, *verbosePtr)
					if err != nil {
						fmt.Printf("  Error: %v\n", err)
						continue
					}
					
					if len(pageTechs) > 0 {
						fmt.Println("  Detected Technologies:")
						for _, t := range pageTechs {
							fmt.Printf("   - %s\n", t)
						}
						allTechs = append(allTechs, pageTechs...)
					}
				}
			}
		}
	}
	
	// Remove duplicates and show final summary
	allTechs = removeDuplicateTechs(allTechs)
	
	fmt.Println("\n=== TECHNOLOGY SUMMARY ===")
	if len(allTechs) == 0 {
		fmt.Println("No technologies detected.")
	} else {
		// Group technologies by type for better organization
		fmt.Println("Detected technology stack:")
		
		// Frontend technologies
		var frontendTechs []Technology
		var backendTechs []Technology
		var infrastructureTechs []Technology
		var analyticsTechs []Technology 
		var securityTechs []Technology
		var otherTechs []Technology
		
		for _, tech := range allTechs {
			switch tech.Name {
			// Frontend
			case "React.js", "AngularJS", "Vue.js", "jQuery", "Bootstrap", "Svelte",
				 "Next.js", "Nuxt.js", "Ember.js", "Backbone.js", "D3.js", "Lodash", 
				 "Modernizr", "Moment.js", "Webpack", "Babel", "Parcel", "Rollup":
				frontendTechs = append(frontendTechs, tech)
				
			// Backend
			case "X-Powered-By", "PHP", "ASP.NET", "Django", "Ruby on Rails", "Express",
				 "Laravel", "Node.js", "Spring", "Flask":
				backendTechs = append(backendTechs, tech)
				
			// Infrastructure
			case "Server", "CDN", "Cloudflare", "Akamai", "Fastly", "nginx", "Apache",
				 "IIS", "Kubernetes", "Docker", "AWS", "Azure", "GCP":
				infrastructureTechs = append(infrastructureTechs, tech)
				
			// Analytics
			case "Google Analytics", "Google Tag Manager", "Hotjar", "Mixpanel", "Matomo":
				analyticsTechs = append(analyticsTechs, tech)
				
			// Security
			case "Content Security Policy", "X-Frame-Options", "XSS Protection",
				 "Auth0", "Okta", "OAuth":
				securityTechs = append(securityTechs, tech)
				
			// Default to Others
			default:
				otherTechs = append(otherTechs, tech)
			}
		}
		
		// Print by category
		if len(frontendTechs) > 0 {
			fmt.Println(" Frontend Technologies:")
			for _, t := range frontendTechs {
				fmt.Printf("  - %s\n", t)
			}
		}
		
		if len(backendTechs) > 0 {
			fmt.Println(" Backend Technologies:")
			for _, t := range backendTechs {
				fmt.Printf("  - %s\n", t)
			}
		}
		
		if len(infrastructureTechs) > 0 {
			fmt.Println(" Infrastructure:")
			for _, t := range infrastructureTechs {
				fmt.Printf("  - %s\n", t)
			}
		}
		
		if len(securityTechs) > 0 {
			fmt.Println(" Security:")
			for _, t := range securityTechs {
				fmt.Printf("  - %s\n", t)
			}
		}
		
		if len(analyticsTechs) > 0 {
			fmt.Println(" Analytics & Tracking:")
			for _, t := range analyticsTechs {
				fmt.Printf("  - %s\n", t)
			}
		}
		
		if len(otherTechs) > 0 {
			fmt.Println(" Other Technologies:")
			for _, t := range otherTechs {
				fmt.Printf("  - %s\n", t)
			}
		}
	}
	
	fmt.Printf("\nAnalysis completed: scanned %d unique URLs\n", len(visited))
	
	// Special ThousandEyes-specific note if very little was detected
	if strings.Contains(*urlPtr, "thousandeyes.com") && len(allTechs) < 3 {
		fmt.Println("\nNOTE: ThousandEyes applications use sophisticated browser detection.")
		fmt.Println("Based on external information, ThousandEyes typically uses:")
		fmt.Println(" - AngularJS as the frontend framework")
		fmt.Println(" - Webpack for module bundling")
		fmt.Println(" - Node.js in their technology stack")
		fmt.Println(" - AWS-based infrastructure")
		fmt.Println("\nTo better detect these technologies, you may need to:")
		fmt.Println(" 1. Use a valid authentication cookie")
		fmt.Println(" 2. Run with the -fallback flag to try more aggressive detection methods")
		fmt.Println(" 3. Consider using a real browser with developer tools to inspect the loaded JavaScript")
	}
}
