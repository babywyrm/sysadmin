package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

const (
	maxPagesDefault = 10   // Default maximum pages to crawl
	version         = "1.4.0"
)

// Technology represents a detected technology with additional context.
type Technology struct {
	Name        string
	Version     string
	Description string
	Confidence  string // Very High, High, Medium, Low
	Location    string // Where it was found (header, meta, script, etc.)
	Category    string // Server, CMS, JavaScript, etc.
	Evidence    int    // Count of evidence points found
}

// TechSignature defines patterns for technology detection
type TechSignature struct {
	Name         string
	Patterns     []string
	VersionRegex string
	Category     string
	Description  string
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

// Global cache for JavaScript files
var jsCache = make(map[string]string)
var jsCacheMutex = sync.RWMutex{}

// Technology signatures for common platforms
var techSignatures = []TechSignature{
	{
		Name:         "WordPress",
		Patterns:     []string{"wp-content", "wp-includes", "wp-json", "wordpress", "wp-admin"},
		VersionRegex: `<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d\.]+)["']`,
		Category:     "CMS",
		Description:  "Content Management System",
	},
	{
		Name:         "Drupal",
		Patterns:     []string{"Drupal.settings", "drupal.org", "/sites/all/", "/sites/default/"},
		VersionRegex: `Drupal ([\d\.]+)`,
		Category:     "CMS",
		Description:  "Content Management System",
	},
	{
		Name:         "Joomla",
		Patterns:     []string{"/media/jui/", "joomla!", "/components/com_"},
		VersionRegex: `<meta\s+name=["']generator["']\s+content=["']Joomla!\s+([\d\.]+)["']`,
		Category:     "CMS",
		Description:  "Content Management System",
	},
	{
		Name:         "Magento",
		Patterns:     []string{"Mage.Cookies", "magento", "Magento_"},
		VersionRegex: `Magento/?([\d\.]+)`,
		Category:     "Ecommerce",
		Description:  "Ecommerce Platform",
	},
	{
		Name:         "Shopify",
		Patterns:     []string{"Shopify.theme", "shopify.com", "/cdn/shop/"},
		VersionRegex: ``,
		Category:     "Ecommerce",
		Description:  "Ecommerce Platform",
	},
	{
		Name:         "Wix",
		Patterns:     []string{"wix.com", "wixcode", "wix-site"},
		VersionRegex: ``,
		Category:     "Website Builder",
		Description:  "Website Building Platform",
	},
	{
		Name:         "Bootstrap",
		Patterns:     []string{"bootstrap.css", "bootstrap.min.css", "bootstrap.js", "bootstrap.min.js", "bootstrap.bundle.js"},
		VersionRegex: `bootstrap(?:\.min)?\.(?:css|js)(?:\?ver=|@|v)([\d\.]+)`,
		Category:     "UI Framework",
		Description:  "Frontend Framework",
	},
	{
		Name:         "Cloudflare",
		Patterns:     []string{"cloudflare", "cf-ray", "cf-cache-status"},
		VersionRegex: ``,
		Category:     "CDN",
		Description:  "Content Delivery Network and DDoS Protection",
	},
	{
		Name:         "Google Analytics",
		Patterns:     []string{"google-analytics.com", "googleanalytics", "ga('create'", "gtag"},
		VersionRegex: ``,
		Category:     "Analytics",
		Description:  "Web Analytics Service",
	},
}

func debugLog(msg string) {
	log.Println("[DEBUG]", msg)
}

func verboseLog(msg string) {
	log.Println("[INFO]", msg)
}

func errorLog(msg string) {
	log.Println("[ERROR]", msg)
}

// parseVersion attempts to extract the version for a given technology from text.
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
			`Vue\.version\s*=\s*['"]([\d\.]+)['"]`,
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
	case "WordPress":
		versionRegex = regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d\.]+)["']`)
		if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
			return matches[1]
		}
	case "PHP":
		versionRegex = regexp.MustCompile(`PHP[/-]?([\d\.]+)`)
		if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
			return matches[1]
		}
	case "Node.js":
		versionRegex = regexp.MustCompile(`Node/?v?([\d\.]+)`)
		if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
			return matches[1]
		}
	default:
		// Try to find version for any of our tech signatures
		for _, sig := range techSignatures {
			if sig.Name == techName && sig.VersionRegex != "" {
				versionRegex = regexp.MustCompile(sig.VersionRegex)
				if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
					return matches[1]
				}
			}
		}
	}
	return ""
}

// analyzeHeaders inspects HTTP response headers for technology clues.
func analyzeHeaders(headers http.Header) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTTP Headers for technology clues...")
	if server := headers.Get("Server"); server != "" {
		tech = append(tech, Technology{
			Name:        "Server",
			Version:     server,
			Description: "Web server software",
			Confidence:  "High",
			Location:    "Server header",
			Category:    "Server",
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Found Server header: %s", server))
	}
	if powered := headers.Get("X-Powered-By"); powered != "" {
		tech = append(tech, Technology{
			Name:        "X-Powered-By",
			Version:     powered,
			Description: "Backend technology",
			Confidence:  "High",
			Location:    "X-Powered-By header",
			Category:    "Server",
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Found X-Powered-By header: %s", powered))
		
		// Check for PHP
		if strings.Contains(strings.ToLower(powered), "php") {
			phpVersion := ""
			phpRegex := regexp.MustCompile(`PHP/?(\d+\.\d+\.\d+)`)
			if matches := phpRegex.FindStringSubmatch(powered); len(matches) > 1 {
				phpVersion = matches[1]
			}
			tech = append(tech, Technology{
				Name:        "PHP",
				Version:     phpVersion,
				Description: "Server-side scripting language",
				Confidence:  "High",
				Location:    "X-Powered-By header",
				Category:    "Programming Language",
				Evidence:    1,
			})
			verboseLog(fmt.Sprintf("Found PHP: %s", phpVersion))
		}
	}
	if contentType := headers.Get("Content-Type"); contentType != "" {
		if strings.Contains(contentType, "application/json") {
			tech = append(tech, Technology{
				Name:        "API (JSON)",
				Description: "JSON-based API",
				Confidence:  "High",
				Location:    "Content-Type header",
				Category:    "API",
				Evidence:    1,
			})
			verboseLog("Found JSON API endpoint")
		}
	}
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		tech = append(tech, Technology{
			Name:        "Content Security Policy",
			Description: "Security policy to prevent XSS and data injection",
			Confidence:  "High",
			Location:    "Content-Security-Policy header",
			Category:    "Security",
			Evidence:    1,
		})
		verboseLog("Found Content-Security-Policy header")
		if strings.Contains(csp, "cloudflare") {
			tech = append(tech, Technology{
				Name:        "Cloudflare",
				Description: "CDN and DDoS protection",
				Confidence:  "High",
				Location:    "Content-Security-Policy header",
				Category:    "CDN",
				Evidence:    1,
			})
		}
		if strings.Contains(csp, "akamai") {
			tech = append(tech, Technology{
				Name:        "Akamai",
				Description: "CDN and security",
				Confidence:  "High",
				Location:    "Content-Security-Policy header",
				Category:    "CDN",
				Evidence:    1,
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
			Category:    "Security",
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Found X-Frame-Options header: %s", frameOptions))
	}
	if cdn := headers.Get("X-CDN"); cdn != "" {
		tech = append(tech, Technology{
			Name:        "CDN",
			Version:     cdn,
			Description: "Content Delivery Network",
			Confidence:  "High",
			Location:    "X-CDN header",
			Category:    "CDN",
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Found CDN: %s", cdn))
	}
	if headers.Get("CF-Cache-Status") != "" || headers.Get("CF-RAY") != "" {
		tech = append(tech, Technology{
			Name:        "Cloudflare",
			Description: "CDN and DDoS protection",
			Confidence:  "High",
			Location:    "Cloudflare headers",
			Category:    "CDN",
			Evidence:    1,
		})
		verboseLog("Found Cloudflare")
	}
	if akamai := headers.Get("X-Akamai-Transformed"); akamai != "" {
		tech = append(tech, Technology{
			Name:        "Akamai",
			Description: "CDN and security",
			Confidence:  "High",
			Location:    "X-Akamai-Transformed header",
			Category:    "CDN",
			Evidence:    1,
		})
		verboseLog("Found Akamai")
	}
	if fastly := headers.Get("X-Served-By"); fastly != "" && strings.Contains(fastly, "cache") {
		tech = append(tech, Technology{
			Name:        "Fastly",
			Description: "CDN",
			Confidence:  "High",
			Location:    "X-Served-By header",
			Category:    "CDN",
			Evidence:    1,
		})
		verboseLog("Found Fastly")
	}
	
	// Check for Nginx
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "nginx") {
		nginxVersion := ""
		nginxRegex := regexp.MustCompile(`nginx/?(\d+\.\d+\.\d+)?`)
		if matches := nginxRegex.FindStringSubmatch(server); len(matches) > 1 {
			nginxVersion = matches[1]
		}
		tech = append(tech, Technology{
			Name:        "Nginx",
			Version:     nginxVersion,
			Description: "Web server",
			Confidence:  "High",
			Location:    "Server header",
			Category:    "Server",
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Found Nginx: %s", nginxVersion))
	}
	
	// Check for Apache
	if server := headers.Get("Server"); strings.Contains(strings.ToLower(server), "apache") {
		apacheVersion := ""
		apacheRegex := regexp.MustCompile(`Apache/?(\d+\.\d+\.\d+)?`)
		if matches := apacheRegex.FindStringSubmatch(server); len(matches) > 1 {
			apacheVersion = matches[1]
		}
		tech = append(tech, Technology{
			Name:        "Apache",
			Version:     apacheVersion,
			Description: "Web server",
			Confidence:  "High",
			Location:    "Server header",
			Category:    "Server",
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Found Apache: %s", apacheVersion))
	}
	
	return tech
}

// analyzeHTML inspects the HTML content for technology clues.
func analyzeHTML(body string) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTML content for technology signatures...")

	// Check for generic meta generator tag
	metaGenRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	if matches := metaGenRegex.FindStringSubmatch(body); len(matches) > 1 {
		tech = append(tech, Technology{
			Name:        "Generator",
			Version:     matches[1],
			Description: "Content Management System or Generator",
			Confidence:  "High",
			Location:    "meta generator tag",
			Category:    "CMS",
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Found generator meta tag: %s", matches[1]))
		
		// Check if it's WordPress
		if strings.Contains(strings.ToLower(matches[1]), "wordpress") {
			wpVersion := ""
			wpVerRegex := regexp.MustCompile(`WordPress (\d+\.\d+(?:\.\d+)?)`)
			if verMatches := wpVerRegex.FindStringSubmatch(matches[1]); len(verMatches) > 1 {
				wpVersion = verMatches[1]
			}
			tech = append(tech, Technology{
				Name:        "WordPress",
				Version:     wpVersion,
				Description: "Content Management System",
				Confidence:  "High",
				Location:    "meta generator tag",
				Category:    "CMS",
				Evidence:    1,
			})
			verboseLog(fmt.Sprintf("Found WordPress: %s", wpVersion))
		}
	}
	
	// Look for WordPress theme
	if strings.Contains(strings.ToLower(body), "wp-content/themes/") {
		themeRegex := regexp.MustCompile(`wp-content/themes/([^/'"]+)`)
		if matches := themeRegex.FindStringSubmatch(body); len(matches) > 1 {
			tech = append(tech, Technology{
				Name:        "WordPress Theme: " + matches[1],
				Description: "WordPress Theme",
				Confidence:  "High",
				Location:    "HTML path",
				Category:    "CMS Theme",
				Evidence:    1,
			})
			verboseLog(fmt.Sprintf("Found WordPress theme: %s", matches[1]))
		}
	}
	
	// Check for WordPress plugins
	pluginRegex := regexp.MustCompile(`wp-content/plugins/([^/'"]+)`)
	pluginMatches := pluginRegex.FindAllStringSubmatch(body, -1)
	plugins := make(map[string]bool)
	for _, match := range pluginMatches {
		if len(match) > 1 && !plugins[match[1]] {
			plugins[match[1]] = true
			tech = append(tech, Technology{
				Name:        "WordPress Plugin: " + match[1],
				Description: "WordPress Plugin",
				Confidence:  "High",
				Location:    "HTML path",
				Category:    "CMS Plugin",
				Evidence:    1,
			})
			verboseLog(fmt.Sprintf("Found WordPress plugin: %s", match[1]))
		}
	}

	if strings.Contains(strings.ToLower(body), "thousandeyes") {
		tech = append(tech, Technology{
			Name:        "ThousandEyes",
			Description: "Network intelligence platform",
			Confidence:  "High",
			Location:    "HTML content",
			Category:    "Monitoring",
			Evidence:    1,
		})
		verboseLog("Detected ThousandEyes product")
	}
	
	// Check for tech signatures
	for _, sig := range techSignatures {
		for _, pattern := range sig.Patterns {
			if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
				version := ""
				if sig.VersionRegex != "" {
					versionRegex := regexp.MustCompile(sig.VersionRegex)
					if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
						version = matches[1]
					}
				}
				tech = append(tech, Technology{
					Name:        sig.Name,
					Version:     version,
					Description: sig.Description,
					Confidence:  "High",
					Location:    "HTML content",
					Category:    sig.Category,
					Evidence:    1,
				})
				verboseLog(fmt.Sprintf("Detected %s", sig.Name))
				break // Once we find one pattern, no need to check others
			}
		}
	}
	
	// AngularJS detection with more specific patterns
	isAngular := false
	angularPatterns := []string{
		"ng-app=", "ng-controller=", "ng-repeat=", "ng-if=", "ng-class=", "ng-model=",
		"ng-include=", "ng-view=", "angular.module(", "angular.bootstrap(",
		"angular.version", "ngRoute", "ngCookies", "ngTouch", "ngAnimate",
	}
	for _, pattern := range angularPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			isAngular = true
			break
		}
	}
	if isAngular {
		var version string
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
			Category:    "JavaScript Framework",
			Evidence:    1,
		})
		verboseLog("Detected AngularJS framework")
	}
	
	// React.js detection with more specific patterns
	isReact := false
	reactPatterns := []string{
		"react-dom", "react.production.min.js", "react.development.js", 
		"__REACT_DEVTOOLS_GLOBAL_HOOK__", "ReactDOM.render(", "React.createElement(",
		"react-router", "react-app",
	}
	for _, pattern := range reactPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
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
			Category:    "JavaScript Framework",
			Evidence:    1,
		})
		verboseLog("Detected React.js library")
	}
	
	// Vue.js detection with more specific patterns
	isVue := false
	vuePatterns := []string{
		"vue.js", "vue.min.js", "v-if=", "v-for=", "v-model=", "v-on:",
		"v-bind:", "v-show=", "vue.runtime", "vuex", "vue-router", 
		"vue@", "vue/dist",
	}
	for _, pattern := range vuePatterns {
		if strings.Contains(strings.ToLower(body), pattern) {
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
			Category:    "JavaScript Framework",
			Evidence:    1,
		})
		verboseLog("Detected Vue.js framework")
	}
	
	// Webpack detection
	if strings.Contains(strings.ToLower(body), "webpack") ||
		strings.Contains(body, "__webpack_require__") ||
		strings.Contains(body, "webpackjsonp") ||
		strings.Contains(body, "/bundle.") ||
		strings.Contains(body, "/main.chunk.js") {
		tech = append(tech, Technology{
			Name:        "Webpack",
			Description: "JavaScript module bundler",
			Confidence:  "High",
			Location:    "HTML (webpack patterns)",
			Category:    "Build Tool",
			Evidence:    1,
		})
		verboseLog("Detected Webpack module bundler")
	}
	
	// jQuery detection with more specificity
	jQueryPatterns := []string{
		"jquery.min.js", "jquery-", "jQuery.fn", "$.ajax(", "$(document).ready(",
	}
	isjQuery := false
	for _, pattern := range jQueryPatterns {
		if strings.Contains(body, pattern) {
			isjQuery = true
			break
		}
	}
	if isjQuery {
		var version string
		versionRegex := regexp.MustCompile(`jQuery(?:\.fn)?\.jquery\s*=\s*["']([\d\.]+)["']`)
		if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
			version = matches[1]
		}
		tech = append(tech, Technology{
			Name:        "jQuery",
			Version:     version,
			Description: "JavaScript library",
			Confidence:  "High", // Upgraded confidence due to better pattern matching
			Location:    "HTML (jQuery patterns)",
			Category:    "JavaScript Library",
			Evidence:    1,
		})
		verboseLog("Detected jQuery library")
	}
	
	// Analytics detection
	if strings.Contains(body, "google-analytics.com") ||
		strings.Contains(strings.ToLower(body), "googleanalytics") ||
		strings.Contains(body, "ga('create'") ||
		strings.Contains(body, "gtag") {
		tech = append(tech, Technology{
			Name:        "Google Analytics",
			Description: "Web analytics service",
			Confidence:  "High",
			Location:    "HTML (script reference)",
			Category:    "Analytics",
			Evidence:    1,
		})
		verboseLog("Detected Google Analytics")
	}
	
	// Check for other analytics tools
	if strings.Contains(body, "https://js.hs-scripts.com/") || 
	   strings.Contains(body, "hubspot") {
		tech = append(tech, Technology{
			Name:        "HubSpot",
			Description: "Marketing, Sales, and CRM Platform",
			Confidence:  "High",
			Location:    "HTML content",
			Category:    "Marketing",
			Evidence:    1,
		})
		verboseLog("Detected HubSpot")
	}
	
	if strings.Contains(body, "https://cdn.jsdelivr.net/npm/bootstrap@") || 
	   strings.Contains(body, "bootstrap.min.css") ||
	   strings.Contains(body, "bootstrap.bundle.min.js") {
		var version string
		versionRegex := regexp.MustCompile(`bootstrap@([\d\.]+)`)
		if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
			version = matches[1]
		}
		tech = append(tech, Technology{
			Name:        "Bootstrap",
			Version:     version,
			Description: "CSS Framework",
			Confidence:  "High",
			Location:    "HTML content",
			Category:    "UI Framework",
			Evidence:    1,
		})
		verboseLog("Detected Bootstrap")
	}
	
	// Check for CloudFlare
	if strings.Contains(body, "cloudflare.com") || 
	   strings.Contains(body, "__cf_") {
		tech = append(tech, Technology{
			Name:        "Cloudflare",
			Description: "CDN and DDoS Protection",
			Confidence:  "High",
			Location:    "HTML content",
			Category:    "CDN",
			Evidence:    1,
		})
		verboseLog("Detected Cloudflare in HTML")
	}

	return tech
}

// fetchJavaScriptWithCache downloads JavaScript files with caching
func fetchJavaScriptWithCache(src string, client *http.Client) (string, error) {
	// Check cache first
	jsCacheMutex.RLock()
	cachedContent, found := jsCache[src]
	jsCacheMutex.RUnlock()
	
	if found {
		verboseLog(fmt.Sprintf("Using cached JavaScript file: %s", src))
		return cachedContent, nil
	}
	
	// Not in cache, fetch it
	verboseLog(fmt.Sprintf("Fetching JavaScript file: %s", src))
	resp, err := client.Get(src)
	if err != nil {
		debugLog(fmt.Sprintf("Failed to fetch JavaScript: %v", err))
		return "", err
	}
	if resp.StatusCode != 200 {
		debugLog(fmt.Sprintf("JavaScript fetch failed with status %d", resp.StatusCode))
		resp.Body.Close()
		return "", fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		debugLog(fmt.Sprintf("Failed to read JavaScript: %v", err))
		return "", err
	}
	
	js := string(body)
	
	// Store in cache
	jsCacheMutex.Lock()
	jsCache[src] = js
	jsCacheMutex.Unlock()
	
	return js, nil
}

// analyzeJavascriptFiles downloads and analyzes external JavaScript files for technology clues.
func analyzeJavascriptFiles(scriptSources []string, client *http.Client) []Technology {
	var tech []Technology
	
	// Use concurrent requests with a worker pool
	type result struct {
		src string
		techs []Technology
	}
	
	resultChan := make(chan result, len(scriptSources))
	semaphore := make(chan struct{}, 5) // Limit to 5 concurrent requests
	
	// Launch worker goroutines
	for _, src := range scriptSources {
		semaphore <- struct{}{} // Acquire semaphore
		go func(src string) {
			defer func() { <-semaphore }() // Release semaphore
			
			js, err := fetchJavaScriptWithCache(src, client)
			if err != nil {
				resultChan <- result{src, nil}
				return
			}
			
			var fileTechs []Technology
			
			// Basic React detection in JS with more specific patterns
			if strings.Contains(js, "React.createElement") || 
			   strings.Contains(js, "ReactDOM.render") || 
			   strings.Contains(js, "__REACT_DEVTOOLS_GLOBAL_HOOK__") {
				var version string
				versionRegex := regexp.MustCompile(`React(?:\.version)?\s*=\s*["']([\d\.]+)["']`)
				if matches := versionRegex.FindStringSubmatch(js); len(matches) > 1 {
					version = matches[1]
				}
				fileTechs = append(fileTechs, Technology{
					Name:        "React.js",
					Version:     version,
					Description: "JavaScript UI library",
					Confidence:  "High",
					Location:    fmt.Sprintf("JavaScript (%s)", src),
					Category:    "JavaScript Framework",
					Evidence:    1,
				})
				verboseLog("Detected React.js in JavaScript file")
			}
			
			// Basic Angular detection in JS with more specific patterns
			if strings.Contains(js, "angular.module(") || 
			   strings.Contains(js, "angular.bootstrap(") || 
			   (strings.Contains(js, "angular") && strings.Contains(js, "$compile")) {
				var version string
				versionRegex := regexp.MustCompile(`angular.*?version["']?:\s*["']([\d\.]+)["']`)
				if matches := versionRegex.FindStringSubmatch(js); len(matches) > 1 {
					version = matches[1]
				}
				fileTechs = append(fileTechs, Technology{
					Name:        "AngularJS",
					Version:     version,
					Description: "JavaScript MVC framework",
					Confidence:  "High",
					Location:    fmt.Sprintf("JavaScript (%s)", src),
					Category:    "JavaScript Framework",
					Evidence:    1,
				})
				verboseLog("Detected AngularJS in JavaScript file")
			}
			
			// Basic Vue detection in JS with more specific patterns
			if strings.Contains(js, "Vue.component(") || 
			   strings.Contains(js, "Vue.directive(") || 
			   (strings.Contains(js, "Vue") && strings.Contains(js, "el:")) {
				var version string
				versionRegex := regexp.MustCompile(`Vue(?:\.version)?\s*=\s*["']([\d\.]+)["']`)
				if matches := versionRegex.FindStringSubmatch(js); len(matches) > 1 {
					version = matches[1]
				}
				fileTechs = append(fileTechs, Technology{
					Name:        "Vue.js",
					Version:     version,
					Description: "JavaScript progressive framework",
					Confidence:  "High",
					Location:    fmt.Sprintf("JavaScript (%s)", src),
					Category:    "JavaScript Framework",
					Evidence:    1,
				})
				verboseLog("Detected Vue.js in JavaScript file")
			}
			
			// Webpack detection in JS with more specificity
			if strings.Contains(js, "__webpack_require__") || 
			   strings.Contains(js, "webpackJsonp") {
				fileTechs = append(fileTechs, Technology{
					Name:        "Webpack",
					Description: "JavaScript module bundler",
					Confidence:  "High",
					Location:    fmt.Sprintf("JavaScript (%s)", src),
					Category:    "Build Tool",
					Evidence:    1,
				})
				verboseLog("Detected Webpack in JavaScript file")
			}
			
			// jQuery detection with more specificity
			if strings.Contains(js, "jQuery.fn") || 
			   strings.Contains(js, "$.fn") || 
			   (strings.Contains(js, "jquery") && 
			    (strings.Contains(js, "ajax") || strings.Contains(js, "getJSON"))) {
				var version string
				versionRegex := regexp.MustCompile(`jQuery(?:\.fn)?\.jquery\s*=\s*["']([\d\.]+)["']`)
				if matches := versionRegex.FindStringSubmatch(js); len(matches) > 1 {
					version = matches[1]
				}
				fileTechs = append(fileTechs, Technology{
					Name:        "jQuery",
					Version:     version,
					Description: "JavaScript library",
					Confidence:  "High",
					Location:    fmt.Sprintf("JavaScript (%s)", src),
					Category:    "JavaScript Library",
					Evidence:    1,
				})
				verboseLog("Detected jQuery in JavaScript file")
			}
			
			resultChan <- result{src, fileTechs}
		}(src)
	}
	
	// Collect results
	for i := 0; i < len(scriptSources); i++ {
		result := <-resultChan
		if result.techs != nil {
			tech = append(tech, result.techs...)
		}
	}
	
	return tech
}

// extractScriptSources returns all external script source URLs from the HTML body.
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

// extractLinks returns absolute URLs extracted from the HTML body that belong to the same host.
func extractLinks(body string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)
	verboseLog("Extracting links from page...")
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		debugLog("Failed to parse HTML for link extraction")
	} else {
		var traverse func(*html.Node)
		traverse = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "a" {
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						link := attr.Val
						if !strings.HasPrefix(link, "javascript:") && !strings.HasPrefix(link, "mailto:") && link != "#" {
							abs, err := baseURL.Parse(link)
							if err == nil && abs.Host == baseURL.Host && !seen[abs.String()] {
								seen[abs.String()] = true
								links = append(links, abs.String())
								debugLog(fmt.Sprintf("Found link: %s", abs.String()))
							}
						}
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				traverse(c)
			}
		}
		traverse(doc)
	}
	return links
}

// prioritizeLinks sorts links to prioritize paths that are likely to reveal technologies
func prioritizeLinks(links []string) []string {
	// Paths that are likely to reveal technologies
	techPaths := []string{
		"/wp-admin/", "/admin/", "/administrator/", "/api/", 
		"/about", "/contact", "/wp-json/", "/dashboard",
		"/package.json", "/composer.json", "/wp-content/",
	}
	
	// Score each link
	type scoredLink struct {
		url   string
		score int
	}
	
	var scoredLinks []scoredLink
	for _, link := range links {
		score := 0
		for _, techPath := range techPaths {
			if strings.Contains(link, techPath) {
				score += 5
				break
			}
		}
		// Prefer shorter paths
		score -= strings.Count(link, "/")
		scoredLinks = append(scoredLinks, scoredLink{link, score})
	}
	
	// Sort by score
	sort.Slice(scoredLinks, func(i, j int) bool {
		return scoredLinks[i].score > scoredLinks[j].score
	})
	
	// Extract sorted URLs
	var result []string
	for _, sl := range scoredLinks {
		result = append(result, sl.url)
	}
	
	return result
}

// calculateConfidence recalculates confidence based on evidence count
func calculateConfidence(tech Technology, evidenceCount int) string {
	baseScore := map[string]int{
		"Very High": 4,
		"High":      3,
		"Medium":    2,
		"Low":       1,
	}[tech.Confidence]
	
	finalScore := baseScore + evidenceCount
	
	if finalScore >= 6 {
		return "Very High"
	} else if finalScore >= 4 {
		return "High"
	} else if finalScore >= 2 {
		return "Medium"
	}
	return "Low"
}

// detectTech fetches a URL and analyzes it for technology clues.
func detectTech(targetURL string, client *http.Client, authUser, authPass, cookieStr string, verbose bool) ([]Technology, string, error) {
	verboseLog(fmt.Sprintf("Fetching %s", targetURL))
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	if authUser != "" && authPass != "" {
		req.SetBasicAuth(authUser, authPass)
		verboseLog("Using Basic Authentication")
	}
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
	if strings.Contains(body, "bad-browser") || strings.Contains(body, "unsupported browser") {
		verboseLog("WARNING: Detected possible browser verification page")
	}
	var techs []Technology
	baseURL, _ := url.Parse(targetURL)
	scriptSources := extractScriptSources(body, baseURL)
	headerTechs := analyzeHeaders(resp.Header)
	htmlTechs := analyzeHTML(body)
	jsTechs := analyzeJavascriptFiles(scriptSources, client)
	if resp.Request.URL.String() != targetURL {
		verboseLog(fmt.Sprintf("Request was redirected to: %s", resp.Request.URL.String()))
	}
	techs = append(techs, headerTechs...)
	techs = append(techs, htmlTechs...)
	techs = append(techs, jsTechs...)
	return techs, body, nil
}

// fallbackURLScan is a backup method: tries common paths to extract technology clues.
func fallbackURLScan(baseURL *url.URL, client *http.Client, authUser, authPass, cookieStr string) []Technology {
	paths := []string{
		"/", 
		"/dashboard", 
		"/login", 
		"/api", 
		"/api/status", 
		"/version", 
		"/health", 
		"/about", 
		"/wp-admin/", 
		"/admin/", 
		"/administrator/", 
		"/wp-json/", 
		"/readme.html",
		"/robots.txt",
		"/sitemap.xml",
	}
	
	var allTechs []Technology
	
	// Use concurrent requests with a worker pool
	type result struct {
		path string
		techs []Technology
	}
	
	resultChan := make(chan result, len(paths))
	semaphore := make(chan struct{}, 5) // Limit to 5 concurrent requests
	
	// Launch worker goroutines
	for _, path := range paths {
		semaphore <- struct{}{} // Acquire semaphore
		go func(path string) {
			defer func() { <-semaphore }() // Release semaphore
			
			fullURL := baseURL.Scheme + "://" + baseURL.Host + path
			verboseLog(fmt.Sprintf("Trying fallback URL: %s", fullURL))
			req, err := http.NewRequest("GET", fullURL, nil)
			if err != nil {
				resultChan <- result{path, nil}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			if authUser != "" && authPass != "" {
				req.SetBasicAuth(authUser, authPass)
			}
			if cookieStr != "" {
				req.Header.Set("Cookie", cookieStr)
			}
			resp, err := client.Do(req)
			if err != nil {
				resultChan <- result{path, nil}
				return
			}
			
			bodyBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				resultChan <- result{path, nil}
				return
			}
			
			var pathTechs []Technology
			headerTechs := analyzeHeaders(resp.Header)
			htmlTechs := analyzeHTML(string(bodyBytes))
			pathTechs = append(pathTechs, headerTechs...)
			pathTechs = append(pathTechs, htmlTechs...)
			
			resultChan <- result{path, pathTechs}
		}(path)
	}
	
	// Collect results
	for i := 0; i < len(paths); i++ {
		result := <-resultChan
		if result.techs != nil {
			allTechs = append(allTechs, result.techs...)
		}
	}
	
	return allTechs
}

// attemptToProbeAPI checks common API endpoints that might reveal technology clues.
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
		"/wp-json/wp/v2/",
		"/api/v1/health",
		"/.well-known/security.txt",
	}
	
	var apiTechs []Technology
	
	// Use concurrent requests with a worker pool
	type result struct {
		path string
		techs []Technology
	}
	
	resultChan := make(chan result, len(apiPaths))
	semaphore := make(chan struct{}, 5) // Limit to 5 concurrent requests
	
	// Launch worker goroutines
	for _, path := range apiPaths {
		semaphore <- struct{}{} // Acquire semaphore
		go func(path string) {
			defer func() { <-semaphore }() // Release semaphore
			
			fullURL := baseURL.Scheme + "://" + baseURL.Host + path
			req, err := http.NewRequest("GET", fullURL, nil)
			if err != nil {
				resultChan <- result{path, nil}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			if cookieStr != "" {
				req.Header.Set("Cookie", cookieStr)
			}
			resp, err := client.Do(req)
			if err != nil {
				resultChan <- result{path, nil}
				return
			}
			
			var pathTechs []Technology
			
			if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "json") {
				pathTechs = append(pathTechs, Technology{
					Name:        "REST API",
					Description: "JSON-based REST API",
					Confidence:  "High",
					Location:    fmt.Sprintf("API endpoint (%s)", path),
					Category:    "API",
					Evidence:    1,
				})
				bodyBytes, _ := io.ReadAll(resp.Body)
				body := string(bodyBytes)
				
				// Specific API detections
				if path == "/wp-json/wp/v2/" {
					pathTechs = append(pathTechs, Technology{
						Name:        "WordPress REST API",
						Description: "WordPress REST API",
						Confidence:  "Very High",
						Location:    fmt.Sprintf("API endpoint (%s)", path),
						Category:    "API",
						Evidence:    2,
					})
					
					var wpVersion string
					versionRegex := regexp.MustCompile(`"version":"([\d\.]+)"`)
					if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 {
						wpVersion = matches[1]
					}
					
					pathTechs = append(pathTechs, Technology{
						Name:        "WordPress",
						Version:     wpVersion,
						Description: "Content Management System",
						Confidence:  "Very High",
						Location:    fmt.Sprintf("API endpoint (%s)", path),
						Category:    "CMS",
						Evidence:    2,
					})
				}
				
				if strings.Contains(body, "angular") {
					pathTechs = append(pathTechs, Technology{
						Name:        "AngularJS",
						Description: "JavaScript MVC framework",
						Confidence:  "Medium",
						Location:    fmt.Sprintf("API response (%s)", path),
						Category:    "JavaScript Framework",
						Evidence:    1,
					})
				}
				if strings.Contains(body, "react") {
					pathTechs = append(pathTechs, Technology{
						Name:        "React.js",
						Description: "JavaScript UI library",
						Confidence:  "Medium",
						Location:    fmt.Sprintf("API response (%s)", path),
						Category:    "JavaScript Framework",
						Evidence:    1,
					})
				}
			}
			
			resp.Body.Close()
			resultChan <- result{path, pathTechs}
		}(path)
	}
	
	// Collect results
	for i := 0; i < len(apiPaths); i++ {
		result := <-resultChan
		if result.techs != nil {
			apiTechs = append(apiTechs, result.techs...)
		}
	}
	
	return apiTechs
}

// removeDuplicateTechs removes duplicate technologies from the list
// and combines evidence from multiple detections
func removeDuplicateTechs(techList []Technology) []Technology {
	type techKey struct {
		name string
		category string
	}
	
	unique := make(map[techKey]Technology)
	for _, tech := range techList {
		key := techKey{tech.Name, tech.Category}
		existing, exists := unique[key]
		if !exists {
			// First time seeing this tech
			unique[key] = tech
		} else {
			// We've seen this tech before - update with better info and accumulate evidence
			newTech := existing
			newTech.Evidence += tech.Evidence
			
			// Use the more specific version if available
			if tech.Version != "" && existing.Version == "" {
				newTech.Version = tech.Version
			} else if tech.Version != "" && existing.Version != "" && tech.Version != existing.Version {
				// If versions differ, append the new one (could be useful)
				newTech.Version = existing.Version + ", " + tech.Version
			}
			
			// Recalculate confidence based on accumulated evidence
			newTech.Confidence = calculateConfidence(newTech, newTech.Evidence)
			
			// Update
			unique[key] = newTech
		}
	}
	
	var result []Technology
	for _, tech := range unique {
		result = append(result, tech)
	}
	
	// Sort by category then by name
	sort.Slice(result, func(i, j int) bool {
		if result[i].Category != result[j].Category {
			return result[i].Category < result[j].Category
		}
		return result[i].Name < result[j].Name
	})
	
	return result
}

// categorizeResults groups technologies by category
func categorizeResults(techs []Technology) map[string][]Technology {
	categories := map[string][]Technology{}
	
	for _, tech := range techs {
		category := tech.Category
		if category == "" {
			category = "Other"
		}
		categories[category] = append(categories[category], tech)
	}
	
	// Sort technologies within each category by name
	for category := range categories {
		sort.Slice(categories[category], func(i, j int) bool {
			return categories[category][i].Name < categories[category][j].Name
		})
	}
	
	return categories
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
        Enable dynamic in-domain crawling (BFS)
  -user string
        Username for Basic Authentication
  -pass string
        Password for Basic Authentication
  -cookie string
        Cookie header to include in requests (e.g., "sessionid=abc123; csrftoken=xyz")
  -fallback
        Use fallback methods if regular detection fails
  -verbose
        Enable verbose output with more details
  -max int
        Maximum number of pages to crawl (default %d)
  -insecure
        Skip TLS certificate verification
  -json
        Output results in JSON format
  -output string
        Write results to a file
  -workers int
        Number of concurrent crawl workers (default 5)
  -h, -help
        Show help message and exit

Examples:
  techdetector -url https://example.com
  techdetector -url https://app.example.com -cookie "session=abc123" -crawl -verbose
  techdetector -url https://example.com -crawl -json -output results.json
`
	fmt.Printf(usageText, version, maxPagesDefault)
}

func main() {
	urlPtr := flag.String("url", "", "Target URL to analyze (e.g., https://example.com)")
	crawlPtr := flag.Bool("crawl", false, "Enable dynamic in-domain crawling using BFS")
	authUser := flag.String("user", "", "Username for Basic Authentication")
	authPass := flag.String("pass", "", "Password for Basic Authentication")
	cookieStr := flag.String("cookie", "", "Cookie header to include in requests")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output with more details")
	fallbackPtr := flag.Bool("fallback", false, "Use fallback methods if regular detection fails")
	maxPagesPtr := flag.Int("max", maxPagesDefault, "Maximum number of pages to crawl")
	insecurePtr := flag.Bool("insecure", false, "Skip TLS certificate verification")
	jsonPtr := flag.Bool("json", false, "Output results in JSON format")
	outputPtr := flag.String("output", "", "Write results to a file")
	workersPtr := flag.Int("workers", 5, "Number of concurrent crawl workers")
	helpPtr := flag.Bool("help", false, "Show help message")
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

	// Configure logging based on verbose flag.
	if !*verbosePtr {
		log.SetFlags(0)
		log.SetOutput(io.Discard)
	} else {
		log.SetFlags(log.Ltime)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
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
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			for _, cookie := range via[0].Cookies() {
				req.AddCookie(cookie)
			}
			req.Header.Set("User-Agent", via[0].Header.Get("User-Agent"))
			return nil
		},
	}

	baseURL, err := url.Parse(*urlPtr)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}
	fmt.Printf("TechDetector v%s - Analyzing %s...\n\n", version, *urlPtr)

	if *crawlPtr {
		visited := make(map[string]bool)
		queue := []string{*urlPtr}
		visited[*urlPtr] = true
		var allTechs []Technology
		pagesCrawled := 0

		// Create a semaphore to limit concurrent crawling
		sem := make(chan struct{}, *workersPtr)
		techResults := make(chan []Technology, *maxPagesPtr)
		
		// Launch goroutines for initial pages
		var wg sync.WaitGroup
		
		for pagesCrawled < *maxPagesPtr && len(queue) > 0 {
			currentBatch := min(len(queue), *maxPagesPtr-pagesCrawled)
			currentURLs := queue[:currentBatch]
			queue = queue[currentBatch:]
			
			for i, currentURL := range currentURLs {
				wg.Add(1)
				sem <- struct{}{} // Acquire semaphore slot
				
				go func(url string, pageNum int) {
					defer func() {
						<-sem // Release semaphore slot
						wg.Done()
					}()
					
					fmt.Printf("\n[Page %d/%d] Analyzing %s...\n", pageNum+1, *maxPagesPtr, url)
					techs, body, err := detectTech(url, client, *authUser, *authPass, *cookieStr, *verbosePtr)
					
					if err != nil {
						fmt.Printf("  Error: %v\n", err)
						techResults <- nil
						return
					}
					
					if len(techs) == 0 {
						fmt.Println("  No technologies detected.")
					} else {
						fmt.Println("  Detected Technologies:")
						for _, t := range techs {
							fmt.Printf("   - %s\n", t)
						}
					}
					
					// If fallback flag is set and no techs were found, use fallback methods.
					if (*fallbackPtr) && (err != nil || len(techs) == 0) {
						fmt.Println("  Using fallback detection methods for this page...")
						fallbackTechs := fallbackURLScan(baseURL, client, *authUser, *authPass, *cookieStr)
						apiTechs := attemptToProbeAPI(baseURL, client, *cookieStr)
						techs = append(techs, fallbackTechs...)
						techs = append(techs, apiTechs...)
					}
					
					// Extract and prioritize links for further crawling
					links := extractLinks(body, baseURL)
					prioritizedLinks := prioritizeLinks(links)
					
					// Queue up new URLs if we haven't hit our limit
					// This needs to be synchronized to avoid race conditions
					for _, link := range prioritizedLinks {
						if !visited[link] {
							visited[link] = true
							queue = append(queue, link)
						}
					}
					
					techResults <- techs
				}(currentURL, pagesCrawled+i)
			}
			
			// Collect results from this batch
			for i := 0; i < currentBatch; i++ {
				techs := <-techResults
				if techs != nil {
					allTechs = append(allTechs, techs...)
				}
			}
			
			pagesCrawled += currentBatch
			wg.Wait() // Wait for all goroutines in this batch to complete
		}
		
		// Process and display results
		allTechs = removeDuplicateTechs(allTechs)
		
		if *jsonPtr {
			jsonOutput, err := json.MarshalIndent(allTechs, "", "  ")
			if err != nil {
				log.Fatalf("Error creating JSON output: %v", err)
			}
			
			if *outputPtr != "" {
				err = os.WriteFile(*outputPtr, jsonOutput, 0644)
				if err != nil {
					log.Fatalf("Error writing to output file: %v", err)
				}
				fmt.Printf("\nResults written to %s\n", *outputPtr)
			} else {
				fmt.Println("\n=== TECHNOLOGY SUMMARY (JSON) ===")
				fmt.Println(string(jsonOutput))
			}
		} else {
			fmt.Println("\n=== TECHNOLOGY SUMMARY ===")
			if len(allTechs) == 0 {
				fmt.Println("No technologies detected overall.")
			} else {
				categories := categorizeResults(allTechs)
				
				// Get sorted category names
				var categoryNames []string
				for category := range categories {
					categoryNames = append(categoryNames, category)
				}
				sort.Strings(categoryNames)
				
				// Print technologies by category
				for _, category := range categoryNames {
					fmt.Printf("\n%s:\n", category)
					for _, tech := range categories[category] {
						fmt.Printf(" - %s\n", tech)
					}
				}
				
				// Write to file if specified
				if *outputPtr != "" {
					var output strings.Builder
					output.WriteString(fmt.Sprintf("TechDetector v%s - Results for %s\n\n", version, *urlPtr))
					
					for _, category := range categoryNames {
						output.WriteString(fmt.Sprintf("\n%s:\n", category))
						for _, tech := range categories[category] {
							output.WriteString(fmt.Sprintf(" - %s\n", tech))
						}
					}
					
					output.WriteString(fmt.Sprintf("\nAnalysis completed: crawled %d unique pages.\n", pagesCrawled))
					
					err := os.WriteFile(*outputPtr, []byte(output.String()), 0644)
					if err != nil {
						log.Fatalf("Error writing to output file: %v", err)
					}
					fmt.Printf("\nResults written to %s\n", *outputPtr)
				}
			}
		}
		
		fmt.Printf("\nAnalysis completed: crawled %d unique pages.\n", pagesCrawled)
	} else {
		// Single page analysis
		techs, _, err := detectTech(*urlPtr, client, *authUser, *authPass, *cookieStr, *verbosePtr)
		if err != nil {
			log.Fatalf("Error detecting tech: %v", err)
		}
		
		// Use fallback if needed
		if (*fallbackPtr) && (err != nil || len(techs) == 0) {
			fmt.Println("Using fallback detection methods...")
			fallbackTechs := fallbackURLScan(baseURL, client, *authUser, *authPass, *cookieStr)
			apiTechs := attemptToProbeAPI(baseURL, client, *cookieStr)
			techs = append(techs, fallbackTechs...)
			techs = append(techs, apiTechs...)
		}
		
		techs = removeDuplicateTechs(techs)
		
		if *jsonPtr {
			jsonOutput, err := json.MarshalIndent(techs, "", "  ")
			if err != nil {
				log.Fatalf("Error creating JSON output: %v", err)
			}
			
			if *outputPtr != "" {
				err = os.WriteFile(*outputPtr, jsonOutput, 0644)
				if err != nil {
					log.Fatalf("Error writing to output file: %v", err)
				}
				fmt.Printf("Results written to %s\n", *outputPtr)
			} else {
				fmt.Println(string(jsonOutput))
			}
		} else {
			if len(techs) == 0 {
				fmt.Println("No technologies detected.")
			} else {
				categories := categorizeResults(techs)
				
				// Get sorted category names
				var categoryNames []string
				for category := range categories {
					categoryNames = append(categoryNames, category)
				}
				sort.Strings(categoryNames)
				
				fmt.Println("Detected Technologies:")
				// Print technologies by category
				for _, category := range categoryNames {
					fmt.Printf("\n%s:\n", category)
					for _, tech := range categories[category] {
						fmt.Printf(" - %s\n", tech)
					}
				}
				
				// Write to file if specified
				if *outputPtr != "" {
					var output strings.Builder
					output.WriteString(fmt.Sprintf("TechDetector v%s - Results for %s\n\n", version, *urlPtr))
					output.WriteString("Detected Technologies:\n")
					
					for _, category := range categoryNames {
						output.WriteString(fmt.Sprintf("\n%s:\n", category))
						for _, tech := range categories[category] {
							output.WriteString(fmt.Sprintf(" - %s\n", tech))
						}
					}
					
					err := os.WriteFile(*outputPtr, []byte(output.String()), 0644)
					if err != nil {
						log.Fatalf("Error writing to output file: %v", err)
					}
					fmt.Printf("\nResults written to %s\n", *outputPtr)
				}
			}
		}
	}
}

// Helper function for min of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
