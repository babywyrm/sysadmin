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
	maxPagesDefault = 10
	version         = "1.4.0"
)

type Technology struct {
	Name        string
	Version     string
	Description string
	Confidence  string
	Location    string
	Category    string
	Evidence    int
}

type TechSignature struct {
	Name         string
	Patterns     []string
	VersionRegex []string
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

var (
	jsCache      = make(map[string]string)
	jsCacheMutex = sync.RWMutex{}

	techSignatures = []TechSignature{
		{
			Name:         "WordPress",
			Patterns:     []string{"wp-content", "wp-includes", "wp-json", "wordpress", "wp-admin"},
			VersionRegex: []string{`<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d\.]+)["']`, `WordPress\s+([\d\.]+)`, `wp-includes.*?\?ver=([\d\.]+)`},
			Category:     "CMS",
			Description:  "Content Management System",
		},
		{
			Name:         "Drupal",
			Patterns:     []string{"Drupal.settings", "drupal.org", "/sites/all/", "/sites/default/"},
			VersionRegex: []string{`Drupal ([\d\.]+)`},
			Category:     "CMS",
			Description:  "Content Management System",
		},
		{
			Name:         "jQuery",
			Patterns:     []string{"jquery.min.js", "jquery-", "jQuery.fn", "$.ajax(", "$(document).ready("},
			VersionRegex: []string{`jquery(?:\.min)?\.js\?ver=([\d\.]+)`, `jquery-migrate(?:\.min)?\.js\?ver=([\d\.]+)`, `jquery(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`, `jQuery(?:\.fn)?\.jquery\s*=\s*["']([\d\.]+)["']`},
			Category:     "JavaScript Library",
			Description:  "JavaScript library",
		},
		{
			Name:         "Bootstrap",
			Patterns:     []string{"bootstrap.css", "bootstrap.min.css", "bootstrap.js", "bootstrap@"},
			VersionRegex: []string{`bootstrap@([\d\.]+)`, `bootstrap(?:\.min)?\.(?:css|js)(?:\?ver=|@|v)([\d\.]+)`},
			Category:     "UI Framework",
			Description:  "Frontend Framework",
		},
		{
			Name:         "React.js",
			Patterns:     []string{"react-dom", "react.production.min.js", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "ReactDOM.render(", "React.createElement("},
			VersionRegex: []string{`react(?:\.production|\.development)?\.min\.js(?:\?ver=|@)([\d\.]+)`, `React\.version\s*=\s*["']([\d\.]+)["']`},
			Category:     "JavaScript Framework",
			Description:  "JavaScript UI library",
		},
		{
			Name:         "Vue.js",
			Patterns:     []string{"vue.js", "vue.min.js", "v-if=", "v-for=", "v-model=", "vue@"},
			VersionRegex: []string{`vue(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`, `Vue\.version\s*=\s*["']([\d\.]+)["']`},
			Category:     "JavaScript Framework",
			Description:  "JavaScript progressive framework",
		},
		{
			Name:         "AngularJS",
			Patterns:     []string{"ng-app=", "ng-controller=", "angular.module(", "angular.bootstrap(", "ngRoute"},
			VersionRegex: []string{`angular(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`, `angular.*?version["']?:\s*["']([\d\.]+)["']`},
			Category:     "JavaScript Framework",
			Description:  "JavaScript MVC framework",
		},
		{
			Name:         "Cloudflare",
			Patterns:     []string{"cloudflare", "cf-ray", "cf-cache-status", "__cf_"},
			VersionRegex: []string{},
			Category:     "CDN",
			Description:  "Content Delivery Network and DDoS Protection",
		},
		{
			Name:         "Google Analytics",
			Patterns:     []string{"google-analytics.com", "googleanalytics", "ga('create'", "gtag"},
			VersionRegex: []string{},
			Category:     "Analytics",
			Description:  "Web Analytics Service",
		},
		{
			Name:         "ThousandEyes",
			Patterns:     []string{"thousandeyes"},
			VersionRegex: []string{},
			Category:     "Monitoring",
			Description:  "Network intelligence platform",
		},
	}
)

func debugLog(msg string) {
	if log.Writer() != io.Discard {
		log.Println("[DEBUG]", msg)
	}
}

func verboseLog(msg string) {
	if log.Writer() != io.Discard {
		log.Println("[INFO]", msg)
	}
}

func parseCookieString(cookieStr string) []*http.Cookie {
	var cookies []*http.Cookie
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			cookies = append(cookies, &http.Cookie{
				Name:  strings.TrimSpace(kv[0]),
				Value: strings.TrimSpace(kv[1]),
				Path:  "/",
			})
		}
	}
	return cookies
}

func extractVersion(text, techName string, patterns []string) string {
	for _, pattern := range patterns {
		if regex := regexp.MustCompile(pattern); regex != nil {
			if matches := regex.FindStringSubmatch(text); len(matches) > 1 {
				return matches[1]
			}
		}
	}
	return ""
}

func detectTechFromSignatures(content, location string) []Technology {
	var techs []Technology
	contentLower := strings.ToLower(content)

	for _, sig := range techSignatures {
		found := false
		for _, pat := range sig.Patterns {
			if strings.Contains(contentLower, strings.ToLower(pat)) {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		ver := extractVersion(content, sig.Name, sig.VersionRegex)
		techs = append(techs, Technology{
			Name:        sig.Name,
			Version:     ver,
			Description: sig.Description,
			Confidence:  "High",
			Location:    location,
			Category:    sig.Category,
			Evidence:    1,
		})
		verboseLog(fmt.Sprintf("Detected %s v%s in %s", sig.Name, ver, location))
	}

	// Additional specific detections
	low := strings.ToLower(content)
	specials := []struct {
		patterns []string
		tech     Technology
	}{
		{[]string{"webpack", "__webpack_require__", "webpackjsonp"}, Technology{Name: "Webpack", Description: "JavaScript module bundler", Confidence: "High", Location: location + " (webpack patterns)", Category: "Build Tool", Evidence: 1}},
		{[]string{"https://js.hs-scripts.com/", "hubspot"}, Technology{Name: "HubSpot", Description: "Marketing/CRM Platform", Confidence: "High", Location: location, Category: "Marketing", Evidence: 1}},
	}

	for _, s := range specials {
		for _, p := range s.patterns {
			if strings.Contains(low, p) {
				techs = append(techs, s.tech)
				break
			}
		}
	}

	return techs
}

func analyzeHeaders(headers http.Header) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTTP headers...")

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

		low := strings.ToLower(server)
		if strings.Contains(low, "nginx") {
			if v := extractVersion(server, "Nginx", []string{`nginx/?(\d+\.\d+\.\d+)?`}); v != "" {
				tech = append(tech, Technology{Name: "Nginx", Version: v, Description: "Web server", Confidence: "High", Location: "Server header", Category: "Server", Evidence: 1})
			}
		}
		if strings.Contains(low, "apache") {
			if v := extractVersion(server, "Apache", []string{`Apache/?(\d+\.\d+\.\d+)?`}); v != "" {
				tech = append(tech, Technology{Name: "Apache", Version: v, Description: "Web server", Confidence: "High", Location: "Server header", Category: "Server", Evidence: 1})
			}
		}
	}

	if powered := headers.Get("X-Powered-By"); powered != "" {
		tech = append(tech, Technology{Name: "X-Powered-By", Version: powered, Description: "Backend technology", Confidence: "High", Location: "X-Powered-By header", Category: "Server", Evidence: 1})
		if strings.Contains(strings.ToLower(powered), "php") {
			if v := extractVersion(powered, "PHP", []string{`PHP/?(\d+\.\d+\.\d+)`}); v != "" {
				tech = append(tech, Technology{Name: "PHP", Version: v, Description: "Server-side scripting language", Confidence: "High", Location: "X-Powered-By header", Category: "Programming Language", Evidence: 1})
			}
		}
	}

	if headers.Get("CF-Cache-Status") != "" || headers.Get("CF-RAY") != "" {
		tech = append(tech, Technology{Name: "Cloudflare", Description: "CDN and DDoS protection", Confidence: "High", Location: "Cloudflare headers", Category: "CDN", Evidence: 1})
	}

	return tech
}

func analyzeHTML(body string) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTML...")

	// Meta generator
	if re := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`); re != nil {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			tech = append(tech, Technology{Name: "Generator", Version: m[1], Description: "CMS or Generator", Confidence: "High", Location: "meta generator tag", Category: "CMS", Evidence: 1})
		}
	}

	// WordPress specific
	if re := regexp.MustCompile(`wp-content/themes/([^/'"]+)`); re != nil {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			tech = append(tech, Technology{Name: "WordPress Theme: " + m[1], Description: "WordPress Theme", Confidence: "High", Location: "HTML path", Category: "CMS Theme", Evidence: 1})
		}
	}

	if re := regexp.MustCompile(`wp-content/plugins/([^/'"]+)`); re != nil {
		seen := map[string]bool{}
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && !seen[m[1]] {
				seen[m[1]] = true
				tech = append(tech, Technology{Name: "WordPress Plugin: " + m[1], Description: "WordPress Plugin", Confidence: "High", Location: "HTML path", Category: "CMS Plugin", Evidence: 1})
			}
		}
	}

	tech = append(tech, detectTechFromSignatures(body, "HTML content")...)
	return tech
}

// extractScriptSources extracts JavaScript file URLs from script tags in the HTML body.
func extractScriptSources(body string, baseURL *url.URL) []string {
	var out []string
	seen := map[string]bool{}
	// Regex to find script tags with a src attribute
	if re := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`); re != nil {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				// Parse the URL to resolve relative paths
				if u, err := baseURL.Parse(m[1]); err == nil {
					s := u.String()
					if !seen[s] {
						seen[s] = true
						out = append(out, s)
						debugLog(fmt.Sprintf("Found JS script source: %s", s))
					}
				} else {
					debugLog(fmt.Sprintf("Error parsing script source %s: %v", m[1], err))
				}
			}
		}
	}
	return out
}

func fetchJavaScriptWithCache(src string, client *http.Client) (string, error) {
	jsCacheMutex.RLock()
	if c, ok := jsCache[src]; ok {
		jsCacheMutex.RUnlock()
		debugLog(fmt.Sprintf("Cache hit for JS: %s", src))
		return c, nil
	}
	jsCacheMutex.RUnlock()

	resp, err := client.Get(src)
	if err != nil {
		debugLog(fmt.Sprintf("Fetch JS failed for %s: %v", src, err))
		return "", fmt.Errorf("fetch JS failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		debugLog(fmt.Sprintf("Fetch JS for %s returned status %d", src, resp.StatusCode))
		return "", fmt.Errorf("fetch JS for %s returned status %d", src, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	js := string(body)
	jsCacheMutex.Lock()
	jsCache[src] = js
	jsCacheMutex.Unlock()
	verboseLog(fmt.Sprintf("Fetched JS and cached: %s", src))
	return js, nil
}

func analyzeJavascriptFiles(sources []string, client *http.Client) []Technology {
	type res struct {
		techs []Technology
	}
	ch := make(chan res, len(sources))
	sem := make(chan struct{}, 5) // Limit concurrent JS fetches

	var wg sync.WaitGroup

	for _, src := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			sem <- struct{}{} // Acquire token
			defer func() { <-sem }() // Release token

			js, err := fetchJavaScriptWithCache(src, client)
			if err != nil {
				ch <- res{nil}
				return
			}
			var techs []Technology
			// Analyze the URL itself for signatures (e.g., jquery.min.js?ver=X)
			techs = append(techs, detectTechFromSignatures(src, fmt.Sprintf("JavaScript URL (%s)", src))...)
			// Analyze the content of the JavaScript file
			techs = append(techs, detectTechFromSignatures(js, fmt.Sprintf("JavaScript content (%s)", src))...)
			ch <- res{techs}
		}(src)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var all []Technology
	for r := range ch { // Loop until channel is closed
		if r.techs != nil {
			all = append(all, r.techs...)
		}
	}
	return all
}

// extractAuthLinks now extracts all relevant links from HTML and potential paths from JS
func extractAuthLinks(body string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	// Using golang.org/x/net/html for robust HTML parsing
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		debugLog(fmt.Sprintf("Error parsing HTML for links: %v", err))
		return nil
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		// Look for <a> tags with href attributes
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" && a.Val != "" && !strings.HasPrefix(a.Val, "javascript:") && !strings.HasPrefix(a.Val, "mailto:") && a.Val != "#" {
					if u, err := baseURL.Parse(a.Val); err == nil {
						// Ensure it's the same host or a subdomain
						if u.Host == baseURL.Host || strings.HasSuffix(u.Host, "."+baseURL.Host) {
							s := u.String()
							// Normalize path to avoid duplicate entries for same page (ignore query params and fragments for uniqueness)
							if u.Path != "" && u.Path != "/" {
								s = u.Scheme + "://" + u.Host + u.Path
							}
							if !seen[s] {
								seen[s] = true
								links = append(links, s)
								debugLog(fmt.Sprintf("Found HTML link: %s", s))
							}
						}
					} else {
						debugLog(fmt.Sprintf("Error parsing HTML link %s: %v", a.Val, err))
					}
				}
			}
		}
		// Look for <script> and <link> tags for their src/href attributes
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "link") {
			for _, a := range n.Attr {
				if a.Key == "src" || a.Key == "href" {
					if a.Val != "" {
						if u, err := baseURL.Parse(a.Val); err == nil {
							if u.Host == baseURL.Host || strings.HasSuffix(u.Host, "."+baseURL.Host) {
								s := u.String()
								if !seen[s] {
									seen[s] = true
									// Add these as potential crawl targets as well, especially if they are HTML documents
									// or could lead to dynamic content. `extractScriptSources` will handle actual JS files.
									links = append(links, s)
									debugLog(fmt.Sprintf("Found %s resource: %s", n.Data, s))
								}
							}
						}
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	// Extract potential internal paths from JavaScript content (less reliable, but can catch SPAs)
	// Looking for paths that start with '/' and are likely internal routes
	// Excludes common file extensions to avoid treating them as pages to crawl
	jsPathRegex := regexp.MustCompile(`["'](/[a-zA-Z0-9/._-]+?)["']`)
	for _, match := range jsPathRegex.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			path := match[1]
			// Basic filtering for common static file extensions
			if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".png") ||
				strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".gif") || strings.HasSuffix(path, ".svg") ||
				strings.HasSuffix(path, ".ico") || strings.Contains(path, "?") || strings.Contains(path, "#") { // Also filter paths with query or fragment
				continue
			}

			if u, err := baseURL.Parse(path); err == nil {
				if u.Host == baseURL.Host || strings.HasSuffix(u.Host, "."+baseURL.Host) {
					s := u.Scheme + "://" + u.Host + u.Path // Normalize for uniqueness
					if !seen[s] {
						seen[s] = true
						links = append(links, s)
						debugLog(fmt.Sprintf("Found JS internal path: %s", s))
					}
				}
			}
		}
	}

	return links
}

// validateSession checks if a given session (via cookies) is active by probing known authenticated endpoints.
func validateSession(client *http.Client, baseURL *url.URL) bool {
	testURLs := []string{
		"/api/user", "/api/profile", "/dashboard", "/admin", "/settings", "/", // Adding root to check initial redirect behavior
	}

	for _, path := range testURLs {
		testURL := baseURL.Scheme + "://" + baseURL.Host + path
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			debugLog(fmt.Sprintf("Error creating validation request for %s: %v", testURL, err))
			continue
		}
		// Set a specific User-Agent for validation requests if needed
		req.Header.Set("User-Agent", "TechDetector/SessionValidator")

		resp, err := client.Do(req)
		if err != nil {
			debugLog(fmt.Sprintf("Error validating session for %s: %v", testURL, err))
			continue
		}
		defer resp.Body.Close()

		// If we get anything other than 401/403, session might be valid.
		// A 200 OK or even a 302 redirect to another authenticated page would indicate success.
		// Be careful with 302s to login pages, though.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			verboseLog(fmt.Sprintf("Session validated successfully with %s (Status: %d)", testURL, resp.StatusCode))
			return true
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			verboseLog(fmt.Sprintf("Session check for %s returned %d (Unauthorized/Forbidden).", testURL, resp.StatusCode))
		} else {
			debugLog(fmt.Sprintf("Session check for %s returned unexpected status %d.", testURL, resp.StatusCode))
		}
	}
	return false
}

func detectTech(targetURL string, client *http.Client, authUser, authPass, cookieStr string, verbose bool) ([]Technology, string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	if authUser != "" && authPass != "" {
		req.SetBasicAuth(authUser, authPass)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	body := string(bodyBytes)
	baseURL, _ := url.Parse(targetURL) // This parse will handle relative URLs in extractScriptSources

	var techs []Technology
	techs = append(techs, analyzeHeaders(resp.Header)...)
	techs = append(techs, analyzeHTML(body)...)
	techs = append(techs, analyzeJavascriptFiles(extractScriptSources(body, baseURL), client)...)

	return techs, body, nil
}

func crawlAuthenticated(baseURL *url.URL, client *http.Client, maxPages int, authUser, authPass, cookieStr string) []Technology {
	// Validate session if cookies provided
	if cookieStr != "" {
		if !validateSession(client, baseURL) {
			fmt.Println("Warning: Session appears invalid or expired for initial tests. Continuing with crawl, but results may be limited.")
		} else {
			verboseLog("Session validation successful for initial tests.")
		}
	}

	visited := make(map[string]bool)
	var allTechsMutex sync.Mutex // Mutex for allTechs slice
	var allTechs []Technology

	// Buffered channel for the queue. Size allows some look-ahead without infinite growth.
	// We'll limit processing by `maxPages` and use the buffer to hold discovered but not-yet-processed links.
	queue := make(chan string, maxPages*5) // Increased buffer to allow more links to be queued before blocking

	// A channel to receive results (technologies) from worker goroutines
	resultCh := make(chan struct {
		techs []Technology
		err   error
		url   string
	})

	// Counter for unique pages successfully processed
	processedPagesCounter := 0
	var processedPagesMutex sync.Mutex // Mutex for processedPagesCounter

	// Function to add a link to the queue, with normalization and visited check
	addLinkToQueue := func(u string) {
		// Normalize URL: remove query params, fragments, and trailing slashes (unless it's root)
		normalizedURL := u
		if parsedU, err := url.Parse(u); err == nil {
			if parsedU.Path != "" && parsedU.Path != "/" {
				normalizedURL = parsedU.Scheme + "://" + parsedU.Host + strings.TrimRight(parsedU.Path, "/")
			} else {
				normalizedURL = parsedU.Scheme + "://" + parsedU.Host + "/"
			}
			// Important: Ensure URL is still within the same domain/subdomain before adding
			if !(parsedU.Host == baseURL.Host || strings.HasSuffix(parsedU.Host, "."+baseURL.Host)) {
				debugLog(fmt.Sprintf("Skipping out-of-scope link: %s", u))
				return
			}
		} else {
			debugLog(fmt.Sprintf("Failed to parse URL %s: %v", u, err))
			return
		}

		if !visited[normalizedURL] {
			visited[normalizedURL] = true // Mark as visited immediately to prevent duplicates entering the queue
			select {
			case queue <- normalizedURL:
				debugLog(fmt.Sprintf("Added to queue: %s (Current queue size: %d/%d)", normalizedURL, len(queue), cap(queue)))
			default:
				debugLog(fmt.Sprintf("Queue buffer full, skipping: %s", normalizedURL))
			}
		} else {
			debugLog(fmt.Sprintf("Already visited/queued, skipping: %s", normalizedURL))
		}
	}

	// Add initial high-value authenticated pages to the queue
	initialURLs := []string{
		baseURL.String(),
		baseURL.String() + "/dashboard",
		baseURL.String() + "/admin",
		baseURL.String() + "/api",
		baseURL.String() + "/settings",
	}
	for _, url := range initialURLs {
		addLinkToQueue(url)
	}

	// WaitGroup to track active worker goroutines
	var wg sync.WaitGroup
	// Semaphore to limit concurrent HTTP requests
	crawlerSem := make(chan struct{}, 5) // Concurrency limit for HTTP requests (5 parallel fetches)

	// Goroutine to dispatch worker requests from the queue
	go func() {
		for {
			select {
			case urlToCrawl := <-queue:
				// Before processing, check if we've hit the maxPages limit
				processedPagesMutex.Lock()
				if processedPagesCounter >= maxPages {
					processedPagesMutex.Unlock()
					debugLog(fmt.Sprintf("Max pages (%d) reached, discarding queued URL: %s", maxPages, urlToCrawl))
					continue // Don't process this URL, but continue draining the queue channel
				}
				processedPagesCounter++ // Increment the counter for successfully scheduled pages
				pageNumber := processedPagesCounter
				processedPagesMutex.Unlock()

				wg.Add(1)
				go func(currentURL string, pageNum int) {
					defer wg.Done()
					crawlerSem <- struct{}{} // Acquire concurrency token
					defer func() { <-crawlerSem }() // Release token

					fmt.Printf("\n[Page %d/%d] Analyzing %s...\n", pageNum, maxPages, currentURL)

					techs, body, err := detectTech(currentURL, client, authUser, authPass, cookieStr, false)
					if err != nil {
						fmt.Printf("  Error analyzing %s: %v\n", currentURL, err)
						resultCh <- struct {
							techs []Technology
							err   error
							url   string
						}{nil, err, currentURL} // Send error back
						return
					}

					if len(techs) > 0 {
						fmt.Println("  Detected Technologies:")
						for _, t := range techs {
							fmt.Printf("   - %s\n", t)
						}
					} else {
						fmt.Println("  No new technologies detected on this page.")
					}

					// Extract new links from the current page's body and add them to the queue
					newLinks := extractAuthLinks(body, baseURL)
					fmt.Printf("  Found %d potential new links. Adding to queue...\n", len(newLinks))
					for _, link := range newLinks {
						addLinkToQueue(link)
					}

					resultCh <- struct {
						techs []Technology
						err   error
						url   string
					}{techs, nil, currentURL} // Send successful results
				}(urlToCrawl, pageNumber)

			case <-time.After(5 * time.Second): // Timeout if no new URLs for a while
				// If the queue is empty AND no workers are active, we can stop.
				// Wait for any remaining workers to finish before deciding to terminate.
				debugLog("Queue empty or no new URLs detected for 5s. Checking active workers...")
				wg.Wait() // Wait for any currently running `detectTech` calls to finish
				if len(queue) == 0 && processedPagesCounter >= len(visited) { // If queue is still empty and all visited links were processed
					debugLog("Queue is truly empty and no pending links. Terminating crawler.")
					close(queue) // Signal that no more URLs will be added to the queue
					return
				}
			}
		}
	}()

	// Goroutine to close resultCh once all workers are done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Main loop to collect results
	finalProcessedCount := 0
	for res := range resultCh {
		if res.techs != nil {
			allTechsMutex.Lock()
			allTechs = append(allTechs, res.techs...)
			allTechsMutex.Unlock()
			finalProcessedCount++
		}
	}
	// Note: finalProcessedCount might be slightly different from processedPagesCounter
	// if some goroutines failed to send results or exited early.

	fmt.Printf("\nAnalysis completed: crawled %d unique pages.\n", finalProcessedCount)
	return allTechs
}

func fallbackURLScan(baseURL *url.URL, client *http.Client, authUser, authPass, cookieStr string) []Technology {
	paths := []string{"/", "/robots.txt", "/sitemap.xml", "/wp-json/", "/api/", "/index.html"}
	var allTechs []Technology

	for _, path := range paths {
		full := baseURL.Scheme + "://" + baseURL.Host + path
		fmt.Printf("  Attempting fallback scan on: %s\n", full)
		req, err := http.NewRequest("GET", full, nil)
		if err != nil {
			debugLog(fmt.Sprintf("Fallback: Error creating request for %s: %v", full, err))
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if authUser != "" && authPass != "" {
			req.SetBasicAuth(authUser, authPass)
		}
		resp, err := client.Do(req)
		if err != nil {
			debugLog(fmt.Sprintf("Fallback: Error fetching %s: %v", full, err))
			continue
		}

		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			debugLog(fmt.Sprintf("Fallback: Error reading body from %s: %v", full, err))
			continue
		}

		techs := analyzeHeaders(resp.Header)
		techs = append(techs, analyzeHTML(string(b))...)
		// Also analyze JavaScript files found on fallback pages
		techs = append(techs, analyzeJavascriptFiles(extractScriptSources(string(b), baseURL), client)...)
		allTechs = append(allTechs, techs...)
	}

	return allTechs
}

func attemptToProbeAPI(baseURL *url.URL, client *http.Client, cookieStr string) []Technology {
	paths := []string{"/api/info", "/api/status", "/wp-json/wp/v2/", "/api/v1/health", "/graphql"}
	var allTechs []Technology

	for _, p := range paths {
		full := baseURL.Scheme + "://" + baseURL.Host + p
		fmt.Printf("  Probing API endpoint: %s\n", full)
		req, err := http.NewRequest("GET", full, nil)
		if err != nil {
			debugLog(fmt.Sprintf("API probe: Error creating request for %s: %v", full, err))
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "application/json, application/graphql") // Accept JSON and GraphQL

		resp, err := client.Do(req)
		if err != nil {
			debugLog(fmt.Sprintf("API probe: Error fetching %s: %v", full, err))
			continue
		}

		if resp.StatusCode == 200 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			body := string(bodyBytes)
			if strings.Contains(resp.Header.Get("Content-Type"), "json") {
				techs := []Technology{{
					Name:        "REST API",
					Description: "JSON-based REST API",
					Confidence:  "High",
					Location:    fmt.Sprintf("API endpoint (%s)", p),
					Category:    "API",
					Evidence:    1,
				}}

				if p == "/wp-json/wp/v2/" {
					if v := extractVersion(body, "WordPress", []string{`"version":"([\d\.]+)"`}); v != "" {
						techs = append(techs, Technology{
							Name:        "WordPress",
							Version:     v,
							Description: "Content Management System",
							Confidence:  "Very High",
							Location:    fmt.Sprintf("API endpoint (%s)", p),
							Category:    "CMS",
							Evidence:    2,
						})
					}
				}
				allTechs = append(allTechs, techs...)
			} else if strings.Contains(resp.Header.Get("Content-Type"), "graphql") || p == "/graphql" && strings.Contains(body, "data") {
				// Very basic detection for GraphQL. Could be improved by schema introspection.
				allTechs = append(allTechs, Technology{
					Name:        "GraphQL API",
					Description: "GraphQL API endpoint",
					Confidence:  "High",
					Location:    fmt.Sprintf("GraphQL endpoint (%s)", p),
					Category:    "API",
					Evidence:    1,
				})
			}
		}
		resp.Body.Close()
	}

	return allTechs
}

func removeDuplicateTechs(techList []Technology) []Technology {
	type key struct{ name, category string }
	unique := make(map[key]Technology)

	for _, t := range techList {
		k := key{t.Name, t.Category}
		if ex, ok := unique[k]; ok {
			ex.Evidence += t.Evidence

			// Merge versions
			versions := make(map[string]bool)
			for _, v := range strings.Split(ex.Version+","+t.Version, ",") {
				v = strings.TrimSpace(v)
				if v != "" {
					versions[v] = true
				}
			}
			var vList []string
			for v := range versions {
				vList = append(vList, v)
			}
			sort.Strings(vList) // Sort versions for consistent output
			ex.Version = strings.Join(vList, ", ")

			// Merge locations
			locations := make(map[string]bool)
			for _, l := range strings.Split(ex.Location+","+t.Location, ",") {
				l = strings.TrimSpace(l)
				if l != "" {
					locations[l] = true
				}
			}
			var lList []string
			for l := range locations {
				lList = append(lList, l)
			}
			sort.Strings(lList) // Sort locations for consistent output
			ex.Location = strings.Join(lList, ", ")

			// Update confidence based on evidence
			switch {
			case ex.Evidence >= 4:
				ex.Confidence = "Very High"
			case ex.Evidence >= 2:
				ex.Confidence = "High"
			default:
				ex.Confidence = "Medium"
			}

			unique[k] = ex
		} else {
			unique[k] = t
		}
	}

	var out []Technology
	for _, v := range unique {
		out = append(out, v)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})

	return out
}

func categorizeResults(techs []Technology) map[string][]Technology {
	cats := make(map[string][]Technology)
	for _, t := range techs {
		c := t.Category
		if c == "" {
			c = "Other"
		}
		cats[c] = append(cats[c], t)
	}
	for c := range cats {
		sort.Slice(cats[c], func(i, j int) bool {
			return cats[c][i].Name < cats[c][j].Name
		})
	}
	return cats
}

func outputResults(allTechs []Technology, jsonOutput bool, outputFile, targetURL string) {
	if jsonOutput {
		out, err := json.MarshalIndent(allTechs, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		if outputFile != "" {
			if err := os.WriteFile(outputFile, out, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing JSON to file %s: %v\n", outputFile, err)
			} else {
				fmt.Printf("Results written to %s\n", outputFile)
			}
		} else {
			fmt.Println(string(out))
		}
	} else {
		fmt.Println("\n=== TECHNOLOGY SUMMARY ===")
		if len(allTechs) == 0 {
			fmt.Println("No technologies detected overall.")
		} else {
			cats := categorizeResults(allTechs)
			var names []string
			for c := range cats {
				names = append(names, c)
			}
			sort.Strings(names)

			var sb strings.Builder
			if outputFile != "" {
				sb.WriteString(fmt.Sprintf("TechDetector v%s - Results for %s\n", version, targetURL))
			}

			for _, c := range names {
				fmt.Printf("\n%s:\n", c)
				if outputFile != "" {
					sb.WriteString(fmt.Sprintf("\n%s:\n", c))
				}
				for _, t := range cats[c] {
					fmt.Printf(" - %s\n", t)
					if outputFile != "" {
						sb.WriteString(fmt.Sprintf(" - %s\n", t))
					}
				}
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, []byte(sb.String()), 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing text results to file %s: %v\n", outputFile, err)
				} else {
					fmt.Printf("\nResults written to %s\n", outputFile)
				}
			}
		}
	}
}

func printUsage() {
	fmt.Printf(`
TechDetector v%s - Web Technology Detection Tool

Usage: techdetector -url URL [options]

Options:
  -url string        Target URL to analyze (required)
  -crawl             Enable dynamic in-domain crawling (BFS)
  -user string       Username for Basic Authentication
  -pass string       Password for Basic Authentication
  -cookie string     Cookie header to include in requests (e.g., "name1=val1; name2=val2")
  -fallback          Use fallback methods if regular detection fails or for deeper scan
  -verbose           Enable verbose output with more details (includes DEBUG logs)
  -max int           Maximum number of unique pages to crawl (default %d)
  -insecure          Skip TLS certificate verification
  -json              Output results in JSON format
  -output string     Write results to a file
  -h, -help          Show help message and exit

Examples:
  techdetector -url https://example.com
  techdetector -url https://example.com -crawl -verbose -max 20
  techdetector -url https://app.example.com -crawl -cookie "session=abc123" -max 50
  techdetector -url https://example.com -json -output results.json
  techdetector -url https://internalapp.local -user admin -pass password -insecure -crawl
`, version, maxPagesDefault)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	urlPtr := flag.String("url", "", "Target URL to analyze")
	crawlPtr := flag.Bool("crawl", false, "Enable dynamic in-domain crawling")
	authUser := flag.String("user", "", "Username for Basic Authentication")
	authPass := flag.String("pass", "", "Password for Basic Authentication")
	cookieStr := flag.String("cookie", "", "Cookie header to include in requests")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output")
	fallbackPtr := flag.Bool("fallback", false, "Use fallback methods if detection fails or for deeper scan")
	maxPagesPtr := flag.Int("max", maxPagesDefault, "Maximum number of pages to crawl")
	insecurePtr := flag.Bool("insecure", false, "Skip TLS certificate verification")
	jsonPtr := flag.Bool("json", false, "Output results in JSON format")
	outputPtr := flag.String("output", "", "Write results to a file")
	helpPtr := flag.Bool("help", false, "Show help message")
	flag.BoolVar(helpPtr, "h", false, "Show help message")
	flag.Parse()

	if *helpPtr || *urlPtr == "" {
		printUsage()
		if *urlPtr == "" {
			os.Exit(1) // Exit with error code if URL is missing
		}
		return
	}

	if !*verbosePtr {
		log.SetOutput(io.Discard)
	}

	baseURL, err := url.Parse(*urlPtr)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}

	jar, _ := cookiejar.New(nil) // Ignore error as nil is fine
	if *cookieStr != "" {
		cookies := parseCookieString(*cookieStr)
		if len(cookies) > 0 {
			jar.SetCookies(baseURL, cookies)
			verboseLog(fmt.Sprintf("Injected %d cookies for %s", len(cookies), baseURL.Host))
		} else {
			verboseLog("No valid cookies parsed from input string.")
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second, // Increased timeout for potentially slower crawls
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecurePtr},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Copy User-Agent header from previous request to new redirected request
			if len(via) > 0 {
				req.Header.Set("User-Agent", via[0].Header.Get("User-Agent"))
			}
			return nil
		},
	}

	fmt.Printf("TechDetector v%s - Analyzing %s...\n", version, *urlPtr)

	var allTechs []Technology
	if *crawlPtr {
		allTechs = crawlAuthenticated(baseURL, client, *maxPagesPtr, *authUser, *authPass, *cookieStr)
	} else {
		fmt.Printf("\nAnalyzing single page: %s\n", *urlPtr)
		techs, _, err := detectTech(*urlPtr, client, *authUser, *authPass, *cookieStr, *verbosePtr)
		if err != nil {
			log.Fatalf("Error detecting technologies for %s: %v", *urlPtr, err)
		}
		allTechs = techs
		fmt.Println("Single page analysis complete.")
	}

	// Apply fallback if initial detection was limited or explicitly requested
	if (len(allTechs) == 0 && !*crawlPtr) || *fallbackPtr { // If no tech found on single page OR fallback explicitly requested
		fmt.Println("\nUsing fallback methods (initial, robots.txt, API probes)...")
		allTechs = append(allTechs, fallbackURLScan(baseURL, client, *authUser, *authPass, *cookieStr)...)
		allTechs = append(allTechs, attemptToProbeAPI(baseURL, client, *cookieStr)...)
	}

	allTechs = removeDuplicateTechs(allTechs)
	outputResults(allTechs, *jsonPtr, *outputPtr, *urlPtr)
}
