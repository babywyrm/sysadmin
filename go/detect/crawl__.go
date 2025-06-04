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
	version         = "1.5.3"
)

// Technology represents a detected technology with metadata
type Technology struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Confidence  string `json:"confidence"`
	Location    string `json:"location"`
	Category    string `json:"category"`
	Evidence    int    `json:"evidence"`
}

// TechSignature defines patterns for technology detection
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

// Global JavaScript cache to avoid re-downloading
var (
	jsCache      = make(map[string]string)
	jsCacheMutex = sync.RWMutex{}
)

// Logging functions - initialized based on verbose flag
var (
	verboseLog = func(msg string) {}
	debugLog   = func(msg string) {}
	errorLog   = func(msg string) { log.Println("[ERROR]", msg) }
)

// Technology signatures for detection
var techSignatures = []TechSignature{
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
		Name:         "Bootstrap",
		Patterns:     []string{"bootstrap.css", "bootstrap.min.css", "bootstrap.js", "bootstrap@"},
		VersionRegex: []string{`bootstrap@([\d\.]+)`, `bootstrap(?:\.min)?\.(?:css|js)(?:\?ver=|@|v)([\d\.]+)`},
		Category:     "UI Framework",
		Description:  "Frontend Framework",
	},
	{
		Name:         "jQuery",
		Patterns:     []string{"jquery.min.js", "jquery-", "jQuery.fn", "$.ajax(", "$(document).ready("},
		VersionRegex: []string{`jquery(?:\.min)?\.js(?:\?ver=|@)([\d\.]+)`, `jQuery(?:\.fn)?\.jquery\s*=\s*["']([\d\.]+)["']`},
		Category:     "JavaScript Library",
		Description:  "JavaScript library",
	},
	{
		Name:         "React.js",
		Patterns:     []string{"react-dom", "react.production.min.js", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "ReactDOM.render("},
		VersionRegex: []string{`react(?:\.production|\.development)?\.min\.js(?:\?ver=|@)([\d\.]+)`, `React\.version\s*=\s*["']([\d\.]+)["']`},
		Category:     "JavaScript Framework",
		Description:  "JavaScript UI library",
	},
	{
		Name:         "Vue.js",
		Patterns:     []string{"vue.js", "vue.min.js", "v-if=", "v-for=", "Vue.component(", "vue@"},
		VersionRegex: []string{`vue(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`, `Vue\.version\s*=\s*["']([\d\.]+)["']`},
		Category:     "JavaScript Framework",
		Description:  "JavaScript progressive framework",
	},
	{
		Name:         "Cloudflare",
		Patterns:     []string{"cloudflare", "cf-ray", "cf-cache-status", "__cf_"},
		VersionRegex: []string{},
		Category:     "CDN",
		Description:  "Content Delivery Network",
	},
	{
		Name:         "Google Analytics",
		Patterns:     []string{"google-analytics.com", "googleanalytics", "ga('create'", "gtag"},
		VersionRegex: []string{},
		Category:     "Analytics",
		Description:  "Web Analytics Service",
	},
	{
		Name:         "Nginx",
		Patterns:     []string{},
		VersionRegex: []string{`nginx/?(\d+\.\d+\.\d+)?`},
		Category:     "Server",
		Description:  "Web server",
	},
	{
		Name:         "Apache",
		Patterns:     []string{},
		VersionRegex: []string{`Apache/?(\d+\.\d+\.\d+)?`},
		Category:     "Server",
		Description:  "Web server",
	},
}

// parseCookieString converts raw cookie string to http.Cookie slice
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

// extractVersion attempts to extract version using regex patterns
func extractVersion(text string, versionRegexes []string) string {
	for _, pattern := range versionRegexes {
		regex := regexp.MustCompile(pattern)
		if matches := regex.FindStringSubmatch(text); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

// detectTechFromSignatures applies all signatures to content
func detectTechFromSignatures(content, location string) []Technology {
	var detectedTechs []Technology
	contentLower := strings.ToLower(content)

	for _, sig := range techSignatures {
		found := false
		for _, pat := range sig.Patterns {
			if strings.Contains(contentLower, strings.ToLower(pat)) {
				found = true
				break
			}
		}
		if found {
			ver := extractVersion(content, sig.VersionRegex)
			detectedTechs = append(detectedTechs, Technology{
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
	}
	return detectedTechs
}

// analyzeHeaders inspects HTTP response headers
func analyzeHeaders(headers http.Header) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTTP Headers...")

	for headerKey, headerValues := range headers {
		content := fmt.Sprintf("%s: %s", headerKey, strings.Join(headerValues, ", "))
		
		// Specific header analysis
		switch strings.ToLower(headerKey) {
		case "server":
			tech = append(tech, Technology{
				Name:        "Server",
				Version:     strings.Join(headerValues, ", "),
				Description: "Web server software",
				Confidence:  "High",
				Location:    "Server header",
				Category:    "Server",
				Evidence:    1,
			})
		case "x-powered-by":
			tech = append(tech, Technology{
				Name:        "X-Powered-By",
				Version:     strings.Join(headerValues, ", "),
				Description: "Backend technology",
				Confidence:  "High",
				Location:    "X-Powered-By header",
				Category:    "Server",
				Evidence:    1,
			})
		}

		// Apply general signatures to header content
		tech = append(tech, detectTechFromSignatures(content, fmt.Sprintf("%s header", headerKey))...)
	}

	// Security headers detection
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		tech = append(tech, Technology{
			Name: "Content Security Policy", 
			Description: "Security policy", 
			Confidence: "High", 
			Location: "CSP header", 
			Category: "Security", 
			Evidence: 1,
		})
	}

	return tech
}

// analyzeHTML inspects HTML content for technology signatures
func analyzeHTML(body string) []Technology {
	var tech []Technology
	verboseLog("Analyzing HTML content...")

	// Check for meta generator tag
	metaGenRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	if matches := metaGenRegex.FindStringSubmatch(body); len(matches) > 1 {
		genValue := matches[1]
		genTech := Technology{
			Name:        "Generator",
			Version:     genValue,
			Description: "Content Management System",
			Confidence:  "High",
			Location:    "meta generator tag",
			Category:    "CMS",
			Evidence:    1,
		}
		
		// Try to match with known signatures
		for _, sig := range techSignatures {
			for _, pat := range sig.Patterns {
				if strings.Contains(strings.ToLower(genValue), strings.ToLower(pat)) {
					genTech.Name = sig.Name
					if ver := extractVersion(genValue, sig.VersionRegex); ver != "" {
						genTech.Version = ver
					}
					genTech.Category = sig.Category
					break
				}
			}
		}
		tech = append(tech, genTech)
	}

	// WordPress specific detection
	if strings.Contains(strings.ToLower(body), "wp-content/themes/") {
		themeRegex := regexp.MustCompile(`wp-content/themes/([^/'"]+)`)
		if matches := themeRegex.FindStringSubmatch(body); len(matches) > 1 {
			tech = append(tech, Technology{
				Name: "WordPress Theme: " + matches[1], 
				Description: "WordPress Theme", 
				Confidence: "High", 
				Location: "HTML path", 
				Category: "CMS Theme", 
				Evidence: 1,
			})
		}
	}

	// Apply general signatures to HTML content
	tech = append(tech, detectTechFromSignatures(body, "HTML content")...)

	return tech
}

// fetchJavaScriptWithCache downloads JS files with caching
func fetchJavaScriptWithCache(srcURL string, client *http.Client) (string, error) {
	jsCacheMutex.RLock()
	if cachedContent, found := jsCache[srcURL]; found {
		jsCacheMutex.RUnlock()
		debugLog(fmt.Sprintf("Cache hit for JS: %s", srcURL))
		return cachedContent, nil
	}
	jsCacheMutex.RUnlock()

	verboseLog(fmt.Sprintf("Fetching JavaScript: %s", srcURL))
	resp, err := client.Get(srcURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch JS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("JS fetch returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	js := string(body)
	jsCacheMutex.Lock()
	jsCache[srcURL] = js
	jsCacheMutex.Unlock()

	return js, nil
}

// analyzeJavaScriptFiles downloads and analyzes external JS files
func analyzeJavaScriptFiles(scriptSources []string, client *http.Client) []Technology {
	if len(scriptSources) == 0 {
		return nil
	}

	verboseLog(fmt.Sprintf("Analyzing %d JavaScript files...", len(scriptSources)))
	
	var allTech []Technology
	var techMutex sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent requests

	for _, srcURL := range scriptSources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			js, err := fetchJavaScriptWithCache(url, client)
			if err != nil {
				debugLog(fmt.Sprintf("Failed to fetch JS %s: %v", url, err))
				return
			}

			// Analyze URL patterns and content
			urlTechs := detectTechFromSignatures(url, fmt.Sprintf("JavaScript URL (%s)", url))
			contentTechs := detectTechFromSignatures(js, fmt.Sprintf("JavaScript content (%s)", url))

			techMutex.Lock()
			allTech = append(allTech, urlTechs...)
			allTech = append(allTech, contentTechs...)
			techMutex.Unlock()
		}(srcURL)
	}

	wg.Wait()
	return allTech
}

// extractScriptSources returns all external script URLs from HTML
func extractScriptSources(body string, baseURL *url.URL) []string {
	var sources []string
	seen := make(map[string]bool)
	
	scriptSrcRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptSrcRegex.FindAllStringSubmatch(body, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			srcURL, err := baseURL.Parse(match[1])
			if err != nil {
				continue
			}
			
			if (srcURL.Scheme == "http" || srcURL.Scheme == "https") && !seen[srcURL.String()] {
				seen[srcURL.String()] = true
				sources = append(sources, srcURL.String())
			}
		}
	}
	return sources
}

// extractURLsFromContent discovers new URLs to crawl
func extractURLsFromContent(body, contentType string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	addUniqueLink := func(rawURL string) {
		parsedURL, err := baseURL.Parse(rawURL)
		if err != nil {
			return
		}

		// Ensure same host or subdomain
		if !(parsedURL.Host == baseURL.Host || strings.HasSuffix(parsedURL.Host, "."+baseURL.Host)) {
			return
		}

		normalizedURL := parsedURL.Scheme + "://" + parsedURL.Host
		if parsedURL.Path != "" && parsedURL.Path != "/" {
			normalizedURL += strings.TrimRight(parsedURL.Path, "/")
		} else {
			normalizedURL += "/"
		}

		if !seen[normalizedURL] {
			seen[normalizedURL] = true
			links = append(links, normalizedURL)
		}
	}

	// HTML parsing for links
	if strings.Contains(contentType, "text/html") {
		doc, err := html.Parse(strings.NewReader(body))
		if err == nil {
			var traverse func(*html.Node)
			traverse = func(n *html.Node) {
				if n.Type == html.ElementNode {
					switch n.Data {
					case "a", "form":
						for _, attr := range n.Attr {
							if (attr.Key == "href" || attr.Key == "action") && 
							   attr.Val != "" && !strings.HasPrefix(attr.Val, "javascript:") {
								addUniqueLink(attr.Val)
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
	}

	// Extract paths from JavaScript
	jsPathRegex := regexp.MustCompile(`["'](/[a-zA-Z0-9/._%-]+?)["']`)
	for _, match := range jsPathRegex.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			path := match[1]
			if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".css") &&
			   !strings.HasSuffix(path, ".png") && !strings.HasSuffix(path, ".jpg") {
				addUniqueLink(path)
			}
		}
	}

	return links
}

// detectTech fetches URL and analyzes content for technologies
func detectTech(targetURL string, client *http.Client, authUser, authPass, cookieStr string, verbose bool) ([]Technology, string, string, error) {
	verboseLog(fmt.Sprintf("Fetching %s", targetURL))
	
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, "", "", err
	}

	// Set common browser headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	if authUser != "" && authPass != "" {
		req.SetBasicAuth(authUser, authPass)
	}
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", err
	}

	body := string(bodyBytes)
	contentType := resp.Header.Get("Content-Type")
	parsedURL, _ := url.Parse(targetURL)

	var techs []Technology
	
	// Analyze headers
	techs = append(techs, analyzeHeaders(resp.Header)...)

	// Analyze content based on type
	if strings.Contains(contentType, "text/html") {
		techs = append(techs, analyzeHTML(body)...)
		scriptSources := extractScriptSources(body, parsedURL)
		techs = append(techs, analyzeJavaScriptFiles(scriptSources, client)...)
	} else if strings.Contains(contentType, "application/json") {
		techs = append(techs, detectTechFromSignatures(body, "API Response")...)
	}

	return techs, body, contentType, nil
}

// crawlAuthenticated performs BFS crawl of the target domain
func crawlAuthenticated(baseURL *url.URL, client *http.Client, maxPages int, authUser, authPass, cookieStr string, maxWorkers int) ([]Technology, int) {
	visited := make(map[string]bool)
	var allTechs []Technology
	var allTechsMutex sync.Mutex
	
	queue := make(chan string, maxPages*5)
	processedPages := 0
	var processedMutex sync.Mutex

	// Add initial URLs
	initialURLs := []string{
		baseURL.String(),
		baseURL.String() + "/dashboard",
		baseURL.String() + "/admin",
		baseURL.String() + "/api",
	}

	addToQueue := func(u string) {
		if normalizedURL := normalizeURL(u, baseURL); normalizedURL != "" && !visited[normalizedURL] {
			visited[normalizedURL] = true
			select {
			case queue <- normalizedURL:
				debugLog(fmt.Sprintf("Added to queue: %s", normalizedURL))
			default:
				debugLog(fmt.Sprintf("Queue full, skipping: %s", normalizedURL))
			}
		}
	}

	for _, url := range initialURLs {
		addToQueue(url)
	}

	type CrawlResult struct {
		techs []Technology
		url   string
		err   error
	}
	resultCh := make(chan CrawlResult)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxWorkers)

	// Worker dispatcher
	go func() {
		for urlToCrawl := range queue {
			processedMutex.Lock()
			if processedPages >= maxPages {
				processedMutex.Unlock()
				continue
			}
			processedPages++
			pageNum := processedPages
			processedMutex.Unlock()

			wg.Add(1)
			go func(currentURL string, pageNum int) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				fmt.Printf("\n[Page %d/%d] Analyzing %s...\n", pageNum, maxPages, currentURL)

				techs, body, contentType, err := detectTech(currentURL, client, authUser, authPass, cookieStr, false)
				if err != nil {
					fmt.Printf("  Error: %v\n", err)
					resultCh <- CrawlResult{nil, currentURL, err}
					return
				}

				if len(techs) > 0 {
					fmt.Println("  Detected Technologies:")
					for _, t := range techs {
						fmt.Printf("   - %s\n", t)
					}
				}

				// Extract new links
				newLinks := extractURLsFromContent(body, contentType, baseURL)
				fmt.Printf("  Found %d new links\n", len(newLinks))
				for _, link := range newLinks {
					addToQueue(link)
				}

				resultCh <- CrawlResult{techs, currentURL, nil}
			}(urlToCrawl, pageNum)
		}
	}()

	// Result collector
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	for result := range resultCh {
		if result.techs != nil {
			allTechsMutex.Lock()
			allTechs = append(allTechs, result.techs...)
			allTechsMutex.Unlock()
		}
	}

	close(queue)
	return allTechs, processedPages
}

// normalizeURL normalizes URLs for consistent comparison
func normalizeURL(rawURL string, baseURL *url.URL) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Resolve relative URLs
	if !parsedURL.IsAbs() {
		parsedURL = baseURL.ResolveReference(parsedURL)
	}

	// Check if same domain
	if !(parsedURL.Host == baseURL.Host || strings.HasSuffix(parsedURL.Host, "."+baseURL.Host)) {
		return ""
	}

	normalizedURL := parsedURL.Scheme + "://" + parsedURL.Host
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		normalizedURL += strings.TrimRight(parsedURL.Path, "/")
	} else {
		normalizedURL += "/"
	}

	return normalizedURL
}

// removeDuplicateTechs consolidates duplicate technologies
func removeDuplicateTechs(techList []Technology) []Technology {
	type techKey struct {
		name     string
		category string
	}

	unique := make(map[techKey]Technology)
	for _, tech := range techList {
		key := techKey{tech.Name, tech.Category}
		if existing, exists := unique[key]; !exists {
			unique[key] = tech
		} else {
			// Merge versions and locations
			newTech := existing
			if tech.Version != "" && !strings.Contains(newTech.Version, tech.Version) {
				if newTech.Version == "" {
					newTech.Version = tech.Version
				} else {
					newTech.Version += ", " + tech.Version
				}
			}
			if tech.Location != "" && !strings.Contains(newTech.Location, tech.Location) {
				if newTech.Location == "" {
					newTech.Location = tech.Location
				} else {
					newTech.Location += ", " + tech.Location
				}
			}
			newTech.Evidence += tech.Evidence
			
			// Update confidence based on evidence
			if newTech.Evidence >= 3 {
				newTech.Confidence = "Very High"
			} else if newTech.Evidence >= 2 {
				newTech.Confidence = "High"
			}
			
			unique[key] = newTech
		}
	}

	var result []Technology
	for _, tech := range unique {
		result = append(result, tech)
	}

	// Sort by category then name
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
	categories := make(map[string][]Technology)
	for _, tech := range techs {
		category := tech.Category
		if category == "" {
			category = "Other"
		}
		categories[category] = append(categories[category], tech)
	}
	
	// Sort within categories
	for category := range categories {
		sort.Slice(categories[category], func(i, j int) bool {
			return categories[category][i].Name < categories[category][j].Name
		})
	}
	
	return categories
}

// outputResults handles printing and saving results
func outputResults(allTechs []Technology, jsonOutput bool, outputFile, targetURL string, pagesCrawled int) {
	if jsonOutput {
		out, err := json.MarshalIndent(allTechs, "", "  ")
		if err != nil {
			errorLog(fmt.Sprintf("Error marshaling JSON: %v", err))
			return
		}
		if outputFile != "" {
			if err := os.WriteFile(outputFile, out, 0644); err != nil {
				errorLog(fmt.Sprintf("Error writing to file: %v", err))
			} else {
				fmt.Printf("Results written to %s\n", outputFile)
			}
		} else {
			fmt.Println(string(out))
		}
	} else {
		fmt.Println("\n=== TECHNOLOGY SUMMARY ===")
		if len(allTechs) == 0 {
			fmt.Println("No technologies detected.")
		} else {
			categories := categorizeResults(allTechs)
			var categoryNames []string
			for name := range categories {
				categoryNames = append(categoryNames, name)
			}
			sort.Strings(categoryNames)

			var output strings.Builder
			if outputFile != "" {
				output.WriteString(fmt.Sprintf("TechDetector v%s - Results for %s\n", version, targetURL))
			}

			for _, category := range categoryNames {
				fmt.Printf("\n%s:\n", category)
				if outputFile != "" {
					output.WriteString(fmt.Sprintf("\n%s:\n", category))
				}
				for _, tech := range categories[category] {
					fmt.Printf(" - %s\n", tech)
					if outputFile != "" {
						output.WriteString(fmt.Sprintf(" - %s\n", tech))
					}
				}
			}

			if outputFile != "" {
				output.WriteString(fmt.Sprintf("\nCrawled %d pages.\n", pagesCrawled))
				if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
					errorLog(fmt.Sprintf("Error writing to file: %v", err))
				} else {
					fmt.Printf("\nResults written to %s\n", outputFile)
				}
			}
		}
	}
}

func printUsage() {
	fmt.Printf(`TechDetector v%s - Web Technology Detection Tool

Usage: techdetector -url URL [options]

Options:
  -url string      Target URL (required)
  -crawl          Enable dynamic crawling 
  -user string    Username for Basic Auth
  -pass string    Password for Basic Auth  
  -cookie string  Cookie header
  -verbose        Enable verbose output
  -max int        Max pages to crawl (default %d)
  -insecure       Skip TLS verification
  -json           JSON output format
  -output string  Output file
  -workers int    Concurrent workers (default 5)
  -h, -help       Show help

Examples:
  techdetector -url https://example.com
  techdetector -url https://app.example.com -cookie "session=abc" -crawl -verbose
  techdetector -url https://example.com -crawl -json -output results.json
`, version, maxPagesDefault)
}

func main() {
	var (
		urlPtr      = flag.String("url", "", "Target URL")
		crawlPtr    = flag.Bool("crawl", false, "Enable crawling")
		authUser    = flag.String("user", "", "Basic auth username")
		authPass    = flag.String("pass", "", "Basic auth password")
		cookieStr   = flag.String("cookie", "", "Cookie header")
		verbosePtr  = flag.Bool("verbose", false, "Verbose output")
		maxPagesPtr = flag.Int("max", maxPagesDefault, "Max pages to crawl")
		insecurePtr = flag.Bool("insecure", false, "Skip TLS verification")
		jsonPtr     = flag.Bool("json", false, "JSON output")
		outputPtr   = flag.String("output", "", "Output file")
		workersPtr  = flag.Int("workers", 5, "Concurrent workers")
		helpPtr     = flag.Bool("help", false, "Show help")
	)
	flag.BoolVar(helpPtr, "h", false, "Show help")
	flag.Parse()

	if *helpPtr || *urlPtr == "" {
		printUsage()
		if *urlPtr == "" {
			os.Exit(1)
		}
		return
	}

	// Configure logging
	if *verbosePtr {
		verboseLog = func(msg string) { log.Println("[INFO]", msg) }
		debugLog = func(msg string) { log.Println("[DEBUG]", msg) }
	} else {
		log.SetOutput(io.Discard)
	}

	baseURL, err := url.Parse(*urlPtr)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}

	// Setup HTTP client
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("Error creating cookie jar: %v", err)
	}
	
	if *cookieStr != "" {
		cookies := parseCookieString(*cookieStr)
		jar.SetCookies(baseURL, cookies)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecurePtr},
		},
	}

	fmt.Printf("TechDetector v%s - Analyzing %s...\n", version, *urlPtr)

	var allTechs []Technology
	var processedPages int

	if *crawlPtr {
		allTechs, processedPages = crawlAuthenticated(baseURL, client, *maxPagesPtr, *authUser, *authPass, *cookieStr, *workersPtr)
	} else {
		techs, _, _, err := detectTech(*urlPtr, client, *authUser, *authPass, *cookieStr, *verbosePtr)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		allTechs = techs
		processedPages = 1
	}

	allTechs = removeDuplicateTechs(allTechs)
	outputResults(allTechs, *jsonPtr, *outputPtr, *urlPtr, processedPages)
}
