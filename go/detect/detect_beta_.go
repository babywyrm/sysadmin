package main

import (
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
	maxPages = 5 // Limit crawling to a few pages
)

// Technology represents a detected technology with an optional version.
type Technology struct {
	Name    string
	Version string
}

func (t Technology) String() string {
	if t.Version != "" {
		return fmt.Sprintf("%s (v%s)", t.Name, t.Version)
	}
	return t.Name
}

func debugLog(msg string) {
	log.Println("[DEBUG]", msg)
}

// parseVersion attempts to extract the version for a given technology
// from the provided text. It uses regex patterns on known script filenames.
func parseVersion(text, techName string) string {
	var versionRegex *regexp.Regexp
	switch techName {
	case "React.js":
		// e.g., react.production.min.js?ver=16.13.1 or react.production.min.js@16.13.1
		versionRegex = regexp.MustCompile(`react(?:\.production|\.development)?\.min\.js(?:\?ver=|@)([\d\.]+)`)
	case "AngularJS":
		versionRegex = regexp.MustCompile(`angular(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`)
	case "Vue.js":
		versionRegex = regexp.MustCompile(`vue(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`)
	case "jQuery":
		versionRegex = regexp.MustCompile(`jquery(?:\.min)?\.js(?:\?v=|@)([\d\.]+)`)
	default:
		return ""
	}
	matches := versionRegex.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractScriptSrcVersions scans the HTML document for <script> tags and tries
// to extract versions based on the provided technology.
func extractScriptSrcVersions(body string, techName string) string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return ""
	}
	var version string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					version = parseVersion(attr.Val, techName)
					if version != "" {
						return
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
			if version != "" {
				return
			}
		}
	}
	f(doc)
	return version
}

// analyzeHeaders inspects HTTP response headers for technology clues.
func analyzeHeaders(headers http.Header) []Technology {
	var tech []Technology
	debugLog("Analyzing HTTP Headers...")

	if server := headers.Get("Server"); server != "" {
		tech = append(tech, Technology{Name: "Server", Version: server})
		debugLog(fmt.Sprintf("Found Server header: %s", server))
	}
	if powered := headers.Get("X-Powered-By"); powered != "" {
		tech = append(tech, Technology{Name: "X-Powered-By", Version: powered})
		debugLog(fmt.Sprintf("Found X-Powered-By header: %s", powered))
	}
	if generator := headers.Get("X-Generator"); generator != "" {
		tech = append(tech, Technology{Name: "Generator", Version: generator})
		debugLog(fmt.Sprintf("Found X-Generator header: %s", generator))
	}
	return tech
}

// analyzeHTML parses the HTML content for meta tags, inline scripts, and comments.
func analyzeHTML(body string) []Technology {
	var tech []Technology
	debugLog("Analyzing HTML content...")

	// Lowercase version for easier matching.
	bodyLower := strings.ToLower(body)

	// Detect CMS / Static generators via meta generator tag.
	metaGenRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	if matches := metaGenRegex.FindStringSubmatch(body); len(matches) > 1 {
		tech = append(tech, Technology{Name: "Generator", Version: matches[1]})
		debugLog(fmt.Sprintf("Found generator meta tag: %s", matches[1]))
	}

	// Define helper to detect tech and update version from both embedded
	// text and <script> src attributes.
	detectTech := func(techName, marker string) {
		if strings.Contains(bodyLower, strings.ToLower(marker)) {
			ver := parseVersion(bodyLower, techName)
			// Check <script> tag src attributes for potentially better version info.
			srcVer := extractScriptSrcVersions(body, techName)
			if srcVer != "" {
				ver = srcVer
			}
			tech = append(tech, Technology{Name: techName, Version: ver})
			debugLog(fmt.Sprintf("Detected %s %s", techName, ver))
		}
	}

	// Detect React.
	detectTech("React.js", "react.production.min.js")
	// Detect AngularJS.
	detectTech("AngularJS", "angular.min.js")
	// Detect Vue.js.
	detectTech("Vue.js", "vue.min.js")
	// Detect jQuery.
	detectTech("jQuery", "jquery")
	// Detect Ember.js.
	if strings.Contains(bodyLower, "ember.js") {
		tech = append(tech, Technology{Name: "Ember.js"})
		debugLog("Detected Ember.js")
	}
	// Detect Backbone.js.
	if strings.Contains(bodyLower, "backbone.js") {
		tech = append(tech, Technology{Name: "Backbone.js"})
		debugLog("Detected Backbone.js")
	}
	// Detect Google Analytics.
	if strings.Contains(bodyLower, "www.google-analytics.com") {
		tech = append(tech, Technology{Name: "Google Analytics"})
		debugLog("Detected Google Analytics")
	}
	// Detect Svelte.
	if strings.Contains(bodyLower, "svelte") {
		tech = append(tech, Technology{Name: "Svelte"})
		debugLog("Detected Svelte")
	}
	// Check for static site generators.
	if strings.Contains(body, "Generated by Jekyll") {
		tech = append(tech, Technology{Name: "Jekyll"})
		debugLog("Detected Jekyll")
	}
	if strings.Contains(body, "Powered by Hugo") {
		tech = append(tech, Technology{Name: "Hugo"})
		debugLog("Detected Hugo")
	}

	return tech
}

// extractLinks returns absolute URLs found in the HTML body belonging to the same host.
func extractLinks(body string, baseURL *url.URL) []string {
	var links []string
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		token := tokenizer.Token()
		if token.DataAtom.String() == "a" {
			for _, attr := range token.Attr {
				if attr.Key == "href" {
					link := attr.Val
					abs, err := baseURL.Parse(link)
					if err == nil && abs.Host == baseURL.Host {
						links = append(links, abs.String())
					}
				}
			}
		}
	}
	return links
}

// detectTech fetches a URL using optional authentication (basic auth and cookies),
// analyzes HTTP headers and HTML content, and returns detected technologies and HTML body.
func detectTech(targetURL string, client *http.Client, authUser, authPass, cookieStr string) ([]Technology, string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	// Set basic auth if provided.
	if authUser != "" && authPass != "" {
		req.SetBasicAuth(authUser, authPass)
		debugLog("Using Basic Authentication.")
	}
	// Set Cookie header if provided.
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
		debugLog("Using provided cookie header.")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	debugLog(fmt.Sprintf("Received response: %s", resp.Status))
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	body := string(bodyBytes)
	var techs []Technology
	techs = append(techs, analyzeHeaders(resp.Header)...)
	techs = append(techs, analyzeHTML(body)...)
	return techs, body, nil
}

// printUsage prints the usage message.
func printUsage() {
	usageText := `
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
  -h, -help
        Show this help message and exit
`
	fmt.Println(usageText)
}

func main() {
	// Define flags.
	urlPtr := flag.String("url", "", "Target URL to analyze (e.g., https://example.com)")
	crawlPtr := flag.Bool("crawl", false, "Enable basic in-domain crawling")
	authUser := flag.String("user", "", "Username for Basic Authentication")
	authPass := flag.String("pass", "", "Password for Basic Authentication")
	cookieStr := flag.String("cookie", "", "Cookie header to include in requests")
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

	// Create HTTP client with a cookie jar.
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
	}

	fmt.Printf("Analyzing %s...\n", *urlPtr)
	techs, body, err := detectTech(*urlPtr, client, *authUser, *authPass, *cookieStr)
	if err != nil {
		log.Fatalf("Error detecting tech: %v", err)
	}

	if len(techs) == 0 {
		fmt.Println("No technologies detected on the main page.")
	} else {
		fmt.Println("Detected Technologies on main page:")
		for _, t := range techs {
			fmt.Printf(" - %s\n", t)
		}
	}

	// If crawling is enabled, extract links on the same domain and analyze them.
	baseURL, err := url.Parse(*urlPtr)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}
	if *crawlPtr {
		links := extractLinks(body, baseURL)
		if len(links) > maxPages {
			links = links[:maxPages]
		}
		if len(links) > 0 {
			fmt.Println("\nCrawling additional pages:")
			visited := make(map[string]bool)
			for _, link := range links {
				if visited[link] {
					continue
				}
				visited[link] = true
				fmt.Printf("\nAnalyzing %s...\n", link)
				pageTechs, _, err := detectTech(link, client, *authUser, *authPass, *cookieStr)
				if err != nil {
					fmt.Printf(" Error: %v\n", err)
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
			}
		} else {
			fmt.Println("No additional in-domain links found for crawling.")
		}
	}
}
