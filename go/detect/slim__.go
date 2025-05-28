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

func fetchJavaScriptWithCache(src string, client *http.Client) (string, error) {
    jsCacheMutex.RLock()
    if c, ok := jsCache[src]; ok {
        jsCacheMutex.RUnlock()
        return c, nil
    }
    jsCacheMutex.RUnlock()

    resp, err := client.Get(src)
    if err != nil || resp.StatusCode != 200 {
        if resp != nil {
            resp.Body.Close()
        }
        return "", fmt.Errorf("fetch JS failed: %v", err)
    }
    body, err := io.ReadAll(resp.Body)
    resp.Body.Close()
    if err != nil {
        return "", err
    }

    js := string(body)
    jsCacheMutex.Lock()
    jsCache[src] = js
    jsCacheMutex.Unlock()
    return js, nil
}

func analyzeJavascriptFiles(sources []string, client *http.Client) []Technology {
    type res struct{ techs []Technology }
    ch := make(chan res, len(sources))
    sem := make(chan struct{}, 5)

    for _, src := range sources {
        go func(src string) {
            sem <- struct{}{}
            defer func() { <-sem }()
            js, err := fetchJavaScriptWithCache(src, client)
            if err != nil {
                ch <- res{nil}
                return
            }
            var techs []Technology
            techs = append(techs, detectTechFromSignatures(src, fmt.Sprintf("JavaScript (%s)", src))...)
            techs = append(techs, detectTechFromSignatures(js, fmt.Sprintf("JavaScript (%s)", src))...)
            ch <- res{techs}
        }(src)
    }

    var all []Technology
    for i := 0; i < len(sources); i++ {
        if r := <-ch; r.techs != nil {
            all = append(all, r.techs...)
        }
    }
    return all
}

func extractScriptSources(body string, baseURL *url.URL) []string {
    var out []string
    seen := map[string]bool{}
    if re := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`); re != nil {
        for _, m := range re.FindAllStringSubmatch(body, -1) {
            if len(m) > 1 {
                if u, err := baseURL.Parse(m[1]); err == nil {
                    s := u.String()
                    if !seen[s] {
                        seen[s] = true
                        out = append(out, s)
                    }
                }
            }
        }
    }
    return out
}

func extractAuthLinks(body string, baseURL *url.URL) []string {
    var links []string
    seen := make(map[string]bool) // Fixed: removed the {} from make()
    
    // Traditional HTML links
    if doc, err := html.Parse(strings.NewReader(body)); err == nil {
        var f func(*html.Node)
        f = func(n *html.Node) {
            if n.Type == html.ElementNode && n.Data == "a" {
                for _, a := range n.Attr {
                    if a.Key == "href" && a.Val != "" && !strings.HasPrefix(a.Val, "javascript:") && !strings.HasPrefix(a.Val, "mailto:") && a.Val != "#" {
                        if u, err := baseURL.Parse(a.Val); err == nil && u.Host == baseURL.Host {
                            s := u.String()
                            if !seen[s] {
                                seen[s] = true
                                links = append(links, s)
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
    }
    
    // Auth-specific patterns for SPAs
    authPatterns := []string{
        `/dashboard`, `/admin`, `/api/`, `/settings`, `/profile`, 
        `/account`, `/user`, `/management`, `/reports`, `/config`,
    }
    
    // Extract from JavaScript route definitions (fixed regex)
    jsRouteRegex := regexp.MustCompile(`['"](/[a-zA-Z0-9/_-]+)['"]`)
    for _, match := range jsRouteRegex.FindAllStringSubmatch(body, -1) {
        if len(match) > 1 {
            for _, pattern := range authPatterns {
                if strings.Contains(match[1], pattern) {
                    if u, err := baseURL.Parse(match[1]); err == nil {
                        s := u.String()
                        if !seen[s] {
                            seen[s] = true
                            links = append(links, s)
                        }
                    }
                    break
                }
            }
        }
    }
    
    return links
}

func validateSession(client *http.Client, baseURL *url.URL) bool {
    testURLs := []string{
        "/api/user", "/api/profile", "/dashboard", "/admin",
    }
    
    for _, path := range testURLs {
        testURL := baseURL.Scheme + "://" + baseURL.Host + path
        resp, err := client.Get(testURL)
        if err != nil {
            continue
        }
        resp.Body.Close()
        
        // If we get anything other than 401/403, session might be valid
        if resp.StatusCode != 401 && resp.StatusCode != 403 {
            return true
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
    baseURL, _ := url.Parse(targetURL)

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
            fmt.Println("Warning: Session appears invalid or expired")
        } else {
            verboseLog("Session validation successful")
        }
    }
    
    visited := make(map[string]bool)
    var allTechs []Technology
    
    // Start with high-value auth pages
    priority := []string{
        baseURL.String(),
        baseURL.String() + "/dashboard",
        baseURL.String() + "/api",
        baseURL.String() + "/admin",
        baseURL.String() + "/settings",
    }
    
    queue := make([]string, 0, maxPages)
    for _, url := range priority {
        if !visited[url] {
            visited[url] = true
            queue = append(queue, url)
        }
    }
    
    for i := 0; i < len(queue) && i < maxPages; i++ {
        url := queue[i]
        fmt.Printf("\n[Page %d/%d] Analyzing %s...\n", i+1, min(len(queue), maxPages), url)
        
        techs, body, err := detectTech(url, client, authUser, authPass, cookieStr, false)
        if err != nil {
            fmt.Printf("  Error: %v\n", err)
            continue
        }
        
        if len(techs) > 0 {
            fmt.Println("  Detected Technologies:")
            for _, t := range techs {
                fmt.Printf("   - %s\n", t)
            }
            allTechs = append(allTechs, techs...)
        } else {
            fmt.Println("  No technologies detected.")
        }
        
        // Add new auth-relevant links (limited to prevent explosion)
        if len(queue) < maxPages {
            newLinks := extractAuthLinks(body, baseURL)
            added := 0
            for _, link := range newLinks {
                if !visited[link] && len(queue) < maxPages && added < 3 {
                    visited[link] = true
                    queue = append(queue, link)
                    added++
                }
            }
        }
    }
    
    fmt.Printf("\nAnalysis completed: crawled %d unique pages.\n", len(queue))
    return allTechs
}

func fallbackURLScan(baseURL *url.URL, client *http.Client, authUser, authPass, cookieStr string) []Technology {
    paths := []string{"/", "/robots.txt", "/sitemap.xml", "/wp-json/", "/api/"}
    var allTechs []Technology
    
    for _, path := range paths {
        full := baseURL.Scheme + "://" + baseURL.Host + path
        req, err := http.NewRequest("GET", full, nil)
        if err != nil {
            continue
        }
        req.Header.Set("User-Agent", "Mozilla/5.0")
        if authUser != "" && authPass != "" {
            req.SetBasicAuth(authUser, authPass)
        }
        resp, err := client.Do(req)
        if err != nil {
            continue
        }
        
        b, err := io.ReadAll(resp.Body)
        resp.Body.Close()
        if err != nil {
            continue
        }
        
        techs := analyzeHeaders(resp.Header)
        techs = append(techs, analyzeHTML(string(b))...)
        allTechs = append(allTechs, techs...)
    }
    
    return allTechs
}

func attemptToProbeAPI(baseURL *url.URL, client *http.Client, cookieStr string) []Technology {
    paths := []string{"/api/info", "/api/status", "/wp-json/wp/v2/", "/api/v1/health"}
    var allTechs []Technology
    
    for _, p := range paths {
        full := baseURL.Scheme + "://" + baseURL.Host + p
        req, err := http.NewRequest("GET", full, nil)
        if err != nil {
            continue
        }
        req.Header.Set("User-Agent", "Mozilla/5.0")
        req.Header.Set("Accept", "application/json")
        resp, err := client.Do(req)
        if err != nil {
            continue
        }
        
        if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "json") {
            techs := []Technology{{
                Name:        "REST API",
                Description: "JSON-based REST API",
                Confidence:  "High",
                Location:    fmt.Sprintf("API endpoint (%s)", p),
                Category:    "API",
                Evidence:    1,
            }}
            
            if p == "/wp-json/wp/v2/" {
                b, _ := io.ReadAll(resp.Body)
                if v := extractVersion(string(b), "WordPress", []string{`"version":"([\d\.]+)"`}); v != "" {
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
        out, _ := json.MarshalIndent(allTechs, "", "  ")
        if outputFile != "" {
            os.WriteFile(outputFile, out, 0644)
            fmt.Printf("Results written to %s\n", outputFile)
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
            
            for _, c := range names {
                fmt.Printf("\n%s:\n", c)
                for _, t := range cats[c] {
                    fmt.Printf(" - %s\n", t)
                }
            }
            
            if outputFile != "" {
                var sb strings.Builder
                sb.WriteString(fmt.Sprintf("TechDetector v%s - Results for %s\n", version, targetURL))
                for _, c := range names {
                    sb.WriteString(fmt.Sprintf("\n%s:\n", c))
                    for _, t := range cats[c] {
                        sb.WriteString(fmt.Sprintf(" - %s\n", t))
                    }
                }
                os.WriteFile(outputFile, []byte(sb.String()), 0644)
                fmt.Printf("\nResults written to %s\n", outputFile)
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
  -cookie string     Cookie header to include in requests
  -fallback          Use fallback methods if regular detection fails
  -verbose           Enable verbose output with more details
  -max int           Maximum number of pages to crawl (default %d)
  -insecure          Skip TLS certificate verification
  -json              Output results in JSON format
  -output string     Write results to a file
  -h, -help          Show help message and exit

Examples:
  techdetector -url https://example.com
  techdetector -url https://example.com -crawl -verbose
  techdetector -url https://app.example.com -crawl -cookie "session=abc123"
  techdetector -url https://example.com -json -output results.json
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
    fallbackPtr := flag.Bool("fallback", false, "Use fallback methods if detection fails")
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
            log.Fatal("Error: Please provide a URL using the -url flag")
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

    jar, _ := cookiejar.New(nil)
    if *cookieStr != "" {
        cookies := parseCookieString(*cookieStr)
        jar.SetCookies(baseURL, cookies)
        verboseLog(fmt.Sprintf("Injected %d cookies for %s", len(cookies), baseURL.Host))
    }

    client := &http.Client{
        Timeout: 15 * time.Second,
        Jar:     jar,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecurePtr},
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 10 {
                return fmt.Errorf("stopped after 10 redirects")
            }
            req.Header.Set("User-Agent", via[0].Header.Get("User-Agent"))
            return nil
        },
    }

    fmt.Printf("TechDetector v%s - Analyzing %s...\n", version, *urlPtr)
    
    var allTechs []Technology
    if *crawlPtr {
        allTechs = crawlAuthenticated(baseURL, client, *maxPagesPtr, *authUser, *authPass, *cookieStr)
    } else {
        techs, _, err := detectTech(*urlPtr, client, *authUser, *authPass, *cookieStr, *verbosePtr)
        if err != nil {
            log.Fatalf("Error: %v", err)
        }
        allTechs = techs
    }
    
    // Apply fallback if needed
    if len(allTechs) == 0 && *fallbackPtr {
        fmt.Println("Using fallback methods...")
        allTechs = append(allTechs, fallbackURLScan(baseURL, client, *authUser, *authPass, *cookieStr)...)
        allTechs = append(allTechs, attemptToProbeAPI(baseURL, client, *cookieStr)...)
    }
    
    allTechs = removeDuplicateTechs(allTechs)
    outputResults(allTechs, *jsonPtr, *outputPtr, *urlPtr)
}
