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
    version         = "1.4.1"
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
    }
)

func debugLog(msg string)   { log.Println("[DEBUG]", msg) }
func verboseLog(msg string) { log.Println("[INFO]", msg) }
func errorLog(msg string)   { log.Println("[ERROR]", msg) }

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
        detected := false
        for _, pattern := range sig.Patterns {
            if strings.Contains(contentLower, strings.ToLower(pattern)) {
                detected = true
                break
            }
        }
        if detected {
            version := extractVersion(content, sig.Name, sig.VersionRegex)
            techs = append(techs, Technology{
                Name:        sig.Name,
                Version:     version,
                Description: sig.Description,
                Confidence:  "High",
                Location:    location,
                Category:    sig.Category,
                Evidence:    1,
            })
            verboseLog(fmt.Sprintf("Detected %s with version: %s", sig.Name, version))
        }
    }
    return techs
}

func analyzeHeaders(headers http.Header) []Technology {
    var tech []Technology
    verboseLog("Analyzing HTTP Headers for technology clues...")

    headerChecks := map[string]func(string) []Technology{
        "Server": func(value string) []Technology {
            var result []Technology
            result = append(result, Technology{
                Name:        "Server",
                Version:     value,
                Description: "Web server software",
                Confidence:  "High",
                Location:    "Server header",
                Category:    "Server",
                Evidence:    1,
            })
            if strings.Contains(strings.ToLower(value), "nginx") {
                if version := extractVersion(value, "Nginx", []string{`nginx/?(\d+\.\d+\.\d+)?`}); version != "" {
                    result = append(result, Technology{
                        Name:        "Nginx",
                        Version:     version,
                        Description: "Web server",
                        Confidence:  "High",
                        Location:    "Server header",
                        Category:    "Server",
                        Evidence:    1,
                    })
                }
            }
            if strings.Contains(strings.ToLower(value), "apache") {
                if version := extractVersion(value, "Apache", []string{`Apache/?(\d+\.\d+\.\d+)?`}); version != "" {
                    result = append(result, Technology{
                        Name:        "Apache",
                        Version:     version,
                        Description: "Web server",
                        Confidence:  "High",
                        Location:    "Server header",
                        Category:    "Server",
                        Evidence:    1,
                    })
                }
            }
            return result
        },
        "X-Powered-By": func(value string) []Technology {
            var result []Technology
            result = append(result, Technology{
                Name:        "X-Powered-By",
                Version:     value,
                Description: "Backend technology",
                Confidence:  "High",
                Location:    "X-Powered-By header",
                Category:    "Server",
                Evidence:    1,
            })
            if strings.Contains(strings.ToLower(value), "php") {
                if version := extractVersion(value, "PHP", []string{`PHP/?(\d+\.\d+\.\d+)`}); version != "" {
                    result = append(result, Technology{
                        Name:        "PHP",
                        Version:     version,
                        Description: "Server-side scripting language",
                        Confidence:  "High",
                        Location:    "X-Powered-By header",
                        Category:    "Programming Language",
                        Evidence:    1,
                    })
                }
            }
            return result
        },
    }

    for header, checker := range headerChecks {
        if value := headers.Get(header); value != "" {
            tech = append(tech, checker(value)...)
            verboseLog(fmt.Sprintf("Found %s header: %s", header, value))
        }
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
    }
    return tech
}

func analyzeHTML(body string) []Technology {
    var tech []Technology
    verboseLog("Analyzing HTML content for technology signatures...")

    if metaGenRegex := regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`); metaGenRegex != nil {
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
        }
    }

    if strings.Contains(strings.ToLower(body), "wp-content/themes/") {
        if themeRegex := regexp.MustCompile(`wp-content/themes/([^/'"]+)`); themeRegex != nil {
            if matches := themeRegex.FindStringSubmatch(body); len(matches) > 1 {
                tech = append(tech, Technology{
                    Name:        "WordPress Theme: " + matches[1],
                    Description: "WordPress Theme",
                    Confidence:  "High",
                    Location:    "HTML path",
                    Category:    "CMS Theme",
                    Evidence:    1,
                })
            }
        }
    }

    if pluginRegex := regexp.MustCompile(`wp-content/plugins/([^/'"]+)`); pluginRegex != nil {
        plugins := make(map[string]bool)
        for _, match := range pluginRegex.FindAllStringSubmatch(body, -1) {
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
            }
        }
    }

    htmlTechs := detectTechFromSignatures(body, "HTML content")
    tech = append(tech, htmlTechs...)

    specialDetections := []struct {
        patterns []string
        tech     Technology
    }{
        {[]string{"thousandeyes"}, Technology{Name: "ThousandEyes", Description: "Network intelligence platform", Confidence: "High", Location: "HTML content", Category: "Monitoring", Evidence: 1}},
        {[]string{"webpack", "__webpack_require__", "webpackjsonp"}, Technology{Name: "Webpack", Description: "JavaScript module bundler", Confidence: "High", Location: "HTML (webpack patterns)", Category: "Build Tool", Evidence: 1}},
        {[]string{"https://js.hs-scripts.com/", "hubspot"}, Technology{Name: "HubSpot", Description: "Marketing, Sales, and CRM Platform", Confidence: "High", Location: "HTML content", Category: "Marketing", Evidence: 1}},
    }

    bodyLower := strings.ToLower(body)
    for _, det := range specialDetections {
        for _, p := range det.patterns {
            if strings.Contains(bodyLower, p) {
                tech = append(tech, det.tech)
                break
            }
        }
    }
    return tech
}

func fetchJavaScriptWithCache(src string, client *http.Client) (string, error) {
    jsCacheMutex.RLock()
    if cached, found := jsCache[src]; found {
        jsCacheMutex.RUnlock()
        return cached, nil
    }
    jsCacheMutex.RUnlock()

    resp, err := client.Get(src)
    if err != nil || resp.StatusCode != 200 {
        if resp != nil {
            resp.Body.Close()
        }
        return "", fmt.Errorf("failed to fetch: %v", err)
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

func analyzeJavascriptFiles(scriptSources []string, client *http.Client) []Technology {
    type result struct{ techs []Technology }
    resultChan := make(chan result, len(scriptSources))
    semaphore := make(chan struct{}, 5)

    for _, src := range scriptSources {
        go func(src string) {
            semaphore <- struct{}{}
            defer func() { <-semaphore }()

            js, err := fetchJavaScriptWithCache(src, client)
            if err != nil {
                resultChan <- result{nil}
                return
            }
            var techs []Technology
            urlTechs := detectTechFromSignatures(src, fmt.Sprintf("JavaScript (%s)", src))
            contentTechs := detectTechFromSignatures(js, fmt.Sprintf("JavaScript (%s)", src))
            techs = append(techs, urlTechs...)
            techs = append(techs, contentTechs...)
            resultChan <- result{techs}
        }(src)
    }

    var allTechs []Technology
    for i := 0; i < len(scriptSources); i++ {
        if res := <-resultChan; res.techs != nil {
            allTechs = append(allTechs, res.techs...)
        }
    }
    return allTechs
}

func extractScriptSources(body string, baseURL *url.URL) []string {
    var sources []string
    seen := make(map[string]bool)
    if re := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`); re != nil {
        for _, match := range re.FindAllStringSubmatch(body, -1) {
            if len(match) > 1 {
                if u, err := baseURL.Parse(match[1]); err == nil {
                    abs := u.String()
                    if !seen[abs] {
                        seen[abs] = true
                        sources = append(sources, abs)
                    }
                }
            }
        }
    }
    return sources
}

func extractLinks(body string, baseURL *url.URL) []string {
    var links []string
    seen := make(map[string]bool)
    if doc, err := html.Parse(strings.NewReader(body)); err == nil {
        var trav func(*html.Node)
        trav = func(n *html.Node) {
            if n.Type == html.ElementNode && n.Data == "a" {
                for _, a := range n.Attr {
                    if a.Key == "href" && a.Val != "" &&
                        !strings.HasPrefix(a.Val, "javascript:") &&
                        !strings.HasPrefix(a.Val, "mailto:") && a.Val != "#" {
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
                trav(c)
            }
        }
        trav(doc)
    }
    return links
}

func prioritizeLinks(links []string) []string {
    techPaths := []string{"/wp-admin/", "/admin/", "/api/", "/about", "/wp-json/", "/dashboard"}

    type scoredLink struct {
        url   string
        score int
    }
    var scored []scoredLink

    for _, link := range links {
        score := -strings.Count(link, "/")
        for _, p := range techPaths {
            if strings.Contains(link, p) {
                score += 10
                break
            }
        }
        scored = append(scored, scoredLink{link, score})
    }

    sort.Slice(scored, func(i, j int) bool {
        return scored[i].score > scored[j].score
    })

    out := make([]string, len(scored))
    for i, s := range scored {
        out[i] = s.url
    }
    return out
}

func detectTech(targetURL string, client *http.Client, authUser, authPass, cookieStr string, verbose bool) ([]Technology, string, error) {
    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return nil, "", err
    }
    req.Header.Set("User-Agent", "Mozilla/5.0")
    req.Header.Set("Accept", "text/html")

    if authUser != "" && authPass != "" {
        req.SetBasicAuth(authUser, authPass)
    }
    if cookieStr != "" {
        req.Header.Set("Cookie", cookieStr)
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

func runConcurrentAnalysis(urls []string, fn func(string) []Technology) []Technology {
    type res struct{ techs []Technology }
    c := make(chan res, len(urls))
    sem := make(chan struct{}, 5)

    for _, u := range urls {
        go func(u string) {
            sem <- struct{}{}
            defer func() { <-sem }()
            c <- res{fn(u)}
        }(u)
    }

    var all []Technology
    for i := 0; i < len(urls); i++ {
        if r := <-c; r.techs != nil {
            all = append(all, r.techs...)
        }
    }
    return all
}

func fallbackURLScan(baseURL *url.URL, client *http.Client, authUser, authPass, cookieStr string) []Technology {
    paths := []string{"/", "/dashboard", "/login", "/api", "/wp-admin/", "/admin/", "/wp-json/", "/robots.txt"}
    return runConcurrentAnalysis(paths, func(p string) []Technology {
        full := baseURL.Scheme + "://" + baseURL.Host + p
        if req, err := http.NewRequest("GET", full, nil); err == nil {
            req.Header.Set("User-Agent", "Mozilla/5.0")
            if authUser != "" && authPass != "" {
                req.SetBasicAuth(authUser, authPass)
            }
            if cookieStr != "" {
                req.Header.Set("Cookie", cookieStr)
            }
            if resp, err := client.Do(req); err == nil {
                defer resp.Body.Close()
                if b, err := io.ReadAll(resp.Body); err == nil {
                    techs := analyzeHeaders(resp.Header)
                    techs = append(techs, analyzeHTML(string(b))...)
                    return techs
                }
            }
        }
        return nil
    })
}

func attemptToProbeAPI(baseURL *url.URL, client *http.Client, cookieStr string) []Technology {
    paths := []string{"/api/info", "/api/status", "/wp-json/wp/v2/", "/api/v1/health"}
    return runConcurrentAnalysis(paths, func(p string) []Technology {
        full := baseURL.Scheme + "://" + baseURL.Host + p
        if req, err := http.NewRequest("GET", full, nil); err == nil {
            req.Header.Set("User-Agent", "Mozilla/5.0")
            req.Header.Set("Accept", "application/json")
            if cookieStr != "" {
                req.Header.Set("Cookie", cookieStr)
            }
            if resp, err := client.Do(req); err == nil {
                defer resp.Body.Close()
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
                        if b, _ := io.ReadAll(resp.Body); b != nil {
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
                    }
                    return techs
                }
            }
        }
        return nil
    })
}

// Updated to dedupe versions & locations
func removeDuplicateTechs(techList []Technology) []Technology {
    type key struct{ name, category string }
    unique := make(map[key]Technology)

    for _, t := range techList {
        k := key{t.Name, t.Category}
        if ex, ok := unique[k]; ok {
            ex.Evidence += t.Evidence

            // merge versions
            vs := make(map[string]bool)
            var listV []string
            for _, v := range strings.Split(ex.Version, ",") {
                v = strings.TrimSpace(v)
                if v != "" && !vs[v] {
                    vs[v] = true
                    listV = append(listV, v)
                }
            }
            for _, v := range strings.Split(t.Version, ",") {
                v = strings.TrimSpace(v)
                if v != "" && !vs[v] {
                    vs[v] = true
                    listV = append(listV, v)
                }
            }
            ex.Version = strings.Join(listV, ", ")

            // merge locations
            ls := make(map[string]bool)
            var listL []string
            for _, l := range strings.Split(ex.Location, ",") {
                l = strings.TrimSpace(l)
                if l != "" && !ls[l] {
                    ls[l] = true
                    listL = append(listL, l)
                }
            }
            for _, l := range strings.Split(t.Location, ",") {
                l = strings.TrimSpace(l)
                if l != "" && !ls[l] {
                    ls[l] = true
                    listL = append(listL, l)
                }
            }
            ex.Location = strings.Join(listL, ", ")

            // recalc confidence
            base := map[string]int{"Very High": 4, "High": 3, "Medium": 2, "Low": 1}[ex.Confidence]
            final := base + ex.Evidence
            switch {
            case final >= 6:
                ex.Confidence = "Very High"
            case final >= 4:
                ex.Confidence = "High"
            case final >= 2:
                ex.Confidence = "Medium"
            default:
                ex.Confidence = "Low"
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
  -workers int       Number of concurrent crawl workers (default 5)
  -h, -help          Show help message and exit

Examples:
  techdetector -url https://example.com
  techdetector -url https://example.com -crawl -verbose
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
    workersPtr := flag.Int("workers", 5, "Number of concurrent crawl workers")
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

    jar, _ := cookiejar.New(nil)
    client := &http.Client{
        Timeout: 15 * time.Second,
        Jar:     jar,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecurePtr},
        },
    }

    baseURL, err := url.Parse(*urlPtr)
    if err != nil {
        log.Fatalf("Invalid URL: %v", err)
    }

    fmt.Printf("TechDetector v%s - Analyzing %s...\n\n", version, *urlPtr)
    var allTechs []Technology

    if *crawlPtr {
        visited := make(map[string]bool)
        queue := []string{*urlPtr}
        visited[*urlPtr] = true
        pagesCrawled := 0

        for pagesCrawled < *maxPagesPtr && len(queue) > 0 {
            batch := min(len(queue), *maxPagesPtr-pagesCrawled)
            urls := queue[:batch]
            queue = queue[batch:]
            type res struct{ techs []Technology; links []string }
            ch := make(chan res, batch)
            sem := make(chan struct{}, *workersPtr)

            for i, u := range urls {
                go func(u string, idx int) {
                    sem <- struct{}{}
                    defer func() { <-sem }()
                    fmt.Printf("\n[Page %d/%d] Analyzing %s...\n", idx+1, *maxPagesPtr, u)
                    techs, body, err := detectTech(u, client, *authUser, *authPass, *cookieStr, *verbosePtr)
                    if err != nil {
                        fmt.Printf("  Error: %v\n", err)
                        ch <- res{nil, nil}
                        return
                    }
                    if len(techs) == 0 && *fallbackPtr {
                        fmt.Println("  Using fallback detection methods...")
                        fb := fallbackURLScan(baseURL, client, *authUser, *authPass, *cookieStr)
                        api := attemptToProbeAPI(baseURL, client, *cookieStr)
                        techs = append(techs, fb...)
                        techs = append(techs, api...)
                    }
                    if len(techs) > 0 {
                        fmt.Println("  Detected Technologies:")
                        for _, t := range techs {
                            fmt.Printf("   - %s\n", t)
                        }
                    } else {
                        fmt.Println("  No technologies detected.")
                    }
                    links := prioritizeLinks(extractLinks(body, baseURL))
                    ch <- res{techs, links}
                }(u, pagesCrawled+i)
            }

            for i := 0; i < batch; i++ {
                r := <-ch
                if r.techs != nil {
                    allTechs = append(allTechs, r.techs...)
                }
                for _, l := range r.links {
                    if !visited[l] && len(queue) < *maxPagesPtr-pagesCrawled-batch {
                        visited[l] = true
                        queue = append(queue, l)
                    }
                }
            }
            pagesCrawled += batch
        }
        fmt.Printf("\nAnalysis completed: crawled %d unique pages.\n", pagesCrawled)
    } else {
        techs, _, err := detectTech(*urlPtr, client, *authUser, *authPass, *cookieStr, *verbosePtr)
        if err != nil {
            log.Fatalf("Error detecting tech: %v", err)
        }
        if len(techs) == 0 && *fallbackPtr {
            fmt.Println("Using fallback detection methods...")
            fb := fallbackURLScan(baseURL, client, *authUser, *authPass, *cookieStr)
            api := attemptToProbeAPI(baseURL, client, *cookieStr)
            techs = append(techs, fb...)
            techs = append(techs, api...)
        }
        allTechs = techs
    }

    allTechs = removeDuplicateTechs(allTechs)

    if *jsonPtr {
        out, _ := json.MarshalIndent(allTechs, "", "  ")
        if *outputPtr != "" {
            os.WriteFile(*outputPtr, out, 0644)
            fmt.Printf("Results written to %s\n", *outputPtr)
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
            if *outputPtr != "" {
                var sb strings.Builder
                sb.WriteString(fmt.Sprintf("TechDetector v%s - Results for %s\n", version, *urlPtr))
                for _, c := range names {
                    sb.WriteString(fmt.Sprintf("\n%s:\n", c))
                    for _, t := range cats[c] {
                        sb.WriteString(fmt.Sprintf(" - %s\n", t))
                    }
                }
                os.WriteFile(*outputPtr, []byte(sb.String()), 0644)
                fmt.Printf("\nResults written to %s\n", *outputPtr)
            }
        }
    }
}
