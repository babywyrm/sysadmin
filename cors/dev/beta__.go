package main

//
//

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "time"

    "github.com/sirupsen/logrus"
    "golang.org/x/net/html"
)

func main() {
    targetURL := flag.String("target", "", "Target URL to scan")
    cookies := flag.String("cookies", "", "Optional cookies to send with requests")
    wordlistPath := flag.String("wordlist", "", "Optional wordlist file path for additional paths to scan")
    flag.Parse()

    if *targetURL == "" {
        log.Fatal("Target URL is required")
    }

    // Initialize logger
    logger := logrus.New()
    logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
    logger.SetOutput(io.MultiWriter(os.Stdout, createLogFile("cors_scanner.log")))
    logger.SetLevel(logrus.InfoLevel)

    logger.Infof("Starting scan on: %s", *targetURL)

    client := &http.Client{Timeout: 10 * time.Second}
    scanURL(*targetURL, *cookies, client, logger)

    // Use wordlist if provided
    if *wordlistPath != "" {
        logger.Infof("Using wordlist: %s", *wordlistPath)
        processWordlist(*wordlistPath, *targetURL, *cookies, client, logger)
    }
}

func createLogFile(fileName string) *os.File {
    f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("Failed to open log file: %s", err)
    }
    return f
}

func scanURL(target string, cookies string, client *http.Client, logger *logrus.Logger) {
    logger.Infof("Visiting: %s", target)

    req, err := http.NewRequest("GET", target, nil)
    if err != nil {
        logger.Errorf("Failed to create request: %v", err)
        return
    }

    if cookies != "" {
        req.Header.Set("Cookie", cookies)
        logger.Infof("Added cookies to request: %s", cookies)
    }

    resp, err := client.Do(req)
    if err != nil {
        logger.Errorf("Request failed: %v", err)
        return
    }
    defer resp.Body.Close()

    logger.Infof("Received status code: %d for %s", resp.StatusCode, target)

    if origin := "http://evil.com"; checkCORS(target, origin, client, logger) {
        logger.Warnf("CORS vulnerability found at %s with Origin: %s", target, origin)
    }

    links := extractLinks(resp.Body, target, logger)
    for _, link := range links {
        // Ensure the link is absolute
        absoluteURL := resolveURL(link, target)
        if absoluteURL != "" {
            scanURL(absoluteURL, cookies, client, logger)
        }
    }
}

func processWordlist(wordlistPath, baseURL, cookies string, client *http.Client, logger *logrus.Logger) {
    file, err := os.Open(wordlistPath)
    if err != nil {
        logger.Fatalf("Failed to open wordlist file: %v", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        path := strings.TrimSpace(scanner.Text())
        if path == "" {
            continue
        }
        fullURL := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), strings.TrimLeft(path, "/"))
        scanURL(fullURL, cookies, client, logger)
    }

    if err := scanner.Err(); err != nil {
        logger.Fatalf("Error reading wordlist: %v", err)
    }
}

func checkCORS(url string, origin string, client *http.Client, logger *logrus.Logger) bool {
    req, err := http.NewRequest("OPTIONS", url, nil)
    if err != nil {
        logger.Errorf("Failed to create CORS check request: %v", err)
        return false
    }

    req.Header.Set("Origin", origin)
    req.Header.Set("Access-Control-Request-Method", "GET")
    resp, err := client.Do(req)
    if err != nil {
        logger.Errorf("CORS check failed for %s: %v", url, err)
        return false
    }
    defer resp.Body.Close()

    logger.Infof("CORS check for %s with Origin: %s returned status: %d", url, origin, resp.StatusCode)
    if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != "" {
        logger.Infof("Access-Control-Allow-Origin: %s", acao)
        return acao == origin
    }
    return false
}

func extractLinks(body io.Reader, base string, logger *logrus.Logger) []string {
    var links []string
    z := html.NewTokenizer(body)

    for {
        tt := z.Next()
        switch tt {
        case html.ErrorToken:
            return links
        case html.StartTagToken, html.SelfClosingTagToken:
            t := z.Token()
            if t.Data == "a" {
                for _, a := range t.Attr {
                    if a.Key == "href" {
                        link := strings.TrimSpace(a.Val)
                        logger.Infof("Found link: %s", link)
                        links = append(links, link)
                    }
                }
            }
        }
    }
}

func resolveURL(link, base string) string {
    u, err := url.Parse(link)
    if err != nil || u.IsAbs() {
        return link
    }
    baseURL, err := url.Parse(base)
    if err != nil {
        return ""
    }
    return baseURL.ResolveReference(u).String()
}

//
//
