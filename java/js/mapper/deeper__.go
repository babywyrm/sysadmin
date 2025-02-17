package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/network"
)

func main() {
	// Set up basic logging flags.
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Determine target URL from command-line argument or prompt.
	var target string
	if len(os.Args) > 1 {
		target = os.Args[1]
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter target URL (e.g., https://reactjs.org): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read input: %v", err)
		}
		target = strings.TrimSpace(input)
	}
	if target == "" {
		log.Fatal("No target URL provided")
	}

	// Parse target to extract a domain for logfile naming.
	parsedURL, err := url.Parse(target)
	var domain string
	if err == nil && parsedURL.Host != "" {
		domain = parsedURL.Host
	} else {
		domain = target
	}
	// Sanitize domain by replacing ":" with "_" (in case of port numbers).
	sanitizedDomain := strings.ReplaceAll(domain, ":", "_")
	timestamp := time.Now().Format("20060102-150405")
	logFilename := fmt.Sprintf("%s_%s.log", sanitizedDomain, timestamp)

	// Create the target-specific logfile.
	logFile, err := os.Create(logFilename)
	if err != nil {
		log.Fatalf("Failed to create target log file: %v", err)
	}
	defer logFile.Close()

	// Set up a MultiWriter so that logs are written to both stdout and our logfile.
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
	log.Printf("Logging to file: %s", logFilename)

	// Maps to store unique JS assets and detected frameworks.
	uniqueJS := make(map[string]bool)
	detectedFrameworks := make(map[string]bool)

	// List of known JS frameworks to search for.
	frameworks := []string{"react", "angular", "vue", "ember", "backbone", "svelte", "jquery", "polymer"}

	log.Printf("Starting Chrome instance for target: %s", target)

	// Create a new Chrome context with logging enabled.
	ctx, cancel := chromedp.NewContext(context.Background(), chromedp.WithLogf(log.Printf))
	defer cancel()

	// Set an overall timeout for the entire operation.
	ctx, cancelTimeout := context.WithTimeout(ctx, 90*time.Second)
	defer cancelTimeout()

	// Enable network events.
	log.Println("Enabling network events...")
	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		log.Fatalf("Failed to enable network events: %v", err)
	}
	log.Println("Network events enabled.")

	// Listen for network events.
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventResponseReceived:
			url := ev.Response.URL
			log.Printf("Response received: %s (status: %d)", url, int(ev.Response.Status))
			// Check if this is a JS or JS.map asset.
			if strings.HasSuffix(url, ".js") || strings.HasSuffix(url, ".js.map") {
				// Save only unique URLs.
				if !uniqueJS[url] {
					log.Printf("Detected unique JS asset: %s", url)
					uniqueJS[url] = true
					// Try to detect JS frameworks based on URL patterns.
					lowerURL := strings.ToLower(url)
					for _, fw := range frameworks {
						if strings.Contains(lowerURL, fw) {
							detectedFrameworks[fw] = true
						}
					}
				}
			}
		case *network.EventRequestWillBeSent:
			log.Printf("Request sent: %s", ev.Request.URL)
		}
	})

	// Create a separate context for navigation with an extended timeout.
	navCtx, cancelNav := context.WithTimeout(ctx, 12*time.Second)
	defer cancelNav()
	log.Printf("Navigating to target: %s", target)
	err = chromedp.Run(navCtx,
		chromedp.Navigate(target),
		// Allow time for assets to load.
		chromedp.Sleep(10*time.Second),
	)
	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") {
			log.Printf("Navigation timed out (context deadline exceeded): %v", err)
			// Continue processing whatever data has been captured.
		} else {
			log.Fatalf("Failed to navigate: %v", err)
		}
	} else {
		log.Println("Navigation complete.")
	}

	log.Println("Crawling complete!")

	// Log summary: unique JS assets.
	log.Println("===== Unique JS Assets =====")
	for jsURL := range uniqueJS {
		log.Printf(" - %s", jsURL)
	}

	// Log detected frameworks.
	if len(detectedFrameworks) > 0 {
		log.Println("===== Detected JS Frameworks =====")
		for fw := range detectedFrameworks {
			log.Printf(" - %s", fw)
		}
	} else {
		log.Println("No known JS frameworks detected.")
	}

	// Attempt to detect version information for each detected framework.
	frameworkVersionJS := map[string]string{
		"react":    `window.React && window.React.version ? window.React.version : ""`,
		"angular":  `window.angular && window.angular.version ? window.angular.version.full : ""`,
		"vue":      `window.Vue && window.Vue.version ? window.Vue.version : ""`,
		"jquery":   `window.jQuery ? window.jQuery.fn.jquery : ""`,
		"ember":    `window.Ember && window.Ember.VERSION ? window.Ember.VERSION : ""`,
		"backbone": `window.Backbone && window.Backbone.VERSION ? window.Backbone.VERSION : ""`,
		// For svelte and polymer, version detection might not be straightforward.
		"svelte":  `""`,
		"polymer": `""`,
	}

	frameworkVersions := make(map[string]string)
	log.Println("===== Attempting to Detect Framework Versions =====")
	for fw := range detectedFrameworks {
		jsExpr, ok := frameworkVersionJS[fw]
		if ok {
			var version string
			err := chromedp.Run(ctx, chromedp.Evaluate(jsExpr, &version))
			if err != nil {
				log.Printf("Error evaluating version for %s: %v", fw, err)
				version = "error"
			}
			if version == "" {
				version = "not detected"
			}
			frameworkVersions[fw] = version
		} else {
			frameworkVersions[fw] = "unknown"
		}
	}

	// Log the framework version information.
	if len(frameworkVersions) > 0 {
		log.Println("===== Detected JS Framework Versions =====")
		for fw, version := range frameworkVersions {
			log.Printf(" - %s: %s", fw, version)
		}
	} else {
		log.Println("No framework version information detected.")
	}
}
