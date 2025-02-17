package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/network"
)

func main() {
	// Set up logging with timestamps and file:line info.
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

	// Maps to store unique JS assets and detected frameworks.
	uniqueJS := make(map[string]bool)
	detectedFrameworks := make(map[string]bool)

	// List of known JS frameworks to search for.
	frameworks := []string{"react", "angular", "vue", "ember", "backbone", "svelte", "jquery", "polymer"}

	log.Printf("Starting Chrome instance for target: %s", target)

	// Create a new Chrome context with logging enabled.
	ctx, cancel := chromedp.NewContext(context.Background(), chromedp.WithLogf(log.Printf))
	defer cancel()

	// Set a timeout to avoid hanging indefinitely.
	ctx, cancelTimeout := context.WithTimeout(ctx, 30*time.Second)
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

	// Navigate to the target URL.
	log.Printf("Navigating to target: %s", target)
	if err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		// Increase the sleep time if the site loads assets slowly.
		chromedp.Sleep(10*time.Second),
	); err != nil {
		log.Fatalf("Failed to navigate: %v", err)
	}

	log.Println("Crawling complete!")

	// Save unique JS assets to a logfile.
	jsFile, err := os.Create("unique_js_paths.log")
	if err != nil {
		log.Fatalf("Failed to create unique_js_paths.log: %v", err)
	}
	defer jsFile.Close()

	writer := bufio.NewWriter(jsFile)
	for url := range uniqueJS {
		_, err := writer.WriteString(url + "\n")
		if err != nil {
			log.Printf("Failed to write URL to logfile: %v", err)
		}
	}
	writer.Flush()
	log.Println("Unique JS paths saved to unique_js_paths.log")

	// Log detected frameworks.
	if len(detectedFrameworks) > 0 {
		log.Println("Detected JS frameworks:")
		for fw := range detectedFrameworks {
			log.Printf(" - %s", fw)
		}
	} else {
		log.Println("No known JS frameworks detected.")
	}

	// Now attempt to detect version information for each detected framework.
	// Define JavaScript snippets to query each framework's version.
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
	log.Println("Attempting to detect framework versions...")
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
		log.Println("Detected JS framework versions:")
		for fw, version := range frameworkVersions {
			log.Printf(" - %s: %s", fw, version)
		}
	} else {
		log.Println("No framework version information detected.")
	}
}
