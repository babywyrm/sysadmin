package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/chromedp/chromedp"
)

const (
	loginURL = "https://example.com/login" 
	username  = "your_username"             
	password  = "your_password"             
	ajaxDelay = 2 * time.Second
	maxDepth  = 3
)

func main() {
	// Create a new context
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Run the login and crawling process
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	// Log in to the application
	if err := login(ctx); err != nil {
		return err
	}

	// Start crawling from the dashboard
	visitedLinks := make(map[string]bool)
	startingURLs := []string{loginURL} // You can modify this to start from the dashboard
	crawlLinks(ctx, startingURLs, visitedLinks)

	// Save found links to file
	saveLinks(visitedLinks)

	return nil
}

func login(ctx context.Context) error {
	log.Println("Starting login process...")

	// Navigate to the login page
	if err := chromedp.Run(ctx,
		chromedp.Navigate(loginURL),
		chromedp.WaitVisible(`#email`, chromedp.ByID),
		chromedp.SendKeys(`#email`, username, chromedp.ByID),
		chromedp.SendKeys(`#password`, password, chromedp.ByID),
		chromedp.Click(`button[type="submit"]`, chromedp.NodeVisible),
		chromedp.WaitTitleContains("Dashboard"), // Wait for the title to contain "Dashboard"
	); err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	log.Println("Login successful.")
	return nil
}

func extractLinks(ctx context.Context) ([]string, error) {
	var links []string
	err := chromedp.Run(ctx,
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a')).map(a => a.href).filter(href => href.startsWith('https://example.com'))`, &links),
	)
	if err != nil {
		log.Printf("Error extracting links: %v", err)
		return nil, err
	}
	log.Printf("Extracted %d links from the page.", len(links))
	return links, nil
}

func crawlLinks(ctx context.Context, urls []string, visited map[string]bool) {
	for _, url := range urls {
		if visited[url] {
			log.Printf("Already visited %s, skipping...\n", url)
			continue
		}

		log.Printf("Visiting %s\n", url)
		visited[url] = true

		// Navigate to the URL
		if err := chromedp.Run(ctx,
			chromedp.Navigate(url),
			chromedp.Sleep(ajaxDelay), // Wait for AJAX content to load
		); err != nil {
			log.Printf("Failed to navigate to %s: %v\n", url, err)
			continue
		}

		// Extract links from the page
		newLinks, err := extractLinks(ctx)
		if err != nil {
			log.Printf("Failed to extract links from %s: %v\n", url, err)
			continue
		}

		// Recursively crawl the new links
		crawlLinks(ctx, newLinks, visited)
	}
}

func saveLinks(links map[string]bool) {
	file, err := os.Create("crawled_links.txt")
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	for link := range links {
		if _, err := file.WriteString(link + "\n"); err != nil {
			log.Printf("Failed to write link to file: %v", err)
		}
	}

	log.Printf("Crawling complete. %d unique links saved to crawled_links.txt.", len(links))
}
