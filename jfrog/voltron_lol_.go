package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/network"
)

// ------------------ CRAWL MODE ------------------

// crawl launches a headless Chrome instance, navigates to target,
// intercepts network responses for .js and .js.map files, and prints unique URLs.
func crawl(target string) error {
	// Create a new Chrome instance
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Create a map to hold unique JS asset URLs.
	uniqueJS := make(map[string]bool)

	// Enable network events.
	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		return fmt.Errorf("failed to enable network: %w", err)
	}

	// Listen for network responses.
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if res, ok := ev.(*network.EventResponseReceived); ok {
			url := res.Response.URL
			if strings.HasSuffix(url, ".js") || strings.HasSuffix(url, ".js.map") {
				uniqueJS[url] = true
			}
		}
	})

	// Navigate to the target URL and wait a bit for assets to load.
	if err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.Sleep(10*time.Second),
	); err != nil {
		return fmt.Errorf("failed to navigate: %w", err)
	}

	// Print out the unique JS assets.
	fmt.Println("Unique JavaScript assets found:")
	for url := range uniqueJS {
		fmt.Println(url)
	}
	return nil
}

// ------------------ SEARCH MODE ------------------

type Catalog struct {
	Repositories []string `json:"repositories"`
}

type TagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type Manifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
}

type ImageConfig struct {
	Created string `json:"created"`
}

type SearchResult struct {
	Image   string
	Tag     string
	Created time.Time
}

// getImageCreationTime retrieves the manifest and config blob to extract the creation timestamp.
func getImageCreationTime(client *http.Client, baseURL, repository, image, tag string) (*time.Time, error) {
	manifestURL := fmt.Sprintf("%s/%s/%s/manifests/%s", baseURL, repository, image, tag)
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manifest request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest request returned status %s", resp.Status)
	}

	var manifest Manifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("error decoding manifest: %w", err)
	}

	configDigest := manifest.Config.Digest
	if configDigest == "" {
		return nil, fmt.Errorf("no config digest found")
	}

	configURL := fmt.Sprintf("%s/%s/%s/blobs/%s", baseURL, repository, image, configDigest)
	resp, err = client.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("config request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config request returned status %s", resp.Status)
	}

	var config ImageConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("error decoding config: %w", err)
	}

	if config.Created == "" {
		return nil, fmt.Errorf("no creation timestamp in config")
	}

	// Parse the creation timestamp (assumed to be in RFC3339 format).
	created, err := time.Parse(time.RFC3339, config.Created)
	if err != nil {
		return nil, fmt.Errorf("error parsing timestamp: %w", err)
	}
	return &created, nil
}

// searchArtifactory searches the Artifactory Docker repository for images whose tags contain the packageName.
func searchArtifactory(baseURL, repository, packageName string) ([]SearchResult, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	catalogURL := fmt.Sprintf("%s/%s/v2/_catalog", baseURL, repository)
	resp, err := client.Get(catalogURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog request failed: %s", resp.Status)
	}
	var catalog Catalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, err
	}

	results := []SearchResult{}
	for _, image := range catalog.Repositories {
		tagsURL := fmt.Sprintf("%s/%s/%s/tags/list", baseURL, repository, image)
		resp, err := client.Get(tagsURL)
		if err != nil {
			log.Printf("Failed to get tags for image '%s': %v", image, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Failed to get tags for image '%s': %s", image, resp.Status)
			resp.Body.Close()
			continue
		}
		var tagsResp TagsResponse
		if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
			log.Printf("Error decoding tags for image '%s': %v", image, err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		for _, tag := range tagsResp.Tags {
			if strings.Contains(strings.ToLower(tag), strings.ToLower(packageName)) {
				created, err := getImageCreationTime(client, baseURL, repository, image, tag)
				if err != nil {
					log.Printf("Error getting creation time for %s:%s: %v", image, tag, err)
					continue
				}
				results = append(results, SearchResult{
					Image:   image,
					Tag:     tag,
					Created: *created,
				})
				fmt.Printf("Found %s:%s (created: %s)\n", image, tag, created.Format(time.RFC3339))
			}
		}
	}

	// Sort results by creation time (latest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Created.After(results[j].Created)
	})

	return results, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [crawl|search] <options...>\n", os.Args[0])
		os.Exit(1)
	}

	mode := os.Args[1]
	switch mode {
	case "crawl":
		crawlFlags := flag.NewFlagSet("crawl", flag.ExitOnError)
		target := crawlFlags.String("target", "", "Target URL to crawl")
		crawlFlags.Parse(os.Args[2:])
		if *target == "" {
			fmt.Fprintln(os.Stderr, "Error: --target must be provided")
			os.Exit(1)
		}
		if err := crawl(*target); err != nil {
			log.Fatalf("Crawl failed: %v", err)
		}
	case "search":
		searchFlags := flag.NewFlagSet("search", flag.ExitOnError)
		packageName := searchFlags.String("package", "", "Package name to search for in image tags")
		baseURL := searchFlags.String("base-url", "https://your-artifactory-url/artifactory", "Artifactory base URL")
		repository := searchFlags.String("repository", "docker-local", "Docker repository name")
		searchFlags.Parse(os.Args[2:])
		if *packageName == "" {
			fmt.Fprintln(os.Stderr, "Error: --package must be provided")
			os.Exit(1)
		}
		results, err := searchArtifactory(*baseURL, *repository, *packageName)
		if err != nil {
			log.Fatalf("Search failed: %v", err)
		}
		if len(results) == 0 {
			fmt.Println("No matching images found.")
		} else {
			fmt.Println("\nMatching images (sorted by creation time, latest first):")
			for _, res := range results {
				fmt.Printf("Image: %s, Tag: %s, Created: %s\n",
					res.Image, res.Tag, res.Created.Format(time.RFC3339))
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s. Use 'crawl' or 'search'.\n", mode)
		os.Exit(1)
	}
}
